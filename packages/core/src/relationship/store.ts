// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * RelationshipStore — SQLite-backed relationship records backed by the shared
 * P2PTS migration table `relationships` (migration 0005).
 *
 * Uses uuid FK relationships (`local_identity_uuid` → identities.uuid,
 * `remote_identity_uuid` → identities.uuid, `did_document_uuid` → did_documents.uuid)
 * instead of raw VID/DID strings. An {@link IdentityResolver} bridges the
 * agent's string-based DID/VID world to the uuid FK model.
 *
 * ## Key resolution via FK joins
 *
 * The remote peer's Ed25519 / X25519 public keys are resolved at query time
 * by joining `identities.uuid` → `keys.identity_uuid` (populated by
 * IdentityResolver when the remote identity's DID document is first stored).
 * No denormalized BLOB columns on `relationships`; no per-read JSON parsing.
 */

import type { DatabaseSync } from 'node:sqlite';
import type { DidDocument } from '../did/types.js';
import type { TransportAddress } from '../transport/types.js';
import type { IdentityResolver } from '../services/identity-resolver.js';
import type {
  RelationshipRecord,
  RelationshipDirection,
  RelationshipStatus,
} from './types.js';
import { buildCleanPeer4FromDocument, extractDisplayNameFromDocument } from './key-extract.js';
import { ceremonyTrace } from './ceremony-trace.js';
import { generateUuid } from '../db/uuid-helpers.js';

// ---------------------------------------------------------------------------
// Row type (raw migration-table row + JOINed columns)
// ---------------------------------------------------------------------------

interface RelationshipRow {
  uuid: string;
  local_identity_uuid: string;
  remote_identity_uuid: string;
  local_did_document_uuid: string | null;
  remote_did_document_uuid: string | null;
  direction: string;
  status: string;
  remote_transport: string | null;
  rfi_digest: Buffer | null;
  rfa_reply_digest: Buffer | null;
  created_at: number;
  updated_at: number;
  /** Real DID string from did_documents.did. */
  localDid: string;
  /** Real DID string from did_documents.did. */
  remoteDid: string;
  /** FK-joined keys.public_key for Ed25519 (NULL if not yet extracted). */
  remoteEd25519Key: Buffer | null;
  /** FK-joined keys.public_key for X25519 (NULL if not yet extracted). */
  remoteX25519Key: Buffer | null;
  /** FK-joined keys.public_key for MLKEM768-X25519 (NULL if the peer publishes none). */
  remoteHybridKemKey: Buffer | null;
  /** FK-joined keys.public_key for ML-DSA-65 (NULL if the peer publishes none). */
  remoteMlDsa65Key: Buffer | null;
  /** FK-joined identities.subject_kind for the remote identity. */
  remoteSubjectKind: string | null;
  /** Personhood ceremony status. */
  personhood_status: string | null;
}

// ---------------------------------------------------------------------------
// RelationshipStore
// ---------------------------------------------------------------------------

export class RelationshipStore {
  private readonly db: DatabaseSync;
  private readonly resolver: IdentityResolver;

  constructor(db: DatabaseSync, resolver: IdentityResolver) {
    this.db = db;
    this.resolver = resolver;
  }

  // ---------------------------------------------------------------------------
  // Insert outbound (when we send an RFI)
  // ---------------------------------------------------------------------------

  insertOutbound(params: {
    localDid: string;
    localMethod: string;
    remoteDid: string;
    remoteMethod: string;
    /** Optional — the initiator doesn't have the remote peer's DID doc at RFI time. */
    didDocument?: DidDocument;
    remoteTransport: TransportAddress;
    rfiDigest?: Uint8Array;
    /** Subject kind for the remote identity ('human' | 'organization'). Defaults to 'human'. */
    subjectKind?: string;
  }): void {
    const local = this.ensureLocalIdentity(params.localDid);
    const remote = this.resolver.resolveRemoteIdentity({
      did: params.remoteDid,
      method: params.remoteMethod,
      didDocumentJson: params.didDocument
        ? JSON.stringify(buildCleanPeer4FromDocument(params.didDocument))
        : undefined,
      name: params.didDocument ? extractDisplayNameFromDocument(params.didDocument) : undefined,
      isPrimary: false,
      recordedByNode: 'tsp-bridge',
      subjectKind: params.subjectKind,
    });

    ceremonyTrace.identityResolved({
      did: params.remoteDid,
      identityUuid: remote.identityUuid,
      newlyCreated: false,
    });

    const existing = this.db.prepare(`
      SELECT 1 FROM relationships
      WHERE local_identity_uuid = ? AND remote_identity_uuid = ?
    `).get(local.identityUuid, remote.identityUuid);
    if (existing) {
      throw new Error(`RelationshipStore.insertOutbound: relationship already exists`);
    }

    this.db.prepare(`
      INSERT INTO relationships
        (local_identity_uuid, remote_identity_uuid,
         local_did_document_uuid, remote_did_document_uuid,
         direction, status, remote_transport, rfi_digest, uuid, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'outbound', 'pending', ?, ?, ?, unixepoch(), unixepoch())
    `).run(
      local.identityUuid,
      remote.identityUuid,
      local.didDocumentUuid,
      remote.didDocumentUuid,
      JSON.stringify(params.remoteTransport),
      params.rfiDigest ?? null,
      generateUuid(),
    );
  }

  // ---------------------------------------------------------------------------
  // Upsert inbound (when we receive an RFI)
  // ---------------------------------------------------------------------------

  upsertInbound(params: {
    localDid: string;
    localMethod: string;
    remoteDid: string;
    remoteMethod: string;
    didDocument: DidDocument;
    remoteTransport: TransportAddress;
    rfiDigest?: Uint8Array;
    /** Subject kind for the remote identity ('human' | 'organization'). Defaults to 'human'. */
    subjectKind?: string;
  }): 'accepted' | 'rejected-lower-digest' {
    const local = this.ensureLocalIdentity(params.localDid);
    const remote = this.resolver.resolveRemoteIdentity({
      did: params.remoteDid,
      method: params.remoteMethod,
      didDocumentJson: JSON.stringify(buildCleanPeer4FromDocument(params.didDocument)),
      name: extractDisplayNameFromDocument(params.didDocument),
      isPrimary: false,
      recordedByNode: 'tsp-bridge',
      subjectKind: params.subjectKind,
    });

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db.prepare(`
        SELECT direction FROM relationships
        WHERE local_identity_uuid = ? AND remote_identity_uuid = ?
      `).get(local.identityUuid, remote.identityUuid) as { direction: string } | undefined;

      if (existing && existing.direction === 'outbound') {
        this.db.prepare(`
          UPDATE relationships SET direction = 'bidirectional', status = 'established',
            remote_transport = ?, rfi_digest = COALESCE(rfi_digest, ?),
            updated_at = unixepoch()
          WHERE local_identity_uuid = ? AND remote_identity_uuid = ?
        `).run(
          JSON.stringify(params.remoteTransport),
          params.rfiDigest ?? null,
          local.identityUuid,
          remote.identityUuid,
        );
      } else if (existing) {
        this.db.prepare(`
          UPDATE relationships SET direction = 'inbound', status = 'pending',
            remote_transport = ?, rfi_digest = COALESCE(rfi_digest, ?),
            updated_at = unixepoch()
          WHERE local_identity_uuid = ? AND remote_identity_uuid = ?
        `).run(
          JSON.stringify(params.remoteTransport),
          params.rfiDigest ?? null,
          local.identityUuid,
          remote.identityUuid,
        );
      } else {
        this.db.prepare(`
          INSERT INTO relationships
            (local_identity_uuid, remote_identity_uuid,
             local_did_document_uuid, remote_did_document_uuid,
             direction, status, remote_transport, rfi_digest, uuid, created_at, updated_at)
          VALUES (?, ?, ?, ?, 'inbound', 'pending', ?, ?, ?, unixepoch(), unixepoch())
        `).run(
          local.identityUuid,
          remote.identityUuid,
          local.didDocumentUuid,
          remote.didDocumentUuid,
          JSON.stringify(params.remoteTransport),
          params.rfiDigest ?? null,
          generateUuid(),
        );
      }

      this.db.exec('COMMIT');
      return 'accepted';
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }

  // ---------------------------------------------------------------------------
  // Confirm bidirectional (when we receive a valid RFA)
  // ---------------------------------------------------------------------------

  confirmBidirectional(params: {
    localDid: string;
    remoteDid: string;
    remoteTransport: TransportAddress;
    rfaReplyDigest?: Uint8Array;
  }): void {
    const local = this.resolver.lookupByDid(params.localDid);
    const remote = this.resolver.lookupByDid(params.remoteDid);
    if (!local || !remote) {
      throw new Error('RelationshipStore.confirmBidirectional: identity not resolved');
    }

    const result = this.db.prepare(`
      UPDATE relationships SET direction = 'bidirectional', status = 'established',
        remote_transport = ?,
        rfa_reply_digest = COALESCE(?, rfa_reply_digest),
        updated_at = unixepoch()
      WHERE local_identity_uuid = ? AND remote_identity_uuid = ?
    `).run(
      JSON.stringify(params.remoteTransport),
      params.rfaReplyDigest ?? null,
      local.identityUuid,
      remote.identityUuid,
    ) as { changes: number };

    if (result.changes === 0) {
      throw new Error('RelationshipStore.confirmBidirectional: no record found');
    }

    // Relationship is now established. Promote the remote identity's primary
    // DID document so `remoteDid` resolves for outbound sends. Handshake stub
    // rows are `is_primary = 0` (sendRfi/upsertInbound pass `isPrimary: false`),
    // so without this the responder side has `remoteDid === null` and any
    // later RelationshipManager.sendDirect() crashes on `remoteDid.slice(0,12)`,
    // aborting the enclosing transaction (e.g. agent name registration).
    this.promoteRemoteDidToPrimary(local.identityUuid, remote.identityUuid);
  }

  /**
   * Mark a relationship as `rejected` so an initiator stops waiting.
   *
   * Used when the peer DECLINES our invite with a TSP `XRFD`. Without this the
   * outbound-pending record stays as it was and every caller that polls for
   * `bidirectional` (e.g. `TspBridge.waitForBidirectional`) runs to its full
   * timeout with no explanation; with it, the poll can fail immediately and
   * report that the peer declined.
   *
   * Idempotent, and never downgrades an already-established relationship
   * (a stale/duplicate decline for a live relationship is ignored).
   */
  markRejected(localDid: string, remoteDid: string): boolean {
    const local = this.resolver.lookupByDid(localDid);
    const remote = this.resolver.lookupByDid(remoteDid);
    if (!local || !remote) return false;

    const result = this.db.prepare(`
      UPDATE relationships SET status = 'rejected', updated_at = unixepoch()
      WHERE local_identity_uuid = ? AND remote_identity_uuid = ?
        AND status != 'established'
    `).run(local.identityUuid, remote.identityUuid) as { changes: number };

    return result.changes > 0;
  }

  /**
   * Record/promote the remote peer's current libp2p endpoint (from the live
   * transport `fromAddr` of an RFI/RFA/GEN). This lets a peer that restarted
   * with a new node key self-heal its stored endpoint on the OTHER side
   * without manual re-discovery: the handshake message itself carries the
   * current peer_id, and recording it retires any superseded endpoint.
   */
  recordEndpointForRemote(_localDid: string, remoteDid: string, peerId: string): void {
    const remote = this.resolver.lookupByDid(remoteDid) ?? this.resolver.lookupByVid(remoteDid);
    if (!remote) return;
    this.resolver.updatePeerUuidEndpoint(remote.identityUuid, peerId);
  }

  // ---------------------------------------------------------------------------
  // Digest setters
  // ---------------------------------------------------------------------------

  setRfiDigest(localDid: string, remoteDid: string, rfiDigest: Uint8Array): void {
    const local = this.resolver.lookupByDid(localDid);
    const remote = this.resolver.lookupByDid(remoteDid);
    if (!local || !remote) return;

    this.db.prepare(`
      UPDATE relationships SET rfi_digest = ?, updated_at = unixepoch()
      WHERE local_identity_uuid = ? AND remote_identity_uuid = ?
    `).run(rfiDigest, local.identityUuid, remote.identityUuid);
  }

  setRfaReplyDigest(localDid: string, remoteDid: string, rfaReplyDigest: Uint8Array): void {
    const local = this.resolver.lookupByDid(localDid);
    const remote = this.resolver.lookupByDid(remoteDid);
    if (!local || !remote) return;

    this.db.prepare(`
      UPDATE relationships SET rfa_reply_digest = ?, updated_at = unixepoch()
      WHERE local_identity_uuid = ? AND remote_identity_uuid = ?
    `).run(rfaReplyDigest, local.identityUuid, remote.identityUuid);
  }

  // ---------------------------------------------------------------------------
  // Queries — public keys resolved from keys table via FK join
  // ---------------------------------------------------------------------------

  /**
   * Shared column list used by both get() and list().
   *
   * Joins the `keys` table twice — once for ed25519 (rotation_version 0)
   * and once for x25519 (rotation_version 0) — to resolve the remote peer's
   * public keys without JSON-parsing did_documents.document_json on every read.
   * Keys are populated by IdentityResolver when the remote identity is first
   * resolved (see upsertRemotePublicKeys).
   */
  private readonly SELECT_COLUMNS = `
    r.uuid, r.local_identity_uuid, r.remote_identity_uuid,
    r.local_did_document_uuid, r.remote_did_document_uuid,
    r.direction, r.status, r.remote_transport,
    r.rfi_digest, r.rfa_reply_digest,
    r.created_at, r.updated_at, r.personhood_status,
    lid.did AS localDid, rid.did AS remoteDid,
    ked.public_key AS remoteEd25519Key,
    kex.public_key AS remoteX25519Key,
    kmk.public_key AS remoteHybridKemKey,
    kml.public_key AS remoteMlDsa65Key,
    ri.subject_kind AS remoteSubjectKind
  `;

  private readonly FROM_JOINS = `
    FROM relationships r
    LEFT JOIN did_documents lid ON lid.identity_uuid = r.local_identity_uuid AND lid.is_primary = 1
    LEFT JOIN did_documents rid ON rid.identity_uuid = r.remote_identity_uuid AND rid.is_primary = 1
    LEFT JOIN identities ri ON ri.uuid = r.remote_identity_uuid
    LEFT JOIN keys ked ON ked.identity_uuid = ri.uuid
                       AND ked.key_type = 'ed25519'
                       AND ked.rotation_version = 0
    LEFT JOIN keys kex ON kex.identity_uuid = ri.uuid
                       AND kex.key_type = 'x25519'
                       AND kex.rotation_version = 0
    LEFT JOIN keys kmk ON kmk.identity_uuid = ri.uuid
                       AND kmk.key_type = 'mlkem768_x25519'
                       AND kmk.rotation_version = 0
    LEFT JOIN keys kml ON kml.identity_uuid = ri.uuid
                       AND kml.key_type = 'ml_dsa_65'
                       AND kml.rotation_version = 0
  `;

  /**
   * The ML-DSA-65 public key pinned for a remote identity from a document this
   * node already accepted (a completed handshake, or an identity push).
   *
   * Keyed by IDENTITY, not by relationship: an introduction can arrive before any
   * relationship row exists, and the check that needs this key
   * (`checkOobiIntroductionIntegrity`) must be able to reach a peer we know but
   * have no live relationship with. That is also why this cannot be satisfied by
   * the FK-joined `remoteMlDsa65Key` on a relationship record alone.
   *
   * @returns the key, or `undefined` when this node has never accepted a document
   *          for that DID (a true first contact — nothing to verify against).
   */
  getRemoteMlDsa65Key(remoteDid: string): Uint8Array | undefined {
    const remote = this.resolver.lookupByDid(remoteDid) ?? this.resolver.lookupByVid(remoteDid);
    if (!remote) return undefined;

    const row = this.db.prepare(`
      SELECT public_key FROM keys
       WHERE identity_uuid = ? AND key_type = 'ml_dsa_65' AND rotation_version = 0
       LIMIT 1
    `).get(remote.identityUuid) as { public_key: Uint8Array } | undefined;

    return row ? new Uint8Array(row.public_key) : undefined;
  }

  get(localDid: string, remoteDid: string): RelationshipRecord | undefined {
    const local = this.resolver.lookupByDid(localDid);
    const remote = this.resolver.lookupByDid(remoteDid) ?? this.resolver.lookupByVid(remoteDid);
    if (!local || !remote) return undefined;

    const row = this.db.prepare(`
      SELECT ${this.SELECT_COLUMNS}
      ${this.FROM_JOINS}
      WHERE r.local_identity_uuid = ? AND r.remote_identity_uuid = ?
    `).get(local.identityUuid, remote.identityUuid) as RelationshipRow | undefined;

    return row ? this.rowToRecord(row) : undefined;
  }

  /**
   * Look up a relationship record when the caller only knows the remote peer's
   * CESR-encoded VID (the live signing key). Resolves the VID onto the real
   * identity via the `keys` table (IdentityResolver.lookupByVid, Workstream A+C)
   * and returns the record keyed by that identity. Falls back to a direct DID
   * lookup for legacy VID-named rows.
   */
  getByVid(localDid: string, remoteDid: string): RelationshipRecord | undefined {
    const local = this.resolver.lookupByDid(localDid);
    if (!local) return undefined;
    const remote = this.resolver.lookupByVid(remoteDid) ?? this.resolver.lookupByDid(remoteDid);
    if (!remote) return undefined;

    const row = this.db.prepare(`
      SELECT ${this.SELECT_COLUMNS}
      ${this.FROM_JOINS}
      WHERE r.local_identity_uuid = ? AND r.remote_identity_uuid = ?
    `).get(local.identityUuid, remote.identityUuid) as RelationshipRow | undefined;

    return row ? this.rowToRecord(row) : undefined;
  }

  list(localDid: string): RelationshipRecord[] {
    const local = this.resolver.lookupByDid(localDid);
    if (!local) return [];

    const rows = this.db.prepare(`
      SELECT ${this.SELECT_COLUMNS}
      ${this.FROM_JOINS}
      WHERE r.local_identity_uuid = ? ORDER BY r.created_at ASC
    `).all(local.identityUuid) as unknown as RelationshipRow[];

    return rows.map(r => this.rowToRecord(r));
  }

  // ---------------------------------------------------------------------------
  // Store remote peer's DID document (used by initiator when RFA arrives)
  // ---------------------------------------------------------------------------

  /**
   * Store the remote peer's DID document and extract keys into the keys table.
   * Called by processRfa() when the initiator receives the responder's DID
   * document in the RFA payload. Idempotent — safe to call multiple times.
   */
  storeRemoteDidDocument(localDid: string, remoteDid: string, didDocument: DidDocument): void {
    const local = this.resolver.lookupByDid(localDid);
    const remoteBefore = this.resolver.lookupByDid(remoteDid);
    if (!local || !remoteBefore) return;

    // Re-resolve the remote identity with the DID document. The resolver is
    // idempotent — it will update the existing did_documents row and
    // upsertRemotePublicKeys() will populate the keys table if not already done.
    const remote = this.resolver.resolveRemoteIdentity({
      did: remoteDid,
      // The RFA document is the responder's real doc — derive the real method
      // from its id (not a hardcoded 'did:peer:4'), so the upsert in
      // upsertDidDocument updates the stub row created by sendRfi instead of
      // colliding on UNIQUE(identity_uuid, did).
      method: (didDocument.id ?? remoteDid).startsWith('did:scid:vh:')
        ? 'did:scid:vh'
        : 'did:peer:4',
      didDocumentJson: JSON.stringify(buildCleanPeer4FromDocument(didDocument)),
      name: extractDisplayNameFromDocument(didDocument),
      // The RFA carries the responder's real DID document, but the promotion
      // to `is_primary = 1` is done at the ceremony choke point
      // (confirmBidirectional → promoteRemoteDidToPrimary), which covers both
      // the initiator (RFA) and responder (RFI) sides with a single owner.
      isPrimary: false,
      recordedByNode: 'tsp-bridge',
    });

    // Update the relationships FK to point to the newly-stored DID document.
    // This is necessary because the outbound record was inserted without a
    // remote DID document (initiator doesn't have it at RFI time).
    if (remote.didDocumentUuid) {
      this.db.prepare(`
        UPDATE relationships SET
          remote_did_document_uuid = ?,
          updated_at = unixepoch()
        WHERE local_identity_uuid = ? AND remote_identity_uuid = ?
      `).run(remote.didDocumentUuid, local.identityUuid, remote.identityUuid);
    }
  }

  // ---------------------------------------------------------------------------
  // Simple updates
  // ---------------------------------------------------------------------------

  updateTransport(localDid: string, remoteDid: string, transport: TransportAddress): void {
    const local = this.resolver.lookupByDid(localDid);
    const remote = this.resolver.lookupByDid(remoteDid);
    if (!local || !remote) return;

    this.db.prepare(`
      UPDATE relationships SET remote_transport = ?, updated_at = unixepoch()
      WHERE local_identity_uuid = ? AND remote_identity_uuid = ?
    `).run(JSON.stringify(transport), local.identityUuid, remote.identityUuid);
  }

  /**
   * Update the remote identity's subject_kind for a relationship.
   *
   * Used to self-heal a relationship that was previously stored with the
   * wrong subject kind (e.g., a utility server stored as 'human' before the
   * subject-kind tagging was introduced). The remote identity row is updated
   * directly so the change is reflected in subsequent list()/get() reads.
   */
  updateRemoteSubjectKind(localDid: string, remoteDid: string, subjectKind: string): void {
    const local = this.resolver.lookupByDid(localDid);
    const remote = this.resolver.lookupByDid(remoteDid) ?? this.resolver.lookupByVid(remoteDid);
    if (!local || !remote) return;

    this.db.prepare(`
      UPDATE identities SET subject_kind = ?, updated_at = unixepoch()
      WHERE uuid = ? AND subject_kind != ?
    `).run(subjectKind, remote.identityUuid, subjectKind);
  }

  // ---------------------------------------------------------------------------
  // Primary DID document promotion (ceremony choke point)
  // ---------------------------------------------------------------------------

  /**
   * Ensure a remote identity has an `is_primary = 1` did_documents row so the
   * relationship record's `remoteDid` (joined on `is_primary = 1`) resolves.
   *
   * Remote identities are materialised as `is_primary = 0` stubs during the
   * handshake (sendRfi / upsertInbound pass `isPrimary: false`). Called from
   * {@link confirmBidirectional} — the single choke point both the initiator
   * (RFA) and the responder (RFI) fly through — so the promotion happens at
   * ceremony time on a fresh database, not lazily at a later connect.
   *
   * Without it, an established relationship can still carry `remoteDid === null`,
   * and any outbound RelationshipManager.sendDirect() then crashes on
   * `record.remoteDid.slice(0,12)`, failing the enclosing transaction
   * (e.g. agent name registration).
   *
   * Idempotent: promotes only when no primary row exists, preferring the
   * document referenced by the relationship's `remote_did_document_uuid`
   * (that is the current, verified document), falling back to the newest doc.
   */
  private promoteRemoteDidToPrimary(localIdentityUuid: string, remoteIdentityUuid: string): void {
    const hasPrimary = this.db.prepare(
      `SELECT 1 FROM did_documents WHERE identity_uuid = ? AND is_primary = 1 LIMIT 1`,
    ).get(remoteIdentityUuid);
    if (hasPrimary) return; // already healthy

    const rel = this.db.prepare(
      `SELECT remote_did_document_uuid FROM relationships
       WHERE local_identity_uuid = ? AND remote_identity_uuid = ? LIMIT 1`,
    ).get(localIdentityUuid, remoteIdentityUuid) as { remote_did_document_uuid: string | null } | undefined;

    let targetUuid = rel?.remote_did_document_uuid ?? null;
    if (!targetUuid) {
      const doc = this.db.prepare(
        `SELECT uuid FROM did_documents
         WHERE identity_uuid = ? ORDER BY created_at DESC LIMIT 1`,
      ).get(remoteIdentityUuid) as { uuid: string } | undefined;
      targetUuid = doc?.uuid ?? null;
    }
    if (!targetUuid) return;

    this.db.prepare(
      `UPDATE did_documents SET is_primary = 1, updated_at = unixepoch() WHERE uuid = ?`,
    ).run(targetUuid);
    console.log(
      `[RelationshipStore] ✓ promoted did_documents ${targetUuid.slice(0, 12)}... to primary for identity ${remoteIdentityUuid.slice(0, 12)}... (confirmBidirectional)`,
    );
  }

  /**
   * Set the personhood ceremony status for a relationship.
   * Transitions: undefined → 'acknowledged' → 'verified'.
   */
  setPersonhoodStatus(
    localDid: string,
    remoteDid: string,
    status: 'acknowledged' | 'verified',
  ): void {
    const local = this.resolver.lookupByDid(localDid);
    const remote = this.resolver.lookupByDid(remoteDid);
    if (!local || !remote) return;
    this.db.prepare(`
      UPDATE relationships
      SET personhood_status = ?, updated_at = unixepoch()
      WHERE local_identity_uuid = ? AND remote_identity_uuid = ?
    `).run(status, local.identityUuid, remote.identityUuid);
  }

  deleteRecord(localDid: string, remoteDid: string): void {
    const local = this.resolver.lookupByDid(localDid);
    const remote = this.resolver.lookupByDid(remoteDid);
    if (!local || !remote) return;

    this.db.prepare(`
      DELETE FROM relationships WHERE local_identity_uuid = ? AND remote_identity_uuid = ?
    `).run(local.identityUuid, remote.identityUuid);
  }

  pruneStaleOutbound(localDid: string, olderThanSeconds: number): number {
    const local = this.resolver.lookupByDid(localDid);
    if (!local) return 0;

    const cutoff = Math.floor(Date.now() / 1000) - olderThanSeconds;
    const result = this.db.prepare(`
      DELETE FROM relationships
      WHERE local_identity_uuid = ?
        AND direction = 'outbound'
        AND status = 'pending'
        AND created_at < ?
    `).run(local.identityUuid, cutoff) as { changes: number };
    return result.changes;
  }

  // ---------------------------------------------------------------------------
  // Private
  // ---------------------------------------------------------------------------

  private ensureLocalIdentity(did: string) {
    const resolved = this.resolver.lookupByDid(did);
    if (!resolved) {
      throw new Error(`RelationshipStore: local identity "${did}" not resolved`);
    }
    return resolved;
  }

  /**
   * Convert a row to a RelationshipRecord. Remote peer's Ed25519 / X25519 keys
   * come from the FK-joined `keys` table columns (populated by IdentityResolver
   * when the remote identity is first resolved). No JSON parsing required —
   * the keys table is the canonical public key registry.
   */
  private rowToRecord(row: RelationshipRow): RelationshipRecord {
    return {
      localDid: row.localDid,
      remoteDid: row.remoteDid,
      direction: row.direction as RelationshipDirection,
      status: row.status as RelationshipStatus,
      rfiDigest: row.rfi_digest ? new Uint8Array(row.rfi_digest) : undefined,
      rfaReplyDigest: row.rfa_reply_digest ? new Uint8Array(row.rfa_reply_digest) : undefined,
      remoteEd25519Key: row.remoteEd25519Key ? new Uint8Array(row.remoteEd25519Key) : undefined,
      remoteX25519Key: row.remoteX25519Key ? new Uint8Array(row.remoteX25519Key) : undefined,
      remoteHybridKemKey: row.remoteHybridKemKey ? new Uint8Array(row.remoteHybridKemKey) : undefined,
      remoteMlDsa65Key: row.remoteMlDsa65Key ? new Uint8Array(row.remoteMlDsa65Key) : undefined,
      remoteTransport: row.remote_transport
        ? (JSON.parse(row.remote_transport) as TransportAddress)
        : undefined,
      remoteSubjectKind: row.remoteSubjectKind,
      personhoodStatus: (row.personhood_status as 'acknowledged' | 'verified') ?? undefined,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}