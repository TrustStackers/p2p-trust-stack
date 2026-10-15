// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * IdentityResolver — maps the agent's VID/DID string world to the shared
 * migration tables (`identities` + `did_documents`) so that all agent stores
 * can participate in the full P2PTS data model via integer FK relationships.
 *
 * Every VTA controlled by this agent is a `role='vta', custody='local'` row
 * in `identities`. Remote VTAs (peers) are `custody='remote'`. The resolver
 * creates these rows idempotently and returns the integer `identity_id` and
 * `did_document_id` that the downstream stores use as FKs.
 *
 * ## Deterministic UUIDs for replication
 *
 * The schema uses UUIDv5 for identity keys so that any node independently
 * computing the same DID arrives at the same UUID:
 *
 *   identities.uuid = UUIDv5(DID_NAMESPACE, real_did) — deterministic identity key
 *   did_documents.did = the real DID string (identity resolved via FK)
 *
 * Non-identity tables (did_documents, relationships, etc.) use UUIDv7 for
 * their `uuid` column (time-ordered, unique across instances).
 */

import type { DatabaseSync } from 'node:sqlite';
import { didToUuid, generateUuid } from '../db/uuid-helpers.js';
import { cesrDecode, CESR_CODES } from '../crypto/cesr.js';
import {
  extractEd25519PublicKey,
  extractX25519PublicKey,
  extractHybridKemPublicKey,
  extractMlDsa65PublicKey,
} from '../relationship/key-extract.js';
import type { DidDocument } from '../did/types.js';
import { logger } from '../util/logger.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ResolvedIdentity {
  /** Deterministic UUIDv5 derived from the real DID. */
  identityUuid: string;
  /** The did_documents row's own UUIDv7 (the keys/rotation_log FK target). */
  didDocumentUuid: string | null;
}

/**
 * A full copy of a peer's `identities` row, as shared with us during VRC
 * copying. `uuid` is the canonical selection key (UUIDv5 of the real DID) and
 * must be preserved verbatim. On the receiving side everything is written as
 * provided EXCEPT custody, which is forced to 'remote' because the receiver is
 * not the creator of the record and must not control its contents.
 */
export interface RemoteIdentityRecord {
  /** Canonical identity UUID (UUIDv5 of the real DID) — the selection key. */
  uuid: string;
  /** The real DID string (also stored in did_documents.did). */
  realDid: string;
  /** Alias of `realDid` for payloads that use `did` as the field name. */
  did: string;
  method: string;
  name: string | null;
  role: string;
  subjectKind: string;
  /** Sender's custody value (informational) — the receiver overrides to 'remote'. */
  custody: string;
  peerId: string | null;
  vid: string;
  didDocument: DidDocument;
  publicKeys: {
    ed25519: string;   // base64
    x25519: string;    // base64
  };
  dtgSubtype?: string | null;
  bootstrapPeerId?: string | null;
  bootstrapUrl?: string | null;
  recordedByNode?: string | null;
  replicatedAt?: number | null;
  createdAt?: number | null;
}

// ---------------------------------------------------------------------------
// IdentityResolver
// ---------------------------------------------------------------------------

export class IdentityResolver {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  /**
   * Ensure a local VTA identity row exists and return its IDs.
   *
   * Idempotent — if the identity already exists (matched via deterministic
   * UUIDv5), returns the existing IDs without changing anything.
   */
  resolveLocalIdentity(params: {
    did: string;
    name: string;
    method: string;
    peerId: string;
    /** CESR-encoded VID (Ed25519 public key), used for keystore lookups. */
    cesrVid?: string;
    didDocumentJson?: string;
  }): ResolvedIdentity {
    const existing = this.findExistingIdentity(params.did);
    const identityUuid = existing?.uuid ?? didToUuid(params.did);

    if (existing) {
      // Persist the current CESR VID (mirrors the keystore label).
      if (params.cesrVid && existing.vid !== params.cesrVid) {
        this.db.prepare(
          'UPDATE identities SET vid = ?, updated_at = unixepoch() WHERE uuid = ?',
        ).run(params.cesrVid, identityUuid);
      }
    } else {
      this.db.prepare(`
        INSERT INTO identities (uuid, role, subject_kind, custody, name, vid, created_at, updated_at)
        VALUES (?, 'vta', 'human', 'local', ?, ?, unixepoch(), unixepoch())
      `).run(identityUuid, params.name, params.cesrVid ?? null);
    }

    this.upsertPeerEndpoint(identityUuid, params.peerId);

    const didDoc = this.upsertDidDocument({
      identityUuid,
      realDid: params.did,
      method: params.method,
      documentJson: params.didDocumentJson,
      isPrimary: 1,
    });

    return { identityUuid, didDocumentUuid: didDoc.uuid };
  }

  /**
   * Ensure a remote VTA identity row exists and return its IDs.
   */
  resolveRemoteIdentity(params: {
    did: string;
    method: string;
    name?: string;
    peerId?: string;
    role?: string;
    didDocumentJson?: string;
    /** Whether this DID document is primary (default true). Handshake identities use false. */
    isPrimary?: boolean;
    /** Node ID that recorded this row (for replication tracking). */
    recordedByNode?: string;
    /** Subject kind for the remote identity ('human' | 'organization'). Defaults to 'human'. */
    subjectKind?: string;
  }): ResolvedIdentity {
    const subjectKind = params.subjectKind ?? 'human';
    const role = params.role ?? 'vta';

    const existing = this.findExistingIdentity(params.did);
    const identityUuid = existing?.uuid ?? didToUuid(params.did);

    if (existing) {
      // Only update subject_kind when the caller explicitly provides one.
      //
      // The predicate is NULL-safe on purpose: a DOCUMENT-LESS row written by the
      // community/credential fan-out has `subject_kind = NULL` (the fan-out's
      // INSERT omits the column), and `subject_kind != ?` is NULL — not true — for
      // a NULL row, so a plain `!=` would silently refuse to heal it. That matters
      // because `subject_kind` is what gates the "only human VTAs can be founding
      // admins" rule in `createVtc`.
      if (params.subjectKind !== undefined) {
        this.db.prepare(
          'UPDATE identities SET subject_kind = ?, updated_at = unixepoch() WHERE uuid = ? AND (subject_kind IS NULL OR subject_kind != ?)',
        ).run(subjectKind, identityUuid, subjectKind);
      }
      // Only update name when the caller explicitly provides a non-empty one.
      if (params.name) {
        this.db.prepare(
          'UPDATE identities SET name = ?, updated_at = unixepoch() WHERE uuid = ? AND (name IS NULL OR name != ?)',
        ).run(params.name, identityUuid, params.name);
      }
    } else {
      this.db.prepare(`
        INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
        VALUES (?, ?, ?, 'remote', ?, unixepoch(), unixepoch())
      `).run(identityUuid, role, subjectKind, params.name ?? null);
    }

    this.upsertPeerEndpoint(identityUuid, params.peerId);

    const didDoc = this.upsertDidDocument({
      identityUuid,
      realDid: params.did,
      method: params.method,
      documentJson: params.didDocumentJson,
      isPrimary: params.isPrimary !== false ? 1 : 0,
      recordedByNode: params.recordedByNode,
    });

    // Extract and store the remote peer's public keys in the keys table.
    if (params.didDocumentJson && didDoc.uuid) {
      this.upsertRemotePublicKeys(identityUuid, didDoc.uuid, params.didDocumentJson);
    }

    return { identityUuid, didDocumentUuid: didDoc.uuid };
  }

  /**
   * Extract and upsert public keys into the keys table for a remote identity.
   * Only inserts public material — encrypted_secret_key is always NULL for
   * remote identities.
   *
   * When `explicitKeys` is provided it is AUTHORITATIVE and takes precedence:
   * it comes from the record's `publicKeys` field, which the sender derives
   * from its live keystore at identity-share time. Re-extracting from the DID
   * document is only a fallback for payloads that carry no explicit keys —
   * a did:scid:vh document can be stale (its #key-1 may still reference a
   * pre-rotation/next key after agent99 rolled), storing the stale key would
   * break the shared-key canonicalization used by the graph and VTC
   * co-admin checklist.
   */
  private upsertRemotePublicKeys(
    identityUuid: string,
    didDocumentUuid: string | null,
    documentJson: string | undefined,
    explicitKeys?: { ed25519?: string | Uint8Array; x25519?: string | Uint8Array },
  ): void {
    // Only keys supplied EXPLICITLY (sender's live keystore keys carried on the
    // identity record's `publicKeys` field) are authoritative enough to heal an
    // existing key row. Keys re-derived from a DID document are NOT: a
    // did:scid:vh document can legitimately carry a pre-rotation/next key in
    // #key-1 after the sender registered a name and rolled its log, while the
    // sender is still signing with the older live key. Overwriting the stored
    // live key with that doc key would break the shared-Ed25519-key
    // canonicalization used by the graph and VTC co-admin checklist.
    const authoritative = !!explicitKeys;

    const keyEntries: Array<{ keyType: 'ed25519' | 'x25519' | 'mlkem768_x25519' | 'ml_dsa_65'; publicKey: Uint8Array }> = [];

    // Explicit keys from the identity record (base64 strings or raw bytes) are
    // authoritative — they reflect the sender's CURRENT keystore keys.
    if (explicitKeys) {
      if (explicitKeys.ed25519 != null && explicitKeys.ed25519.length > 0) {
        keyEntries.push({
          keyType: 'ed25519',
          publicKey: typeof explicitKeys.ed25519 === 'string'
            ? Buffer.from(explicitKeys.ed25519, 'base64')
            : Uint8Array.from(explicitKeys.ed25519),
        });
      }
      if (explicitKeys.x25519 != null && explicitKeys.x25519.length > 0) {
        keyEntries.push({
          keyType: 'x25519',
          publicKey: typeof explicitKeys.x25519 === 'string'
            ? Buffer.from(explicitKeys.x25519, 'base64')
            : Uint8Array.from(explicitKeys.x25519),
        });
      }
    }

    // Fallback: extract from the DID document when the record carried no
    // explicit publicKeys (e.g. TSP-bridge handshake materialization).
    if (keyEntries.length === 0 && documentJson) {
      let doc: DidDocument;
      try {
        doc = JSON.parse(documentJson) as DidDocument;
      } catch {
        return; // Malformed JSON — skip key extraction.
      }

      // Extract Ed25519 signing key from verificationMethod[0].
      try {
        keyEntries.push({ keyType: 'ed25519', publicKey: extractEd25519PublicKey(doc) });
      } catch {
        // Key not present or malformed — skip.
      }

      // Extract X25519 agreement key from verificationMethod[1].
      try {
        keyEntries.push({ keyType: 'x25519', publicKey: extractX25519PublicKey(doc) });
      } catch {
        // Key not present or malformed — skip.
      }

      // Extract the MLKEM768-X25519 hybrid KEM key from #key-kem, when the peer
      // publishes one. Absent for peers that predate PQ provisioning (and for
      // third-party DIDs), which simply keeps confidential traffic classical.
      try {
        const kemKey = extractHybridKemPublicKey(doc);
        if (kemKey) keyEntries.push({ keyType: 'mlkem768_x25519', publicKey: kemKey });
      } catch {
        // Key not present or malformed — skip.
      }

      // Extract the ML-DSA-65 root-of-trust key from #key-mldsa. This is the key
      // that verifies the peer's OOBI introduction signature, so persisting it is
      // what lets a receiver integrity-check an introduction from a peer whose
      // DID it cannot resolve locally (a did:scid:vh peer: DidPeer4Method.resolve
      // handles only peer4, and ScidVhMethod.resolve needs that did's rotation
      // log). See RelationshipRecord.remoteMlDsa65Key.
      try {
        const mlDsaKey = extractMlDsa65PublicKey(doc);
        if (mlDsaKey) keyEntries.push({ keyType: 'ml_dsa_65', publicKey: mlDsaKey });
      } catch {
        // Key not present or malformed — skip.
      }
    }

    for (const entry of keyEntries) {
      const existing = this.db.prepare(
        'SELECT uuid, public_key FROM keys WHERE identity_uuid = ? AND key_type = ? AND rotation_version = 0',
      ).get(identityUuid, entry.keyType) as { uuid: string; public_key: Uint8Array } | undefined;

      if (existing) {
        // Heal a stale key row ONLY when the incoming key is authoritative
        // (explicit record.publicKeys — e.g. one populated earlier from a stale
        // DID document). Fallback doc-extraction must NEVER overwrite an
        // existing row: it runs during handshake/stub re-materialization and
        // would clobber the sender's live key with the doc's (possibly rolled)
        // #key-1, permanently unlinking the stub from the real identity row.
        if (authoritative) {
          const stored = Buffer.from(existing.public_key);
          const incoming = Buffer.from(entry.publicKey);
          if (!stored.equals(incoming)) {
            this.db.prepare(
              `UPDATE keys SET public_key = ?, did_document_uuid = ?
               WHERE uuid = ?`,
            ).run(incoming, didDocumentUuid, existing.uuid);
          }
        }
        continue;
      }

      const keyUuid = generateUuid();
      this.db.prepare(`
        INSERT INTO keys
          (identity_uuid, did_document_uuid,
           key_type, public_key, rotation_version, uuid, created_at)
        VALUES (?, ?, ?, ?, 0, ?, unixepoch())
      `).run(
        identityUuid,
        didDocumentUuid,
        entry.keyType,
        Buffer.from(entry.publicKey),
        keyUuid,
      );
    }
  }

  /**
   * Copy a peer's full identity record into the local `identities` table, keyed
   * by the record's own UUID (UUIDv5 of the real DID). Every field is written
   * as provided EXCEPT custody, which is forced to 'remote' — the receiver is
   * not the creator and must not control the record's contents. The DID
   * document and public keys are also materialised so the peer resolves
   * normally via lookupByDid() and community/relationship joins.
   */
  storeRemoteIdentityCopy(record: RemoteIdentityRecord): ResolvedIdentity {
    const uuid = record.uuid;
    const realDid = record.realDid || record.did;
    const method = record.method || 'peer4';
    const role = record.role || 'vta';
    const subjectKind = record.subjectKind || 'human';
    // Receiver is never the creator: force custody='remote'.
    const custody = 'remote';
    const now = Math.floor(Date.now() / 1000);

    const existing = this.db.prepare(
      'SELECT uuid FROM identities WHERE uuid = ?',
    ).get(uuid) as { uuid: string } | undefined;

    if (existing) {
      this.db.prepare(
        `UPDATE identities SET
           name = ?, role = ?, subject_kind = ?, custody = ?,
           vid = ?, dtg_subtype = ?, bootstrap_peer_id = ?, bootstrap_url = ?,
           recorded_by_node = ?, replicated_at = ?, updated_at = ?
         WHERE uuid = ?`,
      ).run(
        record.name ?? null, role, subjectKind, custody,
        record.vid ?? null, record.dtgSubtype ?? null,
        record.bootstrapPeerId ?? null, record.bootstrapUrl ?? null,
        record.recordedByNode ?? null, record.replicatedAt ?? null, now,
        uuid,
      );
    } else {
      this.db.prepare(
        `INSERT INTO identities
           (uuid, role, subject_kind, custody, name, vid,
            dtg_subtype, bootstrap_peer_id, bootstrap_url, recorded_by_node,
            replicated_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        uuid, role, subjectKind, custody, record.name ?? null,
        record.vid ?? null, record.dtgSubtype ?? null,
        record.bootstrapPeerId ?? null, record.bootstrapUrl ?? null,
        record.recordedByNode ?? null, record.replicatedAt ?? null,
        record.createdAt ?? now, now,
      );
    }

    this.upsertPeerEndpoint(uuid, record.peerId);

    // Materialise the DID document (real DID) + public keys so the peer
    // resolves via lookupByDid() and community/relationship joins.
    const documentJson = record.didDocument ? JSON.stringify(record.didDocument) : undefined;
    const didDoc = this.upsertDidDocument({
      identityUuid: uuid,
      realDid,
      method,
      documentJson,
      isPrimary: 1,
      recordedByNode: record.recordedByNode ?? undefined,
    });
    // The record's explicit `publicKeys` are the sender's LIVE keystore keys and
    // are authoritative over re-extraction from the DID document (which may be
    // stale — e.g. a did:scid:vh document whose #key-1 still holds a
    // pre-rotation/next key after the agent rolled). Writing the stale key here
    // would break the shared-Ed25519-key canonicalization the graph and VTC
    // co-admin checklist rely on to resolve the peer's display name.
    this.upsertRemotePublicKeys(uuid, didDoc.uuid, documentJson, record.publicKeys);

    return { identityUuid: uuid, didDocumentUuid: didDoc.uuid };
  }

  /**
   * Look up an identity by its CESR-encoded Ed25519 VID (the current signing
   * public key encoded as a CESR ED25519_PUBLIC_KEY string). This is the
   * VID → real identity resolution (Workstream A+C): it finds the identity row
   * whose `keys` table holds the matching current ed25519 public key, so records
   * keyed by the ephemeral VID can be resolved onto the stable DID/UUID identity.
   *
   * This is the ONLY VID-based lookup — it is a resolution helper, NOT a claim
   * that the VID is the identity. All stored/displayed references use the DID/UUID.
   */
  lookupByVid(vid: string): ResolvedIdentity | undefined {
    let bytes: Uint8Array;
    try {
      const dec = cesrDecode(vid);
      if (dec.code !== CESR_CODES.ED25519_PUBLIC_KEY) return undefined;
      bytes = new Uint8Array(dec.bytes);
    } catch {
      return undefined;
    }
    const row = this.db.prepare(
      `SELECT i.uuid,
              (SELECT dd.uuid FROM did_documents dd WHERE dd.identity_uuid = i.uuid AND dd.is_primary = 1) AS didDocumentUuid
         FROM keys k
         JOIN identities i ON i.uuid = k.identity_uuid
         WHERE k.key_type = 'ed25519' AND k.rotation_version = 0 AND k.public_key = ?`,
    ).get(Buffer.from(bytes)) as { uuid: string; didDocumentUuid: string | null } | undefined;
    if (!row) return undefined;
    return { identityUuid: row.uuid, didDocumentUuid: row.didDocumentUuid };
  }

  /**
   * Record/promote a libp2p endpoint for an identity in the normalized
   * `peer_endpoints` table (Workstream B). Host/runtime state is NOT the
   * identity; it lives beside the identity via identity_uuid. Dedup key is the
   * UNIQUE peer_id (no integer FK / no extra uuid on the row).
   *
   * This is the agent-side (synchronous SQLite) counterpart of the DataSource
   * repo `setActiveEndpoint`: activating a new peer retires the identity's
   * other active endpoints, and a peer already claimed by another identity is
   * refused.
   */
  private upsertPeerEndpoint(
    identityUuid: string,
    peerId: string | null | undefined,
  ): void {
    if (!peerId) return;

    // Collision guard: never claim a peer that is ACTIVE on another identity.
    const claimedByOther = this.db.prepare(
      `SELECT identity_uuid FROM peer_endpoints
       WHERE peer_id = ? AND is_active = 1 AND identity_uuid <> ? LIMIT 1`,
    ).get(peerId, identityUuid) as { identity_uuid: string } | undefined;
    if (claimedByOther) {
      logger.warn(
        `[IdentityResolver] refusing to assign peer ${peerId.slice(0, 12)}... ` +
        `to identity ${identityUuid.slice(0, 8)} — already active on ${claimedByOther.identity_uuid.slice(0, 8)}`,
      );
      return;
    }

    const existing = this.db.prepare(
      'SELECT uuid FROM peer_endpoints WHERE peer_id = ?',
    ).get(peerId) as { uuid: string } | undefined;
    if (existing) {
      this.db.prepare(
        'UPDATE peer_endpoints SET identity_uuid = ?, is_active = 1, updated_at = unixepoch() WHERE uuid = ?',
      ).run(identityUuid, existing.uuid);
    } else {
      const rowUuid = generateUuid();
      this.db.prepare(
        `INSERT INTO peer_endpoints
           (uuid, identity_uuid, peer_id, is_active, created_at, updated_at)
         VALUES (?, ?, ?, 1, unixepoch(), unixepoch())`,
      ).run(rowUuid, identityUuid, peerId);
    }

    // Retire any OTHER active endpoint of this identity (single active node).
    this.db.prepare(
      `UPDATE peer_endpoints SET is_active = 0, updated_at = unixepoch()
       WHERE identity_uuid = ? AND peer_id <> ? AND is_active = 1`,
    ).run(identityUuid, peerId);
  }

  /**
   * Look up an identity by its real DID string.
   */
  lookupByDid(did: string): ResolvedIdentity | undefined {
    const ident = this.db.prepare(
      `SELECT i.uuid FROM identities i
        JOIN did_documents d ON d.identity_uuid = i.uuid WHERE d.did = ?`,
    ).get(did) as { uuid: string } | undefined;

    if (!ident) return undefined;

    const didDoc = this.db.prepare(
      'SELECT uuid FROM did_documents WHERE identity_uuid = ? AND is_primary = 1',
    ).get(ident.uuid) as { uuid: string } | undefined;

    return {
      identityUuid: ident.uuid,
      didDocumentUuid: didDoc?.uuid ?? null,
    };
  }

  /**
   * Look up the real DID string for a given identity UUID.
   */
  getRealDid(identityUuid: string): string | undefined {
    const row = this.db.prepare(
      'SELECT did.did FROM did_documents did WHERE did.identity_uuid = ? AND did.is_primary = 1',
    ).get(identityUuid) as { did: string } | undefined;
    return row?.did;
  }

  /**
   * Record/promote a libp2p endpoint for an identity KEYED BY ITS UUID.
   * Same guarded semantics as `upsertPeerEndpoint` but avoids a DID lookup —
   * used by RelationshipStore when it already has the remote identity resolved.
   */
  updatePeerUuidEndpoint(identityUuid: string, peerId: string): void {
    this.upsertPeerEndpoint(identityUuid, peerId);
  }

  /**
   * Update the active libp2p endpoint for an identity (keyed by real DID).
   * Records the live peer in `peer_endpoints` (retiring superseded endpoints).
   * Call this on every agent start()/login so a changed node key is picked up
   * immediately and old endpoints never linger as "active".
   */
  updatePeerId(did: string, peerId: string): void {
    const ident = this.db.prepare(
      `SELECT i.uuid FROM identities i
       JOIN did_documents d ON d.identity_uuid = i.uuid WHERE d.did = ?`,
    ).get(did) as { uuid: string } | undefined;
    if (!ident) return;

    this.upsertPeerEndpoint(ident.uuid, peerId);
  }

  /**
   * Resolve an identity's CURRENT active libp2p endpoint (peer ID + multiaddrs)
   * from the normalized `peer_endpoints` table.
   */
  getActiveEndpoint(did: string): { peerId: string } | null {
    const ident = this.db.prepare(
      `SELECT i.uuid FROM identities i
       JOIN did_documents d ON d.identity_uuid = i.uuid WHERE d.did = ?`,
    ).get(did) as { uuid: string } | undefined;
    if (!ident) return null;

    const row = this.db.prepare(
      `SELECT peer_id FROM peer_endpoints
       WHERE identity_uuid = ? AND is_active = 1
       ORDER BY updated_at DESC, created_at DESC LIMIT 1`,
    ).get(ident.uuid) as { peer_id: string } | undefined;
    return row ? { peerId: row.peer_id } : null;
  }

  // -----------------------------------------------------------------------
  // R-DID Registration (DTG RelationshipCredential)
  // -----------------------------------------------------------------------

  /**
   * Register an R-DID (relationship-scoped DID) via DidManager.
   *
   * R-DIDs are now context-scoped did:peer:4 documents under the caller's root
   * identity (is_primary=0, context_type='relationship'), not separate identity
   * rows. Delegates to DidManager.createRelationshipDid().
   *
   * @param dataSource   DataSource bridge to the agent's SQLite database
   * @param rootIdentityId  The caller's root identity id (the R-DID's owner)
   * @param relationshipId  The relationships.id this R-DID is scoped to
   */
  async registerRdid(
    dataSource: import('../db/data-source.js').DataSource,
    rootIdentityUuid: string,
    relationshipUuid: string,
  ): Promise<ResolvedIdentity> {
    const { DidManager } = await import('./did-manager.js');
    const result = await new DidManager(dataSource).createRelationshipDid(rootIdentityUuid, relationshipUuid);
    return {
      identityUuid: result.identityUuid,
      didDocumentUuid: result.didDocumentUuid,
    };
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  /**
   * Find the `identities` row a DID belongs to, tolerating a DOCUMENT-LESS row.
   *
   * The canonical DID→identity lookup goes through `did_documents` (a DID is only
   * resolvable because a document carries it). That probe CANNOT see a
   * document-less identity row — one keyed by `didToUuid(did)` with no
   * `did_documents` row — and such rows are NORMAL, not damage: the
   * community/credential fan-out writes one per member/issuer/subject
   * (`INSERT OR IGNORE INTO identities (uuid, …)`, see
   * `src/tx/vtc-receive-participant.ts` and
   * `trust-app-api/runtime/tx/credential-receive-participant.ts`) and the pushed
   * package carries no per-member document. The reconcile pass reports them as
   * `orphanIdentities`.
   *
   * Falling back to the deterministic uuid is what stops the caller from
   * INSERTing a SECOND row at that same primary key (migration 0001:
   * `identities.uuid = UUIDv5(did)`). Without the fallback the insert collides —
   * `UNIQUE constraint failed: identities.uuid` — and that throw escapes
   * `RelationshipStore.insertOutbound`/`upsertInbound` out of `sendRfi`, so the
   * OOBI handshake died BEFORE the RFI was sent whenever the peer had already
   * arrived via a community fan-out (the exact "VIC invite, then connect to a
   * third agent" failure). The server-side counterpart
   * (`DsIdentityResolver.resolveRemoteIdentity`) has carried this guard since it
   * was written; this synchronous agent-side resolver did not.
   */
  private findExistingIdentity(did: string): { uuid: string; vid: string | null } | undefined {
    const byDid = this.db.prepare(
      `SELECT i.uuid, i.vid FROM identities i
        JOIN did_documents d ON d.identity_uuid = i.uuid WHERE d.did = ?`,
    ).get(did) as { uuid: string; vid: string | null } | undefined;
    if (byDid) return byDid;

    return this.db.prepare(
      'SELECT uuid, vid FROM identities WHERE uuid = ?',
    ).get(didToUuid(did)) as { uuid: string; vid: string | null } | undefined;
  }

  private upsertDidDocument(params: {
    identityUuid: string;
    realDid: string;     // The actual DID string (e.g., "did:peer:4:...")
    method: string;
    documentJson?: string;
    isPrimary?: number;
    recordedByNode?: string;
  }): { uuid: string | null } {
    // Look up by (identity_uuid, did) — prior lookups by method could MISS a
    // row keyed by the real DID (e.g. a stub created during OOBI/sendRfi) and
    // then try to INSERT a duplicate `did` → UNIQUE violation on RFA.
    const existing = this.db.prepare(
      'SELECT uuid, method, is_primary FROM did_documents WHERE identity_uuid = ? AND did = ?',
    ).get(params.identityUuid, params.realDid) as { uuid: string; method: string; is_primary: number } | undefined;

    if (existing) {
      if (params.documentJson || params.method || params.isPrimary !== undefined || params.recordedByNode) {
        this.db.prepare(
          `UPDATE did_documents SET
             document_json = COALESCE(?, document_json),
             method = COALESCE(?, method),
             is_primary = MAX(is_primary, ?),
             recorded_by_node = COALESCE(?, recorded_by_node),
             updated_at = unixepoch()
           WHERE uuid = ?`,
        ).run(
          params.documentJson ?? null,
          params.method,
          params.isPrimary ?? 0,
          params.recordedByNode ?? null,
          existing.uuid,
        );
      }
      return { uuid: existing.uuid };
    }

    const uuid = generateUuid(); // UUIDv7 — time-ordered for replication
    const now = Math.floor(Date.now() / 1000);
    this.db.prepare(`
      INSERT INTO did_documents
        (identity_uuid, did, method, document_json, is_primary, status, uuid, recorded_by_node, created_at)
      VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)
    `).run(
      params.identityUuid,
      params.realDid,           // The actual DID string
      params.method,
      params.documentJson ?? null,
      params.isPrimary ?? 0,
      uuid,
      params.recordedByNode ?? null,
      now,
    );
    return { uuid };
  }
}