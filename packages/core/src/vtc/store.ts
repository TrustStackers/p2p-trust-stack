// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * VtcStore — VTC governance + VRC credential persistence using the shared
 * P2PTS migration tables `governance` (0007) and `credentials` (0009).
 *
 * ## Mapping
 *
 * | Old agent table       | Shared migration table | Key FK                        |
 * |-----------------------|------------------------|-------------------------------|
 * | vtc_governance_docs   | governance             | community_identity_id → VTC   |
 * | vrcs                  | credentials            | issuer_identity_id → VTC,     |
 * |                       |                        | subject_identity_id → subject |
 *
 * VID/DID strings are resolved to identity_id integers via IdentityResolver.
 * Agent-specific payloads (JSON claims, digests, signatures) are stored in the
 * `claim` / `credential_digest` TEXT columns and `credential_signatures`; the
 * governance doc's own digest lives in `governance.vtc_governance_digest`, and its
 * other fields are derived from `identities` / `memberships` / policy bindings.
 */

import type { DatabaseSync } from 'node:sqlite';
import type { IdentityResolver } from '../services/identity-resolver.js';
import type { Vrc, VrcClaim, VrcSignature, VtcGovernanceDoc } from './types.js';
import { generateUuid } from '../db/uuid-helpers.js';
import { sha256 } from '../crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../crypto/cesr.js';
import { logger } from '../util/logger.js';

// ---------------------------------------------------------------------------
// Row types (raw migration-table rows)
// ---------------------------------------------------------------------------

interface GovernanceRow {
  community_identity_uuid: string;
  admin_threshold_m: number | null;
  admin_threshold_n: number | null;
  vtc_governance_digest: string | null;
  uuid: string;
  updated_at: number | null;
}

interface CredentialRow {
  vc_type: string;
  issuer_identity_uuid: string;
  subject_identity_uuid: string;
  claim: string | null;
  status: string;
  threshold_required: number | null;
  valid_from: number;
  valid_until: number | null;
  credential_digest: string | null;
  uuid: string;
  created_at: number | null;
}

interface SignatureRow {
  uuid: string;
  credential_uuid: string;
  signer_identity_uuid: string;
  signer_did_document_uuid: string | null;
  signature: Buffer | Uint8Array;
  signed_at: number | null;
  /**
   * The signer's current Ed25519 public key, joined in by `SIGNATURE_SELECT` — `null` when the signer has no
   * primary `did_documents` row or no `keys` entry under it.
   */
  signerPublicKey?: Buffer | Uint8Array | null;
}

/**
 * Signature rows for one credential, **with the signer's Ed25519 public key joined in**.
 *
 * The join is the point. `credential_signatures` stores `signer_identity_uuid`, but `VrcSignature.signerVid`
 * is consumed as a **CESR key**: `countValidAdminSignatures` tests `adminVids.includes(sig.signerVid)` and then
 * `decodeVidToPublicKey(sig.signerVid)`. A uuid satisfies neither, so a signature rebuilt from the raw row can
 * never count — which made `verifyVrc` return `insufficient-signatures` for **every** store-loaded VRC. The key
 * is resolved here the same way `resolveAdmins` resolves an admin's, deliberately: same source of truth
 * (`keys`), same rotation rule.
 */
const SIGNATURE_SELECT = `
  SELECT cs.*, k.public_key AS signerPublicKey
    FROM credential_signatures cs
    LEFT JOIN identities i ON i.uuid = cs.signer_identity_uuid
    LEFT JOIN did_documents dd ON dd.identity_uuid = i.uuid AND dd.is_primary = 1
    LEFT JOIN keys k ON k.did_document_uuid = dd.uuid
       AND k.key_type = 'ed25519'
       AND k.rotation_version = (
             SELECT MAX(k2.rotation_version) FROM keys k2
              WHERE k2.did_document_uuid = dd.uuid AND k2.key_type = 'ed25519'
           )
   WHERE cs.credential_uuid = ?
`;

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

function deserializeSignatures(rows: SignatureRow[]): VrcSignature[] {
  return rows.map(r => {
    if (!r.signerPublicKey) {
      // The signer's key is not resolvable locally, so there is no CESR vid to put here. The stored
      // `signer_identity_uuid` is kept as the fallback rather than dropping the row: `saveVrc` → `getVrc` must
      // round-trip what was saved, and `signatureCount` reports what the store HOLDS.
      //
      // This is safe because every consumer treats it correctly without special-casing: `countValidAdminSignatures`
      // rejects it twice over (`adminVids.includes(uuid)` is false, and `decodeVidToPublicKey(uuid)` throws) — so
      // an unverifiable signature counts as 0, which is the honest answer. It is only reached for a signer whose
      // key this node has never seen (a remote admin on a replicated VRC); a locally-known signer resolves through
      // the `keys` join above and gets a real CESR vid, which is what makes `verifyVrc` work.
      logger.warn(
        `[vtc:store] signature by ${r.signer_identity_uuid} has no resolvable Ed25519 key ` +
        `(primary did_document=${r.signer_did_document_uuid ?? 'none'}); reporting its identity uuid, which ` +
        `cannot be verified against a governance doc until the key is known.`,
      );
      return { signerVid: r.signer_identity_uuid, signature: new Uint8Array(r.signature) };
    }
    return {
      signerVid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, new Uint8Array(r.signerPublicKey)),
      signature: new Uint8Array(r.signature),
    };
  });
}

/** The stored digest of a VTC governance doc (base64) — a commitment, never recomputed. */
function governanceDocDigest(doc: VtcGovernanceDoc): string {
  return Buffer.from(doc.digest).toString('base64');
}

/**
 * The current admin set of a VTC, resolved to the two things a governance doc
 * actually needs them to be: a CESR-encoded Ed25519 public key (`adminVids`) and a
 * DID (`adminDids`, parallel, same index).
 *
 * ## Why this is not `SELECT ... identities` alone
 *
 * `adminVids` is consumed as a list of **CESR public keys** — `asEncodedGovernanceDoc`
 * validates every entry with `asCesrVid` (which throws on anything else) and
 * `issueVrc` tests membership with `adminVids.includes(signer.vid)`, where `signer.vid`
 * is a CESR key. The earlier version of this function filled it with display labels
 * (`name ?? uuid`), which made the `issueVrc` admin check **unsatisfiable for every
 * store-loaded doc**: a seeded VTC the caller demonstrably administered still failed
 * with "signer ... is not on the VTC's admin list". See docs/agent-api-layer-implementation-plan.md §3.5.1c.
 *
 * ## Which key
 *
 * `keys` is the authoritative key material (migration 0003), so the key is read from
 * there rather than from the `identities.vid` denormalisation — which is the *same
 * value* for a locally-created identity (`services/vta.ts` derives `cesrVid` from the
 * very public key it then stores) but is NULL for identities created by
 * `services/vtc.ts` (the community itself) and `services/vta.ts`'s remote-push path.
 *
 * Two joins are load-bearing:
 *
 *   - **`did_documents.is_primary = 1`** — an identity legitimately holds several
 *     Ed25519 keys (its authoritative `did:scid:vh` root plus a `did:peer:4`
 *     relationship-handshake stub, both at `rotation_version` 0), so joining `keys` by
 *     `identity_uuid` alone would pick an arbitrary one — see the warning on
 *     `keys-repo.findEd25519KeysByIdentity`. The primary document is the root identity.
 *   - **`MAX(rotation_version)`** — a rotated identity has one row per version; the
 *     current key is the highest.
 *
 * Admins with no resolvable key are **skipped, with a warning**, rather than throwing:
 * `listGovernanceDocs()` is shared by `/api/vtcs` and the community list, so throwing
 * would let one under-provisioned community break an unrelated screen. `adminDids`
 * still carries such an admin's DID, so nothing is lost — a resolution-aware consumer
 * can look the key up itself.
 */
function resolveAdmins(
  db: DatabaseSync,
  communityIdentityUuid: string,
): { adminVids: string[]; adminDids: string[] } {
  const rows = db.prepare(
    `SELECT i.name AS name, i.uuid AS uuid, dd.did AS did, k.public_key AS publicKey
       FROM memberships m
       JOIN identities i ON i.uuid = m.member_identity_uuid
       LEFT JOIN did_documents dd
         ON dd.identity_uuid = i.uuid AND dd.is_primary = 1
       LEFT JOIN keys k
         ON k.did_document_uuid = dd.uuid
        AND k.key_type = 'ed25519'
        AND k.rotation_version = (
              SELECT MAX(k2.rotation_version) FROM keys k2
               WHERE k2.did_document_uuid = dd.uuid AND k2.key_type = 'ed25519'
            )
      WHERE m.community_identity_uuid = ? AND m.role IN ('admin', 'founding_admin')
      ORDER BY i.name IS NULL, i.name, i.uuid`,
  ).all(communityIdentityUuid) as {
    name: string | null;
    uuid: string;
    did: string | null;
    publicKey: Buffer | Uint8Array | null;
  }[];

  const adminVids: string[] = [];
  const adminDids: string[] = [];

  for (const r of rows) {
    if (r.did) adminDids.push(r.did);

    if (!r.publicKey) {
      logger.warn(
        `[vtc:store] admin ${r.name ?? r.uuid} of community ${communityIdentityUuid} has no ` +
        `resolvable Ed25519 key (primary did_document=${r.did ?? 'none'}); omitting it from ` +
        `adminVids. It remains in adminDids.`,
      );
      continue;
    }

    adminVids.push(cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, new Uint8Array(r.publicKey)));
  }

  return { adminVids, adminDids };
}

/**
 * Reconstruct a VtcGovernanceDoc from the governance row + the tables that hold its
 * fields. The digest is the STORED commitment (`row.vtc_governance_digest`); every
 * other field is DERIVED — name/threshold/admin list from `identities` + `governance`
 * + `memberships` + `keys` + `did_documents`, claim types from the community's
 * claim-type-allow bindings — so there is no JSON side-channel to fall out of sync.
 */
function governanceRowToDoc(db: DatabaseSync, row: GovernanceRow, vtcDid: string): VtcGovernanceDoc {
  const identity = db.prepare('SELECT name FROM identities WHERE uuid = ?')
    .get(row.community_identity_uuid) as { name: string | null } | undefined;
  const { adminVids, adminDids } = resolveAdmins(db, row.community_identity_uuid);
  const claimRows = db.prepare(
    `SELECT params FROM community_policy_bindings
      WHERE community_identity_uuid = ? AND enabled = 1
        AND rule_type LIKE 'task:p2pts:rule:claim-type-allow:0.1#%'`,
  ).all(row.community_identity_uuid) as { params: string | null }[];

  const allowedClaimTypes: string[] = [];
  for (const cr of claimRows) {
    try {
      const ct = JSON.parse(cr.params ?? '{}').claim_type;
      if (typeof ct === 'string' && ct.length > 0) allowedClaimTypes.push(ct);
    } catch { /* malformed binding param — skip */ }
  }

  return {
    // The VTC's DID — NOT a CESR key, and deliberately so.
    //
    // This looks like a naming artifact (`vtcVid` holding a DID) and it is one, but the
    // behaviour is load-bearing: `verifyVrc` resolves a governance doc from a VRC's
    // `issuerVid`, which `issueVrc` sets to this field, and `getGovernanceDoc` resolves
    // through `IdentityResolver.lookupByDid`. A CESR key here breaks that lookup.
    //
    // The pre-refactor code documented the split explicitly (the `⚠️ Boundary note` on
    // `VtcApiModule.issueVrc` at 6af60f1): a store-loaded doc's `vtcVid` is the DID, the
    // VRC's `issuerVid` is therefore DID-form, and that is "fine for storage/verification
    // (both are DID/DID-keyed)" — it only must not be fed to the binary codec. `types.ts`
    // says the same: "the store may persist a DID/UUID here".
    //
    // So `vtcVid` and `adminVids` have different jobs and therefore different encodings:
    // `vtcVid` is an identity REFERENCE (DID), `adminVids` is a signature-verification
    // LIST (CESR keys — see `countValidAdminSignatures`).
    vtcVid: vtcDid,
    vtcDid,
    name: identity?.name ?? '',
    // CESR-encoded Ed25519 public keys — the shape `asEncodedGovernanceDoc` validates
    // and `issueVrc` compares a signer's VID against.
    adminVids,
    // DIDs, parallel to adminVids where a key was resolvable (see resolveAdmins).
    ...(adminDids.length > 0 ? { adminDids } : {}),
    threshold: row.admin_threshold_m ?? 0,
    allowedClaimTypes,
    digest: row.vtc_governance_digest
      ? new Uint8Array(Buffer.from(row.vtc_governance_digest, 'base64'))
      : new Uint8Array(0),
    signatures: [],
    createdAt: row.updated_at ?? 0,
  };
}

function credentialRowToVrc(
  row: CredentialRow,
  issuerDid: string,
  subjectDid: string,
  sigRows: SignatureRow[],
): Vrc {
  return {
    subjectVid: subjectDid,
    issuerVid: issuerDid,
    claim: JSON.parse(row.claim ?? '{}') as VrcClaim,
    issuedAt: row.valid_from,
    expiresAt: row.valid_until ?? undefined,
    digest: row.credential_digest
      ? new Uint8Array(Buffer.from(row.credential_digest, 'base64'))
      : new Uint8Array(0),
    signatures: deserializeSignatures(sigRows),
  };
}

// ---------------------------------------------------------------------------
// VtcStore
// ---------------------------------------------------------------------------

export class VtcStore {
  private readonly db: DatabaseSync;
  private readonly resolver: IdentityResolver;

  constructor(db: DatabaseSync, resolver: IdentityResolver) {
    this.db = db;
    this.resolver = resolver;
  }

  // ---------------------------------------------------------------------------
  // Governance docs (→ governance table)
  // ---------------------------------------------------------------------------

  saveGovernanceDoc(doc: VtcGovernanceDoc, kind: 'vtc' | 'vtn' = 'vtc'): void {
    const vtc = this.resolver.resolveRemoteIdentity({
      did: doc.vtcDid,
      method: 'peer4', // VTCs use did:peer:4 by convention
      name: doc.name,
      // The community identity must be tagged 'vtc'/'vtn' (not the default
      // 'vta') so listCommunitiesFromDb() and the utility-server mirror can
      // find it. The co-admin receive path already stores role='vtc'.
      role: kind,
      // VTCs/VTNs are governance organizations, not human subjects.
      subjectKind: 'organization',
    });
    logger.info(
      `[vtc:store] saving governance doc for ${doc.vtcDid.slice(0, 16)}... ` +
      `(identityUuid=${vtc.identityUuid}, admins=${doc.adminVids.length}, threshold=${doc.threshold})`,
    );

    this.db.prepare(`
      INSERT INTO governance
        (community_identity_uuid, admin_threshold_m, admin_threshold_n,
         vtc_governance_digest, uuid, updated_at)
      VALUES (?, ?, ?, ?, ?, unixepoch())
      ON CONFLICT(community_identity_uuid) DO UPDATE SET
        admin_threshold_m = excluded.admin_threshold_m,
        admin_threshold_n = excluded.admin_threshold_n,
        vtc_governance_digest = excluded.vtc_governance_digest,
        updated_at = unixepoch()
    `).run(
      vtc.identityUuid,
      doc.threshold,
      doc.adminVids.length,
      governanceDocDigest(doc),
      generateUuid(),
    );
  }

  getGovernanceDoc(vtcDid: string): VtcGovernanceDoc | undefined {
    const vtc = this.resolver.lookupByDid(vtcDid);
    if (!vtc) return undefined;

    const row = this.db.prepare(`
      SELECT * FROM governance WHERE community_identity_uuid = ?
    `).get(vtc.identityUuid) as GovernanceRow | undefined;

    return row ? governanceRowToDoc(this.db, row, vtcDid) : undefined;
  }

  listGovernanceDocs(): VtcGovernanceDoc[] {
    const rows = this.db.prepare(`
      SELECT g.*, COALESCE(dd.did, g.community_identity_uuid) AS vtcDid
      FROM governance g
      LEFT JOIN did_documents dd ON dd.identity_uuid = g.community_identity_uuid AND dd.is_primary = 1
      ORDER BY g.updated_at ASC
    `).all() as unknown as (GovernanceRow & { vtcDid: string })[];

    return rows.map(r => governanceRowToDoc(this.db, r, r.vtcDid));
  }

  /**
   * Upsert a VTC/VTN governance doc received from a remote utility server.
   * Uses the identity UUID from the payload — the canonical distributed key.
   */
  upsertRemoteVtc(params: {
    identityUuid: string;
    did: string;
    name: string;
    role: string;
    adminThresholdM: number;
    adminThresholdN: number;
    parentCommunityUuid: string | null;
    adminUuids: string[];
    /** Base64 VTC governance-doc digest received from the server (a stored commitment). */
    vtcGovernanceDigest?: string | null;
    /** The community's allowed claim types — written as claim-type bindings. */
    allowedClaimTypes?: string[];
  }): void {
    // Ensure the community identity exists locally with proper role
    this.resolver.resolveRemoteIdentity({
      did: params.did,
      method: 'peer4',
      name: params.name,
      role: params.role,
      subjectKind: 'organization',
    });

    this.db.prepare(`
      INSERT INTO governance
        (community_identity_uuid, admin_threshold_m, admin_threshold_n,
         vtc_governance_digest, uuid, updated_at)
      VALUES (?, ?, ?, ?, ?, unixepoch())
      ON CONFLICT(community_identity_uuid) DO UPDATE SET
        admin_threshold_m = excluded.admin_threshold_m,
        admin_threshold_n = excluded.admin_threshold_n,
        vtc_governance_digest = excluded.vtc_governance_digest,
        updated_at = unixepoch()
    `).run(
      params.identityUuid,
      params.adminThresholdM,
      params.adminThresholdN,
      params.vtcGovernanceDigest ?? null,
      generateUuid(),
    );

    // Claim-type metadata lives in bindings, not a blob: one row per permitted type.
    for (const claimType of params.allowedClaimTypes ?? []) {
      this.db.prepare(`
        INSERT INTO community_policy_bindings
          (uuid, community_identity_uuid, rule_type, enabled, params, updated_at)
        VALUES (?, ?, ?, 1, ?, unixepoch())
        ON CONFLICT(community_identity_uuid, rule_type) DO NOTHING
      `).run(
        generateUuid(), params.identityUuid,
        `task:p2pts:rule:claim-type-allow:0.1#${claimType}`,
        JSON.stringify({ claim_type: claimType }),
      );
    }
  }

  // ---------------------------------------------------------------------------
  // VRCs (→ credentials + credential_signatures tables)
  // ---------------------------------------------------------------------------

  saveVrc(vrc: Vrc, dtgW3cJson?: string): void {
    // Resolve issuer (VTC) and subject (VTA) identities.
    const issuer = this.resolver.resolveRemoteIdentity({
      did: vrc.issuerVid,
      method: 'peer4',
    });
    const subject = this.resolver.resolveRemoteIdentity({
      did: vrc.subjectVid,
      method: 'peer4',
    });

    const credUuid = generateUuid();
    const digestStr = Buffer.from(vrc.digest).toString('base64');

    const credResult = this.db.prepare(`
      INSERT INTO credentials
        (vc_type, issuer_identity_uuid,
         subject_identity_uuid,
         claim, status, valid_from, valid_until, credential_digest,
         uuid, created_at)
      VALUES ('vrc', ?, ?, ?, 'issued', ?, ?, ?, ?, unixepoch())
    `).run(
      issuer.identityUuid,
      subject.identityUuid,
      JSON.stringify(vrc.claim),
      vrc.issuedAt,
      vrc.expiresAt ?? null,
      digestStr,
      credUuid,
    );
    void credResult;

    // Insert credential_signatures.
    for (const sig of vrc.signatures) {
      // `sig.signerVid` is a CESR **key**, not a DID. Resolving it with `resolveRemoteIdentity({ did })` treated
      // the key as a DID and FABRICATED a phantom identity with no did_document and no `keys` row — so the
      // signature was attributed to nobody, `deserializeSignatures` could find no public key for it, and
      // `verifyVrc` answered `insufficient-signatures` for EVERY store-loaded VRC. `lookupByVid` is the correct
      // lookup: a CESR key is exactly what `keys.public_key` holds.
      //
      // The fallback remains for a signer this node genuinely does not know — a remote admin on a replicated
      // VRC. It is still a fabrication, but it preserves the row, and `deserializeSignatures` now omits such a
      // signature from the reconstructed VRC, so it cannot be mistaken for a valid co-signature.
      const signer = this.resolver.lookupByVid(sig.signerVid)
        ?? this.resolver.resolveRemoteIdentity({
          did: sig.signerVid,
          method: 'peer4',
        });
      this.db.prepare(`
        INSERT INTO credential_signatures
          (credential_uuid, signer_identity_uuid,
           signer_did_document_uuid,
           signature, uuid, signed_at)
        VALUES (
          ?, ?,
          NULL,
          ?, ?, unixepoch()
        )
      `).run(credUuid, signer.identityUuid, sig.signature, generateUuid());
    }

    // Store DTG W3C VC JSON if provided
    if (dtgW3cJson) {
      this.db.prepare('UPDATE credentials SET w3c_vc_json = ? WHERE uuid = ?')
        .run(dtgW3cJson, credUuid);
    }
  }

  getVrc(subjectDid: string, issuerDid: string, claimType: string): Vrc | undefined {
    const issuer = this.resolver.lookupByDid(issuerDid);
    const subject = this.resolver.lookupByDid(subjectDid);
    if (!issuer || !subject) return undefined;

    const row = this.db.prepare(`
      SELECT c.* FROM credentials c
      WHERE c.issuer_identity_uuid = ? AND c.subject_identity_uuid = ?
        AND json_extract(c.claim, '$.type') = ?
    `).get(issuer.identityUuid, subject.identityUuid, claimType) as CredentialRow | undefined;

    if (!row) return undefined;

    const sigRows = this.db.prepare(SIGNATURE_SELECT).all(row.uuid) as unknown as SignatureRow[];

    return credentialRowToVrc(row, issuerDid, subjectDid, sigRows);
  }

  listVrcsForSubject(subjectDid: string): Vrc[] {
    const subject = this.resolver.lookupByDid(subjectDid);
    if (!subject) return [];

    const rows = this.db.prepare(`
      SELECT c.*, ddi.did AS issuerDid, dds.did AS subjectDid
      FROM credentials c
      JOIN did_documents ddi ON ddi.identity_uuid = c.issuer_identity_uuid AND ddi.is_primary = 1
      JOIN did_documents dds ON dds.identity_uuid = c.subject_identity_uuid AND dds.is_primary = 1
      WHERE c.subject_identity_uuid = ?
      ORDER BY c.valid_from ASC
    `).all(subject.identityUuid) as unknown as (CredentialRow & { issuerDid: string; subjectDid: string })[];

    return rows.map(r => {
      const sigRows = this.db.prepare(SIGNATURE_SELECT).all(r.uuid) as unknown as SignatureRow[];
      return credentialRowToVrc(r, r.issuerDid, r.subjectDid, sigRows);
    });
  }

  /**
   * Find all identity UUIDs that have an established VRC with the given identity.
   * Queries BOTH the relationships table (bidirectional + established) AND the
   * credentials table (vc_type='vrc' + status='issued'), then resolves any
   * tsp-bridge UUIDs to real VTA UUIDs via the keys table Ed25519 key join.
   *
   * This mirrors the utility server's findEstablishedVrcIdentityUuids() in
   * relationships-repo.ts, adapted for the agent's synchronous SQLite.
   *
   * @param identityDid — The local agent's DID string
   * @returns Array of identity UUIDs (as UUIDv5 strings) for VTAs with established VRCs
   */
  findEstablishedVrcPeerUuids(identityDid: string): string[] {
    const identity = this.resolver.lookupByDid(identityDid);
    if (!identity) {
      logger.warn(`[VtcStore] findEstablishedVrcPeerUuids: identity not found for DID ${identityDid.slice(0, 20)}...`);
      return [];
    }

    const identityUuid = identity.identityUuid;
    logger.info(`[VtcStore] findEstablishedVrcPeerUuids: looking for VRC peers of uuid=${identityUuid.slice(0, 12)}...`);

    // 1. Relationships table: bidirectional, established
    const relRows = this.db.prepare(`
      SELECT
        CASE
          WHEN local_identity_uuid = ? THEN remote_identity_uuid
          ELSE local_identity_uuid
        END as remote_uuid
      FROM relationships
      WHERE (local_identity_uuid = ? OR remote_identity_uuid = ?)
        AND direction = 'bidirectional'
        AND status = 'established'
    `).all(identityUuid, identityUuid, identityUuid) as { remote_uuid: string }[];

    logger.info(`[VtcStore] relationships query: ${relRows.length} results`);

    // 2. Credentials table: vrc type, issued status
    const credRows = this.db.prepare(`
      SELECT
        CASE
          WHEN issuer_identity_uuid = ? THEN subject_identity_uuid
          ELSE issuer_identity_uuid
        END as remote_uuid
      FROM credentials
      WHERE (issuer_identity_uuid = ? OR subject_identity_uuid = ?)
        AND vc_type = 'vrc'
        AND status = 'issued'
    `).all(identityUuid, identityUuid, identityUuid) as { remote_uuid: string }[];

    logger.info(`[VtcStore] credentials query: ${credRows.length} results`);

    // Union dedup
    const seen = new Set<string>();
    for (const r of relRows) seen.add(r.remote_uuid);
    for (const r of credRows) seen.add(r.remote_uuid);

    // Resolve tsp-bridge UUIDs to real VTA UUIDs via shared Ed25519 key.
    // A tsp-bridge fake identity has NO active peer_endpoint and no real VTA data.
    // The keys table links both the fake and real rows via their shared Ed25519 pubkey.
    const resolvedUuids = new Set<string>();
    for (const candidateUuid of seen) {
      // Check if this is a real VTA (has an active endpoint, role=vta)
      const vtaRow = this.db.prepare(
        `SELECT i.uuid FROM identities i
         JOIN peer_endpoints pe ON pe.identity_uuid = i.uuid
         WHERE i.uuid = ? AND i.role = ?`,
      ).get(candidateUuid, 'vta') as { uuid: string } | undefined;
      if (vtaRow) {
        resolvedUuids.add(vtaRow.uuid);
        continue;
      }
      // Not a real VTA — try to resolve via Ed25519 key match
      const real = this.db.prepare(`
        SELECT i.uuid FROM identities i
        JOIN keys k ON k.identity_uuid = i.uuid
        JOIN keys k2 ON k2.public_key = k.public_key AND k2.key_type = 'ed25519'
        JOIN identities i2 ON i2.uuid = k2.identity_uuid
        JOIN peer_endpoints pe ON pe.identity_uuid = i.uuid
        WHERE i2.uuid = ? AND i.role = 'vta'
        ORDER BY k.created_at
        LIMIT 1
      `).get(candidateUuid) as { uuid: string } | undefined;
      if (real) {
        resolvedUuids.add(real.uuid);
      }
    }

    const result = [...resolvedUuids];
    logger.info(`[VtcStore] findEstablishedVrcPeerUuids: ${result.length} resolved UUIDs from ${seen.size} candidates`);
    return result;
  }

  /**
   * Check whether an established VRC exists between two identities (by DID).
   * Checks BOTH the relationships table AND the credentials table.
   */
  hasEstablishedVrcBetween(didA: string, didB: string): boolean {
    const a = this.resolver.lookupByDid(didA);
    const b = this.resolver.lookupByDid(didB);
    if (!a || !b) return false;

    const uuidA = a.identityUuid;
    const uuidB = b.identityUuid;

    // 1. Relationships table
    const relRow = this.db.prepare(`
      SELECT COUNT(*) as cnt FROM relationships
      WHERE ((local_identity_uuid = ? AND remote_identity_uuid = ?)
          OR (local_identity_uuid = ? AND remote_identity_uuid = ?))
        AND direction = 'bidirectional'
        AND status = 'established'
    `).get(uuidA, uuidB, uuidB, uuidA) as { cnt: number };
    if ((relRow?.cnt ?? 0) > 0) return true;

    // 2. Credentials table
    const credRow = this.db.prepare(`
      SELECT COUNT(*) as cnt FROM credentials
      WHERE ((issuer_identity_uuid = ? AND subject_identity_uuid = ?)
          OR (issuer_identity_uuid = ? AND subject_identity_uuid = ?))
        AND vc_type = 'vrc'
        AND status = 'issued'
    `).get(uuidA, uuidB, uuidB, uuidA) as { cnt: number };
    return (credRow?.cnt ?? 0) > 0;
  }

  listVrcsForIssuer(issuerDid: string): Vrc[] {
    const issuer = this.resolver.lookupByDid(issuerDid);
    if (!issuer) return [];

    const rows = this.db.prepare(`
      SELECT c.*, ddi.did AS issuerDid, dds.did AS subjectDid
      FROM credentials c
      JOIN did_documents ddi ON ddi.identity_uuid = c.issuer_identity_uuid AND ddi.is_primary = 1
      JOIN did_documents dds ON dds.identity_uuid = c.subject_identity_uuid AND dds.is_primary = 1
      WHERE c.issuer_identity_uuid = ?
      ORDER BY c.valid_from ASC
    `).all(issuer.identityUuid) as unknown as (CredentialRow & { issuerDid: string; subjectDid: string })[];

    return rows.map(r => {
      const sigRows = this.db.prepare(SIGNATURE_SELECT).all(r.uuid) as unknown as SignatureRow[];
      return credentialRowToVrc(r, r.issuerDid, r.subjectDid, sigRows);
    });
  }

  /**
   * Store a DTG W3C VC JSON received from a remote peer (VRC replication).
   * If a credential with the same digest already exists, it is skipped (idempotent).
   *
   * @param w3cVcJson — The W3C VC JSON string (DTG RelationshipCredential envelope)
   * @param issuerDid — The issuer's DID (the remote peer who sent this VRC)
   * @param subjectDid — The subject's DID (the local agent receiving this VRC)
   */
  storeReceivedDtgVrc(
    w3cVcJson: string,
    issuerDid: string,
    subjectDid: string,
    issuerIdentity?: Record<string, unknown>,
  ): void {
    // Compute digest from the W3C VC JSON for dedup
    const digestBytes = sha256(new TextEncoder().encode(w3cVcJson));
    const digestHex = Array.from(digestBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    // Resolve issuer and subject identities. The issuer's record travels with
    // the VRC (issuerIdentity) so the receiver copies the sender's full
    // `identities` row into its local table. storeRemoteIdentityCopy upserts
    // by the record's own UUID (the canonical selection key), preserves every
    // field, and forces custody='remote' (the receiver does not own the record).
    const issuer = issuerIdentity
      ? this.resolver.storeRemoteIdentityCopy(issuerIdentity as never)
      : this.resolver.resolveRemoteIdentity({
          did: issuerDid,
          method: 'peer4',
        });
    const subject = this.resolver.resolveRemoteIdentity({
      did: subjectDid,
      method: 'peer4',
    });

    // Idempotency — first-wins dedup on TWO independent keys so the same
    // logical VRC can never be written twice by different paths:
    //   1. the exact VC digest (a duplicate delivery of the same envelope), AND
    //   2. any 'vrc' row for the same (issuer, subject) peer pair that already
    //      carries a DTG w3c_vc_json envelope.
    // The second clause closes the cross-path duplicate: the issuer's own
    // minted row (mintPeerVrc, keyed on the *claim* digest) never collides on
    // the *VC* digest used here, so a shared credentials table previously
    // ended up with each of the two VRCs of a ceremony twice. The mirrored
    // copy is byte-identical to the minted envelope, so keeping the existing
    // row loses nothing.
    const existing = this.db.prepare(
      `SELECT uuid FROM credentials
       WHERE vc_type = 'vrc'
         AND (
           credential_digest = ?
           OR (issuer_identity_uuid = ? AND subject_identity_uuid = ? AND w3c_vc_json IS NOT NULL)
         )
       LIMIT 1`,
    ).get(digestHex, issuer.identityUuid, subject.identityUuid) as { uuid: string } | undefined;
    if (existing) {
      logger.info(
        `[VtcStore] Received peer VRC from ${issuerDid.slice(0, 12)}... already present (uuid=${existing.uuid}) — skipping`,
      );
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    const rowUuid = generateUuid();

    // Extract claim from W3C VC if possible
    let claimJson = '{}';
    try {
      const vc = JSON.parse(w3cVcJson);
      if (vc.credentialSubject && typeof vc.credentialSubject === 'object') {
        const { id, ...claimRest } = vc.credentialSubject as Record<string, unknown>;
        claimJson = JSON.stringify(claimRest);
      }
    } catch { /* non-JSON — store empty claim */ }

    this.db.prepare(`
      INSERT INTO credentials
        (vc_type, issuer_identity_uuid,
         subject_identity_uuid,
         w3c_vc_json, claim, status, valid_from, valid_until,
         credential_digest, uuid, created_at)
      VALUES ('vrc', ?, ?, ?, ?, 'issued', ?, NULL, ?, ?, ?)
    `).run(
      issuer.identityUuid,
      subject.identityUuid,
      w3cVcJson,
      claimJson,
      now,
      digestHex,
      rowUuid,
      now,
    );

    logger.info(
      `[VtcStore] Stored received peer VRC from ${issuerDid.slice(0, 12)}... to ${subjectDid.slice(0, 12)}...`,
    );
  }
}