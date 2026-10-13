/**
 * Repository: identities table.
 *
 * Every VTA, VTC, and VTN is a row here, discriminated by `role`.
 *
 * ## identity key vs DID
 *
 * - `uuid` = UUIDv5(DID_NAMESPACE, root_did_string) — a DETERMINISTIC identity
 *   key derived from the real DID, so any node independently computing the same
 *   identity arrives at the same UUID. It is the single cross-node identity
 *   anchor (referenced by did_documents.identity_uuid, keys.identity_uuid, etc.).
 *   Callers may pass an explicit `uuid` (e.g. replication carrying the creator's
 *   key verbatim); otherwise it is derived deterministically from `realDid`.
 * - `did`  = the actual root DID string, resolved via a JOIN with did_documents
 *   (is_primary = 1). This is the human-facing DID, NOT the identity key.
 */

import type { DataSource } from '../data-source.js';
import { didToUuid, generateUuid } from '../uuid-helpers.js';

export type IdentityRole = 'vta' | 'vtc' | 'vtn';
export type SubjectKind = 'human' | 'ai_agent' | 'object' | 'organization';
export type Custody = 'local' | 'remote';

export interface Identity {
  did: string | null;      // the real DID string (resolved from did_documents, primary)
  uuid: string;            // UUIDv5 (deterministic identity key)
  role: IdentityRole;
  subjectKind: SubjectKind | null;
  custody: Custody;
  name: string | null;
  vid: string | null;
  recordedByNode: string | null;
  replicatedAt: number | null;
  createdAt: number | null;
  updatedAt: number | null;
}

export interface CreateIdentityInput {
  /** Real DID string (stored in did_documents, not on the identity row). */
  realDid: string;
  /** Optional stable identity key — generated if not provided (replication carries it verbatim). */
  uuid?: string;
  role: IdentityRole;
  subjectKind?: SubjectKind;
  custody?: Custody;
  name?: string;
  vid?: string;
  peerId?: string;
  recordedByNode?: string;
  replicatedAt?: number;
}

interface IdentityRow {
  did: string | null;
  uuid: string;
  role: IdentityRole;
  subject_kind: SubjectKind | null;
  custody: Custody;
  name: string | null;
  vid: string | null;
  recorded_by_node: string | null;
  replicated_at: number | null;
  created_at: number | null;
  updated_at: number | null;
}

function rowToIdentity(row: IdentityRow): Identity {
  return {
    did: row.did,
    uuid: row.uuid,
    role: row.role,
    subjectKind: row.subject_kind,
    custody: row.custody,
    name: row.name,
    vid: row.vid,
    recordedByNode: row.recorded_by_node,
    replicatedAt: row.replicated_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** Shared SELECT that resolves the real DID via the primary did_document. */
const IDENTITY_SELECT = `SELECT i.*, d.did AS did
  FROM identities i
  LEFT JOIN did_documents d ON d.identity_uuid = i.uuid AND d.is_primary = 1`;

/** Create a new identity row. Returns the new row's uuid. */
export async function create(db: DataSource, input: CreateIdentityInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const identityUuid = input.uuid ?? didToUuid(input.realDid);

  await db.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, vid, recorded_by_node, replicated_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    identityUuid,
    input.role,
    input.subjectKind ?? null,
    input.custody ?? 'remote',
    input.name ?? null,
    input.vid ?? null,
    input.recordedByNode ?? null,
    input.replicatedAt ?? null,
    now,
    now,
  );
  // Workstream B: record the libp2p endpoint beside the identity (host state),
  // never as the identity. Inter-table reference is by identity_uuid ONLY
  // (peer_endpoints carries no integer FKs). Keeps findByPeerId working via
  // peer_endpoints; dedup key is the UNIQUE peer_id.
  //
  // setActiveEndpoint is guarded: it refuses to claim a peer already active on
  // a DIFFERENT identity, and retires any other active endpoint of this
  // identity (an identity has one current node).
  if (input.peerId) {
    const pe = await db.get<{ uuid: string }>(
      'SELECT uuid FROM peer_endpoints WHERE peer_id = ?',
      input.peerId,
    );
    if (pe) {
      // Only reassign if the endpoint isn't actively claimed by another identity.
      const owner = await db.get<{ identity_uuid: string; is_active: number }>(
        'SELECT identity_uuid, is_active FROM peer_endpoints WHERE uuid = ?',
        pe.uuid,
      );
      if (!owner || owner.is_active !== 1 || owner.identity_uuid === identityUuid) {
        await db.run(
          'UPDATE peer_endpoints SET identity_uuid = ?, is_active = 1, updated_at = ? WHERE uuid = ?',
          identityUuid, now, pe.uuid,
        );
        await db.run(
          `UPDATE peer_endpoints SET is_active = 0, updated_at = ?
           WHERE identity_uuid = ? AND peer_id <> ? AND is_active = 1`,
          now, identityUuid, input.peerId,
        );
      } else {
        console.warn(
          `[identities-repo] refusing to assign peer ${String(input.peerId).slice(0, 12)}... ` +
          `to identity ${identityUuid.slice(0, 8)} — already active on ${owner.identity_uuid.slice(0, 8)}`,
        );
      }
    } else {
      const rowUuid = generateUuid();
      await db.run(
        `INSERT INTO peer_endpoints (uuid, identity_uuid, peer_id, is_active, created_at, updated_at)
         VALUES (?, ?, ?, 1, ?, ?)`,
        rowUuid, identityUuid, input.peerId, now, now,
      );
    }
  }

  return identityUuid;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<Identity | null> {
  const row = await db.get<IdentityRow>(`${IDENTITY_SELECT} WHERE i.uuid = ?`, uuid);
  return row ? rowToIdentity(row) : null;
}

/** Find an identity by its real DID string (joins did_documents). */
export async function findByRealDid(db: DataSource, realDid: string): Promise<Identity | null> {
  const row = await db.get<IdentityRow>(`
    SELECT i.*, d.did AS did
    FROM identities i
    JOIN did_documents d ON d.identity_uuid = i.uuid
    WHERE d.did = ?
  `, realDid);
  return row ? rowToIdentity(row) : null;
}

export async function findByPeerId(db: DataSource, peerId: string): Promise<Identity | null> {
  const row = await db.get<IdentityRow>(
    `SELECT i.*, d.did AS did
       FROM identities i
       JOIN peer_endpoints pe ON pe.identity_uuid = i.uuid AND pe.peer_id = ?
       LEFT JOIN did_documents d ON d.identity_uuid = i.uuid AND d.is_primary = 1`,
    peerId,
  );
  return row ? rowToIdentity(row) : null;
}

/**
 * Whether an identity has ANY recorded libp2p endpoint. "Real VTA"
 * discrimination: TSP-bridge fake identities (created to record a handshake
 * keyed by the ephemeral did:peer:4 VID) carry NO endpoint, while real Agent
 * App VTAs record one on every login / identity_push.
 */
export async function hasAnyEndpoint(db: DataSource, identityUuid: string): Promise<boolean> {
  const row = await db.get<{ uuid: string }>(
    `SELECT uuid FROM peer_endpoints
     WHERE identity_uuid = ? LIMIT 1`,
    identityUuid,
  );
  return row != null;
}

export async function findByRole(db: DataSource, role: IdentityRole): Promise<Identity[]> {
  const rows = await db.all<IdentityRow>(`${IDENTITY_SELECT} WHERE i.role = ? ORDER BY i.created_at, i.uuid`, role);
  return rows.map(rowToIdentity);
}

/** List identities by both role and subject_kind, excluding TSP-bridge fakes (no active endpoint). */
export async function findByRoleAndSubjectKind(
  db: DataSource,
  role: IdentityRole,
  subjectKind: SubjectKind,
): Promise<Identity[]> {
  const rows = await db.all<IdentityRow>(
    `${IDENTITY_SELECT} WHERE i.role = ? AND i.subject_kind = ? AND EXISTS (
       SELECT 1 FROM peer_endpoints pe WHERE pe.identity_uuid = i.uuid
     ) ORDER BY i.created_at, i.uuid`,
    role,
    subjectKind,
  );
  return rows.map(rowToIdentity);
}

export async function findByCustody(db: DataSource, custody: Custody): Promise<Identity[]> {
  const rows = await db.all<IdentityRow>(`${IDENTITY_SELECT} WHERE i.custody = ? ORDER BY i.created_at, i.uuid`, custody);
  return rows.map(rowToIdentity);
}

export interface ListFilters {
  role?: IdentityRole;
  custody?: Custody;
  /**
   * Exact match on the CESR VID (`identities.vid`).
   *
   * Added for the `credentials.issue` subject check: a credential's subject is named by VID, and
   * `VtcStore.saveVrc` FABRICATES a placeholder identity for an unresolvable one — so the check has to be
   * able to ask "do I already know this VID?" before that happens.
   */
  vid?: string;
}

export async function list(db: DataSource, filters: ListFilters = {}): Promise<Identity[]> {
  const clauses: string[] = [];
  const params: unknown[] = [];

  if (filters.role) {
    clauses.push('i.role = ?');
    params.push(filters.role);
  }
  if (filters.custody) {
    clauses.push('i.custody = ?');
    params.push(filters.custody);
  }
  if (filters.vid) {
    clauses.push('i.vid = ?');
    params.push(filters.vid);
  }

  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = await db.all<IdentityRow>(`${IDENTITY_SELECT} ${where} ORDER BY i.created_at, i.uuid`, ...params);
  return rows.map(rowToIdentity);
}

/**
 * Upsert from a pubsub replication event. Uses uuid as dedup key.
 * If row already exists, updates name/vid/replicated_at/updated_at.
 * Does NOT change role or custody (immutable after creation).
 * The peer binding is recorded in peer_endpoints (guarded); the legacy
 * identities.peer_id column does not exist in the base schema (0001).
 */
export async function upsertFromReplication(
  db: DataSource,
  input: CreateIdentityInput & { recordedByNode: string; replicatedAt: number },
): Promise<string> {
  // Dedup by the carried uuid (the creator's identity key), then by the
  // deterministic UUIDv5 of the real DID, then by the real DID (via
  // did_documents) when the identity row exists but has no primary doc yet.
  // The deterministic key is the authoritative cross-node identity anchor, so
  // it is the reliable dedup key even before a did_documents row is written.
  let existing = input.uuid ? await findByUuid(db, input.uuid) : null;
  if (!existing) existing = await findByUuid(db, didToUuid(input.realDid));
  if (!existing) existing = await findByRealDid(db, input.realDid);
  const identityUuid = existing?.uuid ?? input.uuid ?? didToUuid(input.realDid);

  if (existing) {
    const now = Math.floor(Date.now() / 1000);
    await db.run(`
      UPDATE identities SET
        name = COALESCE(?, name),
        vid = COALESCE(?, vid),
        replicated_at = ?,
        updated_at = ?
      WHERE uuid = ?
    `,
      input.name ?? null,
      input.vid ?? null,
      input.replicatedAt,
      now,
      identityUuid,
    );

    // Record the carried peer as the identity's active endpoint (guarded).
    if (input.peerId) {
      await upsertEndpointGuarded(db, identityUuid, input.peerId, now);
    }

    return existing.uuid;
  }

  return create(db, input);
}

/**
 * Guarded endpoint write used by replication: never claim a peer that is
 * active on a different identity; otherwise activate it and retire the
 * identity's other active endpoints (mirroring to the legacy column).
 */
async function upsertEndpointGuarded(db: DataSource, identityUuid: string, peerId: string, now: number): Promise<void> {
  const owner = await db.get<{ uuid: string; identity_uuid: string; is_active: number }>(
    'SELECT uuid, identity_uuid, is_active FROM peer_endpoints WHERE peer_id = ?',
    peerId,
  );
  if (owner && owner.is_active === 1 && owner.identity_uuid !== identityUuid) {
    console.warn(
      `[identities-repo] replication refused to assign peer ${peerId.slice(0, 12)}... ` +
      `to identity ${identityUuid.slice(0, 8)} — already active on ${owner.identity_uuid.slice(0, 8)}`,
    );
    return;
  }

  if (owner) {
    await db.run(
      'UPDATE peer_endpoints SET identity_uuid = ?, is_active = 1, updated_at = ? WHERE uuid = ?',
      identityUuid, now, owner.uuid,
    );
  } else {
    const rowUuid = generateUuid();
    await db.run(
      `INSERT INTO peer_endpoints (uuid, identity_uuid, peer_id, is_active, created_at, updated_at)
       VALUES (?, ?, ?, 1, ?, ?)`,
      rowUuid, identityUuid, peerId, now, now,
    );
  }

  await db.run(
    `UPDATE peer_endpoints SET is_active = 0, updated_at = ?
     WHERE identity_uuid = ? AND peer_id <> ? AND is_active = 1`,
    now, identityUuid, peerId,
  );
}
