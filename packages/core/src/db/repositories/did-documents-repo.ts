/**
 * Repository: did_documents table.
 *
 * Holds the actual DID strings (e.g., "did:peer:4:...") bound to an identity.
 * identity_uuid is the distributed FK target; identity_id is for local joins.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export interface DidDocumentRow {
  identityUuid: string;
  did: string;           // the actual DID string
  method: string;
  documentJson: string | null;
  isPrimary: number;
  status: string;
  contextType: string | null;
  contextRefUuid: string | null;
  uuid: string;          // UUIDv7 for cross-node dedup
  recordedByNode: string | null;
  replicatedAt: number | null;
  createdAt: number | null;
  updatedAt: number | null;
}

export interface CreateDidDocumentInput {
  identityUuid: string;
  did: string;
  method: string;
  documentJson?: string;
  isPrimary?: boolean;
  contextType?: string | null;
  contextRefUuid?: string | null;
  recordedByNode?: string;
  replicatedAt?: number;
}

interface DidDocumentDbRow {
  identity_uuid: string;
  did: string;
  method: string;
  document_json: string | null;
  is_primary: number;
  status: string;
  context_type: string | null;
  context_ref_uuid: string | null;
  uuid: string;
  recorded_by_node: string | null;
  replicated_at: number | null;
  created_at: number | null;
  updated_at: number | null;
}

function rowToDidDocument(row: DidDocumentDbRow): DidDocumentRow {
  return {
    identityUuid: row.identity_uuid,
    did: row.did,
    method: row.method,
    documentJson: row.document_json,
    isPrimary: row.is_primary,
    status: row.status,
    contextType: row.context_type,
    contextRefUuid: row.context_ref_uuid,
    uuid: row.uuid,
    recordedByNode: row.recorded_by_node,
    replicatedAt: row.replicated_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function create(db: DataSource, input: CreateDidDocumentInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const rowUuid = generateUuid();

  await db.run(
    `INSERT INTO did_documents (identity_uuid, did, method, document_json, is_primary, status, context_type, context_ref_uuid, uuid, recorded_by_node, replicated_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)`,
    input.identityUuid,
    input.did,
    input.method,
    input.documentJson ?? null,
    input.isPrimary ? 1 : 0,
    input.contextType ?? null,
    input.contextRefUuid ?? null,
    rowUuid,
    input.recordedByNode ?? null,
    input.replicatedAt ?? null,
    now,
    now,
  );
  return rowUuid;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<DidDocumentRow | null> {
  const row = await db.get<DidDocumentDbRow>('SELECT * FROM did_documents WHERE uuid = ?', uuid);
  return row ? rowToDidDocument(row) : null;
}

export async function findByRealDid(db: DataSource, realDid: string): Promise<DidDocumentRow | null> {
  const row = await db.get<DidDocumentDbRow>('SELECT * FROM did_documents WHERE did = ?', realDid);
  return row ? rowToDidDocument(row) : null;
}

export async function findByPeerId(db: DataSource, peerId: string): Promise<DidDocumentRow | null> {
  const row = await db.get<DidDocumentDbRow>(
    `SELECT d.* FROM did_documents d
     JOIN identities i ON i.uuid = d.identity_uuid
     JOIN peer_endpoints pe ON pe.identity_uuid = i.uuid AND pe.peer_id = ?
     WHERE pe.is_active = 1`,
    peerId,
  );
  return row ? rowToDidDocument(row) : null;
}

export async function findByIdentityUuid(db: DataSource, identityUuid: string): Promise<DidDocumentRow[]> {
  const rows = await db.all<DidDocumentDbRow>('SELECT * FROM did_documents WHERE identity_uuid = ? ORDER BY is_primary DESC', identityUuid);
  return rows.map(rowToDidDocument);
}

export async function findPrimaryForIdentity(db: DataSource, identityUuid: string): Promise<DidDocumentRow | null> {
  const row = await db.get<DidDocumentDbRow>('SELECT * FROM did_documents WHERE identity_uuid = ? AND is_primary = 1', identityUuid);
  return row ? rowToDidDocument(row) : null;
}

export async function listByIdentity(db: DataSource, identityUuid: string): Promise<DidDocumentRow[]> {
  const rows = await db.all<DidDocumentDbRow>('SELECT * FROM did_documents WHERE identity_uuid = ? ORDER BY is_primary DESC', identityUuid);
  return rows.map(rowToDidDocument);
}

/**
 * Upsert from a pubsub replication event. Uses uuid as dedup key.
 * If row already exists, updates document_json/status/updated_at/replicated_at.
 * Does NOT change identity_id, did, or method (immutable after creation).
 */
export async function upsertFromReplication(
  db: DataSource,
  input: CreateDidDocumentInput & { status?: string; recordedByNode: string; replicatedAt: number; uuid?: string },
): Promise<string> {
  if (!('uuid' in input) || !input.uuid) return create(db, input);

  const row = await db.get<{ uuid: string }>('SELECT uuid FROM did_documents WHERE uuid = ?', input.uuid);
  if (row) {
    const now = Math.floor(Date.now() / 1000);
    await db.run(`
      UPDATE did_documents SET
        document_json = COALESCE(?, document_json),
        status = COALESCE(?, status),
        replicated_at = ?,
        updated_at = ?
      WHERE uuid = ?
    `, input.documentJson ?? null, input.status ?? null, input.replicatedAt, now, input.uuid);
    return row.uuid;
  }

  return create(db, input);
}
/**
 * Set the given did_document as the primary for its identity, clearing the
 * `is_primary` flag on any other did_documents belonging to that identity first.
 */
export async function setPrimary(db: DataSource, uuid: string, identityUuid: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await db.run('UPDATE did_documents SET is_primary = 0 WHERE identity_uuid = ?', identityUuid);
  await db.run('UPDATE did_documents SET is_primary = 1, updated_at = ? WHERE uuid = ?', now, uuid);
}

export type DidDocumentStatus = 'active' | 'deactivated' | 'superseded';

/** Set the lifecycle status of a did_document. */
export async function setStatus(db: DataSource, uuid: string, status: DidDocumentStatus): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await db.run('UPDATE did_documents SET status = ?, updated_at = ? WHERE uuid = ?', status, now, uuid);
}
