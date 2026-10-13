/**
 * Repository: rotation_log + witness_attestations tables (uuid-first, 0018).
 * Both tables now key by `uuid` (UUIDv7); FK targets are the `*_uuid` columns.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export interface RotationLogRow {
  uuid: string;
  didDocumentUuid: string;
  version: number;
  previousHash: Uint8Array | null;
  newPublicKey: Uint8Array;
  signedEntry: Uint8Array;
  createdAt: number | null;
}

export interface CreateRotationLogInput {
  didDocumentUuid: string;
  version: number;
  previousHash?: Uint8Array;
  newPublicKey: Uint8Array;
  signedEntry: Uint8Array;
}

interface RawRotationRow {
  uuid: string;
  did_document_uuid: string;
  version: number;
  previous_hash: Uint8Array | null;
  new_public_key: Uint8Array;
  signed_entry: Uint8Array;
  created_at: number | null;
}

function rowToRotationLog(row: RawRotationRow): RotationLogRow {
  return {
    uuid: row.uuid,
    didDocumentUuid: row.did_document_uuid,
    version: row.version,
    previousHash: row.previous_hash,
    newPublicKey: row.new_public_key,
    signedEntry: row.signed_entry,
    createdAt: row.created_at,
  };
}

/** Append a rotation log entry. Returns the new row's uuid. */
export async function appendEntry(db: DataSource, input: CreateRotationLogInput): Promise<string> {
  const rowUuid = generateUuid();
  const result = await db.run(
    `INSERT INTO rotation_log (did_document_uuid, version, previous_hash, new_public_key, signed_entry, uuid, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    input.didDocumentUuid,
    input.version,
    input.previousHash ?? null,
    input.newPublicKey,
    input.signedEntry,
    rowUuid,
    Math.floor(Date.now() / 1000),
  );
  void result;
  return rowUuid;
}

/**
 * Insert a rotation entry only when `(did_document_uuid, version)` is absent.
 *
 * Used by the utility server to persist an agent-pushed rotation log
 * (`rotation-log-sync.ts`). Distinct from `appendEntry`, which is an
 * unconditional INSERT: a push re-sends the WHOLE log on every roll, so every
 * already-held version must be a no-op rather than a unique-constraint failure.
 *
 * Returns `true` when a row was actually inserted.
 */
export async function insertIfAbsent(
  db: DataSource,
  input: CreateRotationLogInput & { createdAt?: number | null },
): Promise<boolean> {
  const rowUuid = generateUuid();
  const result = await db.run(
    `INSERT INTO rotation_log (did_document_uuid, version, previous_hash, new_public_key, signed_entry, uuid, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (did_document_uuid, version) DO NOTHING`,
    input.didDocumentUuid,
    input.version,
    input.previousHash ?? null,
    input.newPublicKey,
    input.signedEntry,
    rowUuid,
    input.createdAt ?? Math.floor(Date.now() / 1000),
  );
  return result.changes > 0;
}

export async function findForDidDocument(db: DataSource, didDocumentUuid: string): Promise<RotationLogRow[]> {
  const rows = await db.all<RawRotationRow>(
    'SELECT * FROM rotation_log WHERE did_document_uuid = ? ORDER BY version',
    didDocumentUuid,
  );
  return rows.map(rowToRotationLog);
}

export async function findLatestForDidDocument(
  db: DataSource,
  didDocumentUuid: string,
): Promise<RotationLogRow | null> {
  const row = await db.get<RawRotationRow>(
    'SELECT * FROM rotation_log WHERE did_document_uuid = ? ORDER BY version DESC LIMIT 1',
    didDocumentUuid,
  );
  return row ? rowToRotationLog(row) : null;
}

// ── witness_attestations ──────────────────────────────────────────────────

export interface WitnessAttestationRow {
  uuid: string;
  rotationLogUuid: string;
  witnessDidDocumentUuid: string;
  signature: Uint8Array;
  attestedAt: number | null;
}

export interface CreateWitnessAttestationInput {
  rotationLogUuid: string;
  witnessDidDocumentUuid: string;
  signature: Uint8Array;
}

interface RawAttestationRow {
  uuid: string;
  rotation_log_uuid: string;
  witness_did_document_uuid: string;
  signature: Uint8Array;
  attested_at: number | null;
}

function rowToAttestation(row: RawAttestationRow): WitnessAttestationRow {
  return {
    uuid: row.uuid,
    rotationLogUuid: row.rotation_log_uuid,
    witnessDidDocumentUuid: row.witness_did_document_uuid,
    signature: row.signature,
    attestedAt: row.attested_at,
  };
}

/** Add a witness attestation. Returns the new row's uuid. */
export async function addAttestation(
  db: DataSource,
  input: CreateWitnessAttestationInput,
): Promise<string> {
  const rowUuid = generateUuid();
  const result = await db.run(
    `INSERT INTO witness_attestations (rotation_log_uuid, witness_did_document_uuid, signature, uuid, attested_at)
     VALUES (?, ?, ?, ?, ?)`,
    input.rotationLogUuid, input.witnessDidDocumentUuid, input.signature, rowUuid, Math.floor(Date.now() / 1000),
  );
  void result;
  return rowUuid;
}

export async function findForRotationLog(
  db: DataSource,
  rotationLogUuid: string,
): Promise<WitnessAttestationRow[]> {
  const rows = await db.all<RawAttestationRow>(
    'SELECT * FROM witness_attestations WHERE rotation_log_uuid = ? ORDER BY uuid',
    rotationLogUuid,
  );
  return rows.map(rowToAttestation);
}
