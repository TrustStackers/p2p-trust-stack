/**
 * Repository: credentials table.
 *
 * The VC layer — vmc/vec/vrc/custom_endorsement mirror OpenVTC's four VC
 * types for interop; 'delegation' is a fifth, P2PTS-specific extension.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export type VcType = 'vmc' | 'vec' | 'vrc' | 'vic' | 'custom_endorsement' | 'delegation';
export type CredentialStatus = 'pending_signatures' | 'issued' | 'revoked' | 'expired';

export interface CredentialRow {
  vcType: VcType;
  issuerIdentityUuid: string;
  subjectIdentityUuid: string;
  w3cVcJson: string | null;
  claim: string | null;
  status: CredentialStatus;
  thresholdRequired: number | null;
  validFrom: number;
  validUntil: number | null;
  statusListUuid: string | null;
  statusListIndex: number | null;
  supersededByUuid: string | null;
  credentialDigest: string | null;
  uuid: string;
  recordedByNode: string | null;
  replicatedAt: number | null;
  createdAt: number | null;
}

export interface CreateCredentialInput {
  vcType: VcType;
  issuerIdentityUuid: string;
  subjectIdentityUuid: string;
  w3cVcJson?: string;
  claim?: string;
  status?: CredentialStatus;
  thresholdRequired?: number;
  validFrom: number;
  validUntil?: number;
  credentialDigest?: string;
  recordedByNode?: string;
  replicatedAt?: number;
}

interface RawRow {
  vc_type: VcType;
  issuer_identity_uuid: string;
  subject_identity_uuid: string;
  w3c_vc_json: string | null;
  claim: string | null;
  status: CredentialStatus;
  threshold_required: number | null;
  valid_from: number;
  valid_until: number | null;
  status_list_uuid: string | null;
  status_list_index: number | null;
  superseded_by_uuid: string | null;
  credential_digest: string | null;
  uuid: string;
  recorded_by_node: string | null;
  replicated_at: number | null;
  created_at: number | null;
}

function rowToCredential(row: RawRow): CredentialRow {
  return {
    vcType: row.vc_type,
    issuerIdentityUuid: row.issuer_identity_uuid,
    subjectIdentityUuid: row.subject_identity_uuid, w3cVcJson: row.w3c_vc_json,
    claim: row.claim, status: row.status, thresholdRequired: row.threshold_required,
    validFrom: row.valid_from, validUntil: row.valid_until, statusListUuid: row.status_list_uuid,
    statusListIndex: row.status_list_index, supersededByUuid: row.superseded_by_uuid,
    credentialDigest: row.credential_digest, uuid: row.uuid,
    recordedByNode: row.recorded_by_node, replicatedAt: row.replicated_at,
    createdAt: row.created_at,
  };
}

export async function create(db: DataSource, input: CreateCredentialInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const rowUuid = generateUuid();
  await db.run(
    `INSERT INTO credentials
      (vc_type, issuer_identity_uuid, subject_identity_uuid,
       w3c_vc_json, claim, status, threshold_required, valid_from, valid_until,
       uuid, credential_digest, recorded_by_node, replicated_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    input.vcType,
    input.issuerIdentityUuid,
    input.subjectIdentityUuid,
    input.w3cVcJson ?? null, input.claim ?? null,
    input.status ?? 'issued', input.thresholdRequired ?? null,
    input.validFrom, input.validUntil ?? null, rowUuid,
    input.credentialDigest ?? null, input.recordedByNode ?? null,
    input.replicatedAt ?? null, now,
  );
  return rowUuid;
}

/**
 * Find a credential by its uuid — the trust stack's identifier standard.
 *
 * A `findByRowId()` lived here until 2026-10-10, addressing SQLite's implicit `rowid`. It existed only to serve
 * `credentials.revoke()`/`signatures()`, which took a numeric id that **no DTO ever published** — so those
 * methods were unreachable from any consumer, and the web UI's Revoke button was disabled as a result. Integer
 * row addresses are not a supported way to reach a credential; nothing should reintroduce one.
 */
export async function findByUuid(db: DataSource, uuid: string): Promise<CredentialRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM credentials WHERE uuid = ?', uuid);
  return row ? rowToCredential(row) : null;
}

export async function findByDigest(db: DataSource, digest: string): Promise<CredentialRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM credentials WHERE credential_digest = ?', digest);
  return row ? rowToCredential(row) : null;
}

export async function list(db: DataSource, filters: { subjectUuid?: string; issuerUuid?: string; vcType?: VcType } = {}): Promise<CredentialRow[]> {
  const clauses: string[] = [];
  const params: unknown[] = [];
  if (filters.subjectUuid !== undefined) { clauses.push('subject_identity_uuid = ?'); params.push(filters.subjectUuid); }
  if (filters.issuerUuid !== undefined) { clauses.push('issuer_identity_uuid = ?'); params.push(filters.issuerUuid); }
  if (filters.vcType) { clauses.push('vc_type = ?'); params.push(filters.vcType); }
  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = await db.all<RawRow>(`SELECT * FROM credentials ${where} ORDER BY created_at`, ...params);
  return rows.map(rowToCredential);
}

export async function updateStatus(db: DataSource, uuid: string, status: CredentialStatus): Promise<void> {
  await db.run('UPDATE credentials SET status = ? WHERE uuid = ?', status, uuid);
}

export async function setStatusListSlot(db: DataSource, uuid: string, statusListUuid: string, statusListIndex: number): Promise<void> {
  await db.run('UPDATE credentials SET status_list_uuid = ?, status_list_index = ? WHERE uuid = ?', statusListUuid, statusListIndex, uuid);
}

export async function setSupersededBy(db: DataSource, uuid: string, supersededByUuid: string): Promise<void> {
  await db.run('UPDATE credentials SET superseded_by_uuid = ? WHERE uuid = ?', supersededByUuid, uuid);
}

export async function upsertFromReplication(
  db: DataSource,
  input: CreateCredentialInput & { recordedByNode: string; replicatedAt: number },
): Promise<string> {
  if (input.credentialDigest) {
    const existing = await findByDigest(db, input.credentialDigest);
    if (existing) {
      await db.run('UPDATE credentials SET status = ?, replicated_at = ? WHERE uuid = ?', input.status ?? 'issued', input.replicatedAt, existing.uuid);
      return existing.uuid;
    }
  }
  return create(db, input);
}