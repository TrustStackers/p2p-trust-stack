/**
 * Repository: governance table.
 *
 * Governance parameters per VTC/VTN. admin_threshold_m/n back the M-of-N
 * signature model seen in the mockup's VRC issuance flow.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export interface GovernanceRow {
  communityIdentityUuid: string;
  adminThresholdM: number | null;
  adminThresholdN: number | null;
  /** Base64 VTC governance-doc digest — a STORED commitment (never recomputed). */
  vtcGovernanceDigest: string | null;
  parentCommunityUuid: string | null;
  adminDidDocumentUuids: string | null;
  uuid: string;
  recordedByNode: string | null;
  replicatedAt: number | null;
  updatedAt: number | null;
}

export interface CreateGovernanceInput {
  communityIdentityUuid: string;
  adminThresholdM?: number;
  adminThresholdN?: number;
  vtcGovernanceDigest?: string;
  parentCommunityUuid?: string;
  adminDidDocumentUuids?: string;
  recordedByNode?: string;
  replicatedAt?: number;
}

export interface UpdateGovernanceInput {
  adminThresholdM?: number;
  adminThresholdN?: number;
  vtcGovernanceDigest?: string;
  parentCommunityUuid?: string | null;
  adminDidDocumentUuids?: string;
}

interface RawRow {
  community_identity_uuid: string;
  admin_threshold_m: number | null;
  admin_threshold_n: number | null;
  vtc_governance_digest: string | null;
  parent_community_uuid: string | null;
  admin_did_document_uuids: string | null;
  uuid: string;
  recorded_by_node: string | null;
  replicated_at: number | null;
  updated_at: number | null;
}

function rowToGovernance(row: RawRow): GovernanceRow {
  return {
    communityIdentityUuid: row.community_identity_uuid,
    adminThresholdM: row.admin_threshold_m,
    adminThresholdN: row.admin_threshold_n,
    vtcGovernanceDigest: row.vtc_governance_digest,
    parentCommunityUuid: row.parent_community_uuid,
    adminDidDocumentUuids: row.admin_did_document_uuids,
    uuid: row.uuid,
    recordedByNode: row.recorded_by_node,
    replicatedAt: row.replicated_at,
    updatedAt: row.updated_at,
  };
}

export async function create(db: DataSource, input: CreateGovernanceInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const rowUuid = generateUuid();
  await db.run(
    `INSERT INTO governance
      (community_identity_uuid, admin_threshold_m, admin_threshold_n,
       vtc_governance_digest, parent_community_uuid, admin_did_document_uuids,
       uuid, recorded_by_node, replicated_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    input.communityIdentityUuid,
    input.adminThresholdM ?? null,
    input.adminThresholdN ?? null,
    input.vtcGovernanceDigest ?? null,
    input.parentCommunityUuid ?? null,
    input.adminDidDocumentUuids ?? null,
    rowUuid,
    input.recordedByNode ?? null,
    input.replicatedAt ?? null,
    now,
  );
  return rowUuid;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<GovernanceRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM governance WHERE uuid = ?', uuid);
  return row ? rowToGovernance(row) : null;
}

export async function findForCommunity(
  db: DataSource,
  communityIdentityUuid: string,
): Promise<GovernanceRow | null> {
  const row = await db.get<RawRow>(
    'SELECT * FROM governance WHERE community_identity_uuid = ?',
    communityIdentityUuid,
  );
  return row ? rowToGovernance(row) : null;
}

export async function update(
  db: DataSource,
  communityIdentityUuid: string,
  input: UpdateGovernanceInput,
): Promise<GovernanceRow | null> {
  const existing = await findForCommunity(db, communityIdentityUuid);
  if (!existing) return null;

  await db.run(
    `UPDATE governance
       SET admin_threshold_m = ?,
           admin_threshold_n = ?,
           vtc_governance_digest = ?,
           parent_community_uuid = ?,
           admin_did_document_uuids = ?,
           updated_at = ?
     WHERE community_identity_uuid = ?`,
    input.adminThresholdM !== undefined ? input.adminThresholdM : existing.adminThresholdM,
    input.adminThresholdN !== undefined ? input.adminThresholdN : existing.adminThresholdN,
    input.vtcGovernanceDigest !== undefined ? input.vtcGovernanceDigest : existing.vtcGovernanceDigest,
    input.parentCommunityUuid !== undefined ? input.parentCommunityUuid : existing.parentCommunityUuid,
    input.adminDidDocumentUuids !== undefined ? input.adminDidDocumentUuids : existing.adminDidDocumentUuids,
    Math.floor(Date.now() / 1000),
    communityIdentityUuid,
  );

  return findForCommunity(db, communityIdentityUuid);
}

export async function findOrCreateForCommunity(
  db: DataSource,
  communityIdentityUuid: string,
): Promise<GovernanceRow> {
  const existing = await findForCommunity(db, communityIdentityUuid);
  if (existing) return existing;
  const uuid = await create(db, { communityIdentityUuid });
  return (await findByUuid(db, uuid))!;
}