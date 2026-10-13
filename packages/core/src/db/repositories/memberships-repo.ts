/**
 * Repository: memberships table (uuid-first, 0018).
 *
 * VTA -> VTC, VTC -> VTN. Entity-level membership, DID-level credentials:
 * membership is about an entity joining a community (entity-level), but the
 * VRC/VMC backing it is signed by specific DIDs (DID-level) — the row here
 * points at the backing credential via `membership_credential_uuid` rather
 * than storing raw credential JSON inline.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export type MembershipRole = 'member' | 'admin' | 'founding_admin' | 'moderator' | 'issuer' | (string & {});
export type MembershipStatus = 'pending' | 'active' | 'revoked';

export interface MembershipRow {
  uuid: string;
  memberIdentityUuid: string;
  communityIdentityUuid: string;
  role: MembershipRole;
  status: MembershipStatus;
  membershipCredentialUuid: string | null;
  personhoodAsserted: boolean;
  personhoodAssertedAt: number | null;
  recordedByNode: string | null;
  replicatedAt: number | null;
  issuedAt: number | null;
  revokedAt: number | null;
}

export interface CreateMembershipInput {
  memberIdentityUuid: string;
  communityIdentityUuid: string;
  role?: MembershipRole;
  status?: MembershipStatus;
  recordedByNode?: string;
}

interface RawRow {
  uuid: string;
  member_identity_uuid: string;
  community_identity_uuid: string;
  role: MembershipRole;
  status: MembershipStatus;
  membership_credential_uuid: string | null;
  personhood_asserted: number;
  personhood_asserted_at: number | null;
  recorded_by_node: string | null;
  replicated_at: number | null;
  issued_at: number | null;
  revoked_at: number | null;
}

function rowToMembership(row: RawRow): MembershipRow {
  return {
    uuid: row.uuid,
    memberIdentityUuid: row.member_identity_uuid,
    communityIdentityUuid: row.community_identity_uuid,
    role: row.role,
    status: row.status,
    membershipCredentialUuid: row.membership_credential_uuid,
    personhoodAsserted: row.personhood_asserted === 1,
    personhoodAssertedAt: row.personhood_asserted_at,
    recordedByNode: row.recorded_by_node,
    replicatedAt: row.replicated_at,
    issuedAt: row.issued_at,
    revokedAt: row.revoked_at,
  };
}

/** Create a membership row. Returns the new row's uuid. */
export async function create(db: DataSource, input: CreateMembershipInput): Promise<string> {
  const rowUuid = generateUuid();
  const result = await db.run(
    `INSERT INTO memberships (member_identity_uuid, community_identity_uuid, role, status, uuid, recorded_by_node, issued_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    input.memberIdentityUuid,
    input.communityIdentityUuid,
    input.role ?? 'member',
    input.status ?? 'pending',
    rowUuid,
    input.recordedByNode ?? null,
    input.status === 'active' ? Math.floor(Date.now() / 1000) : null,
  );
  void result;
  return rowUuid;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<MembershipRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM memberships WHERE uuid = ?', uuid);
  return row ? rowToMembership(row) : null;
}

export async function findByPair(
  db: DataSource,
  memberIdentityUuid: string,
  communityIdentityUuid: string,
): Promise<MembershipRow | null> {
  const row = await db.get<RawRow>(
    'SELECT * FROM memberships WHERE member_identity_uuid = ? AND community_identity_uuid = ?',
    memberIdentityUuid, communityIdentityUuid,
  );
  return row ? rowToMembership(row) : null;
}

export interface ListFilters {
  memberIdentityUuid?: string;
  communityIdentityUuid?: string;
  status?: MembershipStatus;
}

export async function list(db: DataSource, filters: ListFilters = {}): Promise<MembershipRow[]> {
  const clauses: string[] = [];
  const params: unknown[] = [];

  if (filters.memberIdentityUuid !== undefined) {
    clauses.push('member_identity_uuid = ?');
    params.push(filters.memberIdentityUuid);
  }
  if (filters.communityIdentityUuid !== undefined) {
    clauses.push('community_identity_uuid = ?');
    params.push(filters.communityIdentityUuid);
  }
  if (filters.status) {
    clauses.push('status = ?');
    params.push(filters.status);
  }

  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = await db.all<RawRow>(`SELECT * FROM memberships ${where} ORDER BY uuid`, ...params);
  return rows.map(rowToMembership);
}

export function findForCommunity(db: DataSource, communityIdentityUuid: string): Promise<MembershipRow[]> {
  return list(db, { communityIdentityUuid });
}

export function findForMember(db: DataSource, memberIdentityUuid: string): Promise<MembershipRow[]> {
  return list(db, { memberIdentityUuid });
}

/** Find memberships by member UUID (canonical distributed identifier). */
export function findForMemberByUuid(db: DataSource, memberUuid: string): Promise<MembershipRow[]> {
  return findForMember(db, memberUuid);
}

export async function approve(
  db: DataSource,
  uuid: string,
  membershipCredentialUuid: string | null,
): Promise<void> {
  await db.run(
    `UPDATE memberships SET status = 'active', membership_credential_uuid = ?, issued_at = ? WHERE uuid = ?`,
    membershipCredentialUuid, Math.floor(Date.now() / 1000), uuid,
  );
}

export async function revoke(db: DataSource, uuid: string): Promise<void> {
  await db.run(`UPDATE memberships SET status = 'revoked', revoked_at = ? WHERE uuid = ?`,
    Math.floor(Date.now() / 1000), uuid,
  );
}

export async function setPersonhoodAsserted(db: DataSource, uuid: string, asserted: boolean): Promise<void> {
  await db.run('UPDATE memberships SET personhood_asserted = ?, personhood_asserted_at = ? WHERE uuid = ?',
    asserted ? 1 : 0,
    asserted ? Math.floor(Date.now() / 1000) : null,
    uuid,
  );
}
