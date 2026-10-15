// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Repository: grants table (uuid-first, 0018).
 *
 * Authorization fast path — "does X currently hold permission Y in scope
 * Z", the cheap, indexed check.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export interface GrantRow {
  uuid: string;
  granteeIdentityUuid: string;
  scopeIdentityUuid: string | null;
  permission: string;
  sourceCredentialUuid: string | null;
  sourceDelegationUuid: string | null;
  grantedAt: number | null;
  revokedAt: number | null;
}

export interface CreateGrantInput {
  granteeIdentityUuid: string;
  scopeIdentityUuid?: string;
  permission: string;
  sourceCredentialUuid?: string;
  sourceDelegationUuid?: string;
}

interface RawRow {
  uuid: string;
  grantee_identity_uuid: string;
  scope_identity_uuid: string | null;
  permission: string;
  source_credential_uuid: string | null;
  source_delegation_uuid: string | null;
  granted_at: number | null;
  revoked_at: number | null;
}

function rowToGrant(row: RawRow): GrantRow {
  return {
    uuid: row.uuid,
    granteeIdentityUuid: row.grantee_identity_uuid,
    scopeIdentityUuid: row.scope_identity_uuid,
    permission: row.permission,
    sourceCredentialUuid: row.source_credential_uuid,
    sourceDelegationUuid: row.source_delegation_uuid,
    grantedAt: row.granted_at,
    revokedAt: row.revoked_at,
  };
}

/** Create a grant row. Returns the new row's uuid. */
export async function create(db: DataSource, input: CreateGrantInput): Promise<string> {
  const rowUuid = generateUuid();
  const result = await db.run(
    `INSERT INTO grants (grantee_identity_uuid, scope_identity_uuid, permission, source_credential_uuid, source_delegation_uuid, granted_at, uuid)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    input.granteeIdentityUuid,
    input.scopeIdentityUuid ?? null,
    input.permission,
    input.sourceCredentialUuid ?? null,
    input.sourceDelegationUuid ?? null,
    Math.floor(Date.now() / 1000),
    rowUuid,
  );
  void result;
  return rowUuid;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<GrantRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM grants WHERE uuid = ?', uuid);
  return row ? rowToGrant(row) : null;
}

export interface ListFilters {
  granteeIdentityUuid?: string;
  scopeIdentityUuid?: string;
  permission?: string;
}

export async function list(db: DataSource, filters: ListFilters = {}): Promise<GrantRow[]> {
  const clauses: string[] = [];
  const params: unknown[] = [];

  if (filters.granteeIdentityUuid !== undefined) { clauses.push('grantee_identity_uuid = ?'); params.push(filters.granteeIdentityUuid); }
  if (filters.scopeIdentityUuid !== undefined) { clauses.push('scope_identity_uuid = ?'); params.push(filters.scopeIdentityUuid); }
  if (filters.permission) { clauses.push('permission = ?'); params.push(filters.permission); }

  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = await db.all<RawRow>(`SELECT * FROM grants ${where} ORDER BY uuid`, ...params);
  return rows.map(rowToGrant);
}

export async function check(
  db: DataSource,
  granteeIdentityUuid: string,
  permission: string,
  scopeIdentityUuid?: string,
): Promise<GrantRow | null> {
  const clauses = ['grantee_identity_uuid = ?', 'permission = ?', 'revoked_at IS NULL'];
  const params: unknown[] = [granteeIdentityUuid, permission];

  if (scopeIdentityUuid !== undefined) {
    clauses.push('(scope_identity_uuid = ? OR scope_identity_uuid IS NULL)');
    params.push(scopeIdentityUuid);
  }

  const row = await db.get<RawRow>(
    `SELECT * FROM grants WHERE ${clauses.join(' AND ')} ORDER BY uuid LIMIT 1`,
    ...params,
  );
  return row ? rowToGrant(row) : null;
}

export async function revoke(db: DataSource, uuid: string): Promise<void> {
  await db.run('UPDATE grants SET revoked_at = ? WHERE uuid = ?', Math.floor(Date.now() / 1000), uuid);
}
