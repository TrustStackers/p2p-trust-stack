// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Repository: delegations table (uuid-first, 0018).
 *
 * Accountability/custody links for non-human subjects.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export type DelegationRelationshipType = 'operates' | 'owns' | 'represents' | 'employs';

export interface DelegationRow {
  uuid: string;
  principalIdentityUuid: string;
  dependentIdentityUuid: string;
  relationshipType: DelegationRelationshipType;
  scope: string | null;
  credentialUuid: string | null;
  grantedAt: number | null;
  expiresAt: number | null;
  revokedAt: number | null;
  recordedByNode: string | null;
  replicatedAt: number | null;
}

export interface CreateDelegationInput {
  principalIdentityUuid: string;
  dependentIdentityUuid: string;
  relationshipType: DelegationRelationshipType;
  scope?: string;
  credentialUuid?: string;
  expiresAt?: number;
  recordedByNode?: string;
  replicatedAt?: number;
}

interface RawRow {
  uuid: string;
  principal_identity_uuid: string;
  dependent_identity_uuid: string;
  relationship_type: DelegationRelationshipType;
  scope: string | null;
  credential_uuid: string | null;
  granted_at: number | null;
  expires_at: number | null;
  revoked_at: number | null;
  recorded_by_node: string | null;
  replicated_at: number | null;
}

function rowToDelegation(row: RawRow): DelegationRow {
  return {
    uuid: row.uuid,
    principalIdentityUuid: row.principal_identity_uuid,
    dependentIdentityUuid: row.dependent_identity_uuid,
    relationshipType: row.relationship_type,
    scope: row.scope,
    credentialUuid: row.credential_uuid,
    grantedAt: row.granted_at,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    recordedByNode: row.recorded_by_node,
    replicatedAt: row.replicated_at,
  };
}

/** Create a delegation row. Returns the new row's uuid. */
export async function create(db: DataSource, input: CreateDelegationInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const rowUuid = generateUuid();
  const result = await db.run(
    `INSERT INTO delegations
      (principal_identity_uuid, dependent_identity_uuid,
       relationship_type, scope, credential_uuid,
       granted_at, expires_at, uuid, recorded_by_node, replicated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    input.principalIdentityUuid,
    input.dependentIdentityUuid,
    input.relationshipType,
    input.scope ?? null,
    input.credentialUuid ?? null,
    now,
    input.expiresAt ?? null,
    rowUuid,
    input.recordedByNode ?? null,
    input.replicatedAt ?? null,
  );
  void result;
  return rowUuid;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<DelegationRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM delegations WHERE uuid = ?', uuid);
  return row ? rowToDelegation(row) : null;
}

export interface ListFilters {
  principalIdentityUuid?: string;
  dependentIdentityUuid?: string;
}

export async function list(db: DataSource, filters: ListFilters = {}): Promise<DelegationRow[]> {
  const clauses: string[] = [];
  const params: unknown[] = [];

  if (filters.principalIdentityUuid !== undefined) {
    clauses.push('principal_identity_uuid = ?');
    params.push(filters.principalIdentityUuid);
  }
  if (filters.dependentIdentityUuid !== undefined) {
    clauses.push('dependent_identity_uuid = ?');
    params.push(filters.dependentIdentityUuid);
  }

  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = await db.all<RawRow>(`SELECT * FROM delegations ${where} ORDER BY uuid`, ...params);
  return rows.map(rowToDelegation);
}

export async function revoke(db: DataSource, uuid: string): Promise<void> {
  await db.run('UPDATE delegations SET revoked_at = ? WHERE uuid = ?', Math.floor(Date.now() / 1000), uuid);
}
