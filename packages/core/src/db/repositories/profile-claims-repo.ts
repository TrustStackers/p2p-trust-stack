// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Repository: profile_claims table (uuid-first, 0018).
 *
 * Individual display-layer claims attached to a profile (Scenario 3),
 * each with its own visibility/disclosure control and an optional
 * commitment+salt pair for future selective-disclosure ZKP verification
 * (Scenario 3 + 8 intersection — R-Card / Agent-Card claims used when
 * composing a VRC's credentialSubject). See mockup/vta-profiles.html and
 * mockup/data-schema-notes.md.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export type ProfileClaimValueType = 'string' | 'text' | 'date' | 'url' | 'image' | 'boolean' | 'number' | 'json';
export type ProfileClaimDisclosure = 'always' | 'discretionary' | 'never' | 'zkp_only';

export interface ProfileClaimRow {
  uuid: string;
  profileUuid: string;
  claimKey: string;
  claimValue: string | null;
  valueType: ProfileClaimValueType;
  disclosure: ProfileClaimDisclosure;
  commitment: string | null;
  salt: string | null;
  displayOrder: number;
  recordedByNode: string | null;
  replicatedAt: number | null;
  createdAt: number | null;
  updatedAt: number | null;
}

export interface CreateProfileClaimInput {
  profileUuid: string;
  claimKey: string;
  claimValue?: string | null;
  valueType?: ProfileClaimValueType;
  disclosure?: ProfileClaimDisclosure;
  commitment?: string | null;
  salt?: string | null;
  displayOrder?: number;
  recordedByNode?: string;
}

interface RawRow {
  uuid: string;
  profile_uuid: string;
  claim_key: string;
  claim_value: string | null;
  value_type: ProfileClaimValueType;
  disclosure: ProfileClaimDisclosure;
  commitment: string | null;
  salt: string | null;
  display_order: number;
  recorded_by_node: string | null;
  replicated_at: number | null;
  created_at: number | null;
  updated_at: number | null;
}

function rowToClaim(row: RawRow): ProfileClaimRow {
  return {
    uuid: row.uuid,
    profileUuid: row.profile_uuid,
    claimKey: row.claim_key,
    claimValue: row.claim_value,
    valueType: row.value_type,
    disclosure: row.disclosure,
    commitment: row.commitment,
    salt: row.salt,
    displayOrder: row.display_order,
    recordedByNode: row.recorded_by_node,
    replicatedAt: row.replicated_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** Create a new profile_claims row. Returns the new row's uuid. */
export async function create(db: DataSource, input: CreateProfileClaimInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const rowUuid = generateUuid();
  const result = await db.run(
    `INSERT INTO profile_claims
      (profile_uuid, claim_key, claim_value, value_type, disclosure, commitment, salt, display_order, uuid, recorded_by_node, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    input.profileUuid,
    input.claimKey,
    input.claimValue ?? null,
    input.valueType ?? 'string',
    input.disclosure ?? 'discretionary',
    input.commitment ?? null,
    input.salt ?? null,
    input.displayOrder ?? 0,
    rowUuid,
    input.recordedByNode ?? null,
    now,
    now,
  );
  void result;
  return rowUuid;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<ProfileClaimRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM profile_claims WHERE uuid = ?', uuid);
  return row ? rowToClaim(row) : null;
}

export async function findForProfile(db: DataSource, profileUuid: string): Promise<ProfileClaimRow[]> {
  const rows = await db.all<RawRow>(
    'SELECT * FROM profile_claims WHERE profile_uuid = ? ORDER BY display_order, uuid',
    profileUuid,
  );
  return rows.map(rowToClaim);
}

export async function findByKey(
  db: DataSource,
  profileUuid: string,
  claimKey: string,
): Promise<ProfileClaimRow | null> {
  const row = await db.get<RawRow>(
    'SELECT * FROM profile_claims WHERE profile_uuid = ? AND claim_key = ?',
    profileUuid,
    claimKey,
  );
  return row ? rowToClaim(row) : null;
}

export interface UpdateProfileClaimInput {
  claimValue?: string | null;
  valueType?: ProfileClaimValueType;
  disclosure?: ProfileClaimDisclosure;
  commitment?: string | null;
  salt?: string | null;
  displayOrder?: number;
}

export async function update(db: DataSource, uuid: string, input: UpdateProfileClaimInput): Promise<void> {
  const sets: string[] = [];
  const params: unknown[] = [];

  if (input.claimValue !== undefined) {
    sets.push('claim_value = ?');
    params.push(input.claimValue);
  }
  if (input.valueType !== undefined) {
    sets.push('value_type = ?');
    params.push(input.valueType);
  }
  if (input.disclosure !== undefined) {
    sets.push('disclosure = ?');
    params.push(input.disclosure);
  }
  if (input.commitment !== undefined) {
    sets.push('commitment = ?');
    params.push(input.commitment);
  }
  if (input.salt !== undefined) {
    sets.push('salt = ?');
    params.push(input.salt);
  }
  if (input.displayOrder !== undefined) {
    sets.push('display_order = ?');
    params.push(input.displayOrder);
  }
  if (sets.length === 0) return;

  sets.push('updated_at = ?');
  params.push(Math.floor(Date.now() / 1000));
  params.push(uuid);

  await db.run(`UPDATE profile_claims SET ${sets.join(', ')} WHERE uuid = ?`, ...(params as never[]));
}

export async function remove(db: DataSource, uuid: string): Promise<void> {
  await db.run('DELETE FROM profile_claims WHERE uuid = ?', uuid);
}
