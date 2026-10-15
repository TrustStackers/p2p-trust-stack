// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Repository: profiles table.
 *
 * Display-layer personas an identity can present (Scenario 3 — "Manage
 * Multiple Profiles"). See mockup/vta-profiles.html and
 * mockup/data-schema-notes.md.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export type ProfileVisibility = 'private' | 'selective' | 'public';

export interface ProfileRow {
  identityUuid: string;
  label: string;
  purpose: string | null;
  visibility: ProfileVisibility;
  isDefault: boolean;
  uuid: string;
  recordedByNode: string | null;
  replicatedAt: number | null;
  createdAt: number | null;
  updatedAt: number | null;
}

export interface CreateProfileInput {
  identityUuid: string;
  label: string;
  purpose?: string;
  visibility?: ProfileVisibility;
  isDefault?: boolean;
  recordedByNode?: string;
}

interface RawRow {
  identity_uuid: string;
  label: string;
  purpose: string | null;
  visibility: ProfileVisibility;
  is_default: number;
  uuid: string;
  recorded_by_node: string | null;
  replicated_at: number | null;
  created_at: number | null;
  updated_at: number | null;
}

function rowToProfile(row: RawRow): ProfileRow {
  return {
    identityUuid: row.identity_uuid,
    label: row.label,
    purpose: row.purpose,
    visibility: row.visibility,
    isDefault: row.is_default === 1,
    uuid: row.uuid,
    recordedByNode: row.recorded_by_node,
    replicatedAt: row.replicated_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** Create a new profile row. If isDefault, unsets any prior default for the identity. Returns the new row's uuid. */
export async function create(db: DataSource, input: CreateProfileInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const rowUuid = generateUuid();

  if (input.isDefault) {
    await db.run('UPDATE profiles SET is_default = 0 WHERE identity_uuid = ?', input.identityUuid);
  }

  await db.run(
    `INSERT INTO profiles (identity_uuid, label, purpose, visibility, is_default, uuid, recorded_by_node, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    input.identityUuid,
    input.label,
    input.purpose ?? null,
    input.visibility ?? 'private',
    input.isDefault ? 1 : 0,
    rowUuid,
    input.recordedByNode ?? null,
    now,
    now,
  );
  return rowUuid;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<ProfileRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM profiles WHERE uuid = ?', uuid);
  return row ? rowToProfile(row) : null;
}

export async function findForIdentity(db: DataSource, identityUuid: string): Promise<ProfileRow[]> {
  const rows = await db.all<RawRow>(
    'SELECT * FROM profiles WHERE identity_uuid = ? ORDER BY is_default DESC, uuid',
    identityUuid,
  );
  return rows.map(rowToProfile);
}

export async function findDefaultForIdentity(db: DataSource, identityUuid: string): Promise<ProfileRow | null> {
  const row = await db.get<RawRow>(
    'SELECT * FROM profiles WHERE identity_uuid = ? AND is_default = 1',
    identityUuid,
  );
  return row ? rowToProfile(row) : null;
}

export async function countForIdentity(db: DataSource, identityUuid: string): Promise<number> {
  const row = await db.get<{ count: number }>(
    'SELECT COUNT(*) as count FROM profiles WHERE identity_uuid = ?',
    identityUuid,
  );
  return (row as { count: number }).count;
}

export interface UpdateProfileInput {
  label?: string;
  purpose?: string | null;
  visibility?: ProfileVisibility;
}

export async function update(db: DataSource, uuid: string, input: UpdateProfileInput): Promise<void> {
  const sets: string[] = [];
  const params: unknown[] = [];

  if (input.label !== undefined) {
    sets.push('label = ?');
    params.push(input.label);
  }
  if (input.purpose !== undefined) {
    sets.push('purpose = ?');
    params.push(input.purpose);
  }
  if (input.visibility !== undefined) {
    sets.push('visibility = ?');
    params.push(input.visibility);
  }
  if (sets.length === 0) return;

  sets.push('updated_at = ?');
  params.push(Math.floor(Date.now() / 1000));
  params.push(uuid);

  await db.run(`UPDATE profiles SET ${sets.join(', ')} WHERE uuid = ?`, ...(params as never[]));
}

export async function setDefault(db: DataSource, uuid: string, identityUuid: string): Promise<void> {
  await db.run('UPDATE profiles SET is_default = 0 WHERE identity_uuid = ?', identityUuid);
  await db.run('UPDATE profiles SET is_default = 1, updated_at = ? WHERE uuid = ?',
    Math.floor(Date.now() / 1000),
    uuid,
  );
}

/** Delete a profile row. Caller is responsible for guarding against removing the last/default profile. */
export async function remove(db: DataSource, uuid: string): Promise<void> {
  await db.run('DELETE FROM profiles WHERE uuid = ?', uuid);
}
