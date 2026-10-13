/**
 * Repository: status_lists + status_list_flips tables.
 *
 * Bitstring Status List mechanics (OpenVTC-compatible).
 *
 * Both `status_lists` and `status_list_flips` are uuid-first (migration 0019/0018);
 * `status_list_flips` references `status_lists` via its `uuid`.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export type StatusListPurpose = 'revocation' | 'suspension';

export interface StatusListRow {
  communityIdentityUuid: string;
  purpose: StatusListPurpose;
  publicUrl: string | null;
  nextFreeIndex: number;
  uuid: string;
  recordedByNode: string | null;
  replicatedAt: number | null;
}

export interface CreateStatusListInput {
  communityIdentityUuid: string;
  purpose: StatusListPurpose;
  publicUrl?: string;
  recordedByNode?: string;
}

interface RawStatusListRow {
  community_identity_uuid: string;
  purpose: StatusListPurpose; public_url: string | null;
  next_free_index: number; uuid: string;
  recorded_by_node: string | null; replicated_at: number | null;
}

function rowToStatusList(row: RawStatusListRow): StatusListRow {
  return { communityIdentityUuid: row.community_identity_uuid, purpose: row.purpose, publicUrl: row.public_url, nextFreeIndex: row.next_free_index, uuid: row.uuid, recordedByNode: row.recorded_by_node, replicatedAt: row.replicated_at };
}

export async function create(db: DataSource, input: CreateStatusListInput): Promise<string> {
  const rowUuid = generateUuid();
  await db.run(`INSERT INTO status_lists (community_identity_uuid, purpose, public_url, uuid, recorded_by_node) VALUES (?, ?, ?, ?, ?)`,
    input.communityIdentityUuid, input.purpose, input.publicUrl ?? null, rowUuid, input.recordedByNode ?? null);
  return rowUuid;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<StatusListRow | null> {
  const row = await db.get<RawStatusListRow>('SELECT * FROM status_lists WHERE uuid = ?', uuid);
  return row ? rowToStatusList(row) : null;
}

export async function findForCommunity(db: DataSource, communityIdentityUuid: string, purpose: StatusListPurpose): Promise<StatusListRow | null> {
  const row = await db.get<RawStatusListRow>('SELECT * FROM status_lists WHERE community_identity_uuid = ? AND purpose = ?', communityIdentityUuid, purpose);
  return row ? rowToStatusList(row) : null;
}

export async function allocateNextIndex(db: DataSource, uuid: string): Promise<number> {
  const row = await db.get<{ next_free_index: number }>('SELECT next_free_index FROM status_lists WHERE uuid = ?', uuid);
  if (!row) throw new Error(`status_list ${uuid} not found`);
  const claimed = row.next_free_index;
  await db.run('UPDATE status_lists SET next_free_index = next_free_index + 1 WHERE uuid = ?', uuid);
  return claimed;
}

// ── status_list_flips (uuid-first since 0018) ────────────────────────────

export interface StatusListFlipRow { uuid: string; statusListUuid: string; slotIndex: number; value: number; flippedAt: number | null; reason: string | null; recordedByNode: string | null; replicatedAt: number | null; }
export interface CreateFlipInput { statusListUuid: string; slotIndex: number; value: number; reason?: string; recordedByNode?: string; }

/** Record a flip. Returns the flip row's uuid. */
export async function flip(db: DataSource, input: CreateFlipInput): Promise<string> {
  const rowUuid = generateUuid();
  const result = await db.run(`INSERT INTO status_list_flips (status_list_uuid, slot_index, value, flipped_at, reason, uuid, recorded_by_node) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    input.statusListUuid, input.slotIndex, input.value, Math.floor(Date.now() / 1000), input.reason ?? null, rowUuid, input.recordedByNode ?? null);
  void result;
  return rowUuid;
}

export async function findFlipsForList(db: DataSource, statusListUuid: string): Promise<StatusListFlipRow[]> {
  const rows = await db.all<any>('SELECT * FROM status_list_flips WHERE status_list_uuid = ? ORDER BY uuid', statusListUuid);
  return rows.map((r: any) => ({ uuid: r.uuid, statusListUuid: r.status_list_uuid, slotIndex: r.slot_index, value: r.value, flippedAt: r.flipped_at, reason: r.reason, recordedByNode: r.recorded_by_node, replicatedAt: r.replicated_at }));
}

export async function getBitstring(db: DataSource, statusListUuid: string): Promise<Record<number, number>> {
  const flips = await findFlipsForList(db, statusListUuid);
  const bits: Record<number, number> = {};
  for (const f of flips) bits[f.slotIndex] = f.value;
  return bits;
}
