// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Repository: relationships table.
 *
 * Direct Layer-2 peer links (libp2p), independent of any VTC/VTN context.
 *
 * direction uses a CRDT lattice merge:
 *   pending < {outbound, inbound} < bidirectional
 *
 * When two nodes report different directions for the same peer pair via
 * pubsub replication, the merged result is the lattice join.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export type Direction = 'pending' | 'outbound' | 'inbound' | 'bidirectional';
export type RelationshipStatus = 'pending' | 'established' | 'rejected';

export interface RelationshipRow {
  localIdentityUuid: string;
  remoteIdentityUuid: string;
  localDidDocumentUuid: string | null;
  remoteDidDocumentUuid: string | null;
  direction: Direction;
  status: RelationshipStatus;
  remoteTransport: string | null;
  uuid: string;
  recordedByNode: string | null;
  replicatedAt: number | null;
  createdAt: number | null;
  updatedAt: number | null;
}

export interface CreateRelationshipInput {
  localIdentityUuid: string;
  remoteIdentityUuid: string;
  localDidDocumentUuid?: string;
  remoteDidDocumentUuid?: string;
  direction: Direction;
  status?: RelationshipStatus;
  remoteTransport?: string;
  recordedByNode?: string;
  replicatedAt?: number;
}

interface RelationshipDbRow {
  local_identity_uuid: string;
  remote_identity_uuid: string;
  local_did_document_uuid: string | null;
  remote_did_document_uuid: string | null;
  direction: string;
  status: string;
  remote_transport: string | null;
  uuid: string;
  recorded_by_node: string | null;
  replicated_at: number | null;
  created_at: number | null;
  updated_at: number | null;
}

// ── CRDT: direction lattice ──────────────────────────────────────────────
// pending < outbound < bidirectional
// pending < inbound < bidirectional
// outbound + inbound → bidirectional

const DIRECTION_LATTICE: Record<string, number> = {
  pending: 0,
  outbound: 1,
  inbound: 1,
  bidirectional: 2,
};

export function mergeDirection(a: string, b: string): Direction {
  if (
    (a === 'outbound' && b === 'inbound') ||
    (a === 'inbound' && b === 'outbound')
  ) {
    return 'bidirectional';
  }
  const rankA = DIRECTION_LATTICE[a] ?? 0;
  const rankB = DIRECTION_LATTICE[b] ?? 0;
  return rankA >= rankB ? (a as Direction) : (b as Direction);
}

function rowToRelationship(row: RelationshipDbRow): RelationshipRow {
  return {
    localIdentityUuid: row.local_identity_uuid,
    remoteIdentityUuid: row.remote_identity_uuid,
    localDidDocumentUuid: row.local_did_document_uuid,
    remoteDidDocumentUuid: row.remote_did_document_uuid,
    direction: row.direction as Direction,
    status: row.status as RelationshipStatus,
    remoteTransport: row.remote_transport,
    uuid: row.uuid,
    recordedByNode: row.recorded_by_node,
    replicatedAt: row.replicated_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function create(db: DataSource, input: CreateRelationshipInput & { uuid?: string }): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const rowUuid = input.uuid ?? generateUuid();

  await db.run(`
    INSERT INTO relationships (
      local_identity_uuid,
      remote_identity_uuid,
      local_did_document_uuid,
      remote_did_document_uuid,
      direction, status, remote_transport,
      uuid, recorded_by_node, replicated_at,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `,
    input.localIdentityUuid,
    input.remoteIdentityUuid,
    input.localDidDocumentUuid ?? null,
    input.remoteDidDocumentUuid ?? null,
    input.direction,
    input.status ?? 'pending',
    input.remoteTransport ?? null,
    rowUuid,
    input.recordedByNode ?? null,
    input.replicatedAt ?? null,
    now,
    now,
  );
  return rowUuid;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<RelationshipRow | null> {
  const row = await db.get<RelationshipDbRow>('SELECT * FROM relationships WHERE uuid = ?', uuid);
  return row ? rowToRelationship(row) : null;
}

export async function findByPair(
  db: DataSource,
  localUuid: string,
  remoteUuid: string,
): Promise<RelationshipRow | null> {
  const row = await db.get<RelationshipDbRow>(
    'SELECT * FROM relationships WHERE local_identity_uuid = ? AND remote_identity_uuid = ?',
    localUuid, remoteUuid,
  );
  return row ? rowToRelationship(row) : null;
}

export async function listByLocal(db: DataSource, localUuid: string): Promise<RelationshipRow[]> {
  const rows = await db.all<RelationshipDbRow>(
    'SELECT * FROM relationships WHERE local_identity_uuid = ? ORDER BY updated_at DESC',
    localUuid,
  );
  return rows.map(rowToRelationship);
}

export async function listByRemote(db: DataSource, remoteUuid: string): Promise<RelationshipRow[]> {
  const rows = await db.all<RelationshipDbRow>(
    'SELECT * FROM relationships WHERE remote_identity_uuid = ? ORDER BY updated_at DESC',
    remoteUuid,
  );
  return rows.map(rowToRelationship);
}

/**
 * Upsert from a pubsub replication event.
 * Uses uuid as dedup key and applies CRDT lattice merge for direction.
 */
export async function upsertFromReplication(
  db: DataSource,
  input: CreateRelationshipInput & { uuid: string; recordedByNode: string; replicatedAt: number },
): Promise<{ uuid: string; directionMerged: boolean }> {
  const existing = await findByUuid(db, input.uuid);

  if (existing) {
    const mergedDirection = mergeDirection(existing.direction, input.direction);
    const directionMerged = mergedDirection !== existing.direction;

    const now = Math.floor(Date.now() / 1000);
    await db.run(`
      UPDATE relationships SET
        direction = ?,
        status = CASE WHEN ? = 'established' THEN 'established' ELSE status END,
        remote_transport = COALESCE(?, remote_transport),
        replicated_at = ?,
        updated_at = ?
      WHERE uuid = ?
    `,
      mergedDirection,
      input.status ?? 'pending',
      input.remoteTransport ?? null,
      input.replicatedAt,
      now,
      input.uuid,
    );
    return { uuid: existing.uuid, directionMerged };
  }

  const uuid = await create(db, input);
  return { uuid, directionMerged: false };
}
/**
 * Find all identity UUIDs that have an established VRC with the given identity.
 * Checks BOTH the relationships table (bidirectional + established) AND the
 * credentials table (vc_type='vrc' + status='issued').
 */
export async function findEstablishedVrcIdentityUuids(
  db: DataSource,
  identityUuid: string,
): Promise<string[]> {
  // 1. Relationships table: bidirectional, established
  const relRows = await db.all<{ remote_uuid: string }>(
    `SELECT
       CASE
         WHEN local_identity_uuid = ? THEN remote_identity_uuid
         ELSE local_identity_uuid
       END as remote_uuid
     FROM relationships
     WHERE (local_identity_uuid = ? OR remote_identity_uuid = ?)
     AND direction = 'bidirectional'
     AND status = 'established'`,
    identityUuid,
    identityUuid,
    identityUuid,
  );

  // 2. Credentials table: vrc type, issued status
  const credRows = await db.all<{ remote_uuid: string }>(
    `SELECT
       CASE
         WHEN issuer_identity_uuid = ? THEN subject_identity_uuid
         ELSE issuer_identity_uuid
       END as remote_uuid
     FROM credentials
     WHERE (issuer_identity_uuid = ? OR subject_identity_uuid = ?)
     AND vc_type = 'vrc'
     AND status = 'issued'`,
    identityUuid,
    identityUuid,
    identityUuid,
  );

  // Union dedup
  const seen = new Set<string>();
  for (const r of relRows) seen.add(r.remote_uuid);
  for (const r of credRows) seen.add(r.remote_uuid);
  return [...seen];
}

/** Check whether an established VRC exists between two identities (by UUID).
 *  Checks BOTH relationships AND credentials tables. */
export async function hasEstablishedVrcBetween(
  db: DataSource,
  uuidA: string,
  uuidB: string,
): Promise<boolean> {
  // 1. Relationships table
  const relRow = await db.get<{ cnt: number }>(
    `SELECT COUNT(*) as cnt FROM relationships
     WHERE ((local_identity_uuid = ? AND remote_identity_uuid = ?)
         OR (local_identity_uuid = ? AND remote_identity_uuid = ?))
     AND direction = 'bidirectional'
     AND status = 'established'`,
    uuidA, uuidB,
    uuidB, uuidA,
  );
  if ((relRow?.cnt ?? 0) > 0) return true;

  // 2. Credentials table
  const credRow = await db.get<{ cnt: number }>(
    `SELECT COUNT(*) as cnt FROM credentials
     WHERE ((issuer_identity_uuid = ? AND subject_identity_uuid = ?)
         OR (issuer_identity_uuid = ? AND subject_identity_uuid = ?))
     AND vc_type = 'vrc'
     AND status = 'issued'`,
    uuidA, uuidB,
    uuidB, uuidA,
  );
  return (credRow?.cnt ?? 0) > 0;
}

/** Check whether an identity has any verified personhood — either a verified
 *  relationship (relationships.personhood_status = 'verified') or an issued
 *  VRC credential (credentials.vc_type = 'vrc', status = 'issued').
 *  Uses UUIDs for cross-table identity resolution, not local integer IDs. */
export async function hasVerifiedPersonhood(db: DataSource, identityUuid: string): Promise<boolean> {
  // Check relationships table via UUIDs (local_identity_uuid / remote_identity_uuid)
  const rel = await db.get<{ cnt: number }>(
    `SELECT COUNT(*) as cnt FROM relationships
     WHERE (local_identity_uuid = ? OR remote_identity_uuid = ?)
     AND personhood_status = 'verified'`,
    identityUuid,
    identityUuid,
  );
  if ((rel?.cnt ?? 0) > 0) return true;

  // Check credentials table via UUIDs (issuer_identity_uuid / subject_identity_uuid)
  const cred = await db.get<{ cnt: number }>(
    `SELECT COUNT(*) as cnt FROM credentials
     WHERE vc_type = 'vrc' AND status = 'issued'
     AND (issuer_identity_uuid = ? OR subject_identity_uuid = ?)`,
    identityUuid,
    identityUuid,
  );
  return (cred?.cnt ?? 0) > 0;
}