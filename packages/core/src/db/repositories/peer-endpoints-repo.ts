// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Repository: peer_endpoints table (uuid-first, 0018).
 *
 * A peer_endpoint is a HOST/runtime identity (a libp2p PeerID + multiaddrs)
 * bound to a DID identity via identity_uuid. It is NOT the agent's identity.
 * Multiple active/historical endpoints per identity support multi-device
 * ("one SCID, many apps"). Written alongside (never instead of) an identity row.
 *
 * ## Endpoint activation model
 *
 * An identity owns at most ONE *active* endpoint at a time — the libp2p node
 * key derives from the identity seed, so the peer ID is stable per identity and
 * only changes when the device/app re-keys. `setActiveEndpoint` retires any
 * other active endpoint for that identity when a live peer is recorded, and a
 * peer_id that is already claimed by a DIFFERENT identity is NEVER silently
 * reassigned (prevents shared-peer corruption).
 *
 * Row identity: `uuid` (UUIDv7) is the PRIMARY KEY; `peer_id` remains the
 * natural key / cross-node dedup key.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export interface PeerEndpoint {
  uuid: string;
  identityUuid: string;
  didDocumentUuid: string | null;
  peerId: string;
  multiaddrs: string | null;
  isActive: boolean;
  recordedByNode: string | null;
  replicatedAt: number | null;
  createdAt: number | null;
  updatedAt: number | null;
  lastSeenAt: number | null;
}

export interface UpsertEndpointInput {
  identityUuid: string;
  peerId: string;
  multiaddrs?: string[];
  didDocumentUuid?: string;
  isActive?: boolean;
  recordedByNode?: string;
  replicatedAt?: number;
}

interface PeerEndpointRow {
  uuid: string;
  identity_uuid: string;
  did_document_uuid: string | null;
  peer_id: string;
  multiaddrs: string | null;
  is_active: number;
  recorded_by_node: string | null;
  replicated_at: number | null;
  created_at: number | null;
  updated_at: number | null;
  last_seen_at: number | null;
}

function rowToEndpoint(row: PeerEndpointRow): PeerEndpoint {
  return {
    uuid: row.uuid,
    identityUuid: row.identity_uuid,
    didDocumentUuid: row.did_document_uuid,
    peerId: row.peer_id,
    multiaddrs: row.multiaddrs,
    isActive: row.is_active === 1,
    recordedByNode: row.recorded_by_node,
    replicatedAt: row.replicated_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastSeenAt: row.last_seen_at,
  };
}

const PEER_SELECT = `SELECT * FROM peer_endpoints`;

export async function findByPeerId(db: DataSource, peerId: string): Promise<PeerEndpoint | null> {
  const row = await db.get<PeerEndpointRow>(`${PEER_SELECT} WHERE peer_id = ?`, peerId);
  return row ? rowToEndpoint(row) : null;
}

export async function findByIdentityUuid(db: DataSource, identityUuid: string): Promise<PeerEndpoint[]> {
  const rows = await db.all<PeerEndpointRow>(
    `${PEER_SELECT} WHERE identity_uuid = ? ORDER BY is_active DESC, created_at ASC`,
    identityUuid,
  );
  return rows.map(rowToEndpoint);
}

export async function findActive(
  db: DataSource,
  identityUuid: string,
): Promise<PeerEndpoint | null> {
  const row = await db.get<PeerEndpointRow>(
    `${PEER_SELECT} WHERE identity_uuid = ? AND is_active = 1 ORDER BY updated_at DESC, created_at DESC LIMIT 1`,
    identityUuid,
  );
  return row ? rowToEndpoint(row) : null;
}

/** Find the active endpoint for an identity by that identity's CESR VID. */
export async function findActiveForVid(
  db: DataSource,
  vid: string,
): Promise<PeerEndpoint | null> {
  const row = await db.get<PeerEndpointRow>(
    `SELECT pe.* FROM peer_endpoints pe
     JOIN identities i ON i.uuid = pe.identity_uuid
     WHERE i.vid = ? AND pe.is_active = 1
     ORDER BY pe.updated_at DESC, pe.created_at DESC LIMIT 1`,
    vid,
  );
  return row ? rowToEndpoint(row) : null;
}

/**
 * Upsert an endpoint for an identity. When an active endpoint with this peer_id
 * exists it is (re)activated; a same peer_id row with is_active=0 is healed.
 * Returns the endpoint's uuid (the PRIMARY KEY).
 */
export async function upsertForIdentity(
  db: DataSource,
  input: UpsertEndpointInput,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const existing = await db.get<{ uuid: string }>(
    'SELECT uuid FROM peer_endpoints WHERE peer_id = ?',
    input.peerId,
  );

  if (existing) {
    await db.run(
      `UPDATE peer_endpoints SET
         identity_uuid = ?, did_document_uuid = ?, multiaddrs = ?, is_active = ?,
         recorded_by_node = ?, replicated_at = ?, updated_at = ?
       WHERE uuid = ?`,
      input.identityUuid,
      input.didDocumentUuid ?? null,
      input.multiaddrs ? JSON.stringify(input.multiaddrs) : null,
      input.isActive === false ? 0 : 1,
      input.recordedByNode ?? null,
      input.replicatedAt ?? now,
      now,
      existing.uuid,
    );
    return existing.uuid;
  }

  const rowUuid = generateUuid();
  const result = await db.run(
    `INSERT INTO peer_endpoints
       (uuid, identity_uuid, did_document_uuid, peer_id, multiaddrs, is_active,
        recorded_by_node, replicated_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    rowUuid,
    input.identityUuid,
    input.didDocumentUuid ?? null,
    input.peerId,
    input.multiaddrs ? JSON.stringify(input.multiaddrs) : null,
    input.isActive === false ? 0 : 1,
    input.recordedByNode ?? null,
    input.replicatedAt ?? now,
    now,
    now,
  );
  void result;
  return rowUuid;
}

/** Deactivate an endpoint (device gone / relay changed). */
export async function deactivate(db: DataSource, peerId: string): Promise<void> {
  await db.run(
    'UPDATE peer_endpoints SET is_active = 0, updated_at = ? WHERE peer_id = ?',
    Math.floor(Date.now() / 1000),
    peerId,
  );
}

/**
 * Whether this peerId is currently recorded as an ACTIVE endpoint on any
 * identity (optionally excluding a specific identity_uuid). Used both to
 * prevent reassigning an endpoint to a different identity and to support
 * "real VTA" discrimination (an identity with an active endpoint is a real,
 * reachable agent).
 */
export async function ownsActiveEndpoint(
  db: DataSource,
  peerId: string,
  excludeIdentityUuid?: string,
): Promise<boolean> {
  const row = await db.get<{ uuid: string }>(
    `SELECT uuid FROM peer_endpoints
     WHERE peer_id = ? AND is_active = 1
       AND (? IS NULL OR identity_uuid <> ?)
     LIMIT 1`,
    peerId,
    excludeIdentityUuid ?? null,
    excludeIdentityUuid ?? null,
  );
  return row != null;
}

export type SetEndpointResult =
  | { applied: true }
  | { applied: false; reason: 'peer-claimed'; ownerUuid: string | null };

/**
 * Record `peerId` as THE active endpoint for `identityUuid`, atomically
 * retiring any other active endpoint of that identity.
 *
 * Collision guard: if `peerId` is already an ACTIVE endpoint owned by a
 * different identity, this REFUSES to reassign it. A peer_id is a physical
 * node key — it can never belong to two identities at once, so silently
 * moving it would re-introduce the shared-peer corruption the old
 * identities.peer_id column was prone to.
 */
export async function setActiveEndpoint(
  db: DataSource,
  input: UpsertEndpointInput & {
    /** Refuse if this peer is active on another identity. Default true. */
    guardClaim?: boolean;
  },
): Promise<SetEndpointResult> {
  const now = Math.floor(Date.now() / 1000);
  const guardClaim = input.guardClaim ?? true;

  const existing = await db.get<{ uuid: string; identity_uuid: string; is_active: number }>(
    'SELECT uuid, identity_uuid, is_active FROM peer_endpoints WHERE peer_id = ?',
    input.peerId,
  );

  if (existing && guardClaim && existing.is_active === 1 && existing.identity_uuid !== input.identityUuid) {
    return { applied: false, reason: 'peer-claimed', ownerUuid: existing.identity_uuid };
  }

  if (existing) {
    await db.run(
      `UPDATE peer_endpoints SET
         identity_uuid = ?, did_document_uuid = ?, multiaddrs = ?, is_active = 1,
         recorded_by_node = ?, replicated_at = ?, updated_at = ?, last_seen_at = ?
       WHERE uuid = ?`,
      input.identityUuid,
      input.didDocumentUuid ?? null,
      input.multiaddrs ? JSON.stringify(input.multiaddrs) : null,
      input.recordedByNode ?? null,
      input.replicatedAt ?? now,
      now,
      now,
      existing.uuid,
    );
  } else {
    const rowUuid = generateUuid();
    await db.run(
      `INSERT INTO peer_endpoints
         (uuid, identity_uuid, did_document_uuid, peer_id, multiaddrs, is_active,
          recorded_by_node, replicated_at, created_at, updated_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      rowUuid,
      input.identityUuid,
      input.didDocumentUuid ?? null,
      input.peerId,
      input.multiaddrs ? JSON.stringify(input.multiaddrs) : null,
      1,
      input.recordedByNode ?? null,
      input.replicatedAt ?? now,
      now,
      now,
      now,
    );
  }

  // Retire any OTHER active endpoint of this identity — an identity has one
  // current node; a changed peer means the previous device/install is gone.
  await db.run(
    `UPDATE peer_endpoints SET is_active = 0, updated_at = ?
     WHERE identity_uuid = ? AND peer_id <> ? AND is_active = 1`,
    now,
    input.identityUuid,
    input.peerId,
  );

  return { applied: true };
}
