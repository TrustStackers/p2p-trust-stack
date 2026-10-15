// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Repository: nonces table.
 *
 * Replay protection — e.g. 'vp_challenge', 'personhood_challenge'.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export interface NonceRow {
  uuid: string;
  identityUuid: string;
  nonce: string;
  purpose: string | null;
  seenAt: number;
  expiresAt: number | null;
}

export interface CreateNonceInput {
  identityUuid: string;
  nonce: string;
  purpose?: string;
  expiresAt?: number;
}

export async function create(db: DataSource, input: CreateNonceInput): Promise<string> {
  const rowUuid = generateUuid();
  await db.run(
    `INSERT INTO nonces (uuid, identity_uuid, nonce, purpose, seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
    rowUuid, input.identityUuid, input.nonce, input.purpose ?? null, Math.floor(Date.now() / 1000), input.expiresAt ?? null,
  );
  return rowUuid;
}

export async function findByIdentityAndNonce(
  db: DataSource, identityUuid: string, nonce: string,
): Promise<NonceRow | null> {
  const row = await db.get<any>('SELECT * FROM nonces WHERE identity_uuid = ? AND nonce = ?', identityUuid, nonce);
  if (!row) return null;
  return { uuid: row.uuid, identityUuid: row.identity_uuid, nonce: row.nonce, purpose: row.purpose, seenAt: row.seen_at, expiresAt: row.expires_at };
}

export async function findByNonce(db: DataSource, nonce: string): Promise<NonceRow | null> {
  const row = await db.get<any>('SELECT * FROM nonces WHERE nonce = ?', nonce);
  if (!row) return null;
  return { uuid: row.uuid, identityUuid: row.identity_uuid, nonce: row.nonce, purpose: row.purpose, seenAt: row.seen_at, expiresAt: row.expires_at };
}

export async function consume(db: DataSource, uuid: string): Promise<void> {
  await db.run('DELETE FROM nonces WHERE uuid = ?', uuid);
}