// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Repository: personhood_events table (uuid-first, 0018).
 *
 * Personhood is a ceremony with its own audit trail, not a bare flag.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export type PersonhoodEvent = 'challenged' | 'asserted' | 'revoked';

export interface PersonhoodEventRow {
  uuid: string;
  membershipUuid: string;
  event: PersonhoodEvent;
  reason: string | null;
  actorIdentityUuid: string | null;
  occurredAt: number | null;
}

export interface CreatePersonhoodEventInput {
  membershipUuid: string;
  event: PersonhoodEvent;
  reason?: string;
  actorIdentityUuid?: string;
}

interface RawRow {
  uuid: string;
  membership_uuid: string;
  event: PersonhoodEvent;
  reason: string | null;
  actor_identity_uuid: string | null;
  occurred_at: number | null;
}

function rowToEvent(row: RawRow): PersonhoodEventRow {
  return {
    uuid: row.uuid,
    membershipUuid: row.membership_uuid,
    event: row.event,
    reason: row.reason,
    actorIdentityUuid: row.actor_identity_uuid,
    occurredAt: row.occurred_at,
  };
}

/** Create a personhood event row. Returns the new row's uuid. */
export async function create(db: DataSource, input: CreatePersonhoodEventInput): Promise<string> {
  const rowUuid = generateUuid();
  const result = await db.run(
    `INSERT INTO personhood_events (membership_uuid, event, reason, actor_identity_uuid, uuid, occurred_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    input.membershipUuid,
    input.event,
    input.reason ?? null,
    input.actorIdentityUuid ?? null,
    rowUuid,
    Math.floor(Date.now() / 1000),
  );
  void result;
  return rowUuid;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<PersonhoodEventRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM personhood_events WHERE uuid = ?', uuid);
  return row ? rowToEvent(row) : null;
}

export async function findForMembership(
  db: DataSource,
  membershipUuid: string,
): Promise<PersonhoodEventRow[]> {
  const rows = await db.all<RawRow>('SELECT * FROM personhood_events WHERE membership_uuid = ? ORDER BY uuid', membershipUuid);
  return rows.map(rowToEvent);
}
