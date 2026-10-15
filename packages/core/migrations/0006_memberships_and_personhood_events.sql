-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0006_memberships_and_personhood_events.sql
-- VTA -> VTC, VTC -> VTN membership rows, plus the personhood ceremony
-- audit trail (challenged / asserted / revoked events).

CREATE TABLE IF NOT EXISTS memberships (
  uuid                         TEXT PRIMARY KEY,  -- UUIDv7 for cross-node dedup
  member_identity_uuid         TEXT NOT NULL,     -- identities.uuid FK target
  community_identity_uuid      TEXT NOT NULL,     -- identities.uuid FK target
  role                         TEXT NOT NULL DEFAULT 'member',
  status                       TEXT NOT NULL CHECK(status IN ('pending', 'active', 'revoked')),
  membership_credential_uuid   TEXT,              -- credentials.uuid FK target
  personhood_asserted          INTEGER NOT NULL DEFAULT 0,
  personhood_asserted_at       INTEGER,
  recorded_by_node             TEXT,
  replicated_at                INTEGER,
  issued_at                    INTEGER,
  revoked_at                   INTEGER,
  UNIQUE(member_identity_uuid, community_identity_uuid)
);

CREATE INDEX IF NOT EXISTS idx_memberships_member_uuid ON memberships(member_identity_uuid);
CREATE INDEX IF NOT EXISTS idx_memberships_community_uuid ON memberships(community_identity_uuid);

CREATE TABLE IF NOT EXISTS personhood_events (
  uuid                  TEXT PRIMARY KEY,      -- UUIDv7 for cross-node dedup
  membership_uuid       TEXT NOT NULL,         -- memberships.uuid FK target
  event                 TEXT NOT NULL CHECK(event IN ('challenged', 'asserted', 'revoked')),
  reason                TEXT,
  actor_identity_uuid   TEXT,                  -- identities.uuid FK target
  recorded_by_node      TEXT,
  replicated_at         INTEGER,
  occurred_at           INTEGER
);

CREATE INDEX IF NOT EXISTS idx_personhood_events_membership_uuid ON personhood_events(membership_uuid);