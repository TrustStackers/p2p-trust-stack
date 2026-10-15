-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0010_status_lists.sql
-- Bitstring Status List mechanics (OpenVTC-compatible). Reserved indices
-- 0-3 are decoys, pre-flipped at mint.

CREATE TABLE IF NOT EXISTS status_lists (
  uuid                    TEXT PRIMARY KEY,           -- UUIDv7 for cross-node dedup
  community_identity_uuid TEXT NOT NULL,              -- identities.uuid FK target
  purpose                 TEXT NOT NULL CHECK(purpose IN ('revocation', 'suspension')),
  public_url              TEXT,
  next_free_index         INTEGER NOT NULL DEFAULT 4,
  recorded_by_node        TEXT,
  replicated_at           INTEGER
);

CREATE TABLE IF NOT EXISTS status_list_flips (
  uuid              TEXT PRIMARY KEY,                 -- UUIDv7 for cross-node dedup
  status_list_uuid  TEXT NOT NULL,                    -- status_lists.uuid FK target
  slot_index        INTEGER NOT NULL,
  value             INTEGER NOT NULL,
  flipped_at        INTEGER,
  reason            TEXT,
  recorded_by_node  TEXT,
  replicated_at     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_status_list_flips_list_uuid ON status_list_flips(status_list_uuid);