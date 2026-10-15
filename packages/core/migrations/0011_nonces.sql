-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0011_nonces.sql
-- Replay protection — local only, never replicated.
-- identity_uuid added for distributed reference consistency.

CREATE TABLE IF NOT EXISTS nonces (
  uuid          TEXT PRIMARY KEY,           -- UUIDv7 for cross-node dedup
  identity_uuid TEXT NOT NULL,              -- identities.uuid FK target
  nonce         TEXT NOT NULL,
  purpose       TEXT,
  seen_at       INTEGER NOT NULL,
  expires_at    INTEGER,
  UNIQUE(identity_uuid, nonce)
);