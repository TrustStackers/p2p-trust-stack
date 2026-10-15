-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0003_keys.sql
-- Key material — only ever populated for identities with custody='local';
-- encrypted_secret_key is NULL for remotely-pushed identities (public_key only).
--
-- identity_uuid / did_document_uuid = distributed references
--
-- ⚠ NOTE — the wide key_type CHECK below is deliberate.
-- Commit b4f80af added 'ml_dsa_65' and 'mlkem768_x25519' in place, on a migration
-- that had already been applied to existing databases. Those databases therefore
-- still carry the narrow CHECK while a fresh one accepts all four types. That is
-- acceptable **pre-release** — see docs/pqc-and-migration-policy.md §2.2 — and
-- adding a key type is deliberately a *code* change rather than a migration,
-- because this CHECK already covers all four key roles the stack provisions.
-- Change BOTH migration sets together: this SQLite one and
-- utility-server/src/db/migrations/ (BYTEA / Postgres spelling).
-- test/db/schema-policy.test.ts fails if the two sets drift.

CREATE TABLE IF NOT EXISTS keys (
  uuid                  TEXT PRIMARY KEY,     -- UUIDv7 for cross-node dedup
  identity_uuid         TEXT NOT NULL,        -- identities.uuid FK target
  did_document_uuid     TEXT,                 -- did_documents.uuid FK target
  key_type              TEXT NOT NULL CHECK(key_type IN ('ed25519', 'x25519', 'ml_dsa_65', 'mlkem768_x25519')),
  public_key            BLOB NOT NULL,
  encrypted_secret_key  BLOB,                 -- NULL when custody='remote'
  salt                  BLOB,
  nonce                 BLOB,
  auth_tag              BLOB,
  rotation_version      INTEGER NOT NULL DEFAULT 0,
  recorded_by_node      TEXT,
  replicated_at         INTEGER,
  created_at            INTEGER,
  UNIQUE(identity_uuid, did_document_uuid, key_type, rotation_version)
);

CREATE INDEX IF NOT EXISTS idx_keys_identity_uuid ON keys(identity_uuid);