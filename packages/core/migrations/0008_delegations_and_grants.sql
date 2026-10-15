-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0008_delegations_and_grants.sql
-- Accountability/custody links for non-human subjects (delegations), plus
-- the fast-path authorization index (grants) derived from credentials and
-- delegations.

CREATE TABLE IF NOT EXISTS delegations (
  uuid                      TEXT PRIMARY KEY,   -- UUIDv7 for cross-node dedup
  principal_identity_uuid   TEXT NOT NULL,      -- identities.uuid FK target
  dependent_identity_uuid   TEXT NOT NULL,      -- identities.uuid FK target
  relationship_type         TEXT NOT NULL CHECK(relationship_type IN ('operates', 'owns', 'represents', 'employs')),
  scope                     TEXT,
  credential_uuid           TEXT,               -- credentials.uuid FK target
  granted_at                INTEGER,
  expires_at                INTEGER,
  revoked_at                INTEGER,
  recorded_by_node          TEXT,
  replicated_at             INTEGER
);

CREATE INDEX IF NOT EXISTS idx_delegations_principal_uuid ON delegations(principal_identity_uuid);
CREATE INDEX IF NOT EXISTS idx_delegations_dependent_uuid ON delegations(dependent_identity_uuid);

CREATE TABLE IF NOT EXISTS grants (
  uuid                    TEXT PRIMARY KEY,   -- UUIDv7 for cross-node dedup
  grantee_identity_uuid   TEXT NOT NULL,      -- identities.uuid FK target
  scope_identity_uuid     TEXT,               -- identities.uuid FK target
  permission              TEXT NOT NULL,
  source_credential_uuid  TEXT,               -- credentials.uuid FK target
  source_delegation_uuid  TEXT,               -- delegations.uuid FK target
  granted_at              INTEGER,
  revoked_at              INTEGER,
  recorded_by_node        TEXT,
  replicated_at           INTEGER
);

CREATE INDEX IF NOT EXISTS idx_grants_grantee_uuid ON grants(grantee_identity_uuid);
CREATE INDEX IF NOT EXISTS idx_grants_scope_uuid ON grants(scope_identity_uuid);
CREATE INDEX IF NOT EXISTS idx_grants_permission ON grants(permission);