-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0002_did_documents.sql
-- One or more DID documents per identity. The root identity (did:scid:vh)
-- has is_primary=1. Context-scoped DIDs (C-DID, M-DID, R-DID, P-DID) are
-- did:peer:4 rows with is_primary=0 and context_type set.
--
-- context_type / context_ref_uuid track which context (community, relationship,
-- persona) a scoped DID belongs to. NULL on the root identity.
--
-- `did` is globally UNIQUE (uuid-first; the 0019 redefinition is folded into this
-- file). An identity may still hold many peer:4 DIDs across different contexts,
-- because each such DID is itself distinct.

CREATE TABLE IF NOT EXISTS did_documents (
  uuid             TEXT PRIMARY KEY,          -- UUIDv7 for cross-node dedup
  identity_uuid    TEXT NOT NULL,             -- identities.uuid FK target for distributed reference
  did              TEXT UNIQUE NOT NULL,      -- the actual DID string
  method           TEXT NOT NULL,
  document_json    TEXT,
  is_primary       INTEGER DEFAULT 0,
  status           TEXT DEFAULT 'active' CHECK(status IN ('active', 'deactivated', 'superseded')),
  context_type     TEXT CHECK(context_type IN ('community', 'relationship', 'persona', NULL)),
  context_ref_uuid TEXT,                      -- identities.uuid / relationships.uuid / profiles.uuid
  recorded_by_node TEXT,
  replicated_at    INTEGER,
  created_at       INTEGER,
  updated_at       INTEGER
);

CREATE INDEX IF NOT EXISTS idx_did_documents_identity_uuid ON did_documents(identity_uuid);
