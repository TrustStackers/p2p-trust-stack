-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0009_credentials_and_signatures.sql
-- The VC layer: vmc/vec/vrc/custom_endorsement mirror OpenVTC's four VC
-- types for interop; 'delegation' is a fifth, P2PTS-specific extension.

CREATE TABLE IF NOT EXISTS credentials (
  uuid                  TEXT PRIMARY KEY,            -- UUIDv7 for cross-node dedup
  vc_type               TEXT NOT NULL CHECK(vc_type IN ('vmc', 'vec', 'vrc', 'vic', 'custom_endorsement', 'delegation')),
  issuer_identity_uuid  TEXT NOT NULL,               -- identities.uuid FK target
  subject_identity_uuid TEXT NOT NULL,               -- identities.uuid FK target
  w3c_vc_json           TEXT,
  claim                 TEXT,
  status                TEXT NOT NULL DEFAULT 'issued' CHECK(status IN ('pending_signatures', 'issued', 'revoked', 'expired')),
  threshold_required    INTEGER,
  valid_from            INTEGER NOT NULL,
  valid_until           INTEGER,
  status_list_uuid      TEXT,                        -- status_lists.uuid FK target
  status_list_index     INTEGER,
  superseded_by_uuid    TEXT,                        -- credentials.uuid FK target
  credential_digest     TEXT,                        -- SHA2-256 dedup key
  recorded_by_node      TEXT,
  replicated_at         INTEGER,
  created_at            INTEGER
);

CREATE INDEX IF NOT EXISTS idx_credentials_issuer_uuid ON credentials(issuer_identity_uuid);
CREATE INDEX IF NOT EXISTS idx_credentials_subject_uuid ON credentials(subject_identity_uuid);
CREATE INDEX IF NOT EXISTS idx_credentials_vc_type ON credentials(vc_type);
CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);
CREATE INDEX IF NOT EXISTS idx_credentials_digest ON credentials(credential_digest) WHERE credential_digest IS NOT NULL;

CREATE TABLE IF NOT EXISTS credential_signatures (
  uuid                        TEXT PRIMARY KEY,      -- UUIDv7 for cross-node dedup
  credential_uuid             TEXT NOT NULL,         -- credentials.uuid FK target
  signer_identity_uuid        TEXT NOT NULL,         -- identities.uuid FK target
  signer_did_document_uuid    TEXT,                  -- did_documents.uuid FK target
  signature                   BLOB NOT NULL,
  recorded_by_node            TEXT,
  replicated_at               INTEGER,
  signed_at                   INTEGER,
  UNIQUE(credential_uuid, signer_identity_uuid)
);

CREATE INDEX IF NOT EXISTS idx_credential_signatures_credential_uuid ON credential_signatures(credential_uuid);