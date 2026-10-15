-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0007_governance.sql
-- Governance parameters per VTC/VTN — exactly one row per community.
-- admin_threshold_m/n back the M-of-N signature model seen in the VRC/VMC flow.
--
-- Policy RULES no longer live here: they are atomic catalog templates
-- (trust_task_templates, family='rule') applied per community through
-- community_policy_bindings. `vtc_governance_digest` is the VTC governance doc's
-- digest — a STORED commitment (never recomputed from mutable fields), since a
-- recompiled digest would invalidate the signatures made over the original.

CREATE TABLE IF NOT EXISTS governance (
  uuid                      TEXT PRIMARY KEY,          -- UUIDv7 for cross-node dedup
  community_identity_uuid   TEXT NOT NULL UNIQUE,      -- identities.uuid FK target
  admin_threshold_m         INTEGER,
  admin_threshold_n         INTEGER,
  vtc_governance_digest     TEXT,                      -- base64 VTC governance-doc digest (stored commitment)
  parent_community_uuid     TEXT,                      -- identities.uuid FK target
  admin_did_document_uuids  TEXT,
  recorded_by_node          TEXT,
  replicated_at             INTEGER,
  updated_at                INTEGER
);