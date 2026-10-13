-- 0020_community_policy_bindings.sql
-- Two-tier modular policy — Phase A, Tier 2: `community_policy_bindings` —
-- per-community application of a catalog rule template (which rules apply, their
-- parameters, and the approval scope for changing each). A binding references a
-- `trust_task_templates` row of `family='rule'` (a `policy` step carrying the whole
-- rule body in `template`).
--
-- Tier 1 — the rule templates themselves — is seeded in 0019_trust_task_catalog.sql, the
-- migration that CREATES `trust_task_templates`: rule DEFINITIONS are catalog rows, while
-- the rule EVALUATOR stays in code (`LocalPolicyEngine` via `GovernanceGuard`).
--
-- `change_approval` scope vocabulary: 'admins' (default) | 'members' | 'all_members'.
--
-- Dialect-neutral: the table has no timestamp defaults, so this file is identical
-- in src/db/migrations (SQLite) and utility-server/src/db/migrations (Postgres).
--
-- PURE DDL: every seed for a table lives in the migration that CREATES that table, so
-- this file creates `community_policy_bindings` and nothing else.

CREATE TABLE IF NOT EXISTS community_policy_bindings (
  uuid                    TEXT PRIMARY KEY,
  community_identity_uuid TEXT NOT NULL,
  rule_type               TEXT NOT NULL,
  enabled                 INTEGER NOT NULL DEFAULT 1,
  params                  TEXT,
  change_approval         TEXT,
  priority                INTEGER,
  recorded_by_node        TEXT,
  replicated_at           INTEGER,
  updated_at              INTEGER,
  UNIQUE(community_identity_uuid, rule_type)
);

CREATE INDEX IF NOT EXISTS idx_cpb_community ON community_policy_bindings(community_identity_uuid);
CREATE INDEX IF NOT EXISTS idx_cpb_rule_type ON community_policy_bindings(rule_type);

