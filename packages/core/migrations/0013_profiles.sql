-- 0013_profiles.sql
-- Multiple Profiles (Scenario 3): display-layer personas an identity can
-- present, plus per-claim visibility/disclosure control.
-- Only profiles with visibility='public' and claims with disclosure='always'
-- are replicated via pubsub. Private/selective profiles stay local.

CREATE TABLE IF NOT EXISTS profiles (
  uuid             TEXT PRIMARY KEY,              -- UUIDv7 for cross-node dedup
  identity_uuid    TEXT NOT NULL,                 -- identities.uuid FK target
  label            TEXT NOT NULL,
  purpose          TEXT,
  visibility       TEXT NOT NULL DEFAULT 'private' CHECK(visibility IN ('private', 'selective', 'public')),
  is_default       INTEGER NOT NULL DEFAULT 0,
  recorded_by_node TEXT,
  replicated_at    INTEGER,
  created_at       INTEGER,
  updated_at       INTEGER
);

CREATE INDEX IF NOT EXISTS idx_profiles_identity_uuid ON profiles(identity_uuid);

CREATE TABLE IF NOT EXISTS profile_claims (
  uuid             TEXT PRIMARY KEY,              -- UUIDv7 for cross-node dedup
  profile_uuid     TEXT NOT NULL,                 -- profiles.uuid FK target
  claim_key        TEXT NOT NULL,
  claim_value      TEXT,
  value_type       TEXT NOT NULL DEFAULT 'string' CHECK(value_type IN ('string', 'text', 'date', 'url', 'image', 'boolean', 'number', 'json')),
  disclosure       TEXT NOT NULL DEFAULT 'discretionary' CHECK(disclosure IN ('always', 'discretionary', 'never', 'zkp_only')),
  commitment       TEXT,
  salt             TEXT,
  display_order    INTEGER NOT NULL DEFAULT 0,
  recorded_by_node TEXT,
  replicated_at    INTEGER,
  created_at       INTEGER,
  updated_at       INTEGER,
  UNIQUE(profile_uuid, claim_key)
);

CREATE INDEX IF NOT EXISTS idx_profile_claims_profile_uuid ON profile_claims(profile_uuid);