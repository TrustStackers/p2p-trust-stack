-- 0001_identities.sql
-- Every VTA, VTC, and VTN is a row here, discriminated by role.
--
-- ## identity key
--
-- identities.uuid = UUIDv5(DID_NAMESPACE, root_did_string) — deterministic, so any
-- node independently computing the same identity arrives at the same UUID. This is
-- the single cross-node identity key. The actual DID string lives in did_documents.did,
-- and did_documents.identity_uuid points here.
--
-- ## libp2p peer binding
--
-- The libp2p PeerID for an identity is NOT stored on this row. Host/runtime
-- endpoints (one or more per identity, of which at most one is active) live in
-- the normalized `peer_endpoints` table (migration 0016), keyed by
-- identity_uuid → identities.uuid, with peer_id as the endpoint's natural key.
-- The legacy identities.peer_id column is intentionally NOT present here.
--
-- Every other entity table uses UUIDv7 (time-ordered) for its own `uuid` column.

CREATE TABLE IF NOT EXISTS identities (
  uuid              TEXT PRIMARY KEY,        -- UUIDv5 derived from the root DID (cross-table identity key)
  role              TEXT NOT NULL CHECK(role IN ('vta', 'vtc', 'vtn')),
  subject_kind      TEXT CHECK(subject_kind IN ('human', 'ai_agent', 'object', 'organization')),
  custody           TEXT NOT NULL DEFAULT 'remote' CHECK(custody IN ('local', 'remote')),
  name              TEXT,
  dtg_subtype       TEXT CHECK(dtg_subtype IN ('RelationshipCredential', 'MembershipCredential', 'InvitationCredential','PersonaCredential', 'EndorsementCredential', 'WitnessCredential')),
  vid               TEXT,                    -- CESR VID; was `metadata` (JSON {cesrVid}) before the 0017 fold
  bootstrap_peer_id TEXT,                    -- peer ID of the bootstrap server this identity registered through
  bootstrap_url     TEXT,                    -- URL of the bootstrap server
  recorded_by_node  TEXT,                    -- which utility-server node recorded this row
  replicated_at     INTEGER,                 -- unix epoch when this was received via pubsub
  created_at        INTEGER,
  updated_at        INTEGER
);

CREATE INDEX IF NOT EXISTS idx_identities_role ON identities(role);
CREATE INDEX IF NOT EXISTS idx_identities_custody ON identities(custody);
-- Community names must be globally unique across VTCs and VTNs.
-- In a multi-YugabyteDB cluster, every utility server writes to the same
-- shared identities table — a duplicate INSERT violates this constraint
-- (SQLITE_CONSTRAINT / PG 23505) regardless of which server submitted it.
CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_community_name
  ON identities(name)
  WHERE role IN ('vtc','vtn') AND name IS NOT NULL;
