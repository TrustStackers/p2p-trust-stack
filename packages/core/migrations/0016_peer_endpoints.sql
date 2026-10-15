-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0016_peer_endpoints.sql
-- Host/runtime peer binding: one or more libp2p endpoints per identity.
--
-- peer_id is a per-device/per-install HOST identity (for did:scid:vh it is the
-- libp2p node key, independent of the DID-rotation keys) — it is NOT the
-- agent's DID/UUID. This table normalizes host/runtime state off the
-- identities row so a device change/relay can never fork an identity.
--
-- Keying: inter-table references are BY UUID only (identity_uuid,
-- did_document_uuid) — no integer FKs, and no integer surrogate key: `uuid` is
-- the primary key. peer_id is UNIQUE and is the endpoint's natural key /
-- cross-node dedup key (replication dedups on peer_id + identity_uuid).
--
-- Endpoints are written by the agent on login (identity-resolver /
-- base-agent.start) and by the utility server on identity_push /
-- ensureServerVta, using the guarded `setActiveEndpoint` semantics: at most
-- one ACTIVE endpoint per identity, and a peer_id is never reassigned to a
-- different identity. There is no backfill from identities.peer_id here —
-- that legacy column does not exist (see 0001).

CREATE TABLE IF NOT EXISTS peer_endpoints (
  uuid                TEXT PRIMARY KEY,              -- UUIDv7 (replaces integer id)
  identity_uuid       TEXT NOT NULL,                 -- identities.uuid FK (inter-table key)
  did_document_uuid   TEXT,                          -- did_documents.uuid FK (doc in effect at binding)
  peer_id             TEXT UNIQUE NOT NULL,          -- libp2p PeerID (natural key / dedup)
  multiaddrs          TEXT,                         -- JSON array of multiaddrs
  is_active           INTEGER NOT NULL DEFAULT 1,
  recorded_by_node    TEXT,
  replicated_at       INTEGER,
  created_at          INTEGER,
  updated_at          INTEGER,
  last_seen_at        INTEGER
);

CREATE INDEX IF NOT EXISTS idx_peer_endpoints_identity_uuid ON peer_endpoints(identity_uuid);
CREATE INDEX IF NOT EXISTS idx_peer_endpoints_peer_id      ON peer_endpoints(peer_id);
