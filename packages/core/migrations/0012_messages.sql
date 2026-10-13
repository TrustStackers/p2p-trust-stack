-- 0012_messages.sql
-- TSP messages, routed to specific DID service endpoints (DID-level, not
-- identity-level). Messages are TSP point-to-point — never replicated via pubsub.

CREATE TABLE IF NOT EXISTS messages (
  uuid                   TEXT PRIMARY KEY,             -- UUIDv7 for cross-node dedup
  from_did_document_uuid TEXT,                         -- did_documents.uuid FK target
  to_did_document_uuid   TEXT,                         -- did_documents.uuid FK target
  type                   TEXT,
  payload                BLOB,
  decrypted_payload      TEXT,
  read                   INTEGER DEFAULT 0,
  created_at             INTEGER
);

CREATE INDEX IF NOT EXISTS idx_messages_to_uuid ON messages(to_did_document_uuid);
CREATE INDEX IF NOT EXISTS idx_messages_from_uuid ON messages(from_did_document_uuid);

-- ── trust-app-api: durable event outbox + durable chat transcript ───────────────
--
-- Both tables back the trust-app-api layer (trust-app-api/events/catalog.ts and
-- trust-app-api/domains/messaging.ts). They are deliberately SEPARATE from the
-- `messages` table above: that one is the utility server's DID-document-routed
-- TSP record, whereas these are the agent's own cursorable, inspectable streams.
-- Keeping them apart is what lets an event log be debugged on its own.
--
-- DIALECT: written to run on BOTH engines with no translation — no DB-side time
-- defaults (`unixepoch()` / `EXTRACT(EPOCH FROM NOW())`), no AUTOINCREMENT, no
-- `INSERT OR IGNORE`. Timestamps are supplied by the application (`BIGINT` is
-- accepted by SQLite as an INTEGER-affinity type). This block is byte-identical
-- in both migration sets — it contains no dialect spelling at all.
-- `test/db/schema-policy.test.ts` asserts the two sets declare the same columns.

CREATE TABLE IF NOT EXISTS agent_events (
  uuid          TEXT PRIMARY KEY,   -- UUIDv7, for cross-node dedup
  sequence      INTEGER NOT NULL,   -- the bus's monotonic replay cursor (app-supplied)
  event_type    TEXT NOT NULL,      -- a name from trust-app-api/events/catalog.ts
  payload_json  TEXT NOT NULL,      -- the typed payload, serialised
  scope_id      TEXT,               -- filter key: peer did, community uuid, context id
  occurred_at   BIGINT NOT NULL,    -- unix MILLISECONDS, app-supplied
  UNIQUE(sequence)
);

CREATE INDEX IF NOT EXISTS idx_agent_events_sequence ON agent_events(sequence);
CREATE INDEX IF NOT EXISTS idx_agent_events_scope    ON agent_events(scope_id, sequence);

CREATE TABLE IF NOT EXISTS agent_messages (
  uuid          TEXT PRIMARY KEY,   -- UUIDv7, for cross-node dedup
  peer_did      TEXT NOT NULL,      -- the conversation key (stable, unique per peer)
  sequence      INTEGER NOT NULL,   -- per-conversation monotonic cursor (app-supplied)
  side          TEXT NOT NULL
                CHECK(side IN ('me','peer')),
  author_name   TEXT NOT NULL,      -- login name of the authoring agent
  body          TEXT NOT NULL,      -- the message text
  confidential  INTEGER NOT NULL DEFAULT 0,
  occurred_at   BIGINT NOT NULL,    -- unix MILLISECONDS, app-supplied
  UNIQUE(peer_did, sequence)
);

CREATE INDEX IF NOT EXISTS idx_agent_messages_peer ON agent_messages(peer_did, sequence);
