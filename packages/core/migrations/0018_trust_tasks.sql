-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0018_trust_tasks.sql
-- Persisted record of a Trust Task document (the P5 bridge envelope).
--
-- Each row is one task DOCUMENT within a ceremony: `thread_id` correlates the
-- documents of a single logical exchange; `type` is the task:p2pts:… identifier;
-- `direction` is 'request' | 'response'. `issuer_did`/`recipient_did` are
-- Verifiable Identifiers; `payload` and `proof` are JSON TEXT.
--
-- Shared convention: `uuid` (the document id) is the primary key; no integer
-- surrogate; inter-table references are BY UUID only. Rows are authored by the
-- AGENT during a ceremony and (eventually) replicated to the utility server, so
-- the table lives in BOTH the core SQLite and the utility Yugabyte schemas
-- (00xx shared).

CREATE TABLE IF NOT EXISTS trust_tasks (
  uuid              TEXT PRIMARY KEY,
  thread_id         TEXT NOT NULL,
  type              TEXT NOT NULL,
  direction         TEXT NOT NULL,
  issuer_did        TEXT,
  recipient_did     TEXT,
  parent_thread_id  TEXT,
  payload           TEXT,
  proof             TEXT,
  status            TEXT NOT NULL DEFAULT 'recorded',
  recorded_by_node  TEXT,
  replicated_at     INTEGER,
  created_at        INTEGER,
  updated_at        INTEGER
);

CREATE INDEX IF NOT EXISTS idx_trust_tasks_thread_id ON trust_tasks(thread_id);
CREATE INDEX IF NOT EXISTS idx_trust_tasks_type      ON trust_tasks(type);
