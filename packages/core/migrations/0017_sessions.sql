-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0017_sessions.sql
-- Session revocation for the utility server's admin surface.
--
-- Audit F-019, ruling R3-b (2026-09-24): **revocable-but-stateless** sessions.
--
-- The design it replaces: the cookie was a self-contained
-- HMAC(identityUuid:expiresAt) token with no server-side record, so
--   * `POST /auth/logout` only deleted the browser's cookie — a copied token
--     stayed valid for the rest of its 8-hour life;
--   * there was no way to terminate ONE session (only rotating the global secret,
--     which signs out everyone);
--   * nothing could be enumerated.
--
-- This table pair adds the *minimum* state that makes termination real while
-- keeping validation stateless (a signature check, plus a lookup that normally
-- misses):
--
--   revoked_sessions    — individual terminations, keyed by the per-session id now
--                         carried in the token. Rows are prunable: once
--                         `expires_at` has passed the token cannot validate
--                         anyway, so the row proves nothing and is deleted.
--   session_revocations — one row per identity: "every session issued before T is
--                         dead". This is what makes `logout-all` possible without
--                         recording issued sessions, and it also kills LEGACY
--                         v1 tokens (which carry no session id) because their
--                         effective issued-at is 0.
--
-- Honest limits of R3-b (stated so nobody assumes more than this delivers):
--   * live sessions cannot be ENUMERATED — that needs issuance records, which is
--     option A and was deliberately not chosen;
--   * the revocation list is fail-OPEN: lose these rows (restore, truncate) and a
--     revoked session becomes valid again until its own expiry;
--   * validation costs one extra indexed lookup per authenticated request.
--
-- DIALECT: written to run on BOTH engines with no translation — no DB-side time
-- defaults (`unixepoch()` / `EXTRACT(EPOCH FROM NOW())`), no AUTOINCREMENT, no
-- `INSERT OR IGNORE`. Timestamps are supplied by the application (`BIGINT` is
-- accepted by SQLite as an INTEGER-affinity type). The file is byte-identical in
-- both migration sets — it contains no dialect spelling at all.
-- `test/db/schema-policy.test.ts` asserts the two sets declare the same columns, so
-- the two cannot drift apart the way `keys.key_type` once did (H5).

CREATE TABLE IF NOT EXISTS revoked_sessions (
  session_id     TEXT PRIMARY KEY,   -- the per-session id embedded in the token
  identity_uuid  TEXT NOT NULL,      -- identities.uuid (whose session this was)
  revoked_at     BIGINT NOT NULL,    -- unix seconds, app-supplied
  expires_at     BIGINT NOT NULL     -- the token's own expiry → the prune bound
);

CREATE INDEX IF NOT EXISTS idx_revoked_sessions_expires ON revoked_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_revoked_sessions_identity ON revoked_sessions(identity_uuid);

CREATE TABLE IF NOT EXISTS session_revocations (
  identity_uuid  TEXT PRIMARY KEY,   -- one cutoff per identity
  revoked_before BIGINT NOT NULL,    -- sessions issued at or before this are dead
  revoked_at     BIGINT NOT NULL
);
