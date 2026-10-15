-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0015_pending_agent_deliveries: Generic queue for utility-server-to-agent delivery.
--
-- Stores pending data pushes that need to be delivered to agents via the
-- transaction coordinator (TSP/libp2p). The `op_type` column IS the
-- transaction operation name, making the queue entirely data-driven.
-- Any ceremony that inserts a row (e.g. 'receive_vtc' for VTC creation,
-- 'credential_issuance' for future credential pushes) will be delivered
-- by the AgentDeliveryQueue service — no queue code changes needed.
--
-- Idempotency: the `idempotency_key` UNIQUE constraint prevents duplicate
-- queue entries if the ceremony is re-run after crash recovery.

CREATE TABLE IF NOT EXISTS pending_agent_deliveries (
    uuid             TEXT PRIMARY KEY,       -- UUIDv7 for cross-node dedup
    member_uuid      TEXT NOT NULL,
    member_peer_id   TEXT,
    member_did       TEXT,
    op_type          TEXT NOT NULL,
    op_params_json   TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK(status IN ('pending','in_flight','delivered','failed')),
    attempts         INTEGER NOT NULL DEFAULT 0,
    max_attempts     INTEGER NOT NULL DEFAULT 10,
    last_error       TEXT,
    created_at       INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at       INTEGER NOT NULL DEFAULT (unixepoch()),
    next_retry_at    INTEGER,
    idempotency_key  TEXT,
    UNIQUE(idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_pending_deliveries_status
    ON pending_agent_deliveries(status);
CREATE INDEX IF NOT EXISTS idx_pending_deliveries_member
    ON pending_agent_deliveries(member_uuid, status);
CREATE INDEX IF NOT EXISTS idx_pending_deliveries_retry
    ON pending_agent_deliveries(next_retry_at)
    WHERE status = 'pending' AND next_retry_at IS NOT NULL;