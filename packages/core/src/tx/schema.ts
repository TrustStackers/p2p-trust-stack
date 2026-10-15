// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Transaction Coordinator — SQLite Schema
 *
 * DDL for the dedicated tx-coordinator.db. This database is separate from
 * the application database (YugabyteDB or agent SQLite) and stores only
 * transaction coordination infrastructure data.
 *
 * Tables:
 *   - tx_log               — append-only transaction lifecycle events
 *   - tx_outbox            — durable outbox (persist-before-send)
 *   - tx_inbox             — idempotency-key dedup registry
 *   - tx_participant_state — per-participant prepare/commit/abort outcome
 */

import type { DataSource } from '../db/data-source.js';

/** Complete DDL for a fresh tx-coordinator.db. */
export const TX_SCHEMA_SQL = `
-- Transaction lifecycle log (append-only, WAL-like)
CREATE TABLE IF NOT EXISTS tx_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  tx_id TEXT NOT NULL,
  event TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  payload TEXT,  -- JSON-serialized payload
  UNIQUE(tx_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_tx_log_tx_id ON tx_log(tx_id);
CREATE INDEX IF NOT EXISTS idx_tx_log_timestamp ON tx_log(timestamp);

-- Durable outbox: messages persisted before send
CREATE TABLE IF NOT EXISTS tx_outbox (
  entry_id TEXT PRIMARY KEY,
  destination TEXT NOT NULL,
  payload TEXT NOT NULL,  -- JSON-serialized payload
  state TEXT NOT NULL DEFAULT 'pending',  -- pending | sent | delivered | failed
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER,
  deliver_by INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tx_outbox_state ON tx_outbox(state);
CREATE INDEX IF NOT EXISTS idx_tx_outbox_deliver_by ON tx_outbox(deliver_by);

-- Durable inbox: idempotency-key dedup
CREATE TABLE IF NOT EXISTS tx_inbox (
  idempotency_key TEXT PRIMARY KEY,
  delivered_at INTEGER NOT NULL,
  -- F-028: what was delivered under this key. A repeat with a DIFFERENT document is
  -- not a replay — it is a conflict, and acknowledging it as success is the finding.
  payload_digest TEXT
);

-- Exchange layer: per-(recordSet, peer) sync watermark.
-- One row per (recordSet, peer) tracks the last synced-at timestamp so the
-- ExchangeEngine can replay only rows newer than the watermark on reconnect
-- (no full rescan) and report staleness to on-demand pullers.
CREATE TABLE IF NOT EXISTS exchange_watermark (
  record_set        TEXT NOT NULL,
  peer              TEXT NOT NULL,
  last_synced_at    INTEGER NOT NULL,
  -- Phase 5: digest of the last materialized+projected payload for ack-gating.
  -- When a push materializes a payload identical to last_pushed_digest, the
  -- engine skips the enqueue — bounding volume to actual changes, not full-state
  -- re-pushes on every reconnect/tick.
  last_pushed_digest TEXT,
  PRIMARY KEY (record_set, peer)
);
CREATE INDEX IF NOT EXISTS idx_exchange_watermark_peer ON exchange_watermark(peer);

-- Per-participant transaction state (durable prepare/commit/abort record)
CREATE TABLE IF NOT EXISTS tx_participant_state (
  tx_id TEXT NOT NULL,
  pid TEXT NOT NULL,
  outcome TEXT NOT NULL DEFAULT 'unknown',  -- unknown | prepared | committed | aborted
  undo_hooks TEXT,  -- JSON array of UndoDescriptor[]
  PRIMARY KEY (tx_id, pid)
);
CREATE INDEX IF NOT EXISTS idx_tx_participant_state_tx_id ON tx_participant_state(tx_id);

-- Ceremony proposals: multi-admin VTC/VTN founding ceremonies (Phase 3)
CREATE TABLE IF NOT EXISTS ceremony_proposals (
  proposal_id     TEXT PRIMARY KEY,
  proposer_did    TEXT NOT NULL,
  proposer_uuid   TEXT,                     -- UUID-based proposer (agent path)
  vtc_did         TEXT NOT NULL,
  name            TEXT NOT NULL,
  kind            TEXT NOT NULL,             -- 'vtc' | 'vtn'
  admin_dids      TEXT NOT NULL,             -- JSON array: admin real DIDs
  admin_uuids     TEXT,                      -- JSON array: admin UUIDs (agent path)
  threshold       INTEGER NOT NULL,          -- M-of-N required for crystallization
  expires_at      INTEGER NOT NULL,          -- Unix ms
  status          TEXT NOT NULL DEFAULT 'pending',  -- pending | crystallized | expired | failed | aborted
  proposal_hash   TEXT NOT NULL,             -- SHA2-256 of canonical proposal JSON
  parent_community_did TEXT,                 -- optional parent VTN DID
  error_reason    TEXT,                      -- failure reason for failed ceremonies
  created_at      INTEGER NOT NULL,
  crystallized_at INTEGER                    -- NULL until crystallization
);
CREATE INDEX IF NOT EXISTS idx_ceremony_proposals_status ON ceremony_proposals(status);
CREATE INDEX IF NOT EXISTS idx_ceremony_proposals_proposer_uuid ON ceremony_proposals(proposer_uuid);

-- Ceremony approvals: Ed25519-signed admin approvals (Phase 3)
CREATE TABLE IF NOT EXISTS ceremony_approvals (
  approval_id   TEXT PRIMARY KEY,
  proposal_id   TEXT NOT NULL REFERENCES ceremony_proposals(proposal_id),
  approver_did  TEXT NOT NULL,
  signature     TEXT NOT NULL,            -- Ed25519 base64 over proposal_hash
  received_at   INTEGER NOT NULL,
  UNIQUE(proposal_id, approver_did)       -- one approval per admin per proposal
);
CREATE INDEX IF NOT EXISTS idx_ceremony_approvals_proposal ON ceremony_approvals(proposal_id);

-- Governance-change proposals: multi-admin consent for a community rule/threshold
-- change. One row per proposed change; approvals are Ed25519 signatures over the
-- proposal hash, one per eligible approver. The change is APPLIED only when the
-- distinct verified approval count reaches required_approver_count (resolved from
-- the setting's approval scope at begin time).
CREATE TABLE IF NOT EXISTS governance_change_proposals (
  proposal_id             TEXT PRIMARY KEY,
  community_uuid          TEXT NOT NULL,
  community_did           TEXT NOT NULL,
  proposer_uuid           TEXT NOT NULL,
  change_json             TEXT NOT NULL,     -- JSON: proposed thresholds + binding ops
  scope                   TEXT NOT NULL,     -- 'admins' | 'members' | 'all_members'
  required_approver_count INTEGER NOT NULL,  -- distinct approvers required
  required_approver_uuids TEXT NOT NULL,     -- JSON array: the eligible set at begin time
  proposal_hash           TEXT NOT NULL,     -- SHA2-256 of the canonical proposal JSON
  status                  TEXT NOT NULL DEFAULT 'pending', -- pending | crystallized | expired | failed | aborted
  error_reason            TEXT,
  expires_at              INTEGER NOT NULL,  -- Unix ms
  created_at              INTEGER NOT NULL,
  crystallized_at         INTEGER
);
CREATE INDEX IF NOT EXISTS idx_gov_change_proposals_status ON governance_change_proposals(status);
CREATE INDEX IF NOT EXISTS idx_gov_change_proposals_community ON governance_change_proposals(community_uuid);

-- Governance-change approvals: Ed25519-signed approver consents.
CREATE TABLE IF NOT EXISTS governance_change_approvals (
  approval_id   TEXT PRIMARY KEY,            -- proposal_id:approver_uuid
  proposal_id   TEXT NOT NULL REFERENCES governance_change_proposals(proposal_id),
  approver_uuid TEXT NOT NULL,
  signature     TEXT NOT NULL,               -- Ed25519 base64 over proposal_hash
  received_at   INTEGER NOT NULL,
  UNIQUE(proposal_id, approver_uuid)         -- one approval per approver per proposal
);
CREATE INDEX IF NOT EXISTS idx_gov_change_approvals_proposal ON governance_change_approvals(proposal_id);

-- VRC personhood ceremonies: durable saga state for the mutual-acknowledgment
-- ceremony that mints each agent's Verifiable Relationship Credential and
-- coordinates delivery to the peer agent and utility server.
-- One row per (local_did, remote_did) ceremony session, mirrored on each agent.
CREATE TABLE IF NOT EXISTS vrc_ceremonies (
  session_id         TEXT PRIMARY KEY,
  local_did          TEXT NOT NULL,
  remote_did         TEXT NOT NULL,
  phase              TEXT NOT NULL DEFAULT 'personhood', -- personhood | minting | sharing | complete | failed
  -- Leg booleans (mirror view on each agent):
  local_minted       INTEGER NOT NULL DEFAULT 0,   -- my VRC minted locally (DTG produced)
  sent_to_peer       INTEGER NOT NULL DEFAULT 0,   -- my VRC delivered to the remote agent
  sent_to_server     INTEGER NOT NULL DEFAULT 0,   -- my VRC archived on the utility server
  peer_vrc_received  INTEGER NOT NULL DEFAULT 0,   -- remote agent's VRC stored locally
  -- Personhood handshake state (mirrored locally)
  local_acked        INTEGER NOT NULL DEFAULT 0,   -- I pressed "I know this person"
  remote_acked       INTEGER NOT NULL DEFAULT 0,   -- remote pressed it too
  ack_sent_to_peer   INTEGER NOT NULL DEFAULT 0,   -- my ack durably DELIVERED to the peer
  archive_deferred   INTEGER NOT NULL DEFAULT 0,   -- utility archive handed to the outbox pipeline
  -- Retry / failure bookkeeping
  current_step       TEXT NOT NULL DEFAULT '',
  failed_step        TEXT,
  attempt            INTEGER NOT NULL DEFAULT 0,
  next_attempt_at    INTEGER,
  last_error         TEXT,
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vrc_ceremonies_remote ON vrc_ceremonies(local_did, remote_did);
CREATE INDEX IF NOT EXISTS idx_vrc_ceremonies_phase ON vrc_ceremonies(phase);
`;

/**
 * SQL statements for the janitor to prune expired entries.
 * Uses parameterized placeholders for cutoff timestamps.
 */

/** Delete log entries for completed transactions older than the cutoff. */
export const JANITOR_PRUNE_COMPLETED_SQL = `
DELETE FROM tx_log
WHERE timestamp < ?
  AND tx_id IN (
    SELECT tx_id FROM tx_log
    WHERE event IN ('committed', 'aborted', 'DONE')
  )
`;

/** Delete log entries for incomplete transactions older than the cutoff. */
export const JANITOR_PRUNE_INCOMPLETE_SQL = `
DELETE FROM tx_log
WHERE timestamp < ?
  AND tx_id NOT IN (
    SELECT tx_id FROM tx_log
    WHERE event IN ('committed', 'aborted', 'DONE')
  )
`;

/** Delete outbox entries older than the cutoff (any state). */
export const JANITOR_PRUNE_OUTBOX_SQL = `
DELETE FROM tx_outbox WHERE created_at < ?
`;

/** Delete inbox entries older than the cutoff. */
export const JANITOR_PRUNE_INBOX_SQL = `
DELETE FROM tx_inbox WHERE delivered_at < ?
`;

/** Delete participant state for completed/aborted transactions older than cutoff. */
export const JANITOR_PRUNE_PARTICIPANT_STATE_SQL = `
DELETE FROM tx_participant_state
WHERE tx_id IN (
  SELECT tx_id FROM tx_participant_state
  WHERE outcome IN ('committed', 'aborted')
)
AND tx_id NOT IN (
  SELECT DISTINCT tx_id FROM tx_log WHERE timestamp >= ?
)
`;

/** Delete crystallized/expired/failed ceremony proposals older than the cutoff. */
export const JANITOR_PRUNE_CEREMONY_PROPOSALS_SQL = `
DELETE FROM ceremony_proposals
WHERE status IN ('crystallized', 'expired', 'failed')
  AND created_at < ?
`;

/** Delete ceremony approvals for crystallized/expired proposals. */
export const JANITOR_PRUNE_CEREMONY_APPROVALS_SQL = `
DELETE FROM ceremony_approvals
WHERE proposal_id IN (
  SELECT proposal_id FROM ceremony_proposals
  WHERE status IN ('crystallized', 'expired', 'failed')
    AND created_at < ?
)
`;

/** Delete settled governance-change proposals older than the cutoff. */
export const JANITOR_PRUNE_GOVERNANCE_CHANGE_PROPOSALS_SQL = `
DELETE FROM governance_change_proposals
WHERE status IN ('crystallized', 'expired', 'failed', 'aborted')
  AND created_at < ?
`;

/** Delete approvals for settled governance-change proposals. */
export const JANITOR_PRUNE_GOVERNANCE_CHANGE_APPROVALS_SQL = `
DELETE FROM governance_change_approvals
WHERE proposal_id IN (
  SELECT proposal_id FROM governance_change_proposals
  WHERE status IN ('crystallized', 'expired', 'failed', 'aborted')
    AND created_at < ?
)
`;

/** Delete completed/failed VRC ceremonies older than the cutoff. */
export const JANITOR_PRUNE_VRC_CEREMONIES_SQL = `
DELETE FROM vrc_ceremonies
WHERE phase IN ('complete', 'failed')
  AND updated_at < ?
`;


// ── Additive column migrations ──────────────────────────────────────────────────
//
// `TX_SCHEMA_SQL` is applied with `CREATE TABLE IF NOT EXISTS`, which leaves an
// ALREADY-EXISTING table untouched — so a column added after a database was first
// created is simply absent at runtime and every statement naming it throws
// "no such column". There is no ALTER-based migration chain for
// tx-coordinator.db, so additions are declared here and applied idempotently by
// `applyTxSchemaAdditions()` on every boot, right after the DDL.

export interface TxAdditiveColumn {
  table: string;
  column: string;
  /** DDL applied ONLY when the column is missing. Must be a constant. */
  ddl: string;
}

export const TX_ADDITIVE_COLUMNS: readonly TxAdditiveColumn[] = [
  {
    // F-028: existing tx-coordinator databases predate the payload fingerprint, so a
    // NULL means "delivered before we recorded fingerprints" — which is treated as
    // comparable-equal (see DurableInbox): we cannot prove a conflict from a row that
    // never carried the information, and inventing one would break legitimate replays.
    table: 'tx_inbox',
    column: 'payload_digest',
    ddl: 'ALTER TABLE tx_inbox ADD COLUMN payload_digest TEXT',
  },
  {
    table: 'vrc_ceremonies',
    column: 'ack_sent_to_peer',
    ddl: 'ALTER TABLE vrc_ceremonies ADD COLUMN ack_sent_to_peer INTEGER NOT NULL DEFAULT 0',
  },
  {
    table: 'vrc_ceremonies',
    column: 'archive_deferred',
    ddl: 'ALTER TABLE vrc_ceremonies ADD COLUMN archive_deferred INTEGER NOT NULL DEFAULT 0',
  },
  {
    // Which coordinator owns an outbox entry. Several agents launched from the
    // same working directory used to share `data/tx/tx-coordinator.db`, so one
    // agent's reconnect drain (and its blanket `state='sent' → 'delivered'`
    // promotion for `server:%` rows) could mark ANOTHER agent's entries
    // delivered. NULL on legacy rows; comparisons use COALESCE so NULL keeps
    // matching NULL.
    table: 'tx_outbox',
    column: 'owner',
    ddl: 'ALTER TABLE tx_outbox ADD COLUMN owner TEXT',
  },
];

/**
 * Apply every missing entry of `TX_ADDITIVE_COLUMNS` to an open tx-coordinator
 * database. Idempotent: present columns are skipped, so this is safe to call on
 * every boot.
 *
 * The table/column names interpolated into the PRAGMA come from the constant
 * list above and never from user input.
 *
 * @returns the `table.column` names actually added by THIS call.
 */
export async function applyTxSchemaAdditions(ds: DataSource): Promise<string[]> {
  const added: string[] = [];
  for (const col of TX_ADDITIVE_COLUMNS) {
    const info = await ds.all<{ name: string }>(`PRAGMA table_info(${col.table})`);
    if (info.some((r) => r.name === col.column)) continue;
    await ds.exec(col.ddl);
    added.push(`${col.table}.${col.column}`);
  }
  return added;
}
