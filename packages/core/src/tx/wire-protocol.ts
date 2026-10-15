// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Wire Protocol — transaction coordination messages over TSP.
 *
 * These message types are additive on the existing ProtocolMessage envelope
 * (protocol, correlationId, payload). They coexist with the legacy
 * name_register_prepare / name_register_commit / etc. messages.
 *
 * The existing _prepare/_commit/_abort suffixes are mapped as a legacy
 * compatibility layer — TspRequestStateMachine continues to work, but new
 * code uses these transaction coordinator wire messages directly.
 */

import type { Operation, Outcome, Vote } from './types.js';
import type { OperationProof } from './operation-proof.js';
import { canonicalJson } from './operation-proof.js';
import { sha256 } from '../crypto/primitives.js';

// ---------------------------------------------------------------------------
// Per-message wire identity (H7 / decision D-4a)
// ---------------------------------------------------------------------------

/**
 * The per-message wire identity every 2PC message carries.
 *
 * `correlationId` on the envelope correlates **responses** — it is not a message
 * identity, and the same txId legitimately carries several distinct messages
 * (`tx_prepare` → `tx_commit` → `tx_inquiry`). That is why inbound dedup could not
 * simply key on the `txId`: a txId-keyed inbox would swallow the `tx_commit` as a
 * "replay" of the `tx_prepare` and **silently break 2PC**, leaving reservations
 * held forever.
 *
 * `(txId, messageId)` is therefore the dedup key — see `inboxKeyFor()`. The field
 * is optional so a peer that predates it still interoperates: absent `messageId`
 * means "no identity to dedup on", and the inbound path must then **pass the
 * message through** rather than guess.
 */
export interface TxMessageIdentity {
  /** Unique per send. Stable across a retry of *the same* message. */
  messageId?: string;
  /**
   * F-010 / ruling R1 (2026-09-24): the actor's signed operation document.
   *
   * Optional and additive — a peer that does not issue proofs still interoperates, and
   * `TSP_OPERATION_PROOF_POLICY` defaults to `warn`, so an upgrade changes no
   * behaviour until an operator opts in. Verified by `gateOperationProof()` in
   * `operation-proof.ts`; required (under `enforce`) only for `tx_prepare`.
   */
  proof?: OperationProof;
}

// ---------------------------------------------------------------------------
// Wire message types
// ---------------------------------------------------------------------------

/** Coordinator → Participant: Phase 1 — reserve, durably vote. */
export interface TxPrepareMessage extends TxMessageIdentity {
  kind: 'tx_prepare';
  txId: string;
  operations: Operation[];
}

/** Participant → Coordinator: Phase 1 result. */
export interface TxPrepareResultMessage extends TxMessageIdentity {
  kind: 'tx_prepare_result';
  txId: string;
  vote: Vote;
  /** Opaque token the coordinator echoes in commit/abort for verification. */
  prepareToken?: string;
}

/** Coordinator → Participant: Phase 2 — finalize. */
export interface TxCommitMessage extends TxMessageIdentity {
  kind: 'tx_commit';
  txId: string;
  prepareToken?: string;
}

/** Participant → Coordinator: Phase 2 result. */
export interface TxCommitResultMessage extends TxMessageIdentity {
  kind: 'tx_commit_result';
  txId: string;
  ok: boolean;
  reason?: string;
}

/** Coordinator → Participant: Roll back / compensate. */
export interface TxAbortMessage extends TxMessageIdentity {
  kind: 'tx_abort';
  txId: string;
  prepareToken?: string;
}

/** Participant → Coordinator: Abort acknowledged. */
export interface TxAbortResultMessage extends TxMessageIdentity {
  kind: 'tx_abort_result';
  txId: string;
  ok: boolean;
}

/** Coordinator → Participant (or P → C): "What was the outcome?" */
export interface TxInquiryMessage extends TxMessageIdentity {
  kind: 'tx_inquiry';
  txId: string;
}

/** Response to inquiry. */
export interface TxInquiryResultMessage extends TxMessageIdentity {
  kind: 'tx_inquiry_result';
  txId: string;
  outcome: Outcome;
}

/**
 * Coordinator → Participant: read-only query.
 *
 * Provides a data-return channel for operations that do not change state
 * (name_resolve, identity_lookup, exchange:*). This keeps such
 * operations inside the transaction coordinator subsystem rather than falling
 * back to a direct, non-durable request/response path.
 */
export interface TxQueryMessage extends TxMessageIdentity {
  kind: 'tx_query';
  txId: string;
  /** The operation the participant should evaluate (e.g. 'name_resolve'). */
  op: string;
  params?: Record<string, unknown>;
}

/** Participant → Coordinator: read-only query result. */
export interface TxQueryResultMessage extends TxMessageIdentity {
  kind: 'tx_query_result';
  txId: string;
  data?: unknown;
  error?: string;
}

/** Bidirectional: progress/status broadcast (monitorable). */
export interface TxStatusMessage extends TxMessageIdentity {
  kind: 'tx_status';
  txId: string;
  state: string;
  detail?: string;
}

/** Union of all transaction wire messages. */
export type TxWireMessage =
  | TxPrepareMessage
  | TxPrepareResultMessage
  | TxCommitMessage
  | TxCommitResultMessage
  | TxAbortMessage
  | TxAbortResultMessage
  | TxInquiryMessage
  | TxInquiryResultMessage
  | TxQueryMessage
  | TxQueryResultMessage
  | TxStatusMessage;

/**
 * The dedup key for an inbound 2PC message: `(txId, messageId)`, never `txId` alone
 * (H7 / decision D-4a — see `TxMessageIdentity` for why).
 *
 * Returns `null` when the message carries no `messageId` (a peer predating H7, or a
 * locally-constructed message). A `null` key means **do not dedup**: passing the
 * message through is the only safe reading, because treating "unknown identity" as
 * "already seen" would drop legitimate traffic, while treating it as "new" merely
 * re-runs a handler that was previously re-run anyway.
 *
 * The composed key is opaque to `tx_inbox` (its column is a plain TEXT primary
 * key); the format is defined here and nowhere else so that a future change to the
 * key shape is a one-line change with one test to update.
 */
export function inboxKeyFor(msg: TxMessageIdentity & { txId: string }): string | null {
  return msg.messageId ? `tx:${msg.txId}:${msg.messageId}` : null;
}

/**
 * **F-028:** the *document* fingerprint for a keyed message — the semantic content
 * only, deliberately excluding `proof` (a retry may legitimately be re-signed with a
 * fresh `issuedAt`, and that must not read as a different document).
 *
 * Two messages that share `(txId, messageId)` but differ here are not a replay: they
 * are a collision, and acknowledging the second as success is the audit's finding.
 */
export function inboxFingerprintFor(
  msg: TxMessageIdentity & { kind: string; txId: string; operations?: unknown },
): string {
  const canonical = canonicalJson({
    kind: msg.kind,
    txId: msg.txId,
    messageId: msg.messageId ?? null,
    operations: msg.operations ?? null,
  });
  return Buffer.from(sha256(new TextEncoder().encode(canonical))).toString('hex');
}

// ---------------------------------------------------------------------------
// Protocol name constants (used as the `protocol` field in ProtocolMessage)
// ---------------------------------------------------------------------------

export const TX_PROTOCOLS = {
  PREPARE: 'tx_prepare',
  PREPARE_RESULT: 'tx_prepare_result',
  COMMIT: 'tx_commit',
  COMMIT_RESULT: 'tx_commit_result',
  ABORT: 'tx_abort',
  ABORT_RESULT: 'tx_abort_result',
  INQUIRY: 'tx_inquiry',
  INQUIRY_RESULT: 'tx_inquiry_result',
  QUERY: 'tx_query',
  QUERY_RESULT: 'tx_query_result',
  STATUS: 'tx_status',
} as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Check if a protocol string is a transaction coordinator message. */
export function isTxProtocol(protocol: string): boolean {
  return Object.values(TX_PROTOCOLS).includes(protocol as typeof TX_PROTOCOLS[keyof typeof TX_PROTOCOLS]);
}

/** Extract the txId from a wire message payload. */
export function extractTxId(payload: unknown): string | undefined {
  if (typeof payload === 'object' && payload !== null && 'txId' in payload) {
    return (payload as { txId: string }).txId;
  }
  return undefined;
}