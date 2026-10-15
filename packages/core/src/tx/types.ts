// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Transaction Coordination Layer — Core Types
 *
 * Adapted from reference-tx/types.ts with production-ready additions:
 *   - Serializable undo descriptors (not closures) for durable compensation
 *   - Cross-server addressing via pid URI scheme
 *   - TTL-aware timestamps for log pruning
 *
 * This module is shared by agent-app, utility-server, and any future shard.
 */

// ---------------------------------------------------------------------------
// Participant addressing (cross-server ready)
// ---------------------------------------------------------------------------

/**
 * Participant identifier using a URI scheme that accommodates:
 *   - `local-db`              — local InProcessParticipant (DataSource wrapper)
 *   - `peer:{vid}`            — remote agent reached via TSP/libp2p
 *   - `server:{serverId}`     — local utility server's own DB operations
 *   - `server:{serverId}/{shardId}` — remote utility server shard (future)
 */
export type ParticipantId = string;

// ---------------------------------------------------------------------------
// Transaction (Layer 2)
// ---------------------------------------------------------------------------

/** A named unit of work a participant must perform. */
export interface Operation {
  op: string;
  params?: Record<string, unknown>;
}

export type Vote = 'yes' | 'no';

export type Outcome = 'unknown' | 'prepared' | 'committed' | 'aborted';

export type TransactionState =
  | 'enlisted'
  | 'preparing'
  | 'commit_intent'
  | 'committed'
  | 'done'
  | 'aborted';

/**
 * Serializable undo descriptor.
 *
 * Unlike the reference implementation (which stores closures), the production
 * layer stores descriptors that a CompensationExecutor replays. This is
 * necessary because closures cannot be serialized to SQLite for durability.
 */
export interface UndoDescriptor {
  /** Discriminator for the CompensationExecutor. */
  type: string;
  /** Arbitrary data needed to reverse the effect. */
  [key: string]: unknown;
}

/** Result of executing one Operation on a participant. */
export interface ExecutionResult {
  ok: boolean;
  reason?: string;
  /** Optional compensation descriptors to reverse what was just applied. */
  undos?: UndoDescriptor[];
}

/**
 * Executes a single Operation against some local state (a database row, an
 * in-memory structure, etc.), returning whether it succeeded and, if so, how to
 * undo it. This is the participant's equivalent of `DataSource.transaction()`.
 */
export type OperationExecutor = (op: Operation) => Promise<ExecutionResult>;

/**
 * A transaction participant (a peer agent, a utility-server shard, or the
 * local database facade). Keys durability requirement: a participant that votes
 * 'yes' must be able to answer inquiry() = 'prepared' afterward.
 */
export interface Participant {
  readonly pid: ParticipantId;
  /** Phase 1 — tentatively apply, durably record 'prepared', vote. */
  prepare(txId: string, operations: Operation[]): Promise<Vote>;
  /** Phase 2 — finalize (idempotent). */
  commit(txId: string): Promise<void>;
  /** Roll back / compensate (idempotent). */
  abort(txId: string): Promise<void>;
  /** Compensate an already-committed transaction (saga cancel). */
  compensate(txId: string): Promise<void>;
  /** Report the recorded outcome (enables coordinator recovery). */
  inquiry(txId: string): Promise<Outcome>;
  /**
   * Optional: evaluate a read-only operation and return its result.
   *
   * Provides a data-return channel for operations that do not change state
   * (name_resolve, identity_lookup, exchange:*). When omitted,
   * the participant does not support read-only queries and the coordinator
   * returns an error for `tx_query` messages targeting it.
   */
  query?(op: string, params?: Record<string, unknown>): Promise<unknown>;
  /**
   * Optional: whether this participant handles the given operation. Used by
   * the coordinator to route inbound `tx_prepare` messages to the correct
   * participant when multiple participants are registered on the same node.
   * When omitted, the participant is assumed to handle every operation.
   */
  handlesOperation?(op: Operation): boolean;
}

// ---------------------------------------------------------------------------
// Delivery (Layer 1)
// ---------------------------------------------------------------------------

export type SendReceiptStatus = 'accepted' | 'unconfirmed';

export interface SendReceipt {
  status: SendReceiptStatus;
  entryId: string;
}

export type OutboxState = 'pending' | 'sent' | 'delivered' | 'failed';

export interface OutboxEntry {
  entryId: string; // idempotency key
  destination: string;
  payload: unknown;
  state: OutboxState;
  attempts: number;
  deliverBy: number;
}

export type ConnState = 'down' | 'connecting' | 'up';

export interface LayerReceipt {
  idempotencyKey: string;
  deliveredAt: number;
}

// ---------------------------------------------------------------------------
// Durable transaction log
// ---------------------------------------------------------------------------

export interface LogEntry {
  seq: number;
  txId: string;
  event: string;
  timestamp: number;
  payload?: unknown;
}

export interface TransactionResult {
  txId: string;
  outcome: 'committed' | 'aborted';
}

export interface Enlisted {
  pid: ParticipantId;
  operations: Operation[];
}

export interface StatusEvent {
  txId: string;
  state: string;
  detail?: string;
}

// ---------------------------------------------------------------------------
// Compensation (durable undo)
// ---------------------------------------------------------------------------

/**
 * A compensation executor knows how to replay UndoDescriptors for a given
 * `type`. Registered by the application at startup.
 */
export interface CompensationHandler {
  /** The `type` string this handler matches (from UndoDescriptor.type). */
  readonly type: string;
  /** Replay a single undo descriptor. */
  execute(descriptor: UndoDescriptor): Promise<void>;
}

// ---------------------------------------------------------------------------
// Janitor / TTL
// ---------------------------------------------------------------------------

export interface JanitorConfig {
  /** How often to run pruning (ms). Default: 300_000 (5 min). */
  intervalMs: number;
  /** Delete committed/aborted log entries older than this (ms). Default: 7 days. */
  completedTtlMs: number;
  /** Delete incomplete (in-flight) log entries older than this (ms). Default: 30 days. */
  incompleteTtlMs: number;
}

export const DEFAULT_JANITOR_CONFIG: JanitorConfig = {
  intervalMs: 5 * 60 * 1000,
  completedTtlMs: 7 * 24 * 60 * 60 * 1000,
  incompleteTtlMs: 30 * 24 * 60 * 60 * 1000,
};