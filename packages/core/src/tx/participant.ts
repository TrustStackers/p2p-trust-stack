// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Participant — the local side of a distributed transaction.
 *
 * Two implementations:
 *   - InProcessParticipant: executes operations against a user-supplied
 *     OperationExecutor and tracks undo descriptors (compensation).
 *   - RemoteParticipant: sends lifecycle messages over a pluggable transport,
 *     simulating a peer agent or utility-server shard on another host.
 *
 * The durability contract for prepare(): a participant that votes 'yes' records
 * outcome='prepared' BEFORE returning, so inquiry() can answer after a crash.
 *
 * Adapted from reference-tx/participant.ts with durable SQLite backing for
 * participant state (tx_participant_state table).
 */

import { randomUUID } from 'node:crypto';
import type { DataSource } from '../db/data-source.js';
import type {
  Operation,
  OperationExecutor,
  Outcome,
  Participant,
  UndoDescriptor,
  Vote,
} from './types.js';
import type {
  TxWireMessage,
} from './wire-protocol.js';
import { logger } from '../util/logger.js';

// ---------------------------------------------------------------------------
// InProcessParticipant (local DB + app-variable operations)
// ---------------------------------------------------------------------------

/**
 * InProcessParticipant — executes operations locally against an
 * OperationExecutor. Tracks undo descriptors for compensation.
 *
 * Participant state (outcome) is durably recorded in the tx_participant_state
 * table of the coordinator SQLite database, satisfying the durability contract
 * that a 'yes' vote must survive a crash.
 */
export class InProcessParticipant implements Participant {
  readonly pid: string;
  private readonly executor: OperationExecutor;
  private readonly ds: DataSource; // tx-coordinator.db DataSource
  private readonly undoCache = new Map<string, UndoDescriptor[]>();

  constructor(pid: string, executor: OperationExecutor, ds: DataSource) {
    this.pid = pid;
    this.executor = executor;
    this.ds = ds;
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    const undos: UndoDescriptor[] = [];

    for (const op of operations) {
      try {
        const result = await this.executor(op);
        if (!result.ok) {
          // Roll back tentatively-applied operations so far, then vote no.
          await this.rollbackLocal(undos);
          return 'no';
        }
        if (result.undos) undos.push(...result.undos);
      } catch {
        await this.rollbackLocal(undos);
        return 'no';
      }
    }

    // Durably record 'prepared' BEFORE voting yes.
    this.undoCache.set(txId, undos);
    await this.ds.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome, undo_hooks)
       VALUES (?, ?, 'prepared', ?)`,
      txId,
      this.pid,
      JSON.stringify(undos),
    );

    logger.info(`[tx-participant] ${this.pid} ${txId.slice(0, 8)} prepared (${operations.length} op(s), ${undos.length} undo(s))`);
    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    // Effects are now final. Undo hooks are retained for potential
    // compensation by a parent transaction (saga/TCC).
    await this.ds.run(
      `UPDATE tx_participant_state SET outcome = 'committed'
       WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
    logger.info(`[tx-participant] ${this.pid} ${txId.slice(0, 8)} committed`);
  }

  async abort(txId: string): Promise<void> {
    const undos = this.undoCache.get(txId) ?? [];
    await this.rollbackLocal(undos);
    this.undoCache.delete(txId);

    await this.ds.run(
      `UPDATE tx_participant_state SET outcome = 'aborted'
       WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
    logger.info(`[tx-participant] ${this.pid} ${txId.slice(0, 8)} aborted`);
  }

  async compensate(txId: string): Promise<void> {
    // Used when an already-COMMITTED child must be undone because its parent
    // aborted (saga cancel).
    const row = await this.ds.get<{ outcome: string; undo_hooks: string | null }>(
      'SELECT outcome, undo_hooks FROM tx_participant_state WHERE tx_id = ? AND pid = ?',
      txId,
      this.pid,
    );
    if (!row || row.outcome !== 'committed') return;

    logger.info(`[tx-participant] ${this.pid} ${txId.slice(0, 8)} compensating (was committed)`);
    const undos: UndoDescriptor[] = row.undo_hooks ? JSON.parse(row.undo_hooks) : [];
    await this.rollbackLocal(undos);

    await this.ds.run(
      `UPDATE tx_participant_state SET outcome = 'aborted'
       WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.ds.get<{ outcome: string }>(
      'SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?',
      txId,
      this.pid,
    );
    return (row?.outcome as Outcome) ?? 'unknown';
  }

  /** Run undo descriptors in reverse (LIFO) order via the executor. */
  private async rollbackLocal(undos: UndoDescriptor[]): Promise<void> {
    for (let i = undos.length - 1; i >= 0; i--) {
      try {
        // Re-use the executor with a synthetic 'undo' operation
        await this.executor({ op: '_undo', params: { descriptor: undos[i] } });
      } catch {
        // Best-effort compensation
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Remote participant (transport-backed)
// ---------------------------------------------------------------------------

/**
 * Pluggable transport so a real peer/libp2p sink can be substituted.
 *
 * The transport sends a TxWireMessage to a remote participant (identified by
 * pid) and returns the response. The pid uses the cross-server URI scheme:
 *   - peer:{vid}            — remote agent via TSP/libp2p
 *   - server:{serverId}     — local utility server
 *   - server:{serverId}/{shardId} — remote utility server shard (future)
 */
export interface ParticipantTransport {
  send(pid: string, msg: TxWireMessage): Promise<TxWireMessage>;

  /**
   * Optional: check whether the transport has an active connection to the
   * peer identified by `pid`.  Used by {@link TspParticipantTransport} to
   * wait for tunnel establishment before sending transaction messages.
   *
   * Return `true` if connected, `false` if not, or leave unimplemented
   * (returns `undefined`) to skip the connectivity pre-flight check.
   */
  isConnected?(pid: string): boolean;
}

/**
 * A participant living on another node, reached over a ParticipantTransport.
 *
 * Each lifecycle method (prepare/commit/abort/inquiry) sends the corresponding
 * wire message and awaits the response. The remote participant is responsible
 * for its own durability (recording 'prepared' before voting 'yes').
 */
export class RemoteParticipant implements Participant {
  readonly pid: string;
  private readonly transport: ParticipantTransport;

  constructor(pid: string, transport: ParticipantTransport) {
    this.pid = pid;
    this.transport = transport;
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    logger.info(`[tx-remote] ${this.pid} ${txId.slice(0, 8)} sending prepare (${operations.length} op(s))`);
    const res = await this.transport.send(this.pid, {
      kind: 'tx_prepare',
      txId,
      operations,
      messageId: randomUUID(),
    });
    if (res.kind !== 'tx_prepare_result') throw new Error('bad prepare response');
    logger.info(`[tx-remote] ${this.pid} ${txId.slice(0, 8)} prepare result: ${res.vote}`);
    return res.vote;
  }

  async commit(txId: string): Promise<void> {
    logger.info(`[tx-remote] ${this.pid} ${txId.slice(0, 8)} sending commit`);
    await this.transport.send(this.pid, { kind: 'tx_commit', txId, messageId: randomUUID() });
  }

  async abort(txId: string): Promise<void> {
    logger.info(`[tx-remote] ${this.pid} ${txId.slice(0, 8)} sending abort`);
    await this.transport.send(this.pid, { kind: 'tx_abort', txId, messageId: randomUUID() });
  }

  async compensate(txId: string): Promise<void> {
    logger.info(`[tx-remote] ${this.pid} ${txId.slice(0, 8)} sending compensate (abort)`);
    await this.transport.send(this.pid, { kind: 'tx_abort', txId, messageId: randomUUID() });
  }

  async inquiry(txId: string): Promise<Outcome> {
    logger.info(`[tx-remote] ${this.pid} ${txId.slice(0, 8)} sending inquiry`);
    const res = await this.transport.send(this.pid, { kind: 'tx_inquiry', txId, messageId: randomUUID() });
    if (res.kind !== 'tx_inquiry_result') throw new Error('bad inquiry response');
    logger.info(`[tx-remote] ${this.pid} ${txId.slice(0, 8)} inquiry result: ${res.outcome}`);
    return res.outcome;
  }

  /**
   * Send a read-only query to the remote participant and return its data.
   *
   * This is the data-return channel for operations that do not change state
   * (name_resolve, identity_lookup, exchange:*). It keeps such
   * operations inside the transaction coordinator subsystem instead of using
   * a direct request/response path.
   */
  async query(op: string, params?: Record<string, unknown>): Promise<unknown> {
    logger.info(`[tx-remote] ${this.pid} sending query ${op}`);
    const res = await this.transport.send(this.pid, {
      kind: 'tx_query',
      txId: randomUUID(),
      op,
      params,
      messageId: randomUUID(),
    });
    if (res.kind !== 'tx_query_result') throw new Error('bad query response');
    if (res.error) throw new Error(res.error);
    return res.data;
  }
}
