// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * TransactionCoordinator — orchestrates N participants through a two-phase
 * commit with a durable decision and crash recovery.
 *
 * Sequence (commit path):
 *   1. write TX_STARTED
 *   2. PREPARE all participants (each durably records 'prepared' before YES)
 *   3. if all YES: write COMMIT_INTENT then COMMITTED (durable decision),
 *      then fan out COMMIT
 *   4. if any NO: write ABORTED (durable decision), then fan out ABORT
 *
 * Recovery:
 *   - COMMITTED in log  -> re-drive COMMIT to un-acknowledged participants
 *   - COMMIT_INTENT (no COMMITTED) -> inquire; all 'prepared' => COMMIT, else ABORT
 *   - otherwise -> ABORT (presumed abort)
 *
 * Adapted from reference-tx/coordinator.ts with durable SQLite backing via
 * TransactionLog + DataSourceLogSink.
 */

import { randomUUID } from 'node:crypto';
import { TransactionLog } from './tx-log.js';
import type {
  Enlisted,
  Operation,
  Participant,
  StatusEvent,
  TransactionResult,
} from './types.js';
import { logger } from '../util/logger.js';

export type StatusListener = (event: StatusEvent) => void;

export interface BeginOptions {
  participants: Enlisted[];
  /** Optional per-transaction timeout (ms). */
  timeoutMs?: number;
}

export interface CoordinatorOptions {
  /**
   * Look up the pid of the participant that handled `prepare` for a txId, from
   * durable state (`tx_participant_state`). Used when this process never saw the
   * prepare — i.e. the coordinator restarted between the two phases, which is
   * routine for the utility server (relay expiry, deploy, crash).
   *
   * Without it, `tx_commit`/`tx_abort`/`tx_inquiry` for a transaction prepared by
   * a PREVIOUS process fell through to `allParticipants()[0]` — the first
   * registered participant, which is generally NOT the one that prepared. The
   * commit then ran against the wrong participant: it "succeeded" (marking a
   * participant-state row nobody prepared) while the real participant was never
   * committed, so its effects were never finalised.
   */
  resolvePreparedPid?: (txId: string) => Promise<string | null>;
}

/**
 * Build a {@link CoordinatorOptions.resolvePreparedPid} over a coordinator
 * database. Shared by the agent and utility-server bootstraps so both recover the
 * same way.
 */
export function makePreparedPidResolver(
  ds: import('../db/data-source.js').DataSource,
): (txId: string) => Promise<string | null> {
  return async (txId: string) => {
    const row = await ds.get<{ pid: string }>(
      `SELECT pid FROM tx_participant_state
        WHERE tx_id = ? AND outcome IN ('prepared', 'committed')
        ORDER BY pid LIMIT 1`,
      txId,
    );
    return row?.pid ?? null;
  };
}

export class TransactionCoordinator {
  private readonly log: TransactionLog;
  private readonly listeners = new Set<StatusListener>();
  private readonly results = new Map<string, TransactionResult>();
  private readonly registry = new Map<string, Participant[]>();
  /** Responder-side: which participant handled the prepare for a given txId. */
  private readonly preparedBy = new Map<string, Participant>();
  private readonly resolvePreparedPid?: (txId: string) => Promise<string | null>;

  constructor(log: TransactionLog, opts: CoordinatorOptions = {}) {
    this.log = log;
    this.resolvePreparedPid = opts.resolvePreparedPid;
  }

  onStatus(listener: StatusListener): void {
    this.listeners.add(listener);
  }

  offStatus(listener: StatusListener): void {
    this.listeners.delete(listener);
  }

  private emit(status: StatusEvent): void {
    for (const l of this.listeners) l(status);
  }

  /** Register a participant by pid. Multiple participants may share a pid. */
  registerParticipant(p: Participant): void {
    const list = this.registry.get(p.pid) ?? [];
    list.push(p);
    this.registry.set(p.pid, list);
  }

  /** Unregister a participant. */
  unregisterParticipant(pid: string): void {
    this.registry.delete(pid);
  }

  /** Get the first registered participant for a pid (initiator-side lookup). */
  getParticipant(pid: string): Participant | undefined {
    return this.registry.get(pid)?.[0];
  }

  /**
   * Resolve the participant for a pid, preferring the one that actually handles
   * the given operations. Multiple local participants may share a pid (e.g.
   * VtcReceive, VrcCeremony and VrcReceive all use `peer:{agentDid}`), so inside
   * a pid we disambiguate by `handlesOperation`; fall back to the first
   * registered participant when none declares support (remote participants
   * sent over their transport, or single-participant pids).
   */
  private getParticipantForPid(pid: string, operations: Operation[]): Participant | undefined {
    const list = this.registry.get(pid) ?? [];
    if (list.length === 0) return undefined;
    if (operations && operations.length > 0) {
      const handles = list.find(
        (p) => typeof p.handlesOperation === "function" &&
               operations.some((op) => p.handlesOperation!(op)),
      );
      if (handles) return handles;
    }
    return list[0];
  }

  /** All registered participants (responder-side routing). */
  private allParticipants(): Participant[] {
    return [...this.registry.values()].flat();
  }

  /** Begin a transaction and commit it, returning the outcome. */
  async execute(options: BeginOptions): Promise<TransactionResult> {
    const txId = randomUUID();

    await this.log.append(txId, 'TX_STARTED', {
      pids: options.participants.map((e) => e.pid),
    });
    logger.info(`[tx-coordinator] ${txId.slice(0, 8)} started with ${options.participants.length} participant(s): ${options.participants.map(e => e.pid).join(', ')}`);
    this.emit({ txId, state: 'preparing' });

    const decision = await this.prepareAndDecide(txId, options);
    logger.info(`[tx-coordinator] ${txId.slice(0, 8)} decision: ${decision}`);
    this.emit({ txId, state: decision });

    if (decision === 'committed') {
      await this.fanOut(txId, options.participants, 'commit');
    } else {
      await this.fanOut(txId, options.participants, 'abort');
    }

    await this.log.append(txId, 'DONE');
    logger.info(`[tx-coordinator] ${txId.slice(0, 8)} done (${decision})`);
    this.emit({ txId, state: 'done' });

    const result: TransactionResult = { txId, outcome: decision };
    this.results.set(txId, result);
    return result;
  }

  /** Crash-safe re-drive of interrupted transactions. */
  async recover(): Promise<TransactionResult[]> {
    logger.info('[tx-coordinator] starting recovery...');
    const recovered: TransactionResult[] = [];
    for (const txId of await this.log.txIds()) {
      const entries = await this.log.read(txId);
      if (entries.some((e) => e.event === 'DONE')) continue;

      // Reconstruct the participant list from the persisted TX_STARTED payload.
      const started = entries.find((e) => e.event === 'TX_STARTED');
      const participants: Enlisted[] = this.participantsFromLog(started);
      if (participants.length === 0) continue;

      const committed = entries.some((e) => e.event === 'committed');
      const aborted = entries.some((e) => e.event === 'aborted');

      if (committed) {
        // Decision was COMMITTED — ensure participants finish committing.
        await this.fanOut(txId, participants, 'commit');
        await this.log.append(txId, 'DONE');
        recovered.push({ txId, outcome: 'committed' });
        continue;
      }

      if (aborted) {
        await this.fanOut(txId, participants, 'abort');
        await this.log.append(txId, 'DONE');
        recovered.push({ txId, outcome: 'aborted' });
        continue;
      }

      // COMMIT_INTENT without COMMITTED: inquire participants.
      const allPrepared = await this.allPrepared(txId, participants);
      if (allPrepared) {
        await this.log.append(txId, 'committed');
        await this.fanOut(txId, participants, 'commit');
      } else {
        await this.log.append(txId, 'aborted');
        await this.fanOut(txId, participants, 'abort');
      }
      await this.log.append(txId, 'DONE');
      recovered.push({ txId, outcome: allPrepared ? 'committed' : 'aborted' });
    }
    logger.info(`[tx-coordinator] recovery complete: ${recovered.length} transaction(s) recovered`);
    return recovered;
  }

  /** Reconstruct the enlisted participants from a TX_STARTED log entry. */
  private participantsFromLog(started?: { payload?: unknown }): Enlisted[] {
    if (!started) return [];
    const pids = (started.payload as { pids?: string[] } | null)?.pids ?? [];
    return pids.map((pid) => ({ pid, operations: [] }));
  }

  /** Phase 1: prepare all; phase 2 decision: write durable decision. */
  private async prepareAndDecide(
    txId: string,
    options: BeginOptions,
  ): Promise<'committed' | 'aborted'> {
    const votes = new Map<string, 'yes' | 'no'>();
    for (const { pid, operations } of options.participants) {
      const p = this.getParticipantForPid(pid, operations);
      if (!p) {
        logger.info(`[tx-coordinator] ${txId.slice(0, 8)} participant not found for ${pid} (${operations.length} op(s))`);
        votes.set(pid, 'no');
        continue;
      }
      try {
        logger.info(`[tx-coordinator] ${txId.slice(0, 8)} preparing ${pid} (${operations.length} op(s))`);
        const vote = await p.prepare(txId, operations);
        logger.info(`[tx-coordinator] ${txId.slice(0, 8)} ${pid} voted: ${vote}`);
        votes.set(pid, vote);
      } catch (err) {
        logger.error(`[tx-coordinator] ${txId.slice(0, 8)} ${pid} prepare error:`, (err as Error)?.message);
        votes.set(pid, 'no');
      }
    }

    const allYes = [...votes.values()].every((v) => v === 'yes');
    if (allYes) {
      await this.log.append(txId, 'COMMIT_INTENT');
      await this.log.append(txId, 'committed');
      return 'committed';
    }
    await this.log.append(txId, 'aborted');
    return 'aborted';
  }

  private async fanOut(
    txId: string,
    participants: Enlisted[],
    phase: 'commit' | 'abort',
  ): Promise<void> {
    for (const { pid, operations } of participants) {
      const p = this.getParticipantForPid(pid, operations ?? []);
      if (!p) continue;
      try {
        if (phase === 'commit') {
          logger.info(`[tx-coordinator] ${txId.slice(0, 8)} committing ${pid}`);
          await p.commit(txId);
        } else {
          logger.info(`[tx-coordinator] ${txId.slice(0, 8)} aborting ${pid}`);
          await p.abort(txId);
        }
      } catch (err) {
        logger.error(`[tx-coordinator] ${txId.slice(0, 8)} ${pid} ${phase} error:`, (err as Error)?.message);
        // idempotent retry on recovery
      }
    }
  }

  private async allPrepared(
    txId: string,
    participants: Enlisted[],
  ): Promise<boolean> {
    for (const { pid, operations } of participants) {
      const p = this.getParticipantForPid(pid, operations ?? []);
      if (!p) return false;
      const outcome = await p.inquiry(txId);
      if (outcome !== 'prepared' && outcome !== 'committed') return false;
    }
    return true;
  }

  getResult(txId: string): TransactionResult | undefined {
    return this.results.get(txId);
  }

  /**
   * Find the participant that handles the given operations.
   *
   * When a participant declares `handlesOperation`, it is selected only if it
   * handles at least one of the operations. When no participant declares the
   * hook, the first registered participant is used (legacy single-participant
   * behavior).
   */
  private findParticipantForOperations(operations: Operation[]): Participant | undefined {
    const all = this.allParticipants();
    if (all.length === 0) return undefined;

    const declarative = all.filter((p) => typeof p.handlesOperation === 'function');
    if (declarative.length > 0) {
      for (const p of declarative) {
        if (operations.some((op) => p.handlesOperation!(op))) return p;
      }
      return undefined;
    }

    return all[0];
  }

  /**
   * Resolve the participant that owns the SECOND phase of an inbound transaction.
   *
   * Order of preference:
   *   1. the in-memory `preparedBy` map — the normal same-process case;
   *   2. durable `tx_participant_state` via the injected resolver — the
   *      coordinator restarted between prepare and commit (routine for the utility
   *      server), so no map entry exists;
   *   3. the first registered participant — last resort, logged, and only when
   *      durable state is unavailable or names an unregistered pid.
   */
  private async participantForPreparedTx(txId: string): Promise<Participant | undefined> {
    const known = this.preparedBy.get(txId);
    if (known) return known;

    const pid = (await this.resolvePreparedPid?.(txId)) ?? null;
    if (pid) {
      const resolved = this.getParticipantForPid(pid, []);
      if (resolved) {
        logger.info(`[tx-coordinator] ${txId.slice(0, 8)} recovered prepared pid '${pid}' from durable state`);
        return resolved;
      }
      logger.warn(
        `[tx-coordinator] ${txId.slice(0, 8)} durable state says pid '${pid}' prepared, but it is not ` +
        `registered in this process — falling back to the first registered participant`,
      );
    }
    return this.allParticipants()[0];
  }

  /**
   * Handle an inbound transaction wire message from a remote coordinator.
   *
   * This is called by the agent or server when it receives a tx_prepare,
   * tx_commit, tx_abort, or tx_inquiry message. The coordinator dispatches
   * to the appropriate registered participant and returns the response.
   *
   * Routing:
   *   - tx_prepare routes by operation (via `handlesOperation`).
   *   - tx_commit / tx_abort / tx_inquiry route to the participant that
   *     previously handled the prepare for this txId (recorded in
   *     `preparedBy`), falling back to the first participant.
   *
   * @returns The response TxWireMessage, or null if the message kind is unknown.
   */
  async handleInboundTxMessage(msg: import('./wire-protocol.js').TxWireMessage): Promise<import('./wire-protocol.js').TxWireMessage | null> {
    const { txId } = msg as { txId: string };

    switch (msg.kind) {
      case 'tx_prepare': {
        const participant = this.findParticipantForOperations(msg.operations);
        if (!participant) {
          logger.info(`[tx-coordinator] inbound prepare ${txId.slice(0, 8)}: no participant handles operations`);
          return { kind: 'tx_prepare_result', txId, vote: 'no' };
        }
        try {
          logger.info(`[tx-coordinator] inbound prepare ${txId.slice(0, 8)} → ${participant.pid}`);
          const vote = await participant.prepare(txId, msg.operations);
          logger.info(`[tx-coordinator] inbound prepare ${txId.slice(0, 8)} ${participant.pid} voted: ${vote}`);
          this.preparedBy.set(txId, participant);
          return { kind: 'tx_prepare_result', txId, vote };
        } catch (err) {
          logger.error(`[tx-coordinator] inbound prepare ${txId.slice(0, 8)} ${participant.pid} error:`, (err as Error)?.message);
          return { kind: 'tx_prepare_result', txId, vote: 'no' };
        }
      }

      case 'tx_commit': {
        const participant = await this.participantForPreparedTx(txId);
        if (!participant) return { kind: 'tx_commit_result', txId, ok: false };
        try {
          logger.info(`[tx-coordinator] inbound commit ${txId.slice(0, 8)} → ${participant.pid}`);
          await participant.commit(txId);
          return { kind: 'tx_commit_result', txId, ok: true };
        } catch (err) {
          logger.error(`[tx-coordinator] inbound commit ${txId.slice(0, 8)} ${participant.pid} error:`, (err as Error)?.message);
          return { kind: 'tx_commit_result', txId, ok: false };
        }
      }

      case 'tx_abort': {
        const participant = await this.participantForPreparedTx(txId);
        if (!participant) return { kind: 'tx_abort_result', txId, ok: false };
        try {
          logger.info(`[tx-coordinator] inbound abort ${txId.slice(0, 8)} → ${participant.pid}`);
          await participant.abort(txId);
          return { kind: 'tx_abort_result', txId, ok: true };
        } catch (err) {
          logger.error(`[tx-coordinator] inbound abort ${txId.slice(0, 8)} ${participant.pid} error:`, (err as Error)?.message);
          return { kind: 'tx_abort_result', txId, ok: false };
        }
      }

      case 'tx_inquiry': {
        const participant = await this.participantForPreparedTx(txId);
        if (!participant) return { kind: 'tx_inquiry_result', txId, outcome: 'unknown' };
        try {
          const outcome = await participant.inquiry(txId);
          return { kind: 'tx_inquiry_result', txId, outcome };
        } catch (err) {
          logger.error(`[tx-coordinator] inbound inquiry ${txId.slice(0, 8)} ${participant.pid} error:`, (err as Error)?.message);
          return { kind: 'tx_inquiry_result', txId, outcome: 'unknown' };
        }
      }

      case 'tx_query': {
        const participant = this.findParticipantForOperations([
          { op: (msg as { op: string }).op, params: (msg as { params?: Record<string, unknown> }).params },
        ]);
        if (!participant) {
          return { kind: 'tx_query_result', txId, error: 'no participant handles the query' };
        }
        if (typeof participant.query !== 'function') {
          return { kind: 'tx_query_result', txId, error: `participant ${participant.pid} does not support queries` };
        }
        try {
          const data = await participant.query(
            (msg as { op: string }).op,
            (msg as { params?: Record<string, unknown> }).params,
          );
          return { kind: 'tx_query_result', txId, data };
        } catch (err) {
          logger.error(`[tx-coordinator] inbound query ${txId.slice(0, 8)} ${participant.pid} error:`, (err as Error)?.message);
          return { kind: 'tx_query_result', txId, error: (err as Error)?.message };
        }
      }

      default:
        return null;
    }
  }
}
