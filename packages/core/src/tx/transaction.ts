// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Transaction — the application-facing scope. Records participant operations
 * and application-variable undo descriptors, and supports NESTED child
 * transactions.
 *
 * App-variable rollback: setVar() records an UndoDescriptor. On abort,
 * descriptors are replayed in reverse (LIFO) order via the
 * CompensationExecutor. Variable mutations are therefore "transactional"
 * even though they never touch the database.
 *
 * Adapted from reference-tx/transaction.ts with serializable undo descriptors
 * instead of closures.
 */

import type {
  Enlisted,
  Operation,
  Participant,
  TransactionResult,
  UndoDescriptor,
} from './types.js';
import { TransactionCoordinator } from './coordinator.js';
import { CompensationExecutor } from './compensation.js';

export interface TransactionOptions {
  coordinator: TransactionCoordinator;
  /** Compensation executor for replaying undo descriptors. */
  compensation: CompensationExecutor;
  /** Optional local participant (for operations executed in-process). */
  localParticipant?: Participant;
}

export class Transaction {
  private readonly coordinator: TransactionCoordinator;
  private readonly compensation: CompensationExecutor;
  private readonly pidToParticipant = new Map<string, Participant>();
  private readonly operations = new Map<string, Operation[]>();
  private readonly undos: UndoDescriptor[] = [];
  private readonly children: Transaction[] = [];
  private finished = false;
  private result: TransactionResult | null = null;

  constructor(opts: TransactionOptions) {
    this.coordinator = opts.coordinator;
    this.compensation = opts.compensation;
    if (opts.localParticipant) {
      this.pidToParticipant.set(opts.localParticipant.pid, opts.localParticipant);
    }
  }

  /** Register a participant accessible from this transaction (for nested scopes). */
  registerParticipant(p: Participant): void {
    this.pidToParticipant.set(p.pid, p);
  }

  /** Enlist a participant with a set of operations for this transaction. */
  enlist(participant: Participant, operations: Operation[]): void {
    this.assertOpen('enlist');
    this.pidToParticipant.set(participant.pid, participant);
    // Register the participant on the coordinator so it can be found during
    // prepare/commit/abort. RemoteParticipants are created on-the-fly and
    // need to be registered before the coordinator can use them.
    this.coordinator.registerParticipant(participant);
    const existing = this.operations.get(participant.pid) ?? [];
    existing.push(...operations);
    this.operations.set(participant.pid, existing);
  }

  /** Enlist a single operation for a participant. */
  update(participant: Participant, operation: Operation): void {
    this.enlist(participant, [operation]);
  }

  /**
   * Record an application-variable mutation plus its undo descriptor.
   * On abort, descriptors are replayed in reverse (LIFO) order via the
   * CompensationExecutor.
   */
  setVar(_name: string, _value: unknown, undo: UndoDescriptor): void {
    this.assertOpen('setVar');
    this.undos.push(undo);
  }

  /**
   * Execute a NESTED child transaction. The child runs independently (its own
   * 2PC); if the parent later aborts, the child is compensated via its
   * participants' compensate().
   */
  async run(fn: (child: Transaction) => Promise<void>): Promise<TransactionResult> {
    this.assertOpen('run');
    const child = new Transaction({
      coordinator: this.coordinator,
      compensation: this.compensation,
    });
    // Share participant registry downward so the child can address the same pids.
    for (const [pid, p] of this.pidToParticipant) child.pidToParticipant.set(pid, p);
    this.children.push(child);

    let childResult: TransactionResult;
    try {
      await fn(child);
      childResult = await child.commit();
    } catch (err) {
      childResult = await child.abort();
      throw err;
    }

    // If the child committed, register its compensation on the parent so a
    // later parent abort can undo the child's now-visible effects.
    if (childResult.outcome === 'committed') {
      this.undos.push({
        type: '_compensateChild',
        childTxId: childResult.txId,
        child,
      } as unknown as UndoDescriptor);
    }

    return childResult;
  }

  /** Commit this transaction (phase 1 + durable decision + phase 2). */
  async commit(): Promise<TransactionResult> {
    this.assertOpen('commit');

    const participants: Enlisted[] = [...this.operations.entries()].map(
      ([pid, ops]) => ({ pid, operations: ops }),
    );

    console.log(`[tx] committing with ${participants.length} participant(s)`);
    const result = await this.coordinator.execute({ participants });

    // If the coordinator aborted (a participant voted NO or prepare failed),
    // roll back application variables too — database/participant effects are
    // already rolled back by the coordinator's abort fan-out.
    if (result.outcome === 'aborted') {
      console.log(`[tx] aborted — running ${this.undos.length} app undo(s)`);
      await this.runAppUndos();
    }

    this.result = result;
    this.finished = true;
    console.log(`[tx] finished: ${result.outcome} (txId=${result.txId.slice(0, 8)})`);
    return result;
  }

  /**
   * Abort this transaction before it has been committed. Participants were
   * never prepared, so only application variables and open children need to be
   * rolled back.
   */
  async abort(): Promise<TransactionResult> {
    if (this.finished) {
      return this.result ?? { txId: '<finished>', outcome: 'aborted' };
    }

    console.log(`[tx] aborting — running ${this.undos.length} app undo(s)`);
    await this.runAppUndos();

    // Abort any child that is still open.
    for (const child of this.children) {
      if (!child.finished) await child.abort();
    }

    const result: TransactionResult = { txId: '<aborted>', outcome: 'aborted' };
    this.result = result;
    this.finished = true;
    return result;
  }

  /** Run recorded app-variable undo descriptors in reverse (LIFO) order. */
  private async runAppUndos(): Promise<void> {
    if (this.undos.length === 0) return;
    const errors = await this.compensation.execute(this.undos);
    if (errors.length > 0) {
      console.warn(`[tx] compensation errors for transaction: ${errors.join('; ')}`);
    }
    this.undos.length = 0;
  }

  /** Compensate an already-committed transaction (used by a parent's abort). */
  async compensate(): Promise<void> {
    for (const { pid } of [...this.operations.entries()].map(([pid, ops]) => ({ pid, operations: ops }))) {
      const p = this.pidToParticipant.get(pid);
      if (p) {
        try {
          await p.compensate(this.result?.txId ?? pid);
        } catch {
          /* best-effort compensation */
        }
      }
    }
    await this.runAppUndos();
  }

  get isFinished(): boolean {
    return this.finished;
  }

  private assertOpen(action: string): void {
    if (this.finished) {
      throw new Error(`Transaction already finished; cannot ${action}.`);
    }
  }
}