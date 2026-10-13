/**
 * TransactionManager — the application-facing boundary (Layer 4 API).
 *
 * Exposes BOTH forms described in the design:
 *   (a) explicit begin/commit/abort
 *   (b) scope-based run() with nesting
 *
 * Applications program to this instead of calling the coordinator directly.
 *
 * Adapted from reference-tx/manager.ts.
 */

import { Transaction } from './transaction.js';
import { TransactionCoordinator } from './coordinator.js';
import { CompensationExecutor } from './compensation.js';
import type { Participant, StatusEvent, TransactionResult } from './types.js';

export class TransactionManager {
  private readonly coordinator: TransactionCoordinator;
  private readonly compensation: CompensationExecutor;
  private readonly localParticipant: Participant | undefined;

  constructor(
    coordinator: TransactionCoordinator,
    compensation: CompensationExecutor,
    localParticipant?: Participant,
  ) {
    this.coordinator = coordinator;
    this.compensation = compensation;
    this.localParticipant = localParticipant;
  }

  /** (a) explicit form — returns an open transaction for enlist/commit/abort. */
  begin(): Transaction {
    return new Transaction({
      coordinator: this.coordinator,
      compensation: this.compensation,
      localParticipant: this.localParticipant,
    });
  }

  /**
   * (b) scope-based form. Runs `fn(tx)` and commits on success; aborts (and
   * propagates) on error. Nested transactions use `tx.run(...)`.
   */
  async run(fn: (tx: Transaction) => Promise<void>): Promise<TransactionResult> {
    const tx = this.begin();
    try {
      await fn(tx);
      return await tx.commit();
    } catch (err) {
      console.error(`[tx-manager] transaction failed: ${(err as Error)?.message ?? err}`);
      await tx.abort();
      throw err;
    }
  }

  /** Register a participant with the underlying coordinator. */
  registerParticipant(p: Participant): void {
    this.coordinator.registerParticipant(p);
  }

  /** Unregister a participant. */
  unregisterParticipant(pid: string): void {
    this.coordinator.unregisterParticipant(pid);
  }

  /** Register a compensation handler for undo descriptor replay. */
  registerCompensationHandler(handler: { type: string; execute: (desc: any) => Promise<void> }): void {
    this.compensation.register(handler);
  }

  /** Subscribe to status/progress events (monitorable). */
  onStatus(listener: (event: StatusEvent) => void): void {
    this.coordinator.onStatus(listener);
  }

  /** Unsubscribe from status events. */
  offStatus(listener: (event: StatusEvent) => void): void {
    this.coordinator.offStatus(listener);
  }

  /** Recover interrupted transactions (coordinator durable decision). */
  recover(): Promise<TransactionResult[]> {
    return this.coordinator.recover();
  }
}