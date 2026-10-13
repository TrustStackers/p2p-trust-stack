/**
 * Transaction Log Janitor — TTL-based pruning of expired entries.
 *
 * Runs on a configurable interval, deleting log entries, outbox entries,
 * inbox entries, and participant state that have exceeded their retention
 * windows. This prevents unbounded growth of the coordinator SQLite database,
 * which is especially important on mobile agents with limited storage.
 *
 * Retention policy (configurable):
 *   - Completed/aborted transactions: 7 days
 *   - Incomplete (in-flight) transactions: 30 days
 */

import type { DataSource } from '../db/data-source.js';
import {
  JANITOR_PRUNE_COMPLETED_SQL,
  JANITOR_PRUNE_INCOMPLETE_SQL,
  JANITOR_PRUNE_OUTBOX_SQL,
  JANITOR_PRUNE_INBOX_SQL,
  JANITOR_PRUNE_PARTICIPANT_STATE_SQL,
  JANITOR_PRUNE_VRC_CEREMONIES_SQL,
} from './schema.js';
import { DEFAULT_JANITOR_CONFIG, type JanitorConfig } from './types.js';

export class TxJanitor {
  private readonly ds: DataSource;
  private readonly config: JanitorConfig;
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(ds: DataSource, config?: Partial<JanitorConfig>) {
    this.ds = ds;
    this.config = { ...DEFAULT_JANITOR_CONFIG, ...config };
  }

  /** Start the background pruning loop. */
  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.prune().catch((err) => {
        console.error('[tx-janitor] prune error:', (err as Error)?.message ?? err);
      });
    }, this.config.intervalMs);
    // Allow the first interval to be unref'd so it doesn't keep the process alive.
    if (this.timer && typeof this.timer.unref === 'function') {
      this.timer.unref();
    }
  }

  /** Stop the background pruning loop. */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /** Run one pruning pass immediately. Returns counts of deleted rows per table. */
  async prune(): Promise<{
    txLogCompleted: number;
    txLogIncomplete: number;
    outbox: number;
    inbox: number;
    participantState: number;
    vrcCeremonies: number;
  }> {
    const now = Date.now();
    const completedCutoff = now - this.config.completedTtlMs;
    const incompleteCutoff = now - this.config.incompleteTtlMs;

    const [txLogCompleted, txLogIncomplete, outbox, inbox, participantState, vrcCeremonies] =
      await Promise.all([
        this.ds.run(JANITOR_PRUNE_COMPLETED_SQL, completedCutoff),
        this.ds.run(JANITOR_PRUNE_INCOMPLETE_SQL, incompleteCutoff),
        this.ds.run(JANITOR_PRUNE_OUTBOX_SQL, completedCutoff),
        this.ds.run(JANITOR_PRUNE_INBOX_SQL, completedCutoff),
        this.ds.run(JANITOR_PRUNE_PARTICIPANT_STATE_SQL, completedCutoff),
        this.ds.run(JANITOR_PRUNE_VRC_CEREMONIES_SQL, completedCutoff),
      ]);

    const result = {
      txLogCompleted: txLogCompleted.changes,
      txLogIncomplete: txLogIncomplete.changes,
      outbox: outbox.changes,
      inbox: inbox.changes,
      participantState: participantState.changes,
      vrcCeremonies: vrcCeremonies.changes,
    };

    const total = result.txLogCompleted + result.txLogIncomplete + result.outbox + result.inbox + result.participantState + result.vrcCeremonies;
    if (total > 0) {
      console.log(`[tx-janitor] pruned ${total} expired row(s): log=${result.txLogCompleted + result.txLogIncomplete} outbox=${result.outbox} inbox=${result.inbox} participant=${result.participantState} vrc=${result.vrcCeremonies}`);
    }

    return result;
  }
}