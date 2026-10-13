/**
 * CeremonyEventReceiveParticipant — agent-side participant for the server's ceremony-PROGRESS nudge
 * (`exchange:ceremony-event`).
 *
 * ## Why this persists nothing
 *
 * The nudge carries no content: `{ threadId, step, communityUuid }`. The agent re-reads `/api/ceremony-log` for
 * the log it renders, so this participant's whole job is to say "something moved". That keeps the durable queue
 * row tiny and avoids shipping a second copy of the log to every admin.
 *
 * ## Why it must exist even though it does nothing
 *
 * The coordinator votes **`'no'`** when no participant claims an operation
 * (`src/tx/coordinator.ts` → `findParticipantForOperations` returns undefined). Without this class the
 * delivery transaction would be refused outright, so "it persists nothing" is not a reason to omit it.
 *
 * ## What it replaces
 *
 * Nothing announced a co-signature. `vtc-membership` fires only on CRYSTALLIZATION (the community does not
 * exist before then), so while a founding was collecting co-signatures an admin watching it could only find out
 * by asking — which is why `communities.html` polled the ceremony log every 4 s.
 *
 * pid: 'peer:{agentDid}' — identifies this agent as a participant.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { Operation, Outcome, Participant, Vote } from '@p2p-trust-stack/core/tx/types.js';

/** Shape pushed by the server's `ceremony-event` materializer. */
export interface CeremonyEventPushData {
  threadId: string;
  /** A coarse marker of WHICH step landed, e.g. `co-sign:1`. Used for the durable idempotency key. */
  step: string | null;
  /** Null until the ceremony has crystallized — the community does not exist before then. */
  communityUuid: string | null;
  at: number | null;
}

/** A ceremony step this agent was told about. */
export interface PersistedCeremonyEvent {
  threadId: string;
  step: string | null;
  communityUuid: string | null;
}

export class CeremonyEventReceiveParticipant implements Participant {
  readonly pid: string;
  private readonly txDb: DataSource;
  /**
   * Called when a ceremony nudge arrives.
   *
   * This participant is the ONLY thing that observes a co-signature landing — nothing else watches for it — so
   * without this hook an observer can only discover progress by polling.
   */
  private readonly onPersisted?: (event: PersistedCeremonyEvent) => void;

  constructor(
    pid: string,
    _appDb: DataSource,
    txDb: DataSource,
    onPersisted?: (event: PersistedCeremonyEvent) => void,
  ) {
    this.pid = pid;
    this.txDb = txDb;
    this.onPersisted = onPersisted;
  }

  handlesOperation(op: Operation): boolean {
    return op.op === 'exchange:ceremony-event';
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    const nudges: PersistedCeremonyEvent[] = [];

    for (const op of operations) {
      if (op.op !== 'exchange:ceremony-event') continue;
      const p = op.params as unknown as CeremonyEventPushData;
      // A nudge without a thread cannot be acted on — refuse rather than vote yes on nothing.
      if (!p?.threadId) return 'no';
      nudges.push({ threadId: p.threadId, step: p.step ?? null, communityUuid: p.communityUuid ?? null });
    }

    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome)
       VALUES (?, ?, 'prepared')`, txId, this.pid,
    );

    // Announce. Guarded on purpose: `prepare()` votes 'no' on any throw, so an observer that threw would ABORT
    // a transaction that has already been accepted — turning a successful nudge into a refusal. The
    // announcement is a side effect and must never decide the 2PC outcome.
    for (const nudge of nudges) {
      try {
        this.onPersisted?.(nudge);
      } catch (err) {
        console.warn(`[ceremony-event-receive] observer failed: ${(err as Error)?.message ?? err}`);
      }
    }

    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'committed' WHERE tx_id = ? AND pid = ?`, txId, this.pid);
  }

  async abort(txId: string): Promise<void> {
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'aborted' WHERE tx_id = ? AND pid = ?`, txId, this.pid);
  }

  async compensate(txId: string): Promise<void> {
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.txDb.get<{ outcome: string }>(
      'SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?', txId, this.pid);
    return (row?.outcome as Outcome) ?? 'unknown';
  }
}
