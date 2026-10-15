// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * GovernanceProposalReceiveParticipant — agent-side participant that persists a
 * governance-change proposal pushed from the utility server over the durable
 * `exchange:governance-proposal` fan-out.
 *
 * Handles the operation type:
 *   - 'exchange:governance-proposal' — the pending proposal (queued by the server's
 *     CRE fan-out, one durable row per required approver). The proposal is IMMUTABLE
 *     (its content is committed to by `proposalHash`), so the local copy is a faithful
 *     mirror used for display + offline visibility; crystallization is driven by the
 *     server.
 *
 * pid: 'peer:{agentDid}' — identifies this agent as a participant.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { Operation, Outcome, Participant, Vote } from '@p2p-trust-stack/core/tx/types.js';
import { GovernanceChangeStore } from '@p2p-trust-stack/core/tx/governance-change-store.js';
import type { ApprovalScope, GovernanceChange } from '@p2p-trust-stack/core/services/governance-change.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';

/** Shape pushed by the server's `governance-proposal` materializer. */
export interface GovernanceProposalPushData {
  proposalId: string;
  communityUuid: string;
  communityDid: string;
  proposalHash: string;
  scope: ApprovalScope;
  requiredApproverCount: number;
  change: GovernanceChange;
  expiresAt: number;
}

/**
 * A proposal this agent just mirrored, announced to an observer.
 *
 * Carries no `status`: the pushed proposal is IMMUTABLE and arrives pending. Its later state changes happen on
 * the server and reach the agent as a `governance` push, not as another proposal.
 */
export interface PersistedProposalEvent {
  proposalId: string;
  communityUuid: string;
}

export class GovernanceProposalReceiveParticipant implements Participant {
  readonly pid: string;
  private readonly txDb: DataSource;
  private readonly store: GovernanceChangeStore;
  /**
   * Called after a proposal is mirrored into the agent's local store.
   *
   * This participant is the ONLY thing that observes a proposal arriving — nothing else watches the store — so
   * without this hook the Rules page can only discover one by polling. Not called on a re-delivery of a
   * proposal we already hold: the proposal is immutable, so that is not a new arrival.
   */
  private readonly onPersisted?: (proposal: PersistedProposalEvent) => void;

  constructor(
    pid: string,
    _appDb: DataSource,
    txDb: DataSource,
    onPersisted?: (proposal: PersistedProposalEvent) => void,
  ) {
    this.pid = pid;
    this.txDb = txDb;
    this.store = new GovernanceChangeStore(txDb);
    this.onPersisted = onPersisted;
  }

  handlesOperation(op: Operation): boolean {
    return op.op === 'exchange:governance-proposal';
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    const mirrored: PersistedProposalEvent[] = [];

    for (const op of operations) {
      if (op.op !== 'exchange:governance-proposal') continue;
      const p = op.params as unknown as GovernanceProposalPushData;
      if (!p?.proposalId || !p?.proposalHash || !p?.communityUuid) return 'no';
      await this.store.mirrorProposal({
        proposalId: p.proposalId,
        communityUuid: p.communityUuid,
        communityDid: p.communityDid,
        proposalHash: p.proposalHash,
        scope: p.scope,
        requiredApproverCount: p.requiredApproverCount,
        change: p.change,
        expiresAt: p.expiresAt,
      });
      logger.info(`[gov-proposal-receive] mirrored proposal ${p.proposalId.slice(0, 8)} for community ${p.communityUuid.slice(0, 8)}`);
      mirrored.push({ proposalId: p.proposalId, communityUuid: p.communityUuid });
    }

    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome)
       VALUES (?, ?, 'prepared')`, txId, this.pid,
    );

    // Announce the arrivals. Guarded on purpose: `prepare()` votes 'no' on any throw, so an observer that threw
    // would ABORT a transaction whose proposal has already been mirrored — turning a successful delivery into a
    // refusal. The announcement is a side effect and must never decide the 2PC outcome.
    for (const event of mirrored) {
      try {
        this.onPersisted?.(event);
      } catch (err) {
        logger.warn(`[gov-proposal-receive] arrival observer failed: ${(err as Error)?.message ?? err}`);
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
