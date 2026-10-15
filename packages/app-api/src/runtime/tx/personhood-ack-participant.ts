// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * PersonhoodAckReceiveParticipant — agent-side participant that receives a
 * peer's personhood acknowledgment ("I know this person") for a ceremony and
 * mirrors it onto the LOCAL ceremony session.
 *
 * Handles:
 *   - 'personhood_ack' — the remote agent confirmed it knows the local user
 *
 * This is the receiving half of the ceremony's `ack_delivery` leg. That leg is a
 * coordinator transaction precisely so an ack cannot be lost silently: this
 * participant writes the flag before voting, so the SENDER learns whether the
 * peer was actually told (`ack_sent_to_peer`) instead of hoping a raw message
 * arrived.
 *
 * Idempotent: a re-prepared transaction (retry after a lost commit) re-runs
 * `ensureSession` + `setRemoteAcked`, both no-ops when the state is already
 * recorded, so the participant keeps voting 'yes'.
 *
 * pid: 'peer:{agentDid}' — identifies this agent as a participant. Several local
 * participants share that pid; the coordinator disambiguates by
 * `handlesOperation`.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type {
  Operation,
  Outcome,
  Participant,
  Vote,
} from '@p2p-trust-stack/core/tx/types.js';
import { VrcCeremonyStore } from '@p2p-trust-stack/core/tx/vrc-ceremony-store.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';

/** Parameters carried by the `personhood_ack` operation. */
export interface PersonhoodAckOpParams {
  /** DID of the acknowledging party (the SENDER of the ack). */
  fromDid?: string;
  /** Sender DID again — same value, kept for wire symmetry with the VRC op. */
  remoteDid?: string;
}

export class PersonhoodAckReceiveParticipant implements Participant {
  readonly pid: string;
  private readonly txDb: DataSource;
  private readonly localDid: string;
  private readonly ceremonyStore: VrcCeremonyStore;
  private readonly onAck?: (remoteDid: string) => void;
  /** txId -> sender DID, so commit/abort can act on the right pair. */
  private readonly pendingAcks = new Map<string, string>();

  constructor(
    pid: string,
    txDb: DataSource,
    localDid: string,
    onAck?: (remoteDid: string) => void,
  ) {
    this.pid = pid;
    this.txDb = txDb;
    this.localDid = localDid;
    // The ceremony saga lives in the same tx-coordinator db as participant state.
    this.ceremonyStore = new VrcCeremonyStore(txDb);
    this.onAck = onAck;
  }

  handlesOperation(op: Operation): boolean {
    return op.op === 'personhood_ack';
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    let ackedFrom: string | undefined;

    for (const op of operations) {
      if (op.op !== 'personhood_ack') continue;
      const params = op.params as unknown as PersonhoodAckOpParams;
      const remoteDid = params?.fromDid ?? params?.remoteDid;
      if (!remoteDid) {
        logger.warn(`[personhood-ack] prepare rejected for tx ${txId.slice(0, 8)}: no sender DID`);
        return 'no';
      }
      try {
        // Mirror onto OUR session for the pair (local = me, remote = sender) —
        // the same pair key the ceremony driver advances on this agent.
        const session = await this.ceremonyStore.ensureSession(this.localDid, remoteDid);
        await this.ceremonyStore.setRemoteAcked(session.sessionId);
        ackedFrom = remoteDid;
        logger.info(`[personhood-ack] recorded personhood ack from ${remoteDid.slice(0, 12)}...`);
      } catch (err) {
        logger.error(`[personhood-ack] prepare failed for tx ${txId.slice(0, 8)}:`, (err as Error)?.message);
        return 'no';
      }
    }

    if (ackedFrom) this.pendingAcks.set(txId, ackedFrom);

    // Durably record 'prepared' BEFORE voting yes — the same contract every
    // participant in this layer honours, so an inquiry can answer after a crash.
    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome)
       VALUES (?, ?, 'prepared')`,
      txId, this.pid,
    );

    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    await this.txDb.run(
      "UPDATE tx_participant_state SET outcome = 'committed' WHERE tx_id = ? AND pid = ?",
      txId, this.pid,
    );
    const remoteDid = this.pendingAcks.get(txId);
    this.pendingAcks.delete(txId);
    logger.info(`[personhood-ack] ${txId.slice(0, 8)} committed`);
    // Durably committed → tell the UI layer (prompt the local user if they have
    // not pressed yet, and push the change to the browser).
    if (remoteDid && this.onAck) {
      try {
        this.onAck(remoteDid);
      } catch (err) {
        logger.error('[personhood-ack] onAck handler error:', (err as Error)?.message ?? err);
      }
    }
  }

  async abort(txId: string): Promise<void> {
    const remoteDid = this.pendingAcks.get(txId);
    this.pendingAcks.delete(txId);

    // The sender's leg did NOT commit, so the ack is not delivered: retract the
    // flag so nothing downstream treats it as confirmed. The sender retries the
    // leg and re-delivers (this participant is idempotent).
    if (remoteDid) {
      try {
        const session = await this.ceremonyStore.getByPair(this.localDid, remoteDid);
        if (session) await this.ceremonyStore.clearRemoteAcked(session.sessionId);
      } catch (err) {
        logger.error(`[personhood-ack] abort retract failed for tx ${txId.slice(0, 8)}:`, (err as Error)?.message);
      }
    }

    await this.txDb.run(
      "UPDATE tx_participant_state SET outcome = 'aborted' WHERE tx_id = ? AND pid = ?",
      txId, this.pid,
    );
    logger.info(`[personhood-ack] ${txId.slice(0, 8)} aborted`);
  }

  async compensate(txId: string): Promise<void> {
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.txDb.get<{ outcome: string }>(
      'SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?',
      txId, this.pid,
    );
    return (row?.outcome as Outcome) ?? 'unknown';
  }
}
