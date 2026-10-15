// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * VrcReceiveParticipant — agent-side participant that receives a peer's VRC
 * (the "reflection" direction of the VRC ceremony) and persists it to the
 * agent's local SQLite credentials table.
 *
 * Handles:
 *   - 'store_remote_vrc' — stores the W3C VC JSON received from the remote peer
 *
 * This mirrors VtcReceiveParticipant but for VRC replication instead of
 * VTC community data. It is registered with the agent's transaction coordinator
 * so that inbound tx_prepare messages carrying this operation are routed here.
 *
 * pid: 'peer:{agentDid}' — identifies this agent as a participant.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type {
  Operation,
  Outcome,
  Participant,
  Vote,
} from '@p2p-trust-stack/core/tx/types.js';
import type { IdentityResolver } from '@p2p-trust-stack/core/services/identity-resolver.js';
import type { VtcStore } from '@p2p-trust-stack/core/vtc/store.js';
import { VrcCeremonyStore } from '@p2p-trust-stack/core/tx/vrc-ceremony-store.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';

export interface StoreRemoteVrcParams {
  w3cVcJson: string;
  issuerDid: string;
  subjectDid: string;
  /** Sender's VID, used to key the mirrored ceremony session consistently. */
  issuerVid?: string;
  /**
   * The sender's full identity record, shared so the receiver can populate its
   * local `identities` table (login name, role, subject kind, public keys, …).
   * The receiver re-derives the row key (deterministic UUIDv5 of the real DID)
   * and stores the record with custody='remote'.
   */
  issuerIdentity?: Record<string, unknown>;
}

export class VrcReceiveParticipant implements Participant {
  readonly pid: string;
  private readonly txDb: DataSource;
  private readonly vtcStore: VtcStore;
  private readonly ceremonyStore: VrcCeremonyStore;

  constructor(
    pid: string,
    _appDb: DataSource,
    txDb: DataSource,
    vtcStore: VtcStore,
    _resolver: IdentityResolver,
  ) {
    this.pid = pid;
    this.txDb = txDb;
    this.vtcStore = vtcStore;
    // The ceremony saga lives in the same tx-coordinator db as participant state.
    this.ceremonyStore = new VrcCeremonyStore(txDb);
  }

  handlesOperation(op: Operation): boolean {
    return op.op === 'store_remote_vrc';
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    for (const op of operations) {
      if (op.op !== 'store_remote_vrc') continue;

      const params = op.params as unknown as StoreRemoteVrcParams;
      if (!params?.w3cVcJson) return 'no';

      try {
        // Store the remote peer's VRC in the local credentials table.
        // storeReceivedDtgVrc is idempotent: digest-based dedup.
        this.vtcStore.storeReceivedDtgVrc(
          params.w3cVcJson,
          params.issuerDid,
          params.subjectDid,
          params.issuerIdentity,
        );

        // Advance the mirrored ceremony session: the remote agent's VRC for us
        // has now been received. Ceremony sessions are keyed by real DIDs
        // (local_did = subjectDid, remote_did = issuerDid), so both mirrors
        // reference the same (local,remote) DID pair and peer_vrc_received
        // lands on the session the driver is advancing.
        if (params.subjectDid && params.issuerDid) {
          const session = await this.ceremonyStore.ensureSession(params.subjectDid, params.issuerDid);
          await this.ceremonyStore.setLeg(session.sessionId, { peerVrcReceived: true });
        }

        logger.info(
          `[vrc-receive] stored remote VRC from ${params.issuerDid.slice(0, 12)}...`,
        );
      } catch (err) {
        logger.error(`[vrc-receive] prepare failed for tx ${txId}:`, (err as Error)?.message);
        return 'no';
      }
    }

    // Durably record 'prepared' BEFORE voting yes.
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
    logger.info(`[vrc-receive] ${txId.slice(0, 8)} committed`);
  }

  async abort(txId: string): Promise<void> {
    // storeReceivedDtgVrc is idempotent (digest dedup), so a precise rollback
    // would delete by credential digest. For now, mark aborted and rely on the
    // next push/election to reconcile state.
    await this.txDb.run(
      "UPDATE tx_participant_state SET outcome = 'aborted' WHERE tx_id = ? AND pid = ?",
      txId, this.pid,
    );
    logger.info(`[vrc-receive] ${txId.slice(0, 8)} aborted`);
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
