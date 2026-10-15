// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * VrcCeremonyParticipant — local InProcessParticipant for the VRC personhood
 * ceremony completion phase (VRC minting + identity push within a 2PC transaction).
 *
 * Handles operations:
 *   - 'mint_vrc'  — calls mintPeerVrc() to write VRC to local credentials table
 *   - 'push_vrc'  — validates push data for the utility server RemoteParticipant
 *
 * pid: 'peer:{agentDid}' — identifies this as an agent-side participant.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type {
  Operation,
  Outcome,
  Participant,
  UndoDescriptor,
  Vote,
} from '@p2p-trust-stack/core/tx/types.js';
import { mintPeerVrc } from '@p2p-trust-stack/core/relationship/vrc-mint.js';
import { driveCeremony } from '@p2p-trust-stack/core/services/trust-tasks/driver.js';
import { registerExecutor } from '@p2p-trust-stack/core/services/trust-tasks/catalog.js';
import { CEREMONY_VRC_PERSONHOOD, RELATIONSHIP_VRC_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/type-uris.js';
import type { IdentityResolver } from '@p2p-trust-stack/core/services/identity-resolver.js';
import type { LocalIdentity, RelationshipRecord } from '@p2p-trust-stack/core/relationship/types.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';

export interface MintVrcOpParams {
  record: RelationshipRecord;
}

export interface PushVrcOpParams {
  w3cVcJson: string;
  remoteDid: string;
  credentials: Array<{
    uuid: string;
    vcType: string;
    issuerIdentityUuid: string;
    subjectIdentityUuid: string;
    w3cVcJson: string | null;
    claim: string | null;
    status: string;
    thresholdRequired: number | null;
    validFrom: number;
    validUntil: number | null;
    credentialDigest: string | null;
    createdAt: number | null;
  }>;
  credentialSignatures: Array<{
    credentialUuid: string;
    signerIdentityUuid: string;
    signature: string;
    signedAt: number | null;
  }>;
  identityPushPayload?: Record<string, unknown>;
}

// ── Registry: the vrc-personhood ceremony's effect executor ──────────────────
// `vrc-personhood` (migration 0020) is effect-only — its gate is the mutual
// personhood ack ("I know this person" on both sides), not a community policy, so
// there is no `policy` step. The executor performs the actual peer-VRC mint; the
// agent drives the ceremony from `prepare` below.
registerExecutor(RELATIONSHIP_VRC_TYPE, async (context) => {
  const record = context.record as RelationshipRecord;
  const result = await mintPeerVrc({
    dataSource: context.dataSource as DataSource,
    resolver: context.resolver as IdentityResolver,
    identity: context.identity as LocalIdentity,
    record,
  });
  // The response's recipient is the remote peer the relationship is with.
  return { ...result, recipientDid: record.remoteDid };
});

export class VrcCeremonyParticipant implements Participant {
  readonly pid: string;
  private readonly appDb: DataSource;
  private readonly txDb: DataSource;
  private readonly resolver: IdentityResolver;
  private identity: LocalIdentity | undefined;

  constructor(
    pid: string,
    appDb: DataSource,
    txDb: DataSource,
    resolver: IdentityResolver,
  ) {
    this.pid = pid;
    this.appDb = appDb;
    this.txDb = txDb;
    this.resolver = resolver;
  }

  setIdentity(identity: LocalIdentity): void {
    this.identity = identity;
  }

  handlesOperation(op: Operation): boolean {
    return op.op === 'mint_vrc' || op.op === 'push_vrc';
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    const undos: UndoDescriptor[] = [];

    for (const op of operations) {
      try {
        if (op.op === 'mint_vrc') {
          const params = op.params as unknown as MintVrcOpParams;
          if (!params?.record) return 'no';
          if (!this.identity) return 'no';

          // Drive the `vrc-personhood` trust-task ceremony rather than minting
          // directly: the effect step performs the mint and every step is recorded
          // to `trust_tasks` under this transaction's id (the ceremony threadId).
          const driven = await driveCeremony(this.appDb, CEREMONY_VRC_PERSONHOOD, txId, {
            context: {
              dataSource: this.appDb,
              resolver: this.resolver,
              identity: this.identity,
              record: params.record,
            },
          });
          const result = (driven.outputs[RELATIONSHIP_VRC_TYPE] ?? {}) as {
            success?: boolean;
            w3cVcJson?: string;
            remoteDid?: string;
          };

          if (!driven.completed || !result.success) {
            logger.warn('[vrc-ceremony] mint_vrc failed');
            return 'no';
          }

          // The local VRC is durable by design. A later delivery-leg failure
          // must NOT roll the mint back — the ceremony retries those legs and
          // the DTG output must persist. We therefore record NO destructive
          // undo for a successful mint.
          logger.info(
            `[vrc-ceremony] mint_vrc succeeded for ${params.record.remoteDid.slice(0, 12)}... ` +
            `(w3c_vc_json=${result.w3cVcJson?.length ?? 0}B)`,
          );
        }

        if (op.op === 'push_vrc') {
          const params = op.params as unknown as PushVrcOpParams;
          if (!params) return 'no';
          // Validation only — actual push is via RemoteParticipant → utility server.
          logger.info(`[vrc-ceremony] push_vrc prepared: ${params.credentials.length} creds`);

          undos.push({
            type: 'push_vrc_compensation_note',
            remoteDid: params.remoteDid,
          });
        }
      } catch (err) {
        logger.error(`[vrc-ceremony] prepare failed for ${txId.slice(0, 8)}, op ${op.op}:`, (err as Error)?.message);
        for (let i = undos.length - 1; i >= 0; i--) {
          await this.replayUndo(undos[i]);
        }
        return 'no';
      }
    }

    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome, undo_hooks)
       VALUES (?, ?, 'prepared', ?)`,
      txId, this.pid, JSON.stringify(undos),
    );

    logger.info(`[vrc-ceremony] ${txId.slice(0, 8)} prepared (${operations.length} op(s), ${undos.length} undo(s))`);
    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    await this.txDb.run(
      'UPDATE tx_participant_state SET outcome = ? WHERE tx_id = ? AND pid = ?',
      'committed', txId, this.pid,
    );
    logger.info(`[vrc-ceremony] ${txId.slice(0, 8)} committed`);
  }

  async abort(txId: string): Promise<void> {
    const row = await this.txDb.get<{ undo_hooks: string | null }>(
      'SELECT undo_hooks FROM tx_participant_state WHERE tx_id = ? AND pid = ?',
      txId, this.pid,
    );

    if (row?.undo_hooks) {
      try {
        const undos: UndoDescriptor[] = JSON.parse(row.undo_hooks);
        for (let i = undos.length - 1; i >= 0; i--) {
          await this.replayUndo(undos[i]);
        }
      } catch (err) {
        logger.error(`[vrc-ceremony] abort undo error: ${(err as Error)?.message}`);
      }
    }

    await this.txDb.run(
      'UPDATE tx_participant_state SET outcome = ? WHERE tx_id = ? AND pid = ?',
      'aborted', txId, this.pid,
    );
    logger.info(`[vrc-ceremony] ${txId.slice(0, 8)} aborted`);
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

  private async replayUndo(desc: UndoDescriptor): Promise<void> {
    if (desc.type !== 'delete_minted_vrc') return;
    const localDid = desc.localDid as string;
    const remoteDid = desc.remoteDid as string;

    const local = this.resolver.lookupByDid(localDid);
    const remote = this.resolver.lookupByDid(remoteDid);
    if (!local || !remote) return;

    const credRow = await this.appDb.get<{ uuid: string }>(
      `SELECT uuid FROM credentials
       WHERE issuer_identity_uuid = ? AND subject_identity_uuid = ?
       AND vc_type = 'vrc'
       ORDER BY created_at DESC LIMIT 1`,
      local.identityUuid, remote.identityUuid,
    );

    if (credRow) {
      await this.appDb.run('DELETE FROM credential_signatures WHERE credential_uuid = ?', credRow.uuid);
      await this.appDb.run('DELETE FROM credentials WHERE uuid = ?', credRow.uuid);
      logger.info(`[vrc-ceremony] undo: deleted VRC for ${remoteDid.slice(0, 12)}...`);
    }
  }
}
