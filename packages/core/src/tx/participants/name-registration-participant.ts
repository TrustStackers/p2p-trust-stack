// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Agent Name Registration Participant — shared-core agent-side participant
 * for name registration via the TransactionCoordinator.
 *
 * When the coordinator calls prepare(), this participant:
 *   1. Validates the speculative rotation entry params
 *   2. Records outcome='prepared' in tx_participant_state
 *   3. Votes 'yes' (the rotation entry is NOT written to the log yet)
 *
 * On commit():
 *   1. Finalizes the rotation entry (writes to rotation log store)
 *   2. Updates the agent's in-memory identity via onFinalize callback
 *   3. Caches the name in the local name_registry table
 *   4. Marks outcome='committed'
 *
 * On abort():
 *   1. Discards the speculative rotation entry (no-op, it was never persisted)
 *   2. Marks outcome='aborted'
 *
 * This is the agent-side counterpart to the utility server's
 * NameRegistryParticipant. Together they form a transaction-coordinated
 * ceremony for name registration.
 */

import type { DataSource } from '../../db/data-source.js';
import type {
  Operation,
  Outcome,
  Participant,
  Vote,
} from '../types.js';
import type { RotationLogEntry } from '../../did/rotation-types.js';
import type { DidDocument } from '../../did/types.js';
import { generateUuid } from '../../db/uuid-helpers.js';

/**
 * Shape of the finalize_rotation operation params.
 * These are computed by the SpeculativeRotationService before the transaction
 * begins, and passed to this participant for finalization on commit.
 */
export interface FinalizeRotationParams {
  /** The pre-computed rotation entry (with name in alsoKnownAs, signed). */
  rotationEntry: RotationLogEntry;
  /** The new DID document (with name in alsoKnownAs). */
  didDocument: DidDocument;
  /** The name being registered. */
  name: string;
  /** The namespace for the name. */
  namespace: string;
  /** The agent's DID. */
  did: string;
  /** The rotation entry digest (for proof_reference in name_registry). */
  rotationDigest?: Uint8Array;
}

/**
 * Minimal abstraction for writing rotation entries to the log store.
 * The actual implementation delegates to RotationLogStore from src/did/.
 */
export interface RotationLogStore {
  appendEntry(did: string, entry: RotationLogEntry): Promise<void> | void;
}

/**
 * Agent-side participant for name registration.
 *
 * pid: 'local-db' — identifies this as a local (in-process) participant.
 */
export class AgentNameRegistrationParticipant implements Participant {
  readonly pid = 'local-db';
  private readonly appDb: DataSource;   // Agent's local SQLite (agent-database.db)
  private readonly txDb: DataSource;    // SQLite (tx-coordinator.db)
  private readonly rotationStore: RotationLogStore;
  private readonly onFinalize: (params: FinalizeRotationParams) => Promise<void>;

  /**
   * @param appDb           Agent's local SQLite database
   * @param txDb            Transaction coordinator SQLite database
   * @param rotationStore   Abstraction for writing to the rotation log
   * @param onFinalize      Callback to update the agent's in-memory identity
   *                        (DID document, etc.) after the rotation is finalized
   */
  constructor(
    appDb: DataSource,
    txDb: DataSource,
    rotationStore: RotationLogStore,
    onFinalize: (params: FinalizeRotationParams) => Promise<void>,
  ) {
    this.appDb = appDb;
    this.txDb = txDb;
    this.rotationStore = rotationStore;
    this.onFinalize = onFinalize;
  }

  handlesOperation(op: Operation): boolean {
    return op.op === 'finalize_rotation';
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    for (const op of operations) {
      if (op.op !== 'finalize_rotation') continue;

      const params = op.params as unknown as FinalizeRotationParams;
      if (!params || !params.rotationEntry || !params.didDocument) {
        console.log(`[agent-name-participant] prepare: missing required params`);
        return 'no';
      }

      // Validate the rotation entry has the expected structure
      const entry = params.rotationEntry;
      if (!entry.digest || !entry.signature || !entry.didDocument) {
        console.log(`[agent-name-participant] prepare: rotation entry missing digest/signature/document`);
        return 'no';
      }

      // Verify the name is in the DID document's alsoKnownAs
      const nameUri = `vta:${params.namespace}:${params.name}`;
      const alsoKnownAs = entry.didDocument.alsoKnownAs ?? [];
      if (!alsoKnownAs.includes(nameUri)) {
        console.log(
          `[agent-name-participant] prepare: name '${nameUri}' not found in ` +
          `rotation entry's alsoKnownAs`,
        );
        return 'no';
      }

      console.log(
        `[agent-name-participant] prepare: rotation entry valid ` +
        `(version ${entry.version}, name '${nameUri}' in alsoKnownAs)`,
      );
    }

    // Durably record 'prepared' BEFORE stashing params.
    // The INSERT must happen first so the UPDATE in storeParams has a row to update.
    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome)
       VALUES (?, ?, 'prepared')`,
      txId,
      this.pid,
    );

    // Stash the operation params in undo_hooks so commit() can retrieve them.
    for (const op of operations) {
      if (op.op !== 'finalize_rotation') continue;
      const params = op.params as unknown as FinalizeRotationParams;
      if (params) {
        await this.storeParams(txId, params);
      }
    }

    console.log(`[agent-name-participant] ${txId.slice(0, 8)} prepared → voting yes`);
    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    // Retrieve the params from the participant state.
    // They were stashed in undo_hooks during the transaction setup.
    const stateRow = await this.txDb.get<{ undo_hooks: string | null }>(
      `SELECT undo_hooks FROM tx_participant_state WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );

    let params: FinalizeRotationParams | null = null;
    if (stateRow?.undo_hooks) {
      try {
        params = JSON.parse(stateRow.undo_hooks) as FinalizeRotationParams;
        // Restore Uint8Array fields that were serialized as arrays
        if (params.rotationEntry.digest && Array.isArray(params.rotationEntry.digest)) {
          (params.rotationEntry as any).digest = new Uint8Array(params.rotationEntry.digest as any);
        }
        if (params.rotationEntry.signature && Array.isArray(params.rotationEntry.signature)) {
          (params.rotationEntry as any).signature = new Uint8Array(params.rotationEntry.signature as any);
        }
        if (params.rotationEntry.prevHash && Array.isArray(params.rotationEntry.prevHash)) {
          (params.rotationEntry as any).prevHash = new Uint8Array(params.rotationEntry.prevHash as any);
        }
        if (params.rotationEntry.nextKeyCommitments && Array.isArray(params.rotationEntry.nextKeyCommitments)) {
          (params.rotationEntry as any).nextKeyCommitments = (params.rotationEntry.nextKeyCommitments as unknown as number[][]).map(
            (k) => new Uint8Array(k),
          );
        }
        if (params.rotationDigest && Array.isArray(params.rotationDigest)) {
          params.rotationDigest = new Uint8Array(params.rotationDigest as any);
        }
      } catch (err) {
        console.error(
          `[agent-name-participant] commit: failed to parse params: ` +
          `${(err as Error).message}`,
        );
      }
    }

    if (!params) {
      console.log(
        `[agent-name-participant] commit: no params found for tx ${txId} — ` +
        `skipping finalization`,
      );
      await this.txDb.run(
        `UPDATE tx_participant_state SET outcome = 'committed'
         WHERE tx_id = ? AND pid = ?`,
        txId,
        this.pid,
      );
      return;
    }

    try {
      console.log(
        `[agent-name-participant] commit: finalizing rotation entry ` +
        `(version ${params.rotationEntry.version})`,
      );

      // 1. Write the rotation entry to the rotation log store.
      //    This is the critical step — the rotation entry was computed
      //    speculatively and is now being permanently committed.
      const did = params.rotationEntry.didDocument.id!;
      await this.rotationStore.appendEntry(did, params.rotationEntry);
      console.log(
        `[agent-name-participant] ✓ rotation entry written to log ` +
        `(version ${params.rotationEntry.version})`,
      );

      // 2. Notify the agent to update its in-memory identity
      //    (DID document with new alsoKnownAs, service endpoints preserved).
      await this.onFinalize(params);
      console.log(`[agent-name-participant] ✓ agent identity updated`);

      // 3. Cache the name in the local name_registry table.
      const now = Math.floor(Date.now() / 1000);
      const proofRef = params.rotationDigest
        ? Buffer.from(params.rotationDigest).toString('base64')
        : null;
      await this.appDb.run(
        `INSERT OR REPLACE INTO name_registry
         (namespace, name, did, identity_uuid, proof_type, proof_reference, claimed_at, uuid)
         VALUES (?, ?, ?, (SELECT i.uuid FROM identities i JOIN did_documents d ON d.identity_uuid = i.uuid WHERE d.did = ?), 'alsoKnownAs', ?, ?, ?)`,
        params.namespace,
        params.name,
        params.did,
        params.did,
        proofRef,
        now,
        generateUuid(),
      );
      console.log(`[agent-name-participant] ✓ name cached locally in name_registry`);

      // Mark committed in the coordinator state.
      await this.txDb.run(
        `UPDATE tx_participant_state SET outcome = 'committed'
         WHERE tx_id = ? AND pid = ?`,
        txId,
        this.pid,
      );

      console.log(`[agent-name-participant] ${txId.slice(0, 8)} committed`);
    } catch (err) {
      console.error(
        `[agent-name-participant] commit error for tx ${txId}:`,
        (err as Error)?.message,
      );
      throw err; // Let the coordinator handle the failure
    }
  }

  async abort(txId: string): Promise<void> {
    // The rotation entry was never written to the log, so there's nothing
    // to roll back. Just mark aborted in the coordinator state.
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'aborted'
       WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
    console.log(`[agent-name-participant] ${txId.slice(0, 8)} aborted (speculative rotation discarded)`);
  }

  async compensate(txId: string): Promise<void> {
    // If this participant was part of a committed child transaction that
    // a parent later aborted, we would need to undo the rotation entry.
    // For now, same as abort.
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.txDb.get<{ outcome: string }>(
      `SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
    return (row?.outcome as Outcome) ?? 'unknown';
  }

  /**
   * Store the finalize params in the participant state so commit() can
   * retrieve them. Called during transaction setup, before the coordinator
   * runs prepare().
   */
  async storeParams(txId: string, params: FinalizeRotationParams): Promise<void> {
    // Serialize Uint8Array fields as arrays for JSON storage
    const serializable = {
      ...params,
      rotationEntry: {
        ...params.rotationEntry,
        digest: params.rotationEntry.digest
          ? Array.from(params.rotationEntry.digest)
          : undefined,
        signature: params.rotationEntry.signature
          ? Array.from(params.rotationEntry.signature)
          : undefined,
        prevHash: params.rotationEntry.prevHash
          ? Array.from(params.rotationEntry.prevHash)
          : undefined,
        nextKeyCommitments: params.rotationEntry.nextKeyCommitments
          ? params.rotationEntry.nextKeyCommitments.map(k => Array.from(k))
          : [],
      },
      rotationDigest: params.rotationDigest
        ? Array.from(params.rotationDigest)
        : undefined,
    };
    await this.txDb.run(
      `UPDATE tx_participant_state SET undo_hooks = ?
       WHERE tx_id = ? AND pid = ?`,
      JSON.stringify(serializable),
      txId,
      this.pid,
    );
  }
}