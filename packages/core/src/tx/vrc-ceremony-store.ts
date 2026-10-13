/**
 * VrcCeremonyStore — durable CRUD for the VRC personhood ceremony saga.
 *
 * Persists to the `vrc_ceremonies` table in the transaction-coordinator
 * database (tx-coordinator.db). Each agent keeps a mirror row for every
 * (local_did, remote_did) ceremony it participates in, so both sides can
 * advance the same ceremony independently and resynchronize via the
 * coordinator-driven legs.
 *
 * Phase model (mirrored on each agent):
 *   personhood ─▶ minting ─▶ sharing ─▶ complete
 *   any ─▶ failed(step)
 *
 * Leg booleans record which coordinator-driven transmissions have durably
 * completed on the local mirror:
 *   ack_sent_to_peer          — my personhood ack DELIVERED to the peer's coordinator
 *   local_minted              — my VRC minted locally (DTG w3c_vc_json produced)
 *   sent_to_peer              — my VRC delivered to the remote agent's coordinator
 *   sent_to_server            — my VRC archived on the utility server
 *   peer_vrc_received         — the remote agent's VRC stored locally
 *
 * Completion (`phase = 'complete'`) requires the PEER-TO-PEER legs only: mutual
 * ack + ack delivered + local mint + peer delivery + peer VRC received.
 * `sent_to_server` is deliberately NOT part of it — the utility archive is a
 * deferred obligation owned by the durable outbox / identity-push pipeline, so
 * two agents complete a ceremony with no bootstrap, relay or utility server.
 */

import type { DataSource } from '../db/data-source.js';
import { randomUUID } from 'node:crypto';

export type VrcCeremonyPhase =
  | 'personhood'
  | 'minting'
  | 'sharing'
  | 'complete'
  | 'failed';

export interface VrcCeremonySession {
  sessionId: string;
  localDid: string;
  remoteDid: string;
  phase: VrcCeremonyPhase;
  localMinted: boolean;
  sentToPeer: boolean;
  sentToServer: boolean;
  peerVrcReceived: boolean;
  localAcked: boolean;
  remoteAcked: boolean;
  /** The local personhood ack was durably DELIVERED to the peer's coordinator. */
  ackSentToPeer: boolean;
  /** The utility archive was handed to the durable outbox/push pipeline. */
  archiveDeferred: boolean;
  currentStep: string;
  failedStep: string | null;
  attempt: number;
  nextAttemptAt: number | null;
  lastError: string | null;
  createdAt: number;
  updatedAt: number;
}

/** Result of running the ceremony forward one step. */
export interface VrcCeremonyStepResult {
  advanced: boolean;
  phase: VrcCeremonyPhase;
  step: string;
  error?: string;
}

export class VrcCeremonyStore {
  private readonly ds: DataSource;

  constructor(ds: DataSource) {
    this.ds = ds;
  }

  /**
   * Get (or create) the ceremony session for a (localDid, remoteDid) pair.
   * Returns the existing session or creates a new one in the `personhood` phase.
   */
  async ensureSession(localDid: string, remoteDid: string): Promise<VrcCeremonySession> {
    const existing = await this.getByPair(localDid, remoteDid);
    if (existing) return existing;

    const now = Date.now();
    const sessionId = randomUUID();
    await this.ds.run(
      `INSERT INTO vrc_ceremonies
        (session_id, local_did, remote_did, phase, local_minted, sent_to_peer,
         sent_to_server, peer_vrc_received, local_acked, remote_acked,
         ack_sent_to_peer, archive_deferred,
         current_step, failed_step, attempt, next_attempt_at, last_error,
         created_at, updated_at)
       VALUES (?, ?, ?, 'personhood', 0, 0, 0, 0, 0, 0, 0, 0, '', NULL, 0, NULL, NULL, ?, ?)`,
      sessionId, localDid, remoteDid, now, now,
    );
    const created = await this.ds.get<RawSession>(
      'SELECT * FROM vrc_ceremonies WHERE local_did = ? AND remote_did = ?',
      localDid, remoteDid,
    );
    return mapSession(created!);
  }

  /** Look up a session by (localDid, remoteDid). */
  async getByPair(localDid: string, remoteDid: string): Promise<VrcCeremonySession | null> {
    const row = await this.ds.get<RawSession>(
      'SELECT * FROM vrc_ceremonies WHERE local_did = ? AND remote_did = ?',
      localDid, remoteDid,
    );
    return row ? mapSession(row) : null;
  }

  async getById(sessionId: string): Promise<VrcCeremonySession | null> {
    const row = await this.ds.get<RawSession>(
      'SELECT * FROM vrc_ceremonies WHERE session_id = ?', sessionId);
    return row ? mapSession(row) : null;
  }

  /** List non-terminal sessions (candidates for the retry driver). */
  async listIncomplete(): Promise<VrcCeremonySession[]> {
    const rows = await this.ds.all<RawSession>(
      "SELECT * FROM vrc_ceremonies WHERE phase != 'complete' AND phase != 'failed' ORDER BY updated_at",
    );
    return rows.map(mapSession);
  }

  async listByLocal(localDid: string): Promise<VrcCeremonySession[]> {
    const rows = await this.ds.all<RawSession>(
      'SELECT * FROM vrc_ceremonies WHERE local_did = ? ORDER BY updated_at',
      localDid,
    );
    return rows.map(mapSession);
  }

  /**
   * Delete the ceremony session for a (localDid, remoteDid) pair.
   *
   * Used by the personhood-ack timeout teardown: when the ceremony has not
   * completed within the ack deadline, the connection state is cleared so the
   * peers can retry a fresh OOBI exchange + connect without leaving stale
   * ceremony/saga state behind.
   *
   * @returns true if a session row was deleted.
   */
  async deleteByPair(localDid: string, remoteDid: string): Promise<boolean> {
    const result = await this.ds.run(
      'DELETE FROM vrc_ceremonies WHERE local_did = ? AND remote_did = ?',
      localDid, remoteDid,
    );
    return result.changes > 0;
  }

  /** Mark the local agent's personhood acknowledgment ("I know this person"). */
  async setLocalAcked(sessionId: string): Promise<void> {
    await this.ds.run(
      'UPDATE vrc_ceremonies SET local_acked = 1, updated_at = ? WHERE session_id = ?',
      Date.now(), sessionId,
    );
  }

  /** Mark the remote agent's personhood acknowledgment (from inbound personhood_ack). */
  async setRemoteAcked(sessionId: string): Promise<void> {
    await this.ds.run(
      'UPDATE vrc_ceremonies SET remote_acked = 1, updated_at = ? WHERE session_id = ?',
      Date.now(), sessionId,
    );
  }

  /**
   * Advance leg booleans and derive the phase.
   *
   * ── COMPLETION GATE (PEER-TO-PEER ONLY) ──────────────────────────────────
   * A session becomes 'complete' when the two AGENTS have done everything
   * between themselves:
   *
   *   mutual ack  +  my ack delivered  +  my VRC minted
   *               +  my VRC delivered  +  the peer's VRC stored locally
   *
   * `sent_to_server` is intentionally NOT part of the gate. The utility archive
   * is a deferred obligation: the durable outbox / identity-push pipeline
   * completes it whenever connectivity returns. Including it here is what made
   * an unreachable utility server fail an otherwise-successful ceremony after
   * `VRC_CEREMONY_MAX_ATTEMPTS` — and the ceremony must complete with nothing
   * but the two agents (no bootstrap, no relay, no utility server).
   *
   * ── PHASE OWNERSHIP ──────────────────────────────────────────────────────
   * The personhood phase belongs to the ACK FLAGS, not the VRC legs. The ack
   * delivery leg completes before anything is minted, so deriving the phase
   * from the VRC legs alone would report 'minting' while both users were still
   * at the button gate — and every "has left the personhood gate" decision
   * (stale-sweep, UI countdown) reads that phase.
   *
   * Flags only ever move 0 → 1, so the phase is monotonic: once 'complete' it
   * stays 'complete' even when a later leg (e.g. the archive) writes again.
   */
  async setLeg(sessionId: string, legs: Partial<{
    ackSentToPeer: boolean;
    localMinted: boolean;
    sentToPeer: boolean;
    sentToServer: boolean;
    peerVrcReceived: boolean;
  }>): Promise<VrcCeremonySession> {
    const current = await this.getById(sessionId);
    if (!current) throw new Error(`VRC ceremony session ${sessionId} not found`);

    const next = {
      ack_sent_to_peer: legs.ackSentToPeer ?? current.ackSentToPeer ? 1 : 0,
      local_minted: legs.localMinted ?? current.localMinted ? 1 : 0,
      sent_to_peer: legs.sentToPeer ?? current.sentToPeer ? 1 : 0,
      sent_to_server: legs.sentToServer ?? current.sentToServer ? 1 : 0,
      peer_vrc_received: legs.peerVrcReceived ?? current.peerVrcReceived ? 1 : 0,
    };

    const mutual = current.localAcked && current.remoteAcked;
    const p2pComplete =
      mutual &&
      next.ack_sent_to_peer === 1 &&
      next.local_minted === 1 &&
      next.sent_to_peer === 1 &&
      next.peer_vrc_received === 1;
    const phase =
      p2pComplete ? 'complete'
        : !mutual ? 'personhood'
          : next.local_minted === 1 ? 'sharing' : 'minting';

    await this.touch(sessionId, { ...next, phase });
    const updated = await this.getById(sessionId);
    return updated!;
  }

  /**
   * Clear the remote-ack flag.
   *
   * Called ONLY when the coordinated ack-delivery transaction ABORTS on this
   * side: the ack must not be treated as delivered before the sender's leg
   * actually commits. The sender retries and re-delivers (idempotently), so
   * nothing is lost — this just keeps the flag honest in the meantime.
   */
  async clearRemoteAcked(sessionId: string): Promise<void> {
    await this.ds.run(
      'UPDATE vrc_ceremonies SET remote_acked = 0, updated_at = ? WHERE session_id = ?',
      Date.now(), sessionId,
    );
  }

  /**
   * Record that the ceremony will NOT archive to the utility server and the
   * durable identity-push pipeline owns that obligation instead (no server
   * configured/available, or the coordinated archive leg aborted).
   *
   * One-shot per session by design: it also stops the retry driver from
   * re-attempting an archive that is now somebody else's job. `sent_to_server`
   * is left at 0 — it means "actually archived", and nothing may claim that
   * without a durable ack from the server.
   *
   * Deliberately does NOT consume the ceremony's failure budget or change the
   * phase: a missing utility server must never fail a peer-to-peer ceremony.
   */
  async markArchiveDeferred(sessionId: string, error: string): Promise<void> {
    await this.touch(sessionId, {
      archive_deferred: 1,
      current_step: 'server_archive_deferred',
      last_error: error,
    });
  }

  /** Record a failed attempt for the current step and schedule a retry. */
  async recordFailure(
    sessionId: string,
    step: string,
    error: string,
    nextAttemptDelayMs: number,
    maxAttempts: number,
  ): Promise<VrcCeremonySession> {
    const current = await this.getById(sessionId);
    if (!current) return current!;

    const attempt = current.attempt + 1;
    const phase: VrcCeremonyPhase = attempt >= maxAttempts ? 'failed' : current.phase;
    await this.touch(sessionId, {
      current_step: step,
      attempt,
      phase,
      failed_step: phase === 'failed' ? step : null,
      last_error: error,
      next_attempt_at: phase === 'failed' ? null : Date.now() + nextAttemptDelayMs,
    });
    const updated = await this.getById(sessionId);
    return updated!;
  }

  /** Clear retry/error bookkeeping when a leg finally succeeds. */
  async clearAttempt(sessionId: string): Promise<void> {
    await this.touch(sessionId, {
      attempt: 0,
      failed_step: null,
      last_error: null,
      next_attempt_at: null,
    });
  }

  /** Low-level JSON-patch of raw columns. */
  private touch(sessionId: string, patch: Record<string, unknown>): Promise<unknown> {
    const keys = Object.keys(patch);
    const setClause = keys.map((k) => `${k} = ?`).join(', ');
    const values = keys.map((k) => patch[k]);
    return this.ds.run(
      `UPDATE vrc_ceremonies SET ${setClause}, updated_at = ? WHERE session_id = ?`,
      ...values, Date.now(), sessionId,
    );
  }
}

interface RawSession {
  session_id: string;
  local_did: string;
  remote_did: string;
  phase: string;
  local_minted: number;
  sent_to_peer: number;
  sent_to_server: number;
  peer_vrc_received: number;
  local_acked: number;
  remote_acked: number;
  ack_sent_to_peer: number;
  archive_deferred: number;
  current_step: string;
  failed_step: string | null;
  attempt: number;
  next_attempt_at: number | null;
  last_error: string | null;
  created_at: number;
  updated_at: number;
}

function mapSession(r: RawSession): VrcCeremonySession {
  return {
    sessionId: r.session_id,
    localDid: r.local_did,
    remoteDid: r.remote_did,
    phase: r.phase as VrcCeremonyPhase,
    localMinted: r.local_minted === 1,
    sentToPeer: r.sent_to_peer === 1,
    sentToServer: r.sent_to_server === 1,
    peerVrcReceived: r.peer_vrc_received === 1,
    localAcked: r.local_acked === 1,
    remoteAcked: r.remote_acked === 1,
    ackSentToPeer: r.ack_sent_to_peer === 1,
    archiveDeferred: r.archive_deferred === 1,
    currentStep: r.current_step,
    failedStep: r.failed_step,
    attempt: r.attempt,
    nextAttemptAt: r.next_attempt_at,
    lastError: r.last_error,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}