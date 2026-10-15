// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * VRC Personhood Ceremony — mutual acknowledgment flow, enclosed in the
 * transaction coordinator as a durable saga.
 *
 *   1. OOBI shared → ceremony session created in the `personhood` phase.
 *   2. Each agent presses "I know this person" (the ack is recorded durably
 *      FIRST) and the ack is DELIVERED to the other agent by the `ack_delivery`
 *      coordinator leg. There is no raw best-effort send: a real commit/abort
 *      result governs the durable `ack_sent_to_peer` flag, and a failed delivery
 *      is retried on the standard backoff ladder instead of being silently lost.
 *   3. When BOTH agents have acked → personhood confirmed; each agent mints
 *      its VRC as a coordinator step.
 *   4. Each agent then sends its VRC to the OTHER agent's transaction
 *      coordinator handler (`store_remote_vrc`) and archives its VRC table
 *      record to the utility server (`identity_push`) — both as coordinator
 *      steps.
 *   5. When every PEER-TO-PEER leg on an agent's mirror is durably done
 *      (mutual ack + ack delivered + own VRC minted + VRC delivered + the peer's
 *      VRC stored locally), that side is `complete` and personhood is
 *      `verified`.
 *
 * The utility archive (leg 3) is NOT part of completion. It is a deferred
 * obligation owned by the durable outbox / identity-push pipeline, so the
 * ceremony completes with nothing but the two agents — no bootstrap, no relay,
 * no utility server — and the archive catches up when connectivity returns.
 *
 * Every transmission is a coordinator step. There is NO fire-and-forget send
 * and NO legacy/alternate error path outside the ceremony coordinator. The ack
 * delivery leg is the one transmission that USED to violate this (a raw TSP_GEN
 * whose error was swallowed by `.catch()`); it is now a coordinator transaction
 * like every other leg. A leg
 * that fails keeps the session `incomplete` and is retried on a backoff
 * schedule by `advanceDueSessions`. When a leg finally fails after
 * `VRC_CEREMONY_MAX_ATTEMPTS` the session becomes `failed({step})`, which the
 * UI surfaces. A delivery-leg failure never rolls back the already-minted
 * local VRC, so the DTG output always persists.
 *
 * ## TSP_GEN Payload Format
 *
 *   Request:  { action: "personhood_ack", from: <did> }
 *
 * ## Personhood Status
 *
 *   relationships.personhood_status:
 *     NULL           → ceremony not started
 *     'acknowledged' → local agent has acknowledged knowing the remote
 *     'verified'     → the local mirror of the ceremony completed
 */

import type { DatabaseSync } from 'node:sqlite';
import type { IdentityResolver } from '../services/identity-resolver.js';
import type { RelationshipStore } from './store.js';
import type { LocalIdentity, RelationshipRecord } from './types.js';
import type { TransactionManager } from '../tx/manager.js';
import type { Participant } from '../tx/types.js';
import type { ParticipantTransport } from '../tx/participant.js';
import { RemoteParticipant } from '../tx/participant.js';
import { generateUuid } from '../db/uuid-helpers.js';
import {
  VrcCeremonyStore,
  type VrcCeremonySession,
  type VrcCeremonyStepResult,
} from '../tx/vrc-ceremony-store.js';
import { logger } from '../util/logger.js';

// ── Ceremony / retry policy ───────────────────────────────────────────────
/** Number of attempts per leg before the ceremony is marked failed. */
export const VRC_CEREMONY_MAX_ATTEMPTS = 6;
/** Backoff ladder (ms) used between leg retries. */
export const VRC_CEREMONY_BACKOFF_MS = [2_000, 5_000, 15_000, 30_000, 60_000];

/**
 * How long the peers have after the OOBI exchange + connect to BOTH press
 * "I know this person". If the personhood ceremony is still at the button
 * gate when this deadline passes, the connection attempt is cleared (button
 * retracted, relationship + ceremony state removed) so the peers can retry a
 * fresh OOBI exchange + connect without leaving stale handshake state.
 *
 * The clock starts at relationship creation (`relationships.created_at`),
 * which is set when the OOBI is pasted + connect pressed (initiator) or when
 * the inbound RFI arrives (responder).
 */
export const VRC_CEREMONY_ACK_TIMEOUT_MS = 60_000;

/** Resolve the ack deadline, honoring an env override (used by tests). */
export function getCeremonyAckTimeoutMs(): number {
  const raw = process.env.LP2P_CEREMONY_ACK_TIMEOUT_MS;
  if (raw && /^\d+$/.test(raw) && Number(raw) > 0) return Number(raw);
  return VRC_CEREMONY_ACK_TIMEOUT_MS;
}

// ── Personhood-ack window (UI view) ────────────────────────────────────────
//
// The 60s mutual-ack window is SERVER-OWNED. Its deadline is derived from
// `relationships.created_at` — the same input `isCeremonyStale` consults — so
// BOTH peers count down to the same absolute instant and the display can never
// disagree with the teardown that actually clears the connection attempt.
// Before this view existed each browser ran its own timer, which is why the two
// displays could show different numbers for the same ceremony.

/**
 * Render view of the personhood-ack gate for one (local, remote) pair.
 *
 * `expired` mirrors `isCeremonyStale`'s predicate so the two always agree, but
 * `isCeremonyStale` remains the AUTHORITATIVE check — this view only decides
 * what the UI draws. A session that has left the gate (both sides pressed and
 * the coordinator legs are running) is never reported as `active`/`expired`;
 * the retry/backoff model owns that stage.
 */
export interface CeremonyAckView {
  /** Window length (ms): `VRC_CEREMONY_ACK_TIMEOUT_MS` unless env-overridden. */
  timeoutMs: number;
  /** Absolute deadline (epoch ms) by which BOTH peers must have pressed. */
  deadlineMs: number;
  /** Time left in the window (ms), clamped at 0. */
  remainingMs: number;
  /** Local user pressed "I know this person" and it is durably recorded. */
  localAcked: boolean;
  /** The peer's acknowledgment is durably recorded locally. */
  remoteAcked: boolean;
  /** Both sides pressed — the ceremony may leave the personhood gate. */
  mutual: boolean;
  /** Local press recorded, still waiting on the peer. */
  awaitingPeer: boolean;
  /** Window open, ceremony still at the gate: render the countdown. */
  active: boolean;
  /** Window passed with the ceremony still at the gate: teardown pending. */
  expired: boolean;
}

/**
 * Absolute personhood-ack deadline (epoch ms) for a relationship.
 *
 * Time units differ deliberately in this codebase: `relationships.created_at`
 * is unix SECONDS (see `RelationshipRecord.createdAt`) while this deadline is
 * in ms, so the conversion is explicit here (as it is in `isCeremonyStale`).
 */
export function getCeremonyAckDeadlineMs(record: RelationshipRecord): number {
  return record.createdAt * 1000 + getCeremonyAckTimeoutMs();
}

/**
 * Build the UI render view for the personhood-ack gate.
 *
 * `session` may be null: the saga row is created lazily on the FIRST press, so
 * before anyone presses there is no `vrc_ceremonies` row while the window is
 * already running. Both displays therefore render the countdown from the
 * relationship record alone — no press is required for the timer to appear.
 */
export function buildCeremonyAckView(
  record: RelationshipRecord,
  session: VrcCeremonySession | null,
  nowMs = Date.now(),
): CeremonyAckView {
  const timeoutMs = getCeremonyAckTimeoutMs();
  const deadlineMs = getCeremonyAckDeadlineMs(record);
  const remainingMs = Math.max(0, deadlineMs - nowMs);
  const localAcked = session?.localAcked ?? false;
  const remoteAcked = session?.remoteAcked ?? false;
  const mutual = localAcked && remoteAcked;

  // Identical at-gate test to `isCeremonyStale`: no session at all, or the
  // pair has not reached MUTUAL acknowledgment. Being mutual is what leaves the
  // gate — the phase can still read 'personhood' for a tick (and does for as
  // long as a mint leg is retrying, since `recordFailure` preserves the phase),
  // so the phase must not be consulted here: doing so would keep a countdown on
  // screen after both users had already confirmed.
  const atGate = !session || !mutual;
  // Identical eligibility test to `isCeremonyStale`: only an established,
  // bidirectional, not-yet-verified human relationship has a window at all
  // (organization/infrastructure relationships have no personhood ceremony).
  const eligible =
    record.direction === 'bidirectional' &&
    record.status === 'established' &&
    record.personhoodStatus !== 'verified' &&
    record.remoteSubjectKind !== 'organization';
  const cancellable = eligible && atGate;

  return {
    timeoutMs,
    deadlineMs,
    remainingMs,
    localAcked,
    remoteAcked,
    mutual,
    awaitingPeer: localAcked && !remoteAcked,
    active: cancellable && remainingMs > 0,
    expired: cancellable && remainingMs <= 0,
  };
}

// ── Message Types ──────────────────────────────────────────────────────────

export interface PersonhoodAckMessage {
  action: 'personhood_ack';
  from: string;  // DID of the acknowledging party
}

// ── Ceremony Handler ───────────────────────────────────────────────────────

export type SendMessageFn = (remoteDid: string, body: Uint8Array) => Promise<void>;

export interface CeremonyContext {
  store: RelationshipStore;
  db: DatabaseSync;
  resolver: IdentityResolver;
  identity: LocalIdentity;
  sendMessage: SendMessageFn;
  /**
   * Called when the local UI needs to prompt the user to acknowledge.
   * `remoteDid` is the peer's canonical DID; `fromDid` is the DID the inbound
   * wire message was actually signed by (they differ only when the peer sends
   * from a DID other than the relationship key).
   */
  onPromptToAcknowledge?: (remoteDid: string, fromDid: string) => void;
  /** Called when the ceremony completes (both parties acknowledged + VRC shared). */
  onCeremonyComplete?: (remoteDid: string) => void;
  /** Called when a leg permanently fails (UI should surface it). */
  onCeremonyFailed?: (remoteDid: string, step: string, error: string) => void;
  /** Called when an uncompleted personhood ceremony expires (connection cleared). */
  onCeremonyExpired?: (remoteDid: string) => void;

  // ── Transaction-coordinator enclosure ──────────────────────────────────
  /** Durable saga store (vrc_ceremonies) on the tx-coordinator db. */
  ceremonyStore: VrcCeremonyStore;
  /** Transaction manager for the coordinator steps. */
  txManager: TransactionManager;
  /** Participant that mints the local VRC (VrcCeremonyParticipant). */
  createLocalVrcParticipant?: () => Participant;
  /** TSP transport that reaches the REMOTE AGENT (not the utility server). */
  peerTransport?: ParticipantTransport;
  /** TSP transport that reaches the UTILITY SERVER (archive leg). */
  serverTransport?: ParticipantTransport;
  /** Utility server participant target (e.g. `peer:{serverDid}`). */
  serverPid?: string;
  /** Remote agent's VID — set at call time by the handlers. */
  remotePeerVid?: string;
}

/** Return seconds until a session is next due for a retry, or 0 if due now. */
function dueForAttempt(s: VrcCeremonySession): boolean {
  if (s.phase === 'complete' || s.phase === 'failed') return false;
  if (s.nextAttemptAt == null) return true;
  return Date.now() >= s.nextAttemptAt;
}

/**
 * Initiate the ceremony from the local side: the user pressed "I know this
 * person". Records the acknowledgment durably, mirrors it into the saga store
 * and notifies the remote peer.
 */
export async function acknowledgePeer(
  ctx: CeremonyContext,
  remoteDid: string,
): Promise<void> {
  const record = ctx.store.get(ctx.identity.did, remoteDid);
  if (!record || record.direction !== 'bidirectional') {
    logger.warn('[ceremony] Cannot acknowledge: no bidirectional relationship');
    return;
  }

  // Durable local + saga state.
  ctx.store.setPersonhoodStatus(ctx.identity.did, record.remoteDid, 'acknowledged');
  const session = await ctx.ceremonyStore.ensureSession(ctx.identity.did, record.remoteDid);
  if (!session.localAcked) {
    await ctx.ceremonyStore.setLocalAcked(session.sessionId);
  }
  logger.info(`[ceremony] Local acknowledged ${remoteDid.slice(0, 12)}...`);

  // NO fire-and-forget send here. The acknowledgment is already durably recorded
  // above; DELIVERY is the `ack_delivery` coordinator leg inside
  // advanceCeremony (durable `ack_sent_to_peer` flag, real commit/abort result,
  // backoff + retries). The raw TSP_GEN that used to live here could lose the ack
  // silently: the peer never learned we confirmed, never pressed, and the window
  // closed with no record of why.
  await advanceCeremony(ctx, session.sessionId);
}

/**
 * Handle an inbound personhood_ack message from a remote peer.
 * Called by the TSP message handler in BaseAgent.
 */
export async function handlePersonhoodAck(
  ctx: CeremonyContext,
  remoteDid: string,
  msg: PersonhoodAckMessage,
): Promise<void> {
  const record = ctx.store.get(ctx.identity.did, remoteDid);
  if (!record || record.direction !== 'bidirectional') {
    logger.warn('[ceremony] Ignoring personhood_ack: no bidirectional relationship');
    return;
  }

  const remoteStatus = record.personhoodStatus;
  const session = await ctx.ceremonyStore.ensureSession(ctx.identity.did, record.remoteDid);
  if (!session.remoteAcked) {
    await ctx.ceremonyStore.setRemoteAcked(session.sessionId);
  }

  // If remote hasn't been acknowledged yet locally, prompt the local user.
  if (remoteStatus === undefined) {
    logger.info(`[ceremony] Remote ${remoteDid.slice(0, 12)}... acknowledged. Prompting local user.`);
    ctx.onPromptToAcknowledge?.(remoteDid, msg.from);
    return;
  }

  // If we already acknowledged, the remote has now confirmed → advance.
  if (remoteStatus === 'acknowledged') {
    await advanceCeremony(ctx, session.sessionId);
  }
}

/**
 * Handle the local user pressing "Do you also know them?" after being prompted.
 */
export async function localUserAcknowledges(
  ctx: CeremonyContext,
  remoteDid: string,
): Promise<void> {
  await acknowledgePeer(ctx, remoteDid);

  const record = ctx.store.get(ctx.identity.did, remoteDid);
  if (record && record.personhoodStatus === 'acknowledged') {
    const session = await ctx.ceremonyStore.ensureSession(ctx.identity.did, record.remoteDid);
    if (session.remoteAcked) {
      await advanceCeremony(ctx, session.sessionId);
    }
  }
}

// ── Ceremony driver ─────────────────────────────────────────────────────────

/**
 * Advance one ceremony session by at most one leg. No-ops for completed,
 * failed, or not-yet-due sessions. This is the single entry point the retry
 * driver and the event handlers call — there is no alternate path.
 */
/**
 * Guarded entry point for advancing a single ceremony.
 *
 * ── PROCESS CONTRACT (see the file-header docstring) ─────────────────────
 * This wrapper enforces a ONE-AT-A-TIME-per-session invariant. The ceremony
 * driver (`advanceDueSessions`) polls on a timer, and a slow leg — e.g. a
 * `peer_delivery` whose `store_remote_vrc` commit waits on the remote agent's
 * `tx_commit_result` over a circuit-relay tunnel — can be slow enough that the
 * next timer tick would otherwise re-enter the SAME session and start a DUPLICATE
 * coordinator transaction for the SAME leg. That duplicate work is what produced the
 * multi-tx retry storm / 500 ms-log-poll flood observed on slow WAN relays.
 * Guarding here, in the function EVERY caller uses, makes the contract
 * unconditional regardless of how the session is advanced (driver timer, an inbound
 * `personhood_ack` triggering an immediate advance, or a manual test).
 *
 * Every leg that mutates shared state MUST run through `runCoordinated`
 * (transaction coordinator) — there is no alternate path. A leg that throws or
 * times out is recorded via `legFailed`, which backs off and retries up to
 * `VRC_CEREMONY_MAX_ATTEMPTS` before marking the session failed. See
 * `runCoordinated` for the per-leg timeout that bounds a hung commit.
 */
const inFlightSessions = new Set<string>();
export async function advanceCeremony(
  ctx: CeremonyContext,
  sessionId: string,
): Promise<VrcCeremonyStepResult> {
  if (inFlightSessions.has(sessionId)) {
    return {
      advanced: false,
      phase: (await ctx.ceremonyStore.getById(sessionId))?.phase ?? 'personhood',
      step: 'in_flight',
    };
  }
  inFlightSessions.add(sessionId);
  try {
    return await advanceCeremonyInner(ctx, sessionId);
  } finally {
    inFlightSessions.delete(sessionId);
  }
}

/**
 * Apply the terminal side effects of a COMPLETED ceremony, exactly once.
 *
 * ── WHY THIS IS NOT INLINE IN THE COMPLETION BLOCK ──────────────────────────
 * `VrcCeremonyStore.setLeg()` DERIVES `phase` from the leg flags, so a session
 * flips to `'complete'` on whichever leg happens to set its LAST flag — not
 * necessarily on the driver pass that reaches the completion block at the
 * bottom of `advanceCeremonyInner`. Two orders produce that:
 *
 *   - `peer_delivery`: the peer's VRC can arrive BEFORE we finish delivering
 *     ours (the two agents run the legs concurrently, and the peer's VRC is
 *     stored by the inbound `store_remote_vrc` commit). Then
 *     `setLeg({ sentToPeer: true })` derives `'complete'` immediately.
 *   - the archive leg with a utility server, where `peer_vrc_received` is
 *     already 1.
 *
 * On the NEXT driver pass `advanceCeremonyInner` returns early on
 * `phase === 'complete'` and the completion block is never reached — which is
 * how a ceremony could report `phase=complete` while the relationship still
 * read `personhood_status='acknowledged'` and `onCeremonyComplete` never fired
 * (so the UI never got its `ceremony-complete` signal and kept the pair out of
 * the "verified" state even though both agents had done everything between
 * themselves).
 *
 * Idempotent by construction: the guard is the relationship's own
 * `personhood_status`, so the `onCeremonyComplete` hand-off fires once per
 * relationship rather than once per 4 s driver tick, and a re-run is a no-op.
 *
 * @returns true when this call is the one that applied the terminal state.
 */
function finalizeCeremonyCompletion(
  ctx: CeremonyContext,
  session: VrcCeremonySession,
): boolean {
  if (session.phase !== 'complete') return false;
  const record = ctx.store.get(ctx.identity.did, session.remoteDid);
  if (!record || record.personhoodStatus === 'verified') return false;
  ctx.store.setPersonhoodStatus(ctx.identity.did, session.remoteDid, 'verified');
  ctx.onCeremonyComplete?.(session.remoteDid);
  return true;
}

/**
 * Apply the completion side effects for every COMPLETED session of this agent
 * whose relationship is not yet `verified`. Returns how many were applied.
 *
 * ── WHY A SWEEP IS NEEDED ON TOP OF `setLegAndFinalize` ─────────────────────
 * `phase` is derived from the leg flags inside `VrcCeremonyStore.setLeg()`, and
 * one of the writes that set a leg's flag is OUTSIDE this module: the inbound
 * `store_remote_vrc` commit stores the peer's VRC and flips `peer_vrc_received`
 * directly (`VrcReceiveParticipant`), deriving `'complete'` on the RECEIVER side
 * when it had already delivered its own VRC. That writer has no CeremonyContext
 * to fire `onCeremonyComplete` with. It is also why `advanceDueSessions` cannot
 * be the only finalizer: it skips sessions whose phase is already
 * `complete`/`failed`, so a session derived complete by any means is never
 * revisited. This sweep makes finalization independent of WHO derived the
 * transition — including sessions left stuck by an older build — while the
 * `personhood_status` guard keeps the hand-off to the UI once-per-relationship.
 */
export async function finalizeCompletedCeremonies(
  ctx: CeremonyContext,
  localDid: string,
): Promise<number> {
  const sessions = await ctx.ceremonyStore.listByLocal(localDid);
  let finalized = 0;
  for (const session of sessions) {
    if (finalizeCeremonyCompletion(ctx, session)) finalized++;
  }
  return finalized;
}

/**
 * Write a leg's flags and apply the completion side effects when THAT write is
 * the one that derived the session to `'complete'`.
 *
 * This is the only way a leg may advance the saga. `advanceDueSessions` skips
 * sessions whose phase is already `complete`/`failed`, so a leg that derives
 * 'complete' is the LAST thing the driver ever does for that session — nobody
 * will come back and reach the completion block. Finalizing here is therefore
 * load-bearing, not belt-and-braces.
 */
async function setLegAndFinalize(
  ctx: CeremonyContext,
  sessionId: string,
  legs: Parameters<VrcCeremonyStore['setLeg']>[1],
): Promise<VrcCeremonySession> {
  const updated = await ctx.ceremonyStore.setLeg(sessionId, legs);
  finalizeCeremonyCompletion(ctx, updated);
  return updated;
}

async function advanceCeremonyInner(
  ctx: CeremonyContext,
  sessionId: string,
): Promise<VrcCeremonyStepResult> {
  const session = await ctx.ceremonyStore.getById(sessionId);
  if (!session) return { advanced: false, phase: 'personhood', step: 'unknown' };
  if (session.phase === 'complete' || session.phase === 'failed') {
    // A session can be DERIVED to 'complete' by `setLeg()` on the leg that set
    // its last flag, so this pass never reaches the completion block below.
    // Self-heal the terminal side effects here (idempotent) so the relationship
    // record and the UI agree with the saga, and so a session that was already
    // stuck this way heals on the next driver tick.
    finalizeCeremonyCompletion(ctx, session);
    return { advanced: false, phase: session.phase, step: session.currentStep };
  }
  if (!dueForAttempt(session)) {
    return { advanced: false, phase: session.phase, step: session.currentStep };
  }

  // ── Leg 0: deliver my personhood ack to the peer, durably ───────────────
  // Ordered BEFORE the personhood gate because delivering my ack is what makes
  // the gate reachable for the peer, and gated on `localAcked` so a peer-first
  // ack never causes anything to be sent on my behalf. Every transmission here
  // is a coordinator transaction: a real commit/abort result, the standard
  // backoff ladder, and the durable `ack_sent_to_peer` flag the UI reads to tell
  // "delivering" apart from "delivered, waiting for them".
  if (session.localAcked && !session.ackSentToPeer) {
    if (!ctx.peerTransport) {
      return await legFailed(ctx, session, 'ack_delivery', 'no peer transport available');
    }
    const committed = await runCoordinated(ctx, async (tx) => {
      const remoteParts = new RemoteParticipant(`peer:${session.remoteDid}`, ctx.peerTransport!);
      tx.enlist(remoteParts, [{
        op: 'personhood_ack',
        params: {
          fromDid: ctx.identity.did,
          localDid: ctx.identity.did,
          remoteDid: session.remoteDid,
        },
      }]);
    });
    if (committed !== 'committed') {
      return await legFailed(ctx, session, 'ack_delivery', 'coordinated ack delivery aborted');
    }
    const phase = (await setLegAndFinalize(ctx, session.sessionId, { ackSentToPeer: true })).phase;
    await ctx.ceremonyStore.clearAttempt(session.sessionId);
    return { advanced: true, phase, step: 'ack_delivery' };
  }

  // Personhood gating: neither side mints until both have acknowledged.
  if (!session.localAcked || !session.remoteAcked) {
    return { advanced: false, phase: 'personhood', step: 'wait_personhood' };
  }

  const myDid = ctx.identity.did;
  logger.info(
    `[ceremony] advance ${session.sessionId.slice(0, 8)} phase=${session.phase} ` +
    `localMinted=${session.localMinted} sentToPeer=${session.sentToPeer} ` +
    `sentToServer=${session.sentToServer} peerVrcReceived=${session.peerVrcReceived} attempt=${session.attempt}`,
  );

  // Leg 1: mint my VRC (idempotent by credential digest). The readable-VRC
  // check also acts as the gate: a stale saga flag (local_minted=1) with no
  // actual credential is healed by re-minting on the next driver tick.
  if (!session.localMinted || !getLocalVc(ctx, session, myDid)) {
    const rec = ctx.store.get(myDid, session.remoteDid);
    if (!rec) return await legFailed(ctx, session, 'mint_local', 'relationship record missing');
    const committed = await runCoordinated(ctx, async (tx) => {
      const localPart = ctx.createLocalVrcParticipant!();
      tx.enlist(localPart, [{ op: 'mint_vrc', params: { record: rec } }]);
    });
    if (committed !== 'committed') {
      return await legFailed(ctx, session, 'personal_local', 'coordinated mint aborted');
    }
    // Verify the coordinator commit actually left a readable local VRC before
    // declaring the mint leg done. Without this, a commit that did not persist
    // (or a stale saga session) would silently carry localMinted=true into the
    // peer_delivery leg and fail there with a misleading error.
    const w3cAfterMint = getLocalVc(ctx, session, myDid);
    const mintRowCount = countLocalVrcRows(ctx, session, myDid);
    if (!w3cAfterMint) {
      logger.error(
        `[ceremony] ✗ mint coordinator committed but local VRC not readable for ${session.remoteDid.slice(0, 12)}... ` +
        `(rows=${mintRowCount}, w3c_vc_json=${w3cAfterMint ? 'present' : 'MISSING'})`,
      );
      return await legFailed(ctx, session, 'mint_local',
        mintRowCount === 0 ? 'mint committed but no credential row' : 'mint committed but w3c_vc_json missing');
    }
    logger.info(`[ceremony] ✓ local VRC minted + verified for ${session.remoteDid.slice(0, 12)}... (rows=${mintRowCount}, w3c=${w3cAfterMint.length}B)`);
    const phase = (await setLegAndFinalize(ctx, session.sessionId, { localMinted: true })).phase;
    await ctx.ceremonyStore.clearAttempt(session.sessionId);
    return { advanced: true, phase, step: 'personal_local' };
  }

  // Leg 2: send our VRC to the remote agent's coordinator handler.
  if (!session.sentToPeer) {
    // Two independent preconditions — report the exact cause, never conflate.
    if (!ctx.peerTransport) {
      return await legFailed(ctx, session, 'peer_delivery', 'no peer transport available');
    }
    const w3c = getLocalVc(ctx, session, myDid);
    if (!w3c) {
      const rows = countLocalVrcRows(ctx, session, myDid);
      return await legFailed(ctx, session, 'peer_delivery', `no locally minted VRC (credential rows=${rows}, w3c_vc_json missing)`);
    }
    logger.info(`[ceremony] peer_delivery: sending store_remote_vrc to ${session.remoteDid.slice(0, 12)}... (w3c=${w3c.length}B)`);
    // The peer_delivery leg shares the local agent's full identity record (not
    // just the VRC) so the receiving agent can populate its local identities
    // table with the sender's login name etc. The receiver re-derives the row
    // key (deterministic UUIDv5 of the real DID) and forces custody='remote'.
    const committed = await runCoordinated(ctx, async (tx) => {
      const remotePart = new RemoteParticipant(`peer:${session.remoteDid}`, ctx.peerTransport!);
      tx.enlist(remotePart, [{
        op: 'store_remote_vrc',
        params: {
          w3cVcJson: w3c,
          issuerDid: myDid,
          subjectDid: session.remoteDid,
          issuerVid: ctx.identity.cesrVid,
          issuerIdentity: buildIdentityRecord(ctx, myDid),
        },
      }]);
    });
    if (committed !== 'committed') {
      return await legFailed(ctx, session, 'peer_delivery', 'coordinated peer deliver aborted');
    }
    const phase = (await setLegAndFinalize(ctx, session.sessionId, { sentToPeer: true })).phase;
    await ctx.ceremonyStore.clearAttempt(session.sessionId);
    return { advanced: true, phase, step: 'peer_delivery' };
  }

  // ── Leg 3: archive my VRC to the utility server (FAST PATH ONLY) ────────
  // The archive is a DEFERRED OBLIGATION, not a requirement of the ceremony.
  // When there is no server, or the attempt fails, the durable identity-push
  // pipeline (outbox + reconnect drain + pumpProfileSync) finishes it later and
  // this ceremony is unaffected. So this leg must not consume the ceremony's
  // failure budget, must not flip the session to 'failed', and must never claim
  // an archive that did not happen (`sent_to_server` stays 0 unless a server
  // durably acked). An unreachable utility server used to fail the whole
  // ceremony here after VRC_CEREMONY_MAX_ATTEMPTS, which broke the pure
  // peer-to-peer guarantee.
  if (!session.sentToServer && !session.archiveDeferred) {
    if (!ctx.serverTransport || !ctx.serverPid) {
      await ctx.ceremonyStore.markArchiveDeferred(
        session.sessionId,
        'no utility server configured — archive deferred to the identity-push pipeline',
      );
      return { advanced: false, phase: session.phase, step: 'server_archive_deferred' };
    }
    const payload = await buildIdentityPushPayload(ctx, session);
    const committed = await runCoordinated(ctx, async (tx) => {
      const serverPart = new RemoteParticipant(ctx.serverPid!, ctx.serverTransport!);
      tx.enlist(serverPart, [{ op: 'exchange:identity', params: { payload } }]);
    });
    if (committed !== 'committed') {
      await ctx.ceremonyStore.markArchiveDeferred(
        session.sessionId,
        'coordinated archive aborted — archive deferred to the identity-push pipeline',
      );
      return { advanced: false, phase: session.phase, step: 'server_archive_deferred' };
    }
    const phase = (await setLegAndFinalize(ctx, session.sessionId, { sentToServer: true })).phase;
    await ctx.ceremonyStore.clearAttempt(session.sessionId);
    return { advanced: true, phase, step: 'server_archive' };
  }

  // Leg 4 — wait for the peer's VRC (set by the inbound store_remote_vrc handler).
  if (!session.peerVrcReceived) {
    return { advanced: false, phase: 'sharing', step: 'wait_peer_vrc' };
  }

  // All legs done → mark verified + fire the completion handler. Routed through
  // the same guarded helper the early `phase === 'complete'` exit uses, so the
  // terminal side effects are applied exactly once regardless of WHICH pass
  // observed the completion (this one, or a leg write elsewhere that derived it).
  await setLegAndFinalize(ctx, session.sessionId, {});
  return { advanced: true, phase: 'complete', step: 'completed' };
}

/**
 * Drive every incomplete ceremony that is due for a retry. Called on a timer
 * by the agent. Returns how many sessions were advanced.
 */
export async function advanceDueSessions(
  ctx: CeremonyContext,
  localDid: string,
): Promise<number> {
  const sessions = await ctx.ceremonyStore.listByLocal(localDid);
  let touched = 0;
  for (const s of sessions) {
    if (s.phase === 'complete' || s.phase === 'failed') continue;
    try {
      const result = await advanceCeremony(ctx, s.sessionId);
      if (result.advanced) touched++;
    } catch (err) {
      logger.warn(`[ceremony] advance error for ${s.sessionId.slice(0, 8)}:`, (err as Error)?.message ?? err);
    }
  }
  return touched;
}

// ── Personhood ack timeout / teardown ──────────────────────────────────────
//
// If an OOBI exchange + connect is followed by radio silence on the
// "I know this person" button (or one side never pushes), the pair is stuck at
// the personhood gate forever. After `VRC_CEREMONY_ACK_TIMEOUT_MS` the
// connection attempt is cleared so the peers can retry a fresh OOBI exchange +
// connect and complete the ceremony without leftover stale state.
//
// A ceremony that has LEFT the personhood gate (both sides pushed in time and
// coordinator legs are running in `minting`/`sharing`) is NOT considered
// stale — the coordinator backoff / `VRC_CEREMONY_MAX_ATTEMPTS` failure model
// owns that stage.

/**
 * Decide whether an established-but-unverified relationship is past the ack
 * deadline with the ceremony still stuck at the button-push gate.
 *
 * Time units differ in this codebase on purpose: `relationships.created_at`
 * is unix SECONDS (`unixepoch()`), while `vrc_ceremonies` uses ms. This
 * function converts explicitly.
 *
 * Organization (utility-server / infra) relationships are never expired —
 * they have no personhood ceremony and must survive indefinitely.
 */
export function isCeremonyStale(
  record: RelationshipRecord,
  session: VrcCeremonySession | null,
  nowMs = Date.now(),
): boolean {
  if (record.direction !== 'bidirectional' || record.status !== 'established') return false;
  if (record.personhoodStatus === 'verified') return false;
  if (record.remoteSubjectKind === 'organization') return false;

  // Still at the personhood gate: no session at all, or the pair has not
  // reached MUTUAL acknowledgment.
  //
  // Mutual acknowledgment is the ONLY thing that leaves the gate. The phase is
  // deliberately NOT consulted: a mutually-acked session can still report
  // phase 'personhood' for a tick, and for as long as a mint/publish leg is
  // retrying (`recordFailure` preserves the current phase). Treating that as
  // stale would tear down a relationship BOTH users consented to — deleting
  // the relationship + ceremony rows and orphaning an already-minted VRC — in
  // precisely the constrained-network case the retry ladder exists to survive.
  const atGate = !session || !(session.localAcked && session.remoteAcked);
  if (!atGate) return false;

  const connectedAtSec = record.createdAt;
  const elapsedSec = Math.floor(nowMs / 1000) - connectedAtSec;
  return elapsedSec > getCeremonyAckTimeoutMs() / 1000;
}

/**
 * Tear down the OOBI-exchange-and-connect state for one relationship so the
 * peers can retry a fresh exchange: deletes the `vrc_ceremonies` session and
 * the `relationships` row (which also clears `personhood_status`), then fires
 * `ctx.onCeremonyExpired` so the UI can log / retract the "I know this person"
 * button. The remote identity stub is deliberately retained — it is inert and
 * reused idempotently on retry, and deleting it could cascade into unrelated
 * chat/credential rows.
 *
 * @returns true if any state was cleared.
 */
export async function teardownCeremony(
  ctx: CeremonyContext,
  remoteDid: string,
): Promise<boolean> {
  const record = ctx.store.get(ctx.identity.did, remoteDid);
  if (!record) return false;

  await ctx.ceremonyStore.deleteByPair(ctx.identity.did, remoteDid);
  ctx.store.deleteRecord(ctx.identity.did, remoteDid);

  logger.info(
    `[ceremony] torn down incomplete ceremony with ${remoteDid.slice(0, 24)}... ` +
    `(relationship + ceremony session cleared; connection attempt reset)`,
  );
  ctx.onCeremonyExpired?.(remoteDid);
  return true;
}

/**
 * Sweep every established-but-unverified relationship that is past the ack
 * deadline and still stuck at the personhood gate, tearing it down so a fresh
 * OOBI exchange + connect can succeed. Returns how many were expired.
 */
export async function expireStaleCeremonies(
  ctx: CeremonyContext,
  localDid: string,
): Promise<number> {
  const records = ctx.store.list(localDid);
  let expired = 0;
  for (const record of records) {
    const session = await ctx.ceremonyStore.getByPair(localDid, record.remoteDid);
    if (!isCeremonyStale(record, session)) continue;
    if (await teardownCeremony(ctx, record.remoteDid)) expired++;
  }
  if (expired > 0) {
    logger.info(`[ceremony] expired ${expired} stale personhood ceremony(s)`);
  }
  return expired;
}

// ── Coordinator leg helpers ────────────────────────────────────────────────

/** Bound on a single coordinator leg. See `runCoordinated` for why. */
const COORDINATED_LEG_TIMEOUT_MS = 20_000;

/**
 * Run one coordinator transaction (durable decision + commit fan-out).
 *
 * ── PROCESS CONTRACT ────────────────────────────────────────────────────────
 * Every mutating leg goes through the transaction coordinator via this helper —
 * there is NO fire-and-forget or alternate error path. A leg that returns
 * 'aborted', throws, or exceeds `COORDINATED_LEG_TIMEOUT_MS` is treated as
 * a normal failure: the caller records it with `legFailed`, which backs off and
 * retries up to `VRC_CEREMONY_MAX_ATTEMPTS` before marking the session failed.
 *
 * The timeout is essential: `ctx.txManager.run` awaits BOTH the durable
 * decision AND the commit fan-out to remote participants, and over a circuit-relay
 * tunnel the remote `tx_commit_result` can lag or (rarely) be lost. Without a
 * bound, a hung commit left the leg pending indefinitely; combined with the timer
 * driven driver it cascaded into duplicate coordinator transactions for the SAME leg
 * (the multi-tx retry storm / log flood seen on slow WAN). Racing the whole leg
 * with a timeout converts "never resolves" into the correct self-healing path:
 * `legFailed` → exponential backoff (`VRC_CEREMONY_BACKOFF_MS`) → up to
 * `VRC_CEREMONY_MAX_ATTEMPTS` → session `failed` surfaced to the UI.
 */
async function runCoordinated(
  ctx: CeremonyContext,
  fn: (tx: import('../tx/transaction.js').Transaction) => Promise<void>,
): Promise<'committed' | 'aborted'> {
  try {
    const result = await withTimeout(
      ctx.txManager.run(fn),
      COORDINATED_LEG_TIMEOUT_MS,
      `coordinated leg timed out after ${COORDINATED_LEG_TIMEOUT_MS}ms`,
    );
    logger.info(`[ceremony] coordinated leg outcome=${result.outcome}`);
    return result.outcome;
  } catch (err) {
    const msg = (err as Error)?.message ?? String(err);
    logger.error('[ceremony] coordinated leg failed:', msg);
    return 'aborted';
  }
}

/**
 * Resolve `p` unless it settles before `ms`; otherwise reject with `message`.
 * The underlying promise's timer/reject path is cleared when `p` settles first so
 * a stale timeout can never fire after a legitimate completion.
 */
function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    p.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

/** Fetch the locally-minted VRC's w3c_vc_json for this peer. */
function getLocalVc(
  ctx: CeremonyContext,
  session: VrcCeremonySession,
  myDid: string,
): string | null {
  const local = ctx.resolver.lookupByDid(myDid);
  const remote = ctx.resolver.lookupByDid(session.remoteDid);
  if (!local || !remote) return null;
  const row = ctx.db.prepare(
    `SELECT w3c_vc_json FROM credentials
     WHERE issuer_identity_uuid = ? AND subject_identity_uuid = ?
       AND vc_type = 'vrc' AND status = 'issued' AND w3c_vc_json IS NOT NULL
     ORDER BY created_at DESC LIMIT 1`,
  ).get(local.identityUuid, remote.identityUuid) as { w3c_vc_json: string | null } | undefined;
  return row?.w3c_vc_json ?? null;
}

/** Count vrc credential rows minted for this session, regardless of w3c_vc_json. */
function countLocalVrcRows(
  ctx: CeremonyContext,
  session: VrcCeremonySession,
  myDid: string,
): number {
  const local = ctx.resolver.lookupByDid(myDid);
  const remote = ctx.resolver.lookupByDid(session.remoteDid);
  if (!local || !remote) return 0;
  const row = ctx.db.prepare(
    `SELECT COUNT(*) AS n FROM credentials
     WHERE issuer_identity_uuid = ? AND subject_identity_uuid = ?
       AND vc_type = 'vrc'`,
  ).get(local.identityUuid, remote.identityUuid) as { n: number } | undefined;
  return Number(row?.n ?? 0);
}

/**
 * Record a leg failure, schedule a retry (or mark failed when the attempt cap
 * is reached) and surface it via the failure hook.
 */
async function legFailed(
  ctx: CeremonyContext,
  session: VrcCeremonySession,
  step: string,
  error: string,
): Promise<VrcCeremonyStepResult> {
  const idx = Math.min(session.attempt, VRC_CEREMONY_BACKOFF_MS.length - 1);
  const delay = VRC_CEREMONY_BACKOFF_MS[idx];
  const updated = await ctx.ceremonyStore.recordFailure(
    session.sessionId, step, error, delay, VRC_CEREMONY_MAX_ATTEMPTS,
  );
  if (updated.phase === 'failed') {
    logger.error(`[ceremony] failed at step ${step}: ${error}`);
    ctx.onCeremonyFailed?.(session.remoteDid, step, error);
  } else {
    logger.warn(`[ceremony] step ${step} attempt ${updated.attempt} failed (retry in ${delay}ms): ${error}`);
  }
  return { advanced: false, phase: updated.phase, step, error };
}

/**
 * Build the local agent's full identity record to share with the peer during
 * VRC sharing (Leg 2). Includes every `identities` row field plus the linked
 * DID document, method, CESR VID and public keys, so the receiver can populate
 * its local `identities` table without inventing any data.
 *
 * The receiver re-derives the row key (deterministic UUIDv5 of the real DID) so
 * this node's `uuid` remains the selection key for other code, and forces
 * `custody='remote'` because the receiver neither created nor controls the
 * record. The `custody` value here is informational only for the sender.
 */
function buildIdentityRecord(
  ctx: CeremonyContext,
  myDid: string,
): Record<string, unknown> {
  const local = ctx.resolver.lookupByDid(myDid);
  let row: Record<string, unknown> | undefined;
  if (local) {
    row = ctx.db.prepare(
      `SELECT i.uuid, i.role, i.subject_kind, i.custody, i.name,
              i.dtg_subtype, i.bootstrap_peer_id,
              i.bootstrap_url, i.recorded_by_node, i.replicated_at,
              i.created_at, dd.did AS realDid, dd.method,
              (SELECT pe.peer_id FROM peer_endpoints pe
                 WHERE pe.identity_uuid = i.uuid AND pe.is_active = 1
                 ORDER BY pe.updated_at DESC, pe.created_at DESC LIMIT 1) AS active_peer_id,
              dd.uuid AS did_document_uuid
       FROM identities i
       LEFT JOIN did_documents dd ON dd.identity_uuid = i.uuid AND dd.is_primary = 1
       WHERE i.uuid = ?`,
    ).get(local.identityUuid) as Record<string, unknown> | undefined;
  }
  const realDid = (row?.realDid as string | undefined) ?? myDid;

  return {
    uuid: (row?.uuid as string) ?? generateUuid(),
    realDid,
    did: realDid,
    method: (row?.method as string | undefined) ?? 'peer4',
    name: row?.name ?? null,
    role: (row?.role as string | undefined) ?? 'vta',
    subjectKind: (row?.subject_kind as string | undefined) ?? 'human',
    custody: (row?.custody as string | undefined) ?? 'local',
    // Source the libp2p endpoint from the normalized peer_endpoints table
    // (active). This prevents a stale/shared column value from being
    // propagated to the peer during identity sharing.
    peerId: (row?.active_peer_id as string | null | undefined) ?? null,
    dtgSubtype: row?.dtg_subtype ?? null,
    bootstrapPeerId: row?.bootstrap_peer_id ?? null,
    bootstrapUrl: row?.bootstrap_url ?? null,
    recordedByNode: row?.recorded_by_node ?? null,
    replicatedAt: row?.replicated_at ?? null,
    createdAt: row?.created_at ?? null,
    vid: ctx.identity.cesrVid,
    didDocument: ctx.identity.didDocument,
    publicKeys: {
      ed25519: Buffer.from(ctx.identity.signingKeyPair.publicKey).toString('base64'),
      x25519: Buffer.from(ctx.identity.agreementKeyPair.publicKey).toString('base64'),
    },
  };
}

/** Build a minimal `identity_push` payload carrying the just-minted VRC. */
async function buildIdentityPushPayload(
  ctx: CeremonyContext,
  session: VrcCeremonySession,
): Promise<Record<string, unknown>> {
  const local = ctx.resolver.lookupByDid(ctx.identity.did);
  const remote = ctx.resolver.lookupByDid(session.remoteDid);
  const creds: Array<Record<string, unknown>> = [];
  const sigs: Array<Record<string, unknown>> = [];
  if (local && remote) {
    const cred = ctx.db.prepare(
      `SELECT * FROM credentials
       WHERE issuer_identity_uuid = ? AND subject_identity_uuid = ? AND vc_type = 'vrc'
         AND w3c_vc_json IS NOT NULL
       ORDER BY created_at DESC LIMIT 1`,
    ).get(local.identityUuid, remote.identityUuid) as Record<string, unknown> | undefined;
    if (cred) {
      creds.push({
        uuid: cred.uuid,
        vcType: cred.vc_type,
        issuerIdentityUuid: cred.issuer_identity_uuid,
        subjectIdentityUuid: cred.subject_identity_uuid,
        w3cVcJson: cred.w3c_vc_json,
        claim: cred.claim,
        status: cred.status,
        thresholdRequired: cred.threshold_required,
        validFrom: cred.valid_from,
        validUntil: cred.valid_until,
        credentialDigest: cred.credential_digest,
        createdAt: cred.created_at,
      });
      const sigRows = ctx.db.prepare(
        'SELECT s.* FROM credential_signatures s WHERE s.credential_uuid = ?',
      ).all(cred.uuid as string) as Array<Record<string, unknown>>;
      for (const s of sigRows) {
        const signer = ctx.db.prepare('SELECT uuid FROM identities WHERE uuid = ?')
          .get((s as { signer_identity_uuid: string }).signer_identity_uuid) as { uuid: string } | undefined;
        if (signer) {
          sigs.push({
            credentialUuid: cred.uuid,
            signerIdentityUuid: signer.uuid,
            signature: Buffer.from(s.signature as Buffer).toString('base64'),
            signedAt: s.signed_at,
          });
        }
      }
    }
  }

  // Resolve the local agent's libp2p peerId so the identity_push carries it.
  // This is sourced from the ACTIVE peer_endpoints row (the live node key),
  // falling back to the legacy identities.peer_id mirror only when no endpoint
  // row exists. The server's createRemoteVta records the endpoint on any
  // pre-existing stub, turning an agent that first appeared as a TSP-bridge
  // fake into a real VTA.
  let localPeerId: string | null = null;
  if (local) {
    const lr = ctx.db.prepare(
      `SELECT (SELECT pe.peer_id FROM peer_endpoints pe
                WHERE pe.identity_uuid = i.uuid AND pe.is_active = 1
                ORDER BY pe.updated_at DESC, pe.created_at DESC LIMIT 1) AS active_peer_id
       FROM identities i WHERE i.uuid = ?`,
    ).get(local.identityUuid) as { active_peer_id: string | null } | undefined;
    localPeerId = lr?.active_peer_id ?? null;
  }

  // Resolve the peer's peerId for the relationship record (best-effort).
  let remotePeerId: string | null = null;
  if (remote) {
    const rr = ctx.db.prepare(
      `SELECT (SELECT pe.peer_id FROM peer_endpoints pe
                WHERE pe.identity_uuid = i.uuid AND pe.is_active = 1
                ORDER BY pe.updated_at DESC, pe.created_at DESC LIMIT 1) AS active_peer_id
       FROM identities i WHERE i.uuid = ?`,
    ).get(remote.identityUuid) as { active_peer_id: string | null } | undefined;
    remotePeerId = rr?.active_peer_id ?? null;
  }

  return {
    realDid: ctx.identity.did,
    name: (ctx.identity as { name?: string }).name,
    subjectKind: 'human',
    peerId: localPeerId ?? undefined,
    didDocument: ctx.identity.didDocument,
    publicKeys: {
      ed25519: Buffer.from(ctx.identity.signingKeyPair.publicKey).toString('base64'),
      x25519: Buffer.from(ctx.identity.agreementKeyPair.publicKey).toString('base64'),
    },
    credentials: creds.length > 0 ? creds : undefined,
    credentialSignatures: sigs.length > 0 ? sigs : undefined,
    // Persist the established bidirectional relationship so the utility
    // server's `relationships` table reflects the VRC pair (createVtc's
    // hasEstablishedVrcBetween governance check reads it there).
    ...(local && remote
      ? {
          relationship: {
            localUuid: local.identityUuid,
            remoteUuid: remote.identityUuid,
            remotePeerId: remotePeerId ?? undefined,
          },
        }
      : {}),
  };
}
