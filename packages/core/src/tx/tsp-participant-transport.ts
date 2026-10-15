// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * TSP Participant Transport — bridges TxWireMessage ↔ TSP ProtocolMessage.
 *
 * Implements the ParticipantTransport interface using the existing TSP
 * protocol envelope (ProtocolMessage with protocol, correlationId, payload).
 *
 * Used by both agent and utility server to address remote participants
 * via their pids (peer:{vid}, server:{serverId}, etc.).
 *
 * Wire format:
 *   ProtocolMessage {
 *     protocol: msg.kind,        // e.g. 'tx_prepare', 'tx_commit'
 *     correlationId: <uuid>,     // for request/response matching
 *     payload: msg               // the TxWireMessage itself
 *   }
 */

import type { ParticipantTransport } from './participant.js';
import type { TxWireMessage } from './wire-protocol.js';
import { inboxKeyFor, inboxFingerprintFor } from './wire-protocol.js';
import { DurableInbox } from './delivery.js';
import { attachOperationProof } from './operation-proof.js';
import { signEd25519 } from '../crypto/primitives.js';
import type { DataSource } from '../db/data-source.js';

/**
 * Low-level send function that delivers a ProtocolMessage to a remote peer
 * and returns the response. Matches the signature of TspClientModule.request().
 */
export type TspRequestFn = (
  destination: string,
  protocol: string,
  payload: unknown,
  timeoutMs?: number,
) => Promise<{ protocol: string; correlationId?: string; payload: unknown }>;

/**
 * Optional connectivity check function.  Returns `true` when the transport
 * has an active connection to the peer identified by `pid`.
 */
export type ConnectivityCheckFn = (pid: string) => boolean;

export interface TspParticipantTransportOptions {
  /** Default request timeout (ms).  Default: 30_000. */
  defaultTimeoutMs?: number;
  /** Max time to wait for connectivity before sending (ms).  Default: 15_000. */
  connectivityTimeoutMs?: number;
  /** How often to poll connectivity (ms).  Default: 500. */
  connectivityPollMs?: number;
  /** Optional connectivity check function.  When provided, `send()` waits
   *  for the peer to be reachable before dispatching the wire message. */
  isConnected?: ConnectivityCheckFn;
  /**
   * Optional VID of the remote utility server.  When set, `server:*` pids
   * (e.g. 'server:us-1') are resolved to this VID instead of the raw
   * server id, which is a logical participant name and not a routable
   * RelationshipManager destination.
   */
  serverDid?: string;
}

/**
 * TspParticipantTransport — adapts a TSP request function to the
 * ParticipantTransport interface.
 *
 * Each TxWireMessage is wrapped in a ProtocolMessage envelope:
 *   { protocol: msg.kind, correlationId, payload: msg }
 *
 * The response is unwrapped from the ProtocolMessage payload.
 *
 * ## Connectivity pre-flight
 *
 * When `isConnected` is provided, `send()` polls it before dispatching the
 * wire message.  This prevents the transaction coordinator from timing out
 * while a circuit-relay tunnel is still being established.  The check is
 * performed on EVERY send (prepare, commit, abort, inquiry) so all future
 * coordinator users benefit automatically.
 */
export class TspParticipantTransport implements ParticipantTransport {
  private readonly request: TspRequestFn;
  private readonly defaultTimeoutMs: number;
  private readonly connectivityTimeoutMs: number;
  private readonly connectivityPollMs: number;
  private readonly isConnectedFn?: ConnectivityCheckFn;
  private readonly serverDid?: string;

  constructor(request: TspRequestFn, options: TspParticipantTransportOptions = {}) {
    this.request = request;
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 30_000;
    this.connectivityTimeoutMs = options.connectivityTimeoutMs ?? 15_000;
    this.connectivityPollMs = options.connectivityPollMs ?? 500;
    this.isConnectedFn = options.isConnected;
    this.serverDid = options.serverDid;
  }

  /** Implements the optional `ParticipantTransport.isConnected`. */
  isConnected(pid: string): boolean {
    if (!this.isConnectedFn) return true; // no checker → assume connected
    return this.isConnectedFn(pid);
  }

  async send(pid: string, msg: TxWireMessage): Promise<TxWireMessage> {
    // Extract the destination VID from the pid.
    // pid format: 'peer:{vid}' → vid, 'server:{serverId}' → serverId
    const destination = this.pidToDestination(pid);

    // ── Connectivity pre-flight ─────────────────────────────────────────
    // Wait for the peer's tunnel to be established before sending.
    // This is the standard step for ALL transaction coordinator messages
    // (prepare, commit, abort, inquiry) — any future coordinator user
    // automatically gets this protection.
    await this.waitForConnectivity(pid, destination);

    console.log(`[tx-tsp-transport] ${pid} ← ${msg.kind} (dest=${destination.slice(0, 12)}...)`);
    // F-010 / R1: attach the signed operation document. The final payload is signed
    // here because this is where `messageId` is already fixed — and because the
    // transport is the one component every coordinator path goes through, so no caller
    // has to remember. A caller-supplied proof wins (attachOperationProof is a no-op
    // then), and a runtime with no installed signer sends none, exactly as before.
    const outbound = attachOperationProof(msg, signEd25519);
    const response = await this.request(
      destination,
      outbound.kind,      // protocol field = the wire message kind
      outbound,           // payload = the wire message itself
      this.defaultTimeoutMs,
    );

    // The response payload is the TxWireMessage from the remote participant
    const result = response.payload as TxWireMessage;
    console.log(`[tx-tsp-transport] ${pid} → ${result.kind}`);
    return result;
  }

  /**
   * Poll `isConnectedFn` until the peer is reachable or the timeout expires.
   *
   * When no connectivity checker is configured this is a no-op (returns
   * immediately).  When the checker is present but the peer never becomes
   * reachable within the timeout, an error is thrown so the coordinator
   * can record the failure and retry later.
   */
  private async waitForConnectivity(pid: string, _destination: string): Promise<void> {
    if (!this.isConnectedFn) return; // no checker → skip

    // Fast path: already connected
    if (this.isConnectedFn(pid)) return;

    const deadline = Date.now() + this.connectivityTimeoutMs;
    let attempt = 0;

    console.log(`[tx-tsp-transport] waiting for connectivity to ${pid.slice(0, 12)}... (timeout=${this.connectivityTimeoutMs}ms)`);

    while (Date.now() < deadline) {
      attempt++;
      await new Promise(resolve => setTimeout(resolve, this.connectivityPollMs));

      if (this.isConnectedFn(pid)) {
        console.log(`[tx-tsp-transport] ✓ connectivity established to ${pid.slice(0, 12)}... after ${attempt} poll(s)`);
        return;
      }
    }

    const elapsed = this.connectivityTimeoutMs;
    throw new Error(
      `TspParticipantTransport: peer ${pid.slice(0, 12)}... not reachable after ${elapsed}ms ` +
      `(${attempt} poll(s)). The peer's circuit-relay tunnel may still be establishing. ` +
      `The transaction coordinator will retry on recovery.`,
    );
  }

  /**
   * Convert a participant pid to a transport destination.
   *
   * pid patterns:
   *   - 'peer:{vid}'            → vid (used as TSP destination)
   *   - 'server:{serverId}'     → serverId (used as TSP destination)
   *   - 'server:{serverId}/{shardId}' → serverId (future: route to shard)
   *   - 'local-db'              → throws (local participant, no transport needed)
   */
  private pidToDestination(pid: string): string {
    if (pid.startsWith('peer:')) {
      // Format: 'peer:{vid}:{peerId}' or 'peer:{vid}'
      // Return the full suffix so the transport can extract both VID and peerId.
      return pid.slice(5); // strip 'peer:' prefix, returns '{vid}:{peerId}' or '{vid}'
    }
    if (pid.startsWith('server:')) {
      const serverPart = pid.slice(7);
      const slashIdx = serverPart.indexOf('/');
      // 'server:{serverId}' pids are logical participant names, not routable
      // destinations.  When the caller configured the utility server's VID,
      // use it so the message routes through the RelationshipManager correctly.
      if (this.serverDid) return this.serverDid;
      return slashIdx >= 0 ? serverPart.slice(0, slashIdx) : serverPart;
    }
    if (pid === 'local-db') {
      throw new Error(
        'TspParticipantTransport: cannot send to local-db participant. ' +
        'Use InProcessParticipant for local operations.',
      );
    }
    return pid;
  }
}

/**
 * Create a response handler for inbound transaction wire messages.
 *
 * When an agent or server receives a ProtocolMessage with a tx_* protocol,
 * this function extracts the TxWireMessage from the payload and routes it
 * to the appropriate handler (typically the TransactionCoordinator).
 *
 * Returns a response TxWireMessage to send back, or null if the message
 * was a response to a pending request (handled by correlationId matching).
 */
export type TxInboundHandler = (
  msg: TxWireMessage,
  correlationId?: string,
) => Promise<TxWireMessage | null>;

/**
 * Wrap a TxInboundHandler as a TSP protocol message handler.
 *
 * The returned function can be registered with the existing TSP message
 * routing (TspBridge, TspClientModule.handleIncoming).
 */
export function createTxProtocolHandler(
  handler: TxInboundHandler,
): (protocol: string, payload: unknown, correlationId?: string) => Promise<{
  protocol: string;
  correlationId?: string;
  payload: unknown;
} | null> {
  return async (_protocol, payload, correlationId) => {
    const msg = payload as TxWireMessage;
    const response = await handler(msg, correlationId);
    if (!response) return null;
    return {
      protocol: response.kind,
      correlationId,
      payload: response,
    };
  };
}

/**
 * The deduped inbound seam, in the shape a RUNTIME needs (H7).
 *
 * `withInboundDedup` returns `TxWireMessage | null`, which conflates two very
 * different outcomes for a caller that has an "unhandled ⇒ store it as unrecognized"
 * fallback (both runtimes do): "the handler produced no response" and "this was a
 * replay we deliberately dropped". A replay must NOT fall through to that fallback —
 * storing a duplicate as unrecognised traffic is the very confusion H7 is about.
 *
 * **F-028:** a third outcome exists — `conflict`, for a message whose `(txId,
 * messageId)` was already delivered carrying a DIFFERENT document (see
 * `inboxFingerprintFor()`). It is neither a replay nor a delivery: the handler is not
 * invoked and the peer is not told the work was done.
 */
export interface DedupedTxInboundResult {
  /** True when the key was already known: the handler did NOT run. */
  duplicate: boolean;
  /** True when the key was known but carried a different document (F-028). */
  conflict: boolean;
  /** The handler's response, or null (never invoked, or genuinely no response). */
  response: TxWireMessage | null;
}

export function createDedupedTxInbound(
  handler: TxInboundHandler,
  ds: DataSource,
): (msg: TxWireMessage, correlationId?: string) => Promise<DedupedTxInboundResult> {
  const inbox = new DurableInbox(ds);

  return async (msg: TxWireMessage, correlationId?: string): Promise<DedupedTxInboundResult> => {
    const key = inboxKeyFor(msg);
    if (key === null) {
      // Pre-H7 peer, or a locally-built message: nothing to dedup on.
      return { duplicate: false, conflict: false, response: await handler(msg, correlationId) };
    }

    // `handleOnce` persists the key BEFORE running the closure (persist-before-respond)
    // and returns early — without running it — when the key is already known.
    const { duplicate, conflict, result } = await inbox.handleOnce<TxWireMessage | null>(
      key,
      () => handler(msg, correlationId),
      // F-028: the document being delivered, so "same key, different document" is
      // detected rather than acknowledged.
      { fingerprint: inboxFingerprintFor(msg) },
    );

    if (duplicate) {
      console.log(`[tx-inbox] duplicate ${msg.kind} suppressed (key ${key}) — handler not re-invoked`);
    }
    return { duplicate, conflict, response: result };
  };
}

/**
 * Wrap a TxInboundHandler with `(txId, messageId)` inbound dedup (H7 / decision D-4a).
 *
 * **Why this exists.** `DurableInbox` was exported and never constructed, so a
 * replayed inbound 2PC message was re-executed rather than deduped. Two sources
 * generate replays by design: the coordinator's `recover()` re-drive and the
 * outbox's retry on reconnect. The operations they carry are **not** idempotent in
 * general (mint VRC, store_remote_vrc, exchange:identity), so a replay could
 * double-apply.
 *
 * **Why not key on `txId`.** One txId legitimately carries several messages
 * (`tx_prepare` → `tx_commit` → `tx_inquiry`); a txId-keyed inbox would swallow the
 * `tx_commit` as a replay of the `tx_prepare` and silently strand the reservation.
 * The key is `(txId, messageId)` — see `inboxKeyFor()`.
 *
 * **What a duplicate returns.** `null`: no response. The handler is NOT re-invoked,
 * and this function deliberately does not fabricate a result the original handler
 * never produced (a cached-response inbox would be a different, larger mechanism —
 * `tx_inbox` records only the key and the delivery time). A coordinator that
 * retried because it never saw a response resolves the outcome through its own
 * inquiry path, which is exactly what that path is for.
 *
 * A message with **no `messageId`** passes straight through: there is no identity
 * to dedup on, and dropping unknown traffic to be safe would be the wrong failure
 * direction.
 *
 * Runtimes should prefer `createDedupedTxInbound` — see why in its comment.
 */
export function withInboundDedup(handler: TxInboundHandler, ds: DataSource): TxInboundHandler {
  const deduped = createDedupedTxInbound(handler, ds);
  return async (msg: TxWireMessage, correlationId?: string): Promise<TxWireMessage | null> => {
    return (await deduped(msg, correlationId)).response;
  };
}