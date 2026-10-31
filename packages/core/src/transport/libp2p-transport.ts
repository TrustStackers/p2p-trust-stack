// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Libp2p-backed implementation of TspTransport — Step 0 (hardened in Step 5).
 *
 * ## Step 5 hardening
 *
 * All three Step 5 tasks are addressed here:
 *
 * **5.1 — Protocol registration:**
 *   - `/tsp/1.0.0` is registered via `node.handle()` with `runOnLimitedConnection: true`.
 *   - `dialProtocol` is called with an `AbortSignal` derived from the send timeout.
 *
 * **5.2 — CESR-framed length-prefixed framing:**
 *   - `lpStream` is used on both inbound and outbound paths.
 *   - `maxDataLength` is set to `options.maxMessageBytes` on every `lpStream()` call,
 *     bounding frame sizes and preventing memory exhaustion from oversized frames.
 *
 * **5.3 — Stream lifecycle (open/close/timeout/backpressure):**
 *   - `send()` is wrapped in an `AbortController` timer; throws `TransportTimeoutError`
 *     if the dial + write + close does not complete within `sendTimeoutMs`.
 *   - Outbound messages larger than `maxMessageBytes` are rejected before dialing
 *     (throws `TransportFrameTooLargeError`).
 *   - Each inbound stream handler runs an idle-read timer; if no frame arrives within
 *     `idleTimeoutMs`, the stream is aborted to free the stream slot.
 *
 * ## Configuration
 *
 * All lifecycle knobs are optional constructor parameters with sensible defaults:
 *   - `maxMessageBytes` — default 1 MiB
 *   - `sendTimeoutMs`   — default 10 s
 *   - `idleTimeoutMs`   — default 30 s
 */

import type { Libp2p } from 'libp2p';
import type { Stream, Connection } from '@libp2p/interface';
import { peerIdFromString } from '@libp2p/peer-id';
import { lpStream } from '@libp2p/utils';
import type { TspTransport, TransportAddress, Libp2pTransportOptions } from './types.js';
import { TransportTimeoutError, TransportFrameTooLargeError } from './types.js';
import { logger } from '../util/logger.js';


/** The dedicated TSP protocol identifier. */
export const TSP_PROTOCOL = '/tsp/1.0.0';

// ---------------------------------------------------------------------------
// Default option values
// ---------------------------------------------------------------------------

const DEFAULT_MAX_MESSAGE_BYTES = 1_048_576; // 1 MiB
const DEFAULT_SEND_TIMEOUT_MS = 10_000;      // 10 seconds
const DEFAULT_IDLE_TIMEOUT_MS = 30_000;      // 30 seconds

// ---------------------------------------------------------------------------
// Libp2pTransport
// ---------------------------------------------------------------------------

/**
 * Libp2p-backed implementation of TspTransport.
 *
 * Accepts an already-created Libp2p node via constructor (dependency injection).
 * All TSP message-layer code should import TspTransport, never Libp2p directly.
 */
export class Libp2pTransport implements TspTransport {
  private messageHandler?: (message: Uint8Array, fromAddr: TransportAddress) => void;
  private node: Libp2p;
  private readonly options: Required<Libp2pTransportOptions>;

  constructor(node: Libp2p, options?: Libp2pTransportOptions) {
    this.node = node;
    this.options = {
      maxMessageBytes: options?.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES,
      sendTimeoutMs: options?.sendTimeoutMs ?? DEFAULT_SEND_TIMEOUT_MS,
      idleTimeoutMs: options?.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS,
    };
  }

  // ---------------------------------------------------------------------------
  // isConnected — check if libp2p has an active connection to a peer
  // ---------------------------------------------------------------------------

  isConnected(peerId: string): boolean {
    try {
      const nodeWithConns = this.node as unknown as {
        getConnections: (peerId: unknown) => Array<{ status: string }>;
      };
      const peerIdObj = peerIdFromString(peerId);
      const conns = nodeWithConns.getConnections?.(peerIdObj) ?? [];
      // libp2p connections may report status 'open' | 'closing' | 'closed'
      return conns.some(c => c.status === 'open' || c.status === 'closing');
    } catch {
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // getPeerMultiaddrs — get current multiaddrs for a peer from libp2p's view
  // ---------------------------------------------------------------------------

  getPeerMultiaddrs(peerId: string): string[] | undefined {
    try {
      const nodeWithConns = this.node as unknown as {
        getConnections: (peerId: unknown) => Array<{ remoteAddr: { toString(): string }; status: string }>;
      };
      const peerIdObj = peerIdFromString(peerId);
      const conns = nodeWithConns.getConnections?.(peerIdObj) ?? [];
      const activeConns = conns.filter(c => c.status === 'open' || c.status === 'closing');
      if (activeConns.length === 0) return undefined;
      return activeConns.map(c => c.remoteAddr.toString());
    } catch {
      return undefined;
    }
  }

  // ---------------------------------------------------------------------------
  // start() — register the /tsp/1.0.0 protocol handler (Task 5.1 + 5.2 + 5.3)
  // ---------------------------------------------------------------------------

  /**
   * Register the /tsp/1.0.0 protocol handler on the underlying libp2p node.
   *
   * Each inbound stream is wrapped with lpStream (maxDataLength bounded) and
   * guarded by an idle-read timeout. If no frame arrives within idleTimeoutMs,
   * the stream is aborted to free the stream slot.
   */
  async start(): Promise<void> {
    await this.node.handle(
      TSP_PROTOCOL,
      async (stream: Stream, connection: Connection) => {
        const lp = lpStream(stream, { maxDataLength: this.options.maxMessageBytes });
        let idleTimer: ReturnType<typeof setTimeout> | undefined;

        const resetIdleTimer = () => {
          clearTimeout(idleTimer);
          idleTimer = setTimeout(() => {
            // Abort the stream if it has been idle for too long.
            stream.abort(new Error('TSP stream idle timeout'));
          }, this.options.idleTimeoutMs);
        };

        // Start the idle clock immediately on stream open.
        resetIdleTimer();

        try {
          while (true) {
            const data = await lp.read();
            if (data === null) break;
            // Reset the idle timer on every successful frame read.
            resetIdleTimer();
            const peerId = connection.remotePeer.toString();
            // An INBOUND connection's remoteAddr is the peer's SOURCE address — for a NAT'd
            // agent an ephemeral outbound port where nothing listens (the field log's
            // 60950/60964/60981/… dials). Prefer the addresses the peer ADVERTISED (peer
            // store: bootstrap registration, identify, or our own successful dials), and fall
            // back to the observed address only when nothing is known — on a plain LAN the
            // source address IS the listen address, and reply dials rely on it.
            let multiaddrs: string[] = [];
            try {
              const known = await this.node.peerStore.get(connection.remotePeer);
              multiaddrs = (known?.addresses ?? []).map((a) => a.multiaddr.toString());
            } catch { /* no address-book entry for this peer yet */ }
            this.dispatchMessage(data.subarray(), {
              peerId,
              multiaddrs: multiaddrs.length > 0 ? multiaddrs : [connection.remoteAddr.toString()],
            });
          }
        } catch {
          // Stream closed or aborted — expected on peer disconnect or idle timeout.
        } finally {
          clearTimeout(idleTimer);
        }
      },
      { runOnLimitedConnection: true },
    );
  }

  // ---------------------------------------------------------------------------
  // stop() — unregister the /tsp/1.0.0 protocol handler
  // ---------------------------------------------------------------------------

  /**
   * Unregister the /tsp/1.0.0 protocol handler.
   */
  async stop(): Promise<void> {
    await this.node.unhandle(TSP_PROTOCOL);
  }

  // ---------------------------------------------------------------------------
  // send() — timeout-wrapped dial + write + close (Task 5.3)
  // ---------------------------------------------------------------------------

  /**
   * Send a raw TSP message to a remote peer.
   *
   * Performs an early size check before dialing. The entire dial + write + close
   * sequence is wrapped in an AbortController timer; if it does not complete
   * within sendTimeoutMs, the stream is aborted and TransportTimeoutError is thrown.
   *
   * @throws TransportFrameTooLargeError if message.length > maxMessageBytes
   * @throws TransportTimeoutError if the operation exceeds sendTimeoutMs
   */
  async send(message: Uint8Array, remoteAddr: TransportAddress): Promise<void> {
    // Early size check — reject before dialing to avoid wasting a connection.
    if (message.length > this.options.maxMessageBytes) {
      throw new TransportFrameTooLargeError(message.length, this.options.maxMessageBytes);
    }

    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.options.sendTimeoutMs);

    try {
      const peerId = peerIdFromString(remoteAddr.peerId);
      const peerIdShort = peerId.toString().slice(0, 12);
      const addrs = remoteAddr.multiaddrs?.join(', ') ?? 'none';
      logger.debug(`[Libp2pTransport] → dialing peerId=${peerIdShort}... addrs=[${addrs}] msgBytes=${message.length}`);

      // If explicit multiaddrs are given, add them to the peer store so libp2p
      // can dial them even if it hasn't discovered this peer via mDNS/DHT yet.
      //
      // MERGE, not patch. An inbound connection's `multiaddrs` is the peer's SOURCE
      // address — for a NAT'd agent an ephemeral outbound port (the field log's
      // 60950/60964/60981/… ports, where nothing listens). `patch()` REPLACED the peer's
      // advertised addresses with that dead hint, so every later `dialProtocol(peerId)`
      // tried it and got `connect ECONNREFUSED`, which the 5s retry loop then repeated
      // forever. Merging keeps the advertised addresses and treats the hint as one more
      // candidate, so a bad hint can no longer erase a good address.
      if (remoteAddr.multiaddrs && remoteAddr.multiaddrs.length > 0) {
        const { multiaddr } = await import('@multiformats/multiaddr');
        await this.node.peerStore.merge(peerId, {
          multiaddrs: remoteAddr.multiaddrs.map((a) => multiaddr(a)),
        });
      }

      // Dial with the abort signal so the dial is cancelled on timeout.
      //
      // Bug fix: `runOnLimitedConnection: true` is REQUIRED here, not just on
      // the inbound `handle()` registration below. libp2p connections
      // established through a circuit relay (i.e. any peer reached via
      // `/p2p-circuit`, which is exactly how a peer on a different WAN/NAT
      // is reached before/without a direct hole-punched connection) are
      // "limited" connections (`connection.limits != null`). Both
      // `Connection.newStream()` (outbound, used internally by
      // `dialProtocol`) AND the inbound stream-accept path independently
      // check `options.runOnLimitedConnection !== true` and throw
      // `LimitedConnectionError('Cannot open protocol stream on limited
      // connection')` if it's missing — this check applies to the DIALING
      // side just as much as the DEDICATED handler side. Without this flag
      // here, every outbound `send()` over a relayed connection failed with
      // exactly this error, even after a relay circuit was successfully
      // established — this was the actual, final blocker for cross-WAN
      // reconnection, independent of the earlier bootstrap-server relay
      // address bugs (which were real, but only get a relay connection
      // OPENED; this flag is what allows a PROTOCOL STREAM to actually be
      // negotiated on top of that connection).
      const stream = await this.node.dialProtocol(peerId, TSP_PROTOCOL, {
        signal: ac.signal,
        runOnLimitedConnection: true,
      } as any);


      const lp = lpStream(stream, { maxDataLength: this.options.maxMessageBytes });
      await lp.write(message);

      // Close the stream; pass the abort signal so a hung close is also cancelled.
      await stream.close({ signal: ac.signal });
    } catch (err) {
      if (ac.signal.aborted) {
        throw new TransportTimeoutError('send', this.options.sendTimeoutMs);
      }

      // Stale-connection repair (B2): a "Cannot write to a stream that is
      // closed" / half-open TCP connection means libp2p cached a broken
      // connection and dialProtocol() returned a dead stream on it. Drop the
      // cached connection and peer-store addrs so the next dialProtocol builds
      // a FRESH connection. Best-effort — never mask the original error.
      const msg = (err as Error)?.message ?? String(err);
      // `ECONNREFUSED` belongs in this list for the same reason as the closed-stream cases:
      // it means the CACHED ADDRESS is dead (the peer re-bound its listening port), so the
      // entry must be invalidated or the 5s retry dials the same dead port forever — the
      // field loop seen on 2026-09-25 (`connect ECONNREFUSED 192.168.1.246:60981` repeated
      // with a new port each cycle). Clearing here is deliberate and does NOT contradict the
      // `merge()` in `send()`: a repair must remove a known-bad address, whereas a send-time
      // hint must never erase a good one.
      if (/stream that is closed|connection closed|ECONNRESET|ECONNREFUSED|connection refused|EHOSTUNREACH|ETIMEDOUT|LIMIT_EXCEEDED|reset/i.test(msg)) {
        await this.invalidatePeer(remoteAddr.peerId, 'stale-connection repair');
      }

      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  // ---------------------------------------------------------------------------
  // invalidatePeer() — drop a cached connection the transport can no longer trust
  // ---------------------------------------------------------------------------

  /**
   * Close libp2p's cached connection(s) to `peerId` and clear the peer-store
   * addresses that produced them, so the NEXT `dialProtocol` builds a fresh
   * connection instead of reusing a dead one. Best-effort: never throws.
   *
   * Called in two situations, both meaning "this peer's cached connection can no
   * longer be trusted":
   *
   *  1. A write failed with a closed-stream / refused / reset error (the
   *     pre-existing B2 repair, now shared through this method).
   *  2. A REQUEST to this peer timed out with no response (see the request
   *     adapters: `createServerTspRequestFn` and the agent's TspClientModule).
   *     This case matters because a half-open / black-holed connection does NOT
   *     fail the write: TCP accepts the bytes into its send buffer, `lp.write()`
   *     and `stream.close()` both resolve, and the frame never reaches the peer.
   *     Without invalidation the wedged connection is reused for EVERY later
   *     request, so one silent loss turns into an indefinite stream of 30s
   *     `TSP request … timed out` failures (the field log's prepare → yes, then
   *     commit/query/peer-prepare all timing out against the same peer).
   */
  async invalidatePeer(peerId: string, why = 'invalidated'): Promise<void> {
    try {
      const peerIdObj = peerIdFromString(peerId);
      const conns = (this.node as any).getConnections?.(peerIdObj) ?? [];
      for (const conn of conns) {
        try { await conn.close(); } catch { /* ignore */ }
      }
      try {
        await this.node.peerStore.patch(peerIdObj, { multiaddrs: [] });
      } catch { /* ignore */ }
      logger.debug(
        `[Libp2pTransport] ${why}: dropped cached connection/addrs to ${peerIdObj.toString().slice(0, 12)}...`,
      );
    } catch {
      // ignore repair failure — the caller's own error/timeout is what matters
    }
  }

  // ---------------------------------------------------------------------------
  // onMessage() — register the incoming message handler
  // ---------------------------------------------------------------------------

  /**
   * Dispatch one inbound frame to the registered handler WITHOUT letting a
   * handler failure escape this read loop.
   *
   * WHY THIS IS NOT A BARE CALL — and why it is deliberately NOT `await`ed.
   *
   * `onMessage()` handlers are written as `async` (the utility server's TSP
   * bridge is), so a bare call returns a promise nobody holds. A rejection inside
   * the handler is then an UNHANDLED REJECTION, and Node's default
   * (`--unhandled-rejections=throw`) escalates that to a fatal error — the
   * process exits.
   *
   * Observed 2026-10-29 on the utility server: a transient YugabyteDB error
   * (`XX000`, `tserver_shared_mem.cc`: "Timed out waiting kResponseSent, state:
   * kProcessingRequest") propagated out of the bridge's `routeProtocolMessage()`,
   * escaped the fire-and-forget dispatch, and terminated the server after ~a
   * night of otherwise-normal operation. A storage hiccup must not be fatal.
   *
   * It is NOT `await`ed on purpose: handler work is per-message and concurrent
   * by design, so awaiting here would serialise frames and back-pressure the
   * stream. This keeps the concurrency contract and adds only the missing error
   * boundary.
   */
  private dispatchMessage(message: Uint8Array, fromAddr: TransportAddress): void {
    let result: unknown;
    try {
      result = this.messageHandler?.(message, fromAddr);
    } catch (err) {
      // A handler that throws SYNCHRONOUSLY (before its first `await`) is the
      // same failure as a rejection, just delivered by a different mechanism.
      logger.error(
        `[Libp2pTransport] inbound handler threw peerId=${fromAddr.peerId.slice(0, 12)}...:`,
        (err as Error)?.message ?? err,
      );
      return;
    }
    // A handler may be sync (returns undefined) or async (returns a promise);
    // only a thenable can reject.
    if (result != null && typeof (result as PromiseLike<unknown>).then === 'function') {
      void (result as Promise<unknown>).catch((err: unknown) => {
        logger.error(
          `[Libp2pTransport] inbound handler failed peerId=${fromAddr.peerId.slice(0, 12)}...:`,
          (err as Error)?.message ?? err,
        );
      });
    }
  }

  /**
   * Register a handler for incoming TSP messages.
   * Replaces any previously registered handler.
   */
  onMessage(handler: (message: Uint8Array, fromAddr: TransportAddress) => void): void {
    this.messageHandler = handler;
  }

}

