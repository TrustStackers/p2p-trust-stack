// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Bootstrap Client — Client-side peer discovery via the bootstrap server.
 *
 * Connects to the bootstrap server using the /bootstrap/2.0.0 protocol,
 * registers the local peer, and discovers other peers for connection.
 *
 * Uses lpStream for length-prefixed framing (matching the server's protocol).
 *
 * ## Auto-reconnect with exponential backoff
 *
 * The keepalive loop detects when the connection to the bootstrap server is
 * lost (consecutive ping failures). When the threshold is reached, the client
 * enters a reconnect state and probes the bootstrap server with exponential
 * backoff (5s → 10s → 20s → 60s max). On success, it re-registers, restarts
 * keepalive, and emits a reconnected event.
 *
 * This is OS-independent — it uses TCP connection probes to the known bootstrap
 * server address, which is the most reliable cross-platform approach.
 */

import { lpStream } from '@libp2p/utils';
import { multiaddr } from '@multiformats/multiaddr';
import { peerIdFromString } from '@libp2p/peer-id';
import { RELAY_V2_HOP_CODEC } from '@libp2p/circuit-relay-v2';
import type { Libp2p, Connection, Stream } from '@libp2p/interface';
import { hasRelayReservation as nodeHasRelayReservation } from './relay-health.js';
import { reconnectAdvertiseAddrs } from './port-range.js';
import { logger } from '../util/logger.js';

// ---------------------------------------------------------------------------
// Bootstrap protocol constants
// ---------------------------------------------------------------------------
//
// NOTE: the bootstrap server's ADDRESS and PEER ID are deliberately NOT
// constants in this file. They are loaded from the component's `.env` through
// `src/config/bootstrap-env.ts` (written by `npm run init:bootstrap`) and passed
// to the constructor by the caller. This removes the hardcoded
// `mediator.fpndtg.com` address and the `process.env.BOOTSTRAP_SERVER_URL`
// override that used to live here.

/** The bootstrap protocol identifier. */
const BOOTSTRAP_PROTOCOL = '/bootstrap/2.0.0';

/**
 * The bootstrap KEEPALIVE protocol identifier.
 *
 * MUST match `BOOTSTRAP_KEEPALIVE_PROTOCOL` in
 * `bootstrap/server/bootstrap-protocol.ts`, which registers the ping→pong echo
 * handler on this exact codec. The client must NEGOTIATE this protocol on the
 * keepalive stream: writing a ping frame on a stream that was opened without
 * protocol negotiation never reaches the server's handler, so no pong can ever
 * come back and every tick is a false-negative failure.
 *
 * Not imported from `bootstrap/` — that package sits outside this project's
 * tsconfig `include` and is deployed separately.
 */
const BOOTSTRAP_KEEPALIVE_PROTOCOL = '/bootstrap/keepalive/1.0.0';

/** Keepalive ping cadence. */
const KEEPALIVE_INTERVAL_MS = 25_000;

/** Per-probe timeout for a ping→pong round trip. */
const KEEPALIVE_TIMEOUT_MS = 5_000;

/**
 * How often to re-assert the circuit-relay reservation if it is missing.
 *
 * Kept independent of the keepalive loop on purpose: the reservation is
 * DELETED by @libp2p/circuit-relay-v2 when the connection to the relay closes,
 * and the library does not re-listen on its own, so losing a reservation needs
 * its own recovery path that does not depend on ping health.
 */
const RELAY_MAINTENANCE_INTERVAL_MS = 60_000;

/**
 * How long to wait for the relay to advertise the circuit-relay HOP codec
 * before giving up on a reservation attempt.
 *
 * WHY: @libp2p/circuit-relay-v2 BLACKLISTS a peer for the lifetime of the node
 * when a reservation attempt fails with `UnsupportedProtocolError`
 * (transport/reservation-store.js: `relayFilter.add(peerId)` → later
 * "The relay was previously invalid"). A single attempt made before identify
 * has reported the relay's protocols therefore disables reservations on that
 * relay PERMANENTLY for this process — the exact "reservation can never be
 * re-established" failure mode. Waiting for the codec to appear costs a few
 * hundred ms; probing blindly costs the relay.
 */
const RELAY_HOP_WAIT_MS = 5_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A peer entry returned by the bootstrap server.
 *
 * **The dual-field contract (decision D-6a, 2026-09-24) — both fields are kept
 * deliberately, and neither substitutes for the other.**
 *
 * A peer is advertised under two identifiers because they serve different jobs
 * and have different lifetimes:
 *
 * - `vid` — the peer's **CESR-encoded Ed25519 public key** (a VID, not a DID).
 *   This is the permanent Slot-A identity key: it is decoupled from the
 *   `did:scid:vh` log, so it **survives a DID log roll**. It is what OOBI
 *   construction needs, and it is the stable handle for a peer whose DID has
 *   changed.
 * - `did` — the peer's **real DID**, the resolvable identity that the strict
 *   4-item OOBI carries and that the addressee check validates.
 *
 * `base-agent.ts` requires **both** before building an OOBI, and places each in
 * its own slot; dropping either would lose a real property rather than simplify
 * anything. The alternative (discovery on DIDs only) was considered and rejected:
 * it would make discovery hostage to DID-log rotation, which is exactly what the
 * decoupled TSP VID exists to avoid.
 *
 * The same two-part discrimination appears in the agent's own identity metadata
 * as `cesrVid` + `did` (`base-agent.ts`), which is the naming this contract
 * intends: the field that holds a key says so.
 */
export interface DiscoveredPeer {
  peerId: string;
  multiaddrs: string[];
  connected: boolean;
  reachable: boolean;
  /** Phase 8: Relay address through the bootstrap server for this peer.
        Used as a fallback when direct connection fails (NAT traversal via circuit relay). */
  relayAddr?: string;
  /** Peer type for role-based discovery (agent vs utility_server). */
  peerType?: string;
  /** CESR-encoded Ed25519 public key (VID) for OOBI construction. Permanent
   *  Slot-A key — survives a `did:scid:vh` log roll. NOT a DID. */
  vid?: string;
  /** The peer's real DID, carried by the strict 4-item OOBI. */
  did?: string;
  /** Network/group (namespace) this peer belongs to, e.g. 'p2pts'. */
  net?: string;
  /** The peer's user name (bootstrap-facing), resolvable as vta:<net>:<agentName>. */
  agentName?: string;
  /** True when the peer currently holds a circuit-relay reservation on the
   *  bootstrap/relay server (authoritative "reachable via relay" signal). */
  reachableViaRelay?: boolean;
  /** Reachability scope derived by the bootstrap (wan|dns|relay|lan|loopback|unknown). */
  reachableScope?: string;
}

/**
 * Response from the bootstrap server after register or query.
 */
export interface BootstrapResponse {
  type: 'registered' | 'query_result';
  serverPeerId: string;
  serverAddrs: string[];
  relayAddr?: string;
  /** The client's source address as seen by the bootstrap server. */
  clientSourceAddr?: string;
  peers: DiscoveredPeer[];
}

/**
 * Result of a bootstrap operation, with convenience methods.
 */
export interface BootstrapResult {
  response: BootstrapResponse;
  /** All peer IDs returned by the server. */
  peerIds: string[];
  /** Peers that are marked as connected (best candidates to dial). */
  connectedPeers: DiscoveredPeer[];
  /** Relay address through this bootstrap server (if available). */
  relayAddr?: string;
  /** The client's source address as seen by the bootstrap server (for network detection). */
  clientSourceAddr?: string;
  /** The underlying libp2p Connection to the bootstrap server (reused for keepalive). */
  bootstrapConnection?: Connection;
}

/**
 * Resolve the live libp2p Connection behind a dialed multiaddr.
 *
 * WHY THIS EXISTS: in @libp2p/interface v3 a `Stream` has NO `connection`
 * property (`stream.d.ts` exposes only id/protocol/status/close/abort/...), so
 * `this.bootstrapConnection = stream.connection` silently stored `undefined` on
 * every dial. Two consequences, both invisible:
 *
 *   1. `connectivity.ts` starts the keepalive only when
 *      `result.bootstrapConnection` is truthy — it never was, so the agent had
 *      NO liveness detection for the bootstrap link at all.
 *   2. `hasRelayReservation()` reported a meaningless value.
 *
 * The connection is looked up from the connection manager by the peer ID
 * encoded in the address that was actually dialed (`/p2p/<id>`), optionally
 * narrowed to the dialed remote address when several connections exist.
 */
function resolveConnectionForAddr(node: Libp2p, maStr: string): Connection | null {
  try {
    const components = multiaddr(maStr).getComponents();
    const p2p = [...components].reverse().find((c) => c.code === 421); // 421 = /p2p
    if (typeof p2p?.value !== 'string') return null;

    const peerId = peerIdFromString(p2p.value);
    const conns: Connection[] = (node as unknown as {
      getConnections?: (p?: unknown) => Connection[];
    }).getConnections?.(peerId) ?? [];
    if (conns.length === 0) return null;

    // Prefer an open connection, and among those one whose remote address
    // matches what we dialed (host/port), then fall back to the first.
    const open = conns.filter((c) => c.status === 'open');
    const pool = open.length > 0 ? open : conns;
    const hostPort = maStr.replace(/\/p2p\/[^/]+$/, '');
    return pool.find((c) => c.remoteAddr?.toString().startsWith(hostPort)) ?? pool[0];
  } catch {
    return null;
  }
}

/**
 * Bootstrap connection status changes emitted by the client.
 *
 * `relay-degraded` / `relay-restored` describe RELAY REACHABILITY, which is
 * independent of bootstrap reachability: the direct TCP/WS connection to the
 * bootstrap server can be perfectly healthy while the circuit-relay
 * reservation is missing (a peer in that state is readable/dialable by nobody
 * across a WAN, yet still shows as "connected"). Keeping them distinct stops
 * the UI from reporting a dead bootstrap when only relay is impaired.
 */
export type BootstrapStatus =
  | 'connected'
  | 'disconnected'
  | 'reconnected'
  | 'relay-degraded'
  | 'relay-restored';

/**
 * Configuration for the auto-reconnect behavior.
 */
export interface BootstrapReconnectOptions {
  /** Maximum consecutive keepalive failures before declaring connection lost. Default: 3 */
  maxKeepaliveFailures?: number;
  /** Initial backoff interval in milliseconds. Default: 5000 */
  initialBackoffMs?: number;
  /** Maximum backoff interval in milliseconds. Default: 60000 */
  maxBackoffMs?: number;
  /** Multiplier for exponential backoff. Default: 2.0 */
  backoffMultiplier?: number;
  /**
   * Keepalive ping cadence in milliseconds. Default: 25000.
   *
   * Exposed so a caller can tighten liveness detection (and so tests can drive
   * a probe without waiting 25 s) — the keepalive is the only liveness signal
   * for the bootstrap connection, so its cadence is operationally meaningful.
   */
  keepaliveIntervalMs?: number;
  /** Per-probe ping→pong timeout in milliseconds. Default: 5000. */
  keepaliveTimeoutMs?: number;
}

// ---------------------------------------------------------------------------
// BootstrapClient
// ---------------------------------------------------------------------------

export class BootstrapClient {
  private bootstrapUrl: string;
  private wsFallbackUrl: string;

  // Reconnect state machine
  private reconnectState: 'connected' | 'probing' | 'disconnected' = 'disconnected';
  private keepaliveFailures = 0;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private backoffMs = 5000;

  // Reconnect configuration
  private maxKeepaliveFailures = 3;
  private initialBackoffMs = 5000;
  private maxBackoffMs = 60000;
  private backoffMultiplier = 2.0;
  private keepaliveIntervalMs = KEEPALIVE_INTERVAL_MS;
  private keepaliveTimeoutMs = KEEPALIVE_TIMEOUT_MS;

  // Status callback
  private onStatus?: (status: BootstrapStatus, info: { message: string; attempts?: number }) => void;

  /**
   * The listen addresses this node most recently REGISTERED with.
   *
   * The reconnect probe re-advertises exactly these. It must not re-derive them
   * from the live node: `reconnectAdvertiseAddrs` falls back to
   * `filterDialableListenAddrs`, whose default port set is the AGENT range
   * (24000-24004), so a non-agent node (the utility server listens on 4003)
   * would re-register with NO addresses — leaving the bootstrap to publish only
   * the NAT source port it observed, which nothing listens on. See
   * `reconnectAdvertiseAddrs` in `port-range.ts` for the full failure mode.
   */
  private registeredMultiaddrs: string[] | undefined;

  /**
   * Create a bootstrap client.
   * @param bootstrapUrl - Full multiaddr of the bootstrap server (TCP). Defaults to the production bootstrap.
   * @param wsFallbackUrl - WebSocket fallback URL. Defaults to the production bootstrap WS URL.
   * @param options - Optional reconnect configuration.
   */
  constructor(bootstrapUrl?: string, wsFallbackUrl?: string, options?: BootstrapReconnectOptions) {
    // The address is REQUIRED and comes from the caller — typically
    // `buildBootstrapUrls(loadBootstrapEnv())` from `src/config/bootstrap-env.ts`.
    // There is deliberately no default: a hardcoded address (or a `process.env`
    // fallback) is exactly what this refactor removed. The WS fallback is
    // optional — when omitted, dialing is TCP-only.
    if (!bootstrapUrl) {
      throw new Error(
        'BootstrapClient: no bootstrap URL supplied. Load it with `loadBootstrapEnv()` ' +
        'from src/config/bootstrap-env.ts (run `npm run init:bootstrap` to create the .env).',
      );
    }
    this.bootstrapUrl = bootstrapUrl;
    this.wsFallbackUrl = wsFallbackUrl ?? '';

    if (options) {
      if (options.maxKeepaliveFailures != null) this.maxKeepaliveFailures = options.maxKeepaliveFailures;
      if (options.initialBackoffMs != null) this.initialBackoffMs = options.initialBackoffMs;
      if (options.maxBackoffMs != null) this.maxBackoffMs = options.maxBackoffMs;
      if (options.backoffMultiplier != null) this.backoffMultiplier = options.backoffMultiplier;
      if (options.keepaliveIntervalMs != null) this.keepaliveIntervalMs = options.keepaliveIntervalMs;
      if (options.keepaliveTimeoutMs != null) this.keepaliveTimeoutMs = options.keepaliveTimeoutMs;
      this.backoffMs = this.initialBackoffMs;
    }
  }

  /**
   * Register a callback for bootstrap connection status changes.
   */
  onStatusChange(handler: (status: BootstrapStatus, info: { message: string; attempts?: number }) => void): void {
    this.onStatus = handler;
  }

  /**
   * Get the primary (TCP) bootstrap server URL.
   */
  getBootstrapUrl(): string {
    return this.bootstrapUrl;
  }

  /**
   * Get the WebSocket fallback URL.
   */
  getWsUrl(): string {
    return this.wsFallbackUrl;
  }

  /**
   * Register this peer with the bootstrap server and discover other peers.
   *
   * @param node - The running libp2p node
   * @param multiaddrs - This peer's listen addresses to register
   * @returns Result with peer list and relay address
   */
  async register(
    node: Libp2p,
    multiaddrs: string[],
    peerType?: 'agent' | 'utility_server',
    vid?: string,
    identity?: { vtaUuid?: string; realDid?: string; name?: string; subjectKind?: string },
    designation?: { net?: string; agentName?: string; nameUri?: string; test?: boolean },
  ): Promise<BootstrapResult> {
    const peerId = node.peerId.toString();

    // Remember what we advertised: the reconnect probe re-registers with THIS
    // set rather than re-deriving it (see `registeredMultiaddrs`).
    this.registeredMultiaddrs = [...multiaddrs];

    const msgObj: Record<string, unknown> = {
      type: 'register',
      peerId,
      multiaddrs,
    };
    if (peerType) {
      msgObj.peerType = peerType;
    }
    if (vid) {
      msgObj.vid = vid;
    }
    if (identity) {
      msgObj.identity = identity;
    }
    // Designation: net/group, the user-facing name, and (for test peers) the
    // test flag. `agentName` is the configured USER name — sent even before name
    // registration has run, so the bootstrap always has a name to show.
    if (designation?.net) {
      msgObj.net = designation.net;
    }
    if (designation?.agentName) {
      msgObj.agentName = designation.agentName;
    }
    if (designation?.nameUri) {
      msgObj.nameUri = designation.nameUri;
    }
    if (designation?.test) {
      msgObj.test = true;
    }
    const msg = JSON.stringify(msgObj);

    const response = await this.sendRequest(node, msg);
    const result = this.parseResult(response);

    // Phase 10 fix: without an active circuit-relay reservation on the
    // bootstrap server, we are dial-only over the relay — the relay server
    // rejects any HOP CONNECT request aimed at us with NO_RESERVATION. This
    // is why cross-WAN reconnection silently failed while LAN peers (which
    // never need the relay) kept working. Establishing the reservation here
    // covers the initial register(), explicit re-register(), AND the
    // internal auto-reconnect probe below (which also calls register()).
    await this.ensureRelayReservation(node);

    return result;
  }

  /**
   * Query the bootstrap server for the current peer list (lighter weight, no registration).

   *
   * @param node - The running libp2p node
   * @returns Result with peer list
   */
  async query(node: Libp2p): Promise<BootstrapResult> {
    const msg = JSON.stringify({ type: 'query' });

    const response = await this.sendRequest(node, msg);
    return this.parseResult(response);
  }

  /**
   * Dial the bootstrap server and send a JSON message, returning the response as a string.
   * Tries TCP first, then falls back to WebSocket.
   */
  private async sendRequest(node: Libp2p, message: string): Promise<BootstrapResponse> {
    const encoder = new TextEncoder();
    const payload = encoder.encode(message);

    // Try TCP first
    try {
      return await this.dialAndSend(node, this.bootstrapUrl, payload);
    } catch (tcpErr) {
      // No WebSocket fallback configured — surface the TCP error directly
      // rather than dialing an empty address.
      if (!this.wsFallbackUrl) throw tcpErr;
      // TCP failed, try WebSocket fallback
      try {
        return await this.dialAndSend(node, this.wsFallbackUrl, payload);
      } catch (wsErr) {
        throw new Error(
          `Bootstrap connection failed (TCP: ${tcpErr instanceof Error ? tcpErr.message : 'unknown'}, ` +
          `WS: ${wsErr instanceof Error ? wsErr.message : 'unknown'})`,
        );
      }
    }
  }

  /**
   * The active connection to the bootstrap server (stored after first successful dial).
   * Reused for keepalive to avoid opening a second TCP connection.
   */
  private bootstrapConnection: Connection | null = null;

  /**
   * The multiaddr string that actually succeeded during the last dial (TCP or WS
   * fallback). Used to build the circuit-relay listen address so we reserve a
   * slot on the SAME bootstrap server we just connected through.
   */
  private lastConnectedUrl: string | null = null;

  /**
   * Whether a circuit-relay v2 reservation has been successfully established on
   * the bootstrap server. Without this, the bootstrap server's relay will reject
   * any HOP CONNECT request targeting this peer with NO_RESERVATION — meaning
   * peers on a different WAN/NAT can never reach us via `/p2p-circuit`, even
   * though direct LAN dials keep working fine (see @libp2p/circuit-relay-v2
   * server `handleConnect()`, which requires `reservationStore.get(dstPeer)`
   * to be non-null before forwarding a relayed connection).
   */
  private relayListenerEstablished = false;

  /**
   * Peer ID of the relay we reserved on (parsed from `lastConnectedUrl` at
   * register time). Needed to ask the circuit-relay transport whether a
   * reservation is ACTUALLY held, instead of trusting a cached boolean.
   */
  private relayPeerId: string | null = null;

  /**
   * Keepalive interval timer. Sends ping frames every 25 seconds.
   */
  private keepaliveInterval: ReturnType<typeof setInterval> | null = null;

  /**
   * Relay-reservation maintenance timer. Re-asserts the reservation when it has
   * been lost, independently of keepalive health.
   */
  private relayMaintenanceTimer: ReturnType<typeof setInterval> | null = null;

  /**
   * Set while a 'relay-degraded' status has been emitted for the current
   * outage, so the 60 s maintenance tick does not spam the same warning and so
   * recovery can emit exactly one 'relay-restored'.
   */
  private relayDegradedNotified = false;

  /**
   * Dial a specific multiaddr, send a message via lpStream, and read the response.
   * Stores the Connection reference for reuse (keepalive runs on same TCP connection).
   */
  private async dialAndSend(node: Libp2p, maStr: string, payload: Uint8Array): Promise<BootstrapResponse> {
    // Dial the bootstrap server using its multiaddr (wrap string in Multiaddr object).
    // runOnLimitedConnection: true is defensive here — the bootstrap server dial
    // is normally direct, but if it is ever reached via a relayed/limited
    // connection (e.g. future relay-of-relay topologies), this avoids the same
    // LimitedConnectionError class of bug fixed elsewhere in this session.
    const stream = await (node as any).dialProtocol(multiaddr(maStr), BOOTSTRAP_PROTOCOL, {
      runOnLimitedConnection: true,
    });


    // Store the connection reference for keepalive reuse (same TCP connection).
    //
    // NOT `stream.connection` — a Stream has no such property in
    // @libp2p/interface v3 (see resolveConnectionForAddr). Assigning from it made
    // every keepalive/relay-reservation consumer see `undefined`.
    this.bootstrapConnection = resolveConnectionForAddr(node, maStr);
    if (this.bootstrapConnection == null) {
      this.onStatus?.('relay-degraded', {
        message:
          'Dialed the bootstrap server but could not resolve the connection object — ' +
          'keepalive and relay-reservation checks will be unavailable until the next dial.',
      });
    }

    // Remember which address actually worked (TCP vs WS fallback) so the
    // circuit-relay reservation dials the SAME server we just connected to.
    this.lastConnectedUrl = maStr;


    const lp = lpStream(stream, { maxDataLength: 65536 });

    // Send the request
    await lp.write(payload);

    // Read the response
    const data = await lp.read();
    if (data === null) {
      throw new Error('Bootstrap server closed connection before responding');
    }

    // Close the stream only — the underlying TCP connection stays alive for keepalive
    try {
      await stream.close();
    } catch {
      // Stream may already be closed
    }

    // Parse the response
    const response = JSON.parse(new TextDecoder().decode(data.slice(0, data.length)));
    return response as BootstrapResponse;
  }

  /**
   * Start the keepalive ping loop on the existing bootstrap connection.
   * Reuses the same TCP connection from the registration dial — no new connection opened.
   * Sends a ping frame every 25 seconds; server responds with pong.
   *
   * After maxKeepaliveFailures consecutive failures, triggers auto-reconnect
   * with exponential backoff probe to the bootstrap server.
   */
  startKeepalive(node: Libp2p): void {
    // Restartable by design. The previous implementation early-returned when an
    // interval already existed, so a successful reconnect could never reset
    // `reconnectState` / `keepaliveFailures` and the loop kept running against
    // stale state. Clear first, then start clean.
    this.stopKeepaliveInterval();

    this.keepaliveFailures = 0;
    this.reconnectState = 'connected';

    this.keepaliveInterval = setInterval(() => {
      void this.probeKeepalive(node);
    }, this.keepaliveIntervalMs);

    // Relay reservation maintenance runs on its own cadence — see
    // RELAY_MAINTENANCE_INTERVAL_MS for why it is not part of the ping loop.
    this.startRelayMaintenance(node);
  }

  /**
   * One keepalive probe: negotiate `/bootstrap/keepalive/1.0.0` on the EXISTING
   * connection (no new TCP connection) and expect a pong.
   *
   * Two bugs are fixed here relative to the previous implementation:
   *
   *  1. `connection.openStream()` does not exist on a libp2p Connection — the
   *     interface only has `newStream(protocols, options)`. Calling it threw a
   *     TypeError on every tick, so the loop could never report success and the
   *     agent's "disconnected/reconnected" status was noise rather than signal.
   *  2. Even with a real stream, the ping must be sent on the KEEPALIVE
   *     protocol codec, because that is where the server registered its
   *     ping→pong echo (`handleKeepaliveStream` in bootstrap-protocol.ts). A
   *     stream opened without protocol negotiation is never dispatched to that
   *     handler, so no pong could ever arrive.
   */
  private async probeKeepalive(node: Libp2p): Promise<void> {
    if (!node) return;

    const conn = this.bootstrapConnection;
    if (conn == null || (conn as { status?: string }).status !== 'open') {
      // No usable connection — fail fast rather than waiting out the timeout.
      this.registerKeepaliveFailure(node, 'bootstrap connection is not open');
      return;
    }

    let stream: Stream | undefined;
    try {
      stream = await conn.newStream(BOOTSTRAP_KEEPALIVE_PROTOCOL, {
        signal: AbortSignal.timeout(this.keepaliveTimeoutMs),
        runOnLimitedConnection: true,
      } as any);

      const lp = lpStream(stream, { maxDataLength: 1024 });
      const ping = new TextEncoder().encode(JSON.stringify({ type: 'ping', ts: Date.now() }));
      await lp.write(ping);

      // Read the pong. `lp.read()` on its own can hang if the stream dies
      // mid-read, so the read is raced against an explicit timeout.
      const pong = await Promise.race([
        lp.read(),
        new Promise<null>((_, reject) =>
          setTimeout(() => reject(new Error('keepalive timeout')), this.keepaliveTimeoutMs),
        ),
      ]);

      if (pong == null) {
        throw new Error('keepalive: server closed the keepalive stream without a pong');
      }

      // Success — the connection is genuinely alive.
      this.keepaliveFailures = 0;
    } catch (err) {
      this.registerKeepaliveFailure(
        node,
        err instanceof Error ? err.message : 'unknown keepalive error',
      );
    } finally {
      if (stream) {
        try {
          await stream.close();
        } catch {
          // Already closed by the failure path — nothing to do.
        }
      }
    }
  }

  /**
   * Record a keepalive failure and, once the threshold is crossed, declare the
   * bootstrap connection lost and start the reconnect probe.
   */
  private registerKeepaliveFailure(node: Libp2p, reason: string): void {
    this.keepaliveFailures++;

    // Log the FIRST failure of a run at warn level: the keepalive is the only
    // liveness signal, so "it failed" is actionable and the reason was
    // previously discarded entirely (the old loop swallowed it in a bare
    // `catch {}`), leaving an operator with nothing to diagnose.
    if (this.keepaliveFailures === 1) {
      logger.warn(`[bootstrap-client] keepalive probe failed: ${reason}`);
    }

    if (this.reconnectState === 'connected' && this.keepaliveFailures >= this.maxKeepaliveFailures) {
      this.reconnectState = 'disconnected';
      this.onStatus?.('disconnected', {
        message: `Bootstrap connection lost after ${this.keepaliveFailures} keepalive failures (${reason})`,
      });
      this.startReconnectProbe(node);
    }
  }

  /**
   * Start the exponential backoff reconnect probe.
   * Tries to re-register with the bootstrap server; on success restarts keepalive.
   */
  private startReconnectProbe(node: Libp2p): void {
    if (this.reconnectTimer) return; // Already probing

    this.reconnectState = 'probing';
    this.reconnectAttempts++;

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;

      try {
        // Filter out relay circuit addresses — these are internally
        // generated by ensureRelayReservation() and should not be sent
        // as direct-dial endpoints to the bootstrap server. Relay
        // reachability is communicated separately via the server's
        // relayAddr field.
        // Advertise only addresses this node can be DIALED on — its own listen ports.
        // `getMultiaddrs()` also returns OBSERVED addresses, which for a NAT'd agent are
        // ephemeral source ports where nothing listens; advertising one made peers dial a dead
        // port on a 5s loop (`connect ECONNREFUSED 192.168.1.246:60981`, field log 2026-09-25).
        // Relay circuits stay excluded as before — the server carries those in `relayAddr`.
        //
        // The set we ALREADY registered wins over a fresh derivation: re-deriving
        // would apply `filterDialableListenAddrs`'s AGENT port default (24000-24004)
        // to a non-agent node and drop every address (the utility server listens on
        // 4003), so the reconnect would re-register with NONE — which is how the
        // bootstrap ended up publishing only the peer's NAT source port and a
        // co-admin could never connect. See `reconnectAdvertiseAddrs`.
        const multiaddrs = reconnectAdvertiseAddrs(
          this.registeredMultiaddrs,
          node.getMultiaddrs().map(a => a.toString()).filter(a => !a.includes('/p2p-circuit')),
        );
        await this.register(node, multiaddrs);

        // Success — restart keepalive on the new connection
        this.keepaliveFailures = 0;
        this.reconnectState = 'connected';
        this.backoffMs = this.initialBackoffMs;

        // Keepalive was stopped by the failed probes; restart it
        this.startKeepalive(node);

        // Report THIS outage's probe count, then clear it.
        //
        // The counter was previously never reset, so it accumulated for the life
        // of the process and every recovery reported a lifetime total — field log
        // 2026-09-25 showed "Bootstrap reconnected after 144/145/147/148/150
        // attempts" for outages that took a single probe each. That reads as a
        // link that is crumbling when the link is fine, which is exactly backwards
        // for the one number an operator uses to judge it.
        const attempts = this.reconnectAttempts;
        this.reconnectAttempts = 0;
        this.onStatus?.('reconnected', {
          message: `Bootstrap reconnected after ${attempts} attempts`,
          attempts,
        });
      } catch {
        // Probe failed — schedule next attempt with exponential backoff
        this.backoffMs = Math.min(this.backoffMs * this.backoffMultiplier, this.maxBackoffMs);
        this.startReconnectProbe(node);
      }
    }, this.backoffMs);
  }

  /**
   * Stop the keepalive loop and cancel any pending reconnect probe.
   *
   * Also stops relay-reservation maintenance: it lives on the same bootstrap
   * connection, and keeping it alive past a deliberate stop would immediately
   * re-create a listener on a connection the caller just tore down.
   */
  stopKeepalive(): void {
    this.stopKeepaliveInterval();

    if (this.relayMaintenanceTimer) {
      clearInterval(this.relayMaintenanceTimer);
      this.relayMaintenanceTimer = null;
    }

    this.cancelReconnect();
    this.bootstrapConnection = null;

    // The relay reservation lives on the connection we just tore down — it
    // will not survive a full stop/restart, so force a fresh reservation
    // attempt on the next successful register().
    this.relayListenerEstablished = false;
    this.relayDegradedNotified = false;
    this.lastConnectedUrl = null;
    this.relayPeerId = null;
  }

  /**
   * Clear only the ping interval (leaving the reconnect probe and relay
   * maintenance state alone). Used by startKeepalive() so a restart is a real
   * restart rather than a silent no-op.
   */
  private stopKeepaliveInterval(): void {
    if (this.keepaliveInterval) {
      clearInterval(this.keepaliveInterval);
      this.keepaliveInterval = null;
    }
  }

  /**
   * What identify has told us about the relay's HOP support.
   *
   * The three-way answer matters:
   *   - `unknown`     — identify has not reported any protocols yet, so HOP
   *                     support cannot be judged; waiting is correct.
   *   - `supported`   — safe to attempt a reservation.
   *   - `unsupported` — identify HAS reported protocols and HOP is not among
   *                     them (e.g. the bootstrap server runs with relay
   *                     disabled). Attempting would blacklist the relay AND
   *                     needlessly block, so the attempt is skipped outright.
   */
  private async relayHopSupport(
    node: Libp2p,
    relayPeerId: string,
  ): Promise<'unknown' | 'supported' | 'unsupported'> {
    try {
      const peer = await (node as unknown as {
        peerStore?: { get?: (p: unknown) => Promise<{ protocols?: string[] } | undefined> };
      }).peerStore?.get?.(peerIdFromString(relayPeerId));
      const protocols = peer?.protocols ?? [];
      if (protocols.length === 0) return 'unknown';
      return protocols.includes(RELAY_V2_HOP_CODEC) ? 'supported' : 'unsupported';
    } catch {
      return 'unknown';
    }
  }

  /**
   * Wait (bounded) for identify to make HOP support knowable, then report it.
   *
   * A reservation must NOT be attempted while support is `unknown` — the
   * library blacklists the relay for the process lifetime on
   * `UnsupportedProtocolError` (see RELAY_HOP_WAIT_MS). But the wait is also
   * bounded AND short-circuited: as soon as identify reports a protocol list
   * without HOP the answer is `unsupported` and the caller skips the attempt
   * immediately rather than blocking for the full window.
   */
  private async waitForRelayHopSupport(
    node: Libp2p,
    relayPeerId: string,
    timeoutMs = RELAY_HOP_WAIT_MS,
  ): Promise<'unknown' | 'supported' | 'unsupported'> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const support = await this.relayHopSupport(node, relayPeerId);
      if (support !== 'unknown') return support;
      if (Date.now() >= deadline) return 'unknown';
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }

  /**
   * Establish (or confirm) a circuit-relay v2 reservation with the bootstrap
   * server so this peer can be dialed via `/p2p-circuit` by peers that cannot
   * reach it directly (different WAN/ISP, symmetric NAT, etc).
   *
   * PUBLIC because both sides need it: the agent (via register()) and the
   * utility server, which held NO reservation at all — its node listens on a
   * bare TCP address only, so the relay answered NO_RESERVATION for every
   * inbound HOP aimed at it and no agent behind NAT could ever reach it through
   * the relay.
   *
   * Root cause this fixes: the agent's libp2p node is only ever configured to
   * *listen* on its bare TCP address (see BaseAgent.createLibp2pNodeOnPortRange),
   * never on a `/p2p-circuit` address. Per @libp2p/circuit-relay-v2, a
   * reservation is only created when a transport listener is started for a
   * `.../p2p-circuit` multiaddr (CircuitListen.exactMatch in the transport's
   * listener.ts) — plain outbound dialing through the relay transport does NOT
   * request one. Without a reservation, the relay server's handleConnect()
   * rejects incoming HOP CONNECT frames aimed at this peer with
   * STATUS.NO_RESERVATION, so relayed reconnection silently fails while LAN
   * peers (who never need the relay) are unaffected — exactly the reported
   * symptom.
   *
   * This calls the same internal `components.transportManager.listen()` API
   * that @libp2p/circuit-relay-v2 itself uses to re-add a relay listener after
   * losing one (see its transport's onStop() fallback), so it is a supported
   * usage pattern rather than a private hack. It is intentionally
   * non-fatal — if the bootstrap server does not have relay enabled, or is
   * briefly unreachable, direct LAN connections and later retries are
   * unaffected.
   */
  async ensureRelayReservation(node: Libp2p): Promise<void> {
    if (!this.lastConnectedUrl) {
      return;
    }

    // Resolve and remember the relay's peer ID so reservation HEALTH can be
    // checked against the transport's live reservation store rather than a
    // cached boolean.
    this.resolveRelayPeerId();

    // Already reserved on this relay? @libp2p/circuit-relay-v2 created the
    // reservation from the listener we started on a previous call and refreshes
    // it itself 5 min before its 2 h TTL, so there is nothing to do.
    //
    // It is important NOT to call listen() unconditionally: TransportManager
    // .listen() creates a fresh listener object per call and has no
    // address-level dedupe, so calling it on every register() leaks one
    // CircuitRelayTransportListener (plus its reservation-store event
    // listeners) each time.
    if (this.relayPeerId && nodeHasRelayReservation(node, this.relayPeerId)) {
      this.relayListenerEstablished = true;
      return;
    }

    // DEFER rather than probe blindly. A reservation attempt against a relay
    // that does not (yet) advertise the HOP codec makes the library blacklist
    // that peer for the whole process — after which `listen()` always throws
    // "The relay was previously invalid" and this peer can never be reached via
    // relay again without an app restart. See RELAY_HOP_WAIT_MS.
    if (this.relayPeerId) {
      const hopSupport = await this.waitForRelayHopSupport(node, this.relayPeerId);

      if (hopSupport === 'unsupported') {
        // The relay has told us (via identify) that it does not speak HOP —
        // e.g. the bootstrap server runs with relay disabled. Nothing to gain
        // from waiting or attempting, and attempting would burn the peer.
        this.relayListenerEstablished = false;
        if (!this.relayDegradedNotified) {
          this.relayDegradedNotified = true;
          this.onStatus?.('relay-degraded', {
            message:
              'Relay reservation unavailable — the bootstrap server does not offer the ' +
              'circuit-relay hop protocol. This peer is reachable directly only.',
          });
        }
        return;
      }

      if (hopSupport === 'unknown') {
        this.relayListenerEstablished = false;
        if (!this.relayDegradedNotified) {
          this.relayDegradedNotified = true;
          this.onStatus?.('relay-degraded', {
            message:
              'Relay reservation deferred — the relay has not advertised the ' +
              'circuit-relay hop protocol yet. Retrying automatically; probing now would ' +
              'permanently blacklist the relay for this session.',
          });
        }
        return;
      }
    }

    try {
      const relayListenAddr = `${this.lastConnectedUrl}/p2p-circuit`;
      await (node as any).components.transportManager.listen([multiaddr(relayListenAddr)]);
      // Confirm against the transport's live store. The reservation is written
      // into the store before listen() resolves (ReservationStore.addRelay sets
      // it, then the listener adds the observed addrs), so this reflects
      // reality. When the relay peer could not be parsed we keep the previous
      // optimistic behaviour and let maintenance re-check later.
      this.relayListenerEstablished = this.relayPeerId
        ? nodeHasRelayReservation(node, this.relayPeerId)
        : true;

      // One-shot recovery notice: only if we previously told the user about a
      // degraded relay does a successful re-assert warrant a "restored".
      if (this.relayListenerEstablished && this.relayDegradedNotified) {
        this.relayDegradedNotified = false;
        this.onStatus?.('relay-restored', {
          message: 'Relay reservation re-established — this peer is reachable via relay again.',
        });
      }
    } catch (err) {
      this.relayListenerEstablished = false;
      // NOTE: 'relay-degraded', NOT 'disconnected' — the bootstrap connection
      // itself may be perfectly healthy. Conflating the two made the agent
      // report a dead bootstrap while only relay reachability was impaired.
      if (!this.relayDegradedNotified) {
        this.relayDegradedNotified = true;
        const reason = err instanceof Error ? err.message : 'unknown';
        // Distinguish the TERMINAL case. @libp2p/circuit-relay-v2 adds the relay
        // to a process-lifetime filter when a reservation attempt fails with
        // UnsupportedProtocolError (or DialError); every later attempt then
        // throws "The relay was previously invalid" and NOTHING in the library
        // clears it (verified — it is not reachable from outside). Reporting
        // that as an ordinary transient failure is what left operators staring
        // at a "requested but not yet confirmed" line that could never clear.
        const blacklisted = /previously invalid/i.test(reason);
        this.onStatus?.('relay-degraded', {
          message: blacklisted
            ? `Relay reservation permanently disabled for this session (${reason}). ` +
              `The circuit-relay transport blacklisted the relay after a failed attempt; ` +
              `this peer is reachable directly only until the process is restarted.`
            : `Relay reservation failed (${reason}). ` +
              `This peer will only be reachable directly (e.g. on the same LAN) until ` +
              `a reservation succeeds on a later reconnect.`,
        });
      }
    }
  }

  /**
   * Parse the relay's peer ID out of the address that was actually dialed.
   * Cheap and idempotent — re-parsed only when it is missing or when a
   * different bootstrap address succeeded on a later register().
   */
  private resolveRelayPeerId(): void {
    if (!this.lastConnectedUrl) return;
    if (this.relayPeerId && this.lastConnectedUrl.includes(this.relayPeerId)) return;
    try {
      // Read the LAST `/p2p/<id>` component — the same technique
      // @libp2p/circuit-relay-v2's own transport uses to find the relay's peer
      // ID (`relayAddr.getComponents().find(c => c.code === CODE_P2P)`).
      // Multiaddr v13 dropped the typed `getPeerId()` helper, hence the code
      // lookup. P2P code 421 = `/p2p`.
      const components = multiaddr(this.lastConnectedUrl).getComponents();
      const p2p = [...components].reverse().find((c) => c.code === 421);
      const peerIdStr = typeof p2p?.value === 'string' ? p2p.value : null;
      this.relayPeerId = peerIdStr ? peerIdFromString(peerIdStr).toString() : null;
    } catch {
      this.relayPeerId = null;
    }
  }

  /**
   * Re-assert the circuit-relay reservation when it has been lost.
   *
   * WHY THIS IS SEPARATE FROM KEEPALIVE: @libp2p/circuit-relay-v2 deletes a
   * reservation when the underlying connection to the relay closes
   * (transport/reservation-store.js `connection:close` handler) and its
   * listener does NOT re-listen — `_onRemoveRelayPeer` only clears the
   * advertised addresses. Nothing inside the library therefore restores a
   * reservation after a relay connection drop; without this maintenance tick a
   * peer silently becomes unreachable via relay forever, and only a fresh
   * `listen()` re-creates the reservation.
   */
  private startRelayMaintenance(node: Libp2p): void {
    if (this.relayMaintenanceTimer) return; // already running
    this.relayMaintenanceTimer = setInterval(() => {
      void this.maintainRelayReservation(node);
    }, RELAY_MAINTENANCE_INTERVAL_MS);
  }

  /** One maintenance tick — see {@link startRelayMaintenance}. */
  private async maintainRelayReservation(node: Libp2p): Promise<void> {
    if (!this.lastConnectedUrl) return;
    this.resolveRelayPeerId();
    if (!this.relayPeerId) return;

    if (nodeHasRelayReservation(node, this.relayPeerId)) {
      this.relayListenerEstablished = true;
      return;
    }

    this.relayListenerEstablished = false;
    if (!this.relayDegradedNotified) {
      this.relayDegradedNotified = true;
      this.onStatus?.('relay-degraded', {
        message:
          'Relay reservation lost — re-asserting it so this peer stays reachable via relay.',
      });
    }
    await this.ensureRelayReservation(node);
  }

  /**
   * Whether a circuit-relay reservation is ACTUALLY held on the bootstrap
   * server's relay right now.
   *
   * Pass the running node to get the live answer from the circuit-relay
   * transport's reservation store. The stored latch is only a fallback for
   * callers that have no node handle, and it is kept in sync by
   * ensureRelayReservation()/maintainRelayReservation() — it is never the
   * primary source of truth, because @libp2p/circuit-relay-v2 deletes
   * reservations without telling us.
   *
   * Useful for status/diagnostic reporting: a peer without an active
   * reservation cannot be reached via relay from a different WAN even though it
   * may still show as "connected" to bootstrap.
   */
  hasRelayReservation(node?: Libp2p): boolean {
    if (node && this.relayPeerId) {
      const held = nodeHasRelayReservation(node, this.relayPeerId);
      this.relayListenerEstablished = held;
      return held;
    }
    return this.relayListenerEstablished;
  }

  /** The relay's peer ID, once a bootstrap dial has resolved it. */
  getRelayPeerId(): string | null {
    return this.relayPeerId;
  }


  /**
   * Cancel any pending reconnect probe timer.
   */
  private cancelReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.reconnectState = 'disconnected';
  }

  /**
   * Get the current reconnect state.
   */
  getReconnectState(): 'connected' | 'probing' | 'disconnected' {
    return this.reconnectState;
  }

  /**
   * Get the number of consecutive keepalive failures.
   */
  getKeepaliveFailures(): number {
    return this.keepaliveFailures;
  }

  /**
   * Get the stored bootstrap connection (for relay circuit awareness).
   */
  getBootstrapConnection(): Connection | null {
    return this.bootstrapConnection;
  }

  /**
   * Parse the raw response into a BootstrapResult with convenience fields.
   */
  private parseResult(response: BootstrapResponse): BootstrapResult {
    const peerIds = response.peers.map(p => p.peerId);
    const connectedPeers = response.peers.filter(p => p.connected || p.reachable);

    return {
      response,
      peerIds,
      connectedPeers,
      relayAddr: response.relayAddr,
      clientSourceAddr: response.clientSourceAddr,
      bootstrapConnection: this.bootstrapConnection ?? undefined,
    };
  }
}