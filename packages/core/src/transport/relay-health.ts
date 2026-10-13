/**
 * RelayHealthModule — live circuit-relay v2 grant introspection.
 *
 * WHY THIS EXISTS
 * ---------------
 * The bootstrap server's circuit-relay enforces a per-relayed-connection
 * duration and byte grant (`reservations.defaultDurationLimit` /
 * `defaultDataLimit` in bootstrap/server/bootstrap-server.ts). When either is
 * exhausted the relay ABORTS both the HOP and STOP streams, the relayed
 * connection dies abruptly, and both ends see `peer:disconnect`. Nothing in
 * this codebase ever read the grant, so every expiry was a surprise and the
 * only possible recovery was a post-hoc reconnect.
 *
 * The grant IS observable. libp2p attaches it to the connection:
 *
 *   `connection.limits?: { bytes?: bigint; seconds?: number }`
 *
 * with `bytes` / `seconds` defined as LIVE GETTERS over the relay's
 * LimitTracker (see `getLimits()` in @libp2p/circuit-relay-v2/src/utils.ts),
 * so they count down as the connection ages and as data flows:
 *
 *   - outbound relayed connection: seeded from the relay's HOP reply
 *     (`status.limit`) — @libp2p/circuit-relay-v2 transport/index.js
 *   - inbound relayed connection:  seeded from the incoming STOP request
 *     (`request.limit`)
 *
 * @libp2p/interface documents this as: "the number of seconds that this
 * connection will remain open for… the connection will normally be closed
 * abruptly if the limits are exceeded."
 *
 * This module turns that into a decision: `needsRefresh()` answers "is any
 * relayed connection about to be cut off, or nearly out of bytes?" so the
 * caller can re-establish the connection BEFORE the relay pulls the plug
 * (a fresh HOP/STOP exchange gets a fresh grant).
 *
 * Kept dependency-light and side-effect free so it is unit-testable without a
 * running libp2p node — `readRelayHealth()` is the only part that touches the
 * node, and it never throws.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Default lead time: refresh a relayed connection when its grant has this long
 * (or less) left. One minute comfortably covers a direct/relay re-dial on a
 * WAN without refreshing so eagerly that we churn connections.
 */
export const RELAY_REFRESH_LEAD_MS = 60_000;

/**
 * Default byte floor: refresh when a relayed connection has this many bytes (or
 * fewer) of grant left. Only the REMAINING count is exposed — never the
 * original grant — so a ratio cannot be computed and an absolute floor is used.
 */
export const RELAY_BYTE_FLOOR = 262_144n; // 256 KiB

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** One live relayed (`/p2p-circuit`) connection, with its remaining grant. */
export interface RelayConnectionInfo {
  /** Remote peer's libp2p peer ID. */
  peerId: string;
  direction: 'inbound' | 'outbound';
  /** Full remote multiaddr (contains `/p2p-circuit`). */
  remoteAddr: string;
  /** Live seconds-remaining countdown on this connection's grant. */
  secondsRemaining?: number;
  /** Live bytes-remaining count on this connection's grant. */
  bytesRemaining?: bigint;
}

/** Point-in-time view of relay reachability for one libp2p node. */
export interface RelayHealthSnapshot {
  /** Every live relayed connection. */
  relayed: RelayConnectionInfo[];
  /** Relay peer IDs we currently hold a reservation on (outbound-reachable). */
  reservations: string[];
  /** True when this node has at least one live relayed connection. */
  hasRelayedConnection: boolean;
  /** True when this node holds at least one reservation (inbound-reachable). */
  hasReservation: boolean;
  /**
   * Smallest `secondsRemaining` across relayed connections, in milliseconds.
   * `undefined` when there are no relayed connections, or none report a
   * duration grant (i.e. unlimited).
   */
  soonestExpiryMs?: number;
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/**
 * Whether a libp2p connection object is a relayed (`/p2p-circuit`) connection.
 *
 * Two independent signals, because either can be the only one present at a
 * given moment: the multiaddr carries `/p2p-circuit` for the whole life of the
 * connection, while `limits` is attached only when the relay granted one.
 */
export function isRelayConnection(conn: unknown): boolean {
  if (conn == null || typeof conn !== 'object') return false;
  const c = conn as { remoteAddr?: { toString(): string }; limits?: unknown };
  try {
    if (
      typeof c.remoteAddr?.toString === 'function' &&
      c.remoteAddr.toString().includes('/p2p-circuit')
    ) {
      return true;
    }
  } catch {
    // fall through to the limits check
  }
  return c.limits != null;
}

/**
 * Extract the live grant from a connection's `limits`, coercing to plain
 * numbers/bigints and dropping nonsense (NaN, negative, wrong type).
 */
export function readConnectionGrant(conn: unknown): {
  secondsRemaining?: number;
  bytesRemaining?: bigint;
} {
  const out: { secondsRemaining?: number; bytesRemaining?: bigint } = {};
  if (conn == null || typeof conn !== 'object') return out;

  // `limits.seconds` / `limits.bytes` are GETTERS on the connection object, so
  // reading them here always yields the CURRENT remaining amount.
  const limits = (conn as { limits?: { seconds?: unknown; bytes?: unknown } }).limits;
  if (limits == null) return out;

  try {
    const seconds = limits.seconds;
    if (typeof seconds === 'number' && Number.isFinite(seconds) && seconds >= 0) {
      out.secondsRemaining = seconds;
    }
  } catch {
    // A throwing getter is treated as "no duration grant".
  }

  try {
    const bytes = limits.bytes;
    if (typeof bytes === 'bigint' && bytes >= 0n) {
      out.bytesRemaining = bytes;
    }
  } catch {
    // A throwing getter is treated as "no byte grant".
  }

  return out;
}

/**
 * The subset of relayed connections whose grant is nearly exhausted.
 *
 * Returns an empty array when everything is healthy or the grants are
 * unlimited, so callers can both branch (`length > 0`) and act per-connection.
 * Pure — no libp2p dependency — so it is cheap to unit test.
 */
export function expiringRelayConnections(
  snapshot: RelayHealthSnapshot,
  options: RelayRefreshOptions = {},
): RelayConnectionInfo[] {
  const leadMs = options.leadMs ?? RELAY_REFRESH_LEAD_MS;
  const byteFloor = options.byteFloor ?? RELAY_BYTE_FLOOR;

  return snapshot.relayed.filter((relay) => {
    const byTime = relay.secondsRemaining != null && relay.secondsRemaining * 1000 <= leadMs;
    const byBytes = relay.bytesRemaining != null && relay.bytesRemaining <= byteFloor;
    return byTime || byBytes;
  });
}

/**
 * Decide whether relayed connectivity should be refreshed pre-emptively.
 *
 * True when any live relayed connection is within `leadMs` of its duration
 * grant, or down to `byteFloor` bytes. `undefined` grants (unlimited) never
 * trigger a refresh.
 *
 * Pure — no libp2p dependency — so it is cheap to unit test.
 */
export function needsRefresh(
  snapshot: RelayHealthSnapshot,
  options: RelayRefreshOptions = {},
): boolean {
  return expiringRelayConnections(snapshot, options).length > 0;
}

/** Options for {@link needsRefresh}. */
export interface RelayRefreshOptions {
  /** Refresh when a grant has this long (or less) left. See {@link RELAY_REFRESH_LEAD_MS}. */
  leadMs?: number;
  /** Refresh when a grant has this many bytes (or fewer) left. See {@link RELAY_BYTE_FLOOR}. */
  byteFloor?: bigint;
}

/**
 * One-line human summary of a snapshot, for status lines and error messages.
 * Deliberately explains the CONSEQUENCE, not just the numbers.
 */
export function describeRelayHealth(snapshot: RelayHealthSnapshot): string {
  if (!snapshot.hasRelayedConnection && !snapshot.hasReservation) {
    return 'No relay connection and no relay reservation — this peer is only reachable directly.';
  }
  if (!snapshot.hasRelayedConnection) {
    return `Relay reservation held (${snapshot.reservations.length}) — no active relayed connection.`;
  }
  if (snapshot.soonestExpiryMs == null) {
    return `${snapshot.relayed.length} relayed connection(s), no duration grant reported.`;
  }
  const secs = Math.max(0, Math.round(snapshot.soonestExpiryMs / 1000));
  return `${snapshot.relayed.length} relayed connection(s); soonest relay grant expires in ~${secs}s.`;
}

/** Coarse relayed-connectivity label, for status lines and logs. */
export function relayHealthLabel(
  snapshot: RelayHealthSnapshot,
): 'direct' | 'relay' | 'relay-expiring' {
  if (!snapshot.hasRelayedConnection) return 'direct';
  return needsRefresh(snapshot) ? 'relay-expiring' : 'relay';
}

// ---------------------------------------------------------------------------
// libp2p readers (internal API surface, used defensively)
// ---------------------------------------------------------------------------

/** The subset of the circuit-relay transport's reservation store we rely on. */
interface CircuitRelayReservationStoreLike {
  hasReservation(peerId: unknown): boolean;
}

/** The subset of the circuit-relay transport we rely on. */
interface CircuitRelayTransportLike {
  reservationStore?: CircuitRelayReservationStoreLike;
}

/**
 * Locate the circuit-relay transport instance on a running node.
 *
 * `components.transportManager` is the same internal API that
 * @libp2p/circuit-relay-v2 itself uses to add a relay listener when it loses
 * one, and that `BootstrapClient.ensureRelayReservation()` already uses — so
 * this is a supported usage pattern, not a private hack. It is duck-typed on
 * `reservationStore.hasReservation` rather than on the transport's tag so a
 * version bump that renames the tag does not silently disable relay health.
 *
 * Returns `undefined` (never throws) when the node is not running, has no
 * transport manager, or has no circuit-relay transport configured.
 */
export function findCircuitRelayTransport(node: unknown): CircuitRelayTransportLike | undefined {
  try {
    const manager = (
      node as { components?: { transportManager?: { getTransports?: () => unknown[] } } }
    )?.components?.transportManager;
    const transports = manager?.getTransports?.() ?? [];
    for (const transport of transports) {
      const candidate = transport as CircuitRelayTransportLike;
      if (typeof candidate?.reservationStore?.hasReservation === 'function') {
        return candidate;
      }
    }
  } catch {
    // Node shutting down / API shape unavailable — treat as "no relay transport".
  }
  return undefined;
}



/**
 * Whether this node currently holds a circuit-relay reservation on `relayPeerId`.
 *
 * This is the LIVE answer, replacing the write-once `relayListenerEstablished`
 * latch that used to go stale: @libp2p/circuit-relay-v2 DELETES a reservation
 * when the underlying connection to the relay closes (transport
 * reservation-store.js, `connection:close` handler) and does not re-listen on
 * its own, so a cached boolean was reporting `true` for a reservation that no
 * longer existed.
 *
 * Returns `false` when the relay peer cannot be resolved or the transport is
 * absent — a caller must then re-assert the reservation, which is idempotent.
 */
export function hasRelayReservation(node: unknown, relayPeerId: unknown): boolean {
  if (relayPeerId == null) return false;
  try {
    const store = findCircuitRelayTransport(node)?.reservationStore;
    if (store == null) return false;
    return store.hasReservation(relayPeerId) === true;
  } catch {
    return false;
  }
}

/**
 * Read the node's live relay health.
 *
 * Never throws: a node that is stopped, mid-restart, or missing the
 * circuit-relay transport yields an empty snapshot (which reads as
 * "direct-only"), never a crash in a status path.
 */
export function readRelayHealth(node: unknown, relayPeerId?: unknown): RelayHealthSnapshot {
  const empty: RelayHealthSnapshot = {
    relayed: [],
    reservations: [],
    hasRelayedConnection: false,
    hasReservation: false,
  };
  if (node == null) return empty;

  const relayed: RelayConnectionInfo[] = [];

  try {
    const connections = (node as { getConnections?: () => unknown[] }).getConnections?.() ?? [];
    for (const conn of connections) {
      if (!isRelayConnection(conn)) continue;
      const c = conn as {
        remotePeer?: { toString(): string };
        remoteAddr?: { toString(): string };
        direction?: string;
      };
      const grant = readConnectionGrant(conn);
      relayed.push({
        peerId: c.remotePeer?.toString() ?? 'unknown',
        direction: c.direction === 'inbound' ? 'inbound' : 'outbound',
        remoteAddr: c.remoteAddr?.toString() ?? '',
        secondsRemaining: grant.secondsRemaining,
        bytesRemaining: grant.bytesRemaining,
      });
    }
  } catch {
    // Connection manager unavailable — report no relayed connections.
  }

  // Soonest expiry over connections that actually report a duration grant.
  let soonestExpiryMs: number | undefined;
  for (const relay of relayed) {
    if (relay.secondsRemaining == null) continue;
    const ms = relay.secondsRemaining * 1000;
    if (soonestExpiryMs == null || ms < soonestExpiryMs) soonestExpiryMs = ms;
  }

  // Reservations: we only ask about the relay we reserved on (a single
  // configured relay today). Introspection failures degrade to "none held".
  const reservations: string[] = [];
  if (relayPeerId != null && hasRelayReservation(node, relayPeerId)) {
    reservations.push(String(relayPeerId));
  }

  return {
    relayed,
    reservations,
    hasRelayedConnection: relayed.length > 0,
    hasReservation: reservations.length > 0,
    soonestExpiryMs,
  };
}

// ---------------------------------------------------------------------------
// Utility-server connectivity status (the single authoritative view)
// ---------------------------------------------------------------------------

/**
 * Which layer of the path from this agent to the utility server is impaired.
 *
 * The distinction matters because the remedies differ:
 *   - `bootstrap-unreachable` → discovery/relay coordination is down
 *   - `unreachable`           → bootstrap is fine, the server peer itself is not
 *   - `relay-expiring`        → still working, but about to be cut off by the
 *                               relay's duration/byte grant
 *   - `reconnecting`          → recovery is in progress right now
 *   - `connected`             → healthy
 */
export type ConnectivityLayer =
  | 'connected'
  | 'relay-expiring'
  | 'reconnecting'
  | 'unreachable'
  | 'bootstrap-unreachable';

/**
 * The agent's authoritative connectivity view. Derived — never stored as a
 * sticky flag — so it cannot drift from reality the way the previous
 * `bootstrapConnected` / `relayListenerEstablished` booleans did.
 */
export interface ConnectivityStatus {
  /** Coarse layer for UI/UX branching. */
  layer: ConnectivityLayer;
  /** Is the bootstrap server reachable (keepalive healthy)? */
  bootstrapConnected: boolean;
  /** Is the utility server reachable (TSP bridge up)? */
  utilityServerConnected: boolean;
  /** Live relay grant view. */
  relay: RelayHealthSnapshot;
  /** Do we hold a relay reservation (i.e. can peers reach us over the relay)? */
  hasRelayReservation: boolean;
  /** Human-readable, safe to show directly in a UI or error message. */
  message: string;
  /** True when this state blocks operations that need the utility server. */
  degraded: boolean;
  /** Consecutive failed recovery attempts (0 when healthy). */
  consecutiveFailures: number;
  /** Last recovery error, for diagnostics. */
  lastError?: string;
}

/** Inputs to {@link deriveConnectivityStatus} — all observable, none cached. */
export interface ConnectivityInputs {
  bootstrapConnected: boolean;
  utilityServerConnected: boolean;
  relay: RelayHealthSnapshot;
  hasRelayReservation: boolean;
  /** True while a reconnect/refresh is actively running. */
  reconnecting?: boolean;
  consecutiveFailures?: number;
  lastError?: string;
}



/**
 * Build the connectivity status from live inputs.
 *
 * Pure — no libp2p, no timers — so it is unit-testable and can be called from a
 * status route on every request without cost.
 *
 * PRECEDENCE: an in-flight reconnect is reported as `reconnecting` even while
 * the bridge still reads connected, because the user-visible truth at that
 * moment is "a re-establish is happening".
 */
export function deriveConnectivityStatus(inputs: ConnectivityInputs): ConnectivityStatus {
  const failures = inputs.consecutiveFailures ?? 0;
  const base = {
    bootstrapConnected: inputs.bootstrapConnected,
    utilityServerConnected: inputs.utilityServerConnected,
    relay: inputs.relay,
    hasRelayReservation: inputs.hasRelayReservation,
    consecutiveFailures: failures,
    lastError: inputs.lastError,
  };

  if (!inputs.bootstrapConnected) {
    return {
      ...base,
      layer: 'bootstrap-unreachable',
      degraded: true,
      message:
        'Not connected to the relay/bootstrap server — this agent cannot be discovered and ' +
        'cannot reach other peers across networks. Reconnecting automatically.',
    };
  }

  if (inputs.reconnecting) {
    return {
      ...base,
      layer: 'reconnecting',
      degraded: true,
      message:
        'Connection to the utility server was lost — re-establishing it in the background. ' +
        'Anything that needs the server is queued and will send automatically.',
    };
  }

  if (!inputs.utilityServerConnected) {
    return {
      ...base,
      layer: 'unreachable',
      degraded: true,
      message:
        failures > 0
          ? `Utility server unreachable (${failures} failed attempt${failures === 1 ? '' : 's'})` +
            (inputs.lastError ? `: ${inputs.lastError}` : '.') +
            ' Retrying in the background.'
          : 'Utility server unreachable. Retrying in the background.',
    };
  }

  if (needsRefresh(inputs.relay)) {
    return {
      ...base,
      layer: 'relay-expiring',
      degraded: false,
      message:
        'Connected via relay, but the relay session is about to reach its time/byte limit — ' +
        'refreshing the connection so it is not dropped.',
    };
  }

  return {
    ...base,
    layer: 'connected',
    degraded: false,
    message: 'Connected to the utility server.',
  };
}

/**
 * Copy for a gated operation that cannot proceed. Names the failed layer and
 * what happens next, instead of the previous context-free
 * "Not connected to utility server."
 */
export function describeConnectivityFailure(
  status: ConnectivityStatus,
  operation: string,
): string {
  switch (status.layer) {
    case 'bootstrap-unreachable':
      return (
        `Cannot ${operation}: this agent is not connected to the relay server, so the utility ` +
        `server cannot be reached. Reconnection is running in the background — try again shortly.`
      );
    case 'unreachable':
      return (
        `Cannot ${operation}: the relay connection to the utility server could not be ` +
        `re-established. Your change has been kept locally and will be sent automatically once ` +
        `the connection is back.` +
        (status.lastError ? ` (last error: ${status.lastError})` : '')
      );
    case 'reconnecting':
      return (
        `Cannot ${operation} yet: the connection to the utility server is being re-established. ` +
        `Retrying automatically — no data has been lost.`
      );
    case 'relay-expiring':
      return `Cannot ${operation}: the relay session is being refreshed. Try again in a moment.`;
    default:
      return `Cannot ${operation}: unexpected connectivity state.`;
  }
}

