// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Fixed port range for libp2p listen — retained for multi-agent deployments.
 *
 * ## Current connection strategy (Phase 9 cleanup)
 *
 * The bootstrap server is the sole coordination mechanism. Connection flow:
 *   1. Direct dial using bootstrap-discovered addresses
 *   2. Circuit relay through bootstrap server (NAT traversal)
 *   3. Last-known addresses as absolute fallback
 *
 * mDNS is intentionally not used (unreliable across networks).
 * LAN port sweep was removed (replaced by circuit relay + bootstrap discovery).
 *
 * The port range (24000-24004) is retained only for the listen side:
 * when multiple agents run on the same machine, each tries the next
 * available port if its preferred one is in use.
 *
 * ## Removed in Phase 9
 *
 * The following were removed as dead code after the bootstrap-centric refactor:
 * - `PORT_SWEEP_DIAL_TIMEOUT_MS` — no longer needed (port sweep removed)
 * - `extractHostFromMultiaddrs` — was only used by RelationshipManager port sweep retry
 * - `dialPeerOnPortRange` — removed from Libp2pTransport (was dead after Phase 8)
 * - `lookupPeer` — removed from Libp2pTransport (zero callers, mDNS was removed)
 */

/** First port in the fixed listen range. */
/**
 * Keep only the addresses this node could plausibly be **dialled on** — its own listen
 * ports. `node.getMultiaddrs()` returns listen AND observed addresses, and an observed
 * address is the peer's SOURCE port for an outbound connection: for a NAT'd agent that is
 * an ephemeral port where nothing listens. Advertising those to the bootstrap server is how
 * a peer ends up dialling `connect ECONNREFUSED 192.168.1.246:60981` on a 5s loop (field log,
 * 2026-09-25) instead of the agent's real listen address.
 *
 * Pure and exported so the filter is testable without standing up libp2p.
 */
export function filterDialableListenAddrs(
  addrs: readonly string[],
  ports: readonly number[] = AGENT_PORT_RANGE,
): string[] {
  const allowed = new Set(ports);
  return addrs.filter((a) => {
    // /ip4/0.0.0.0/tcp/24000, /ip4/10.0.0.5/tcp/24000/p2p/…, /ip6/::/tcp/24000 …
    const m = /\/tcp\/(\d+)(\/|$)/.exec(a);
    if (!m) return false;
    return allowed.has(Number.parseInt(m[1], 10));
  });
}

/**
 * Choose the addresses to **re-advertise** when re-registering after a dropped
 * bootstrap connection.
 *
 * The addresses a node ALREADY registered are authoritative: they were computed
 * by that node's own caller, which knows its listen ports (an agent uses
 * 24000-24004; the utility server uses its own port, e.g. 4003). Re-deriving them
 * here CANNOT work, because the only filter available defaults to the AGENT
 * range — so a non-agent node re-registers with **no** addresses at all.
 *
 * That is not a cosmetic loss: the bootstrap merges the registration's addresses
 * with the address it OBSERVED on the connection (`connection.remoteAddr`), and
 * for a NAT'd peer the observed address is its ephemeral source port — where
 * nothing listens. With the advertised set emptied, the observed port becomes the
 * peer's ONLY published address, so every other node dials a dead port. Field bug
 * 2026-10-10: a co-admin agent could never establish its TspBridge link to the
 * utility server (it discovered `/ip4/<public-ip>/tcp/<ephemeral>`), so it never
 * saw the founding ceremony's pending approval.
 *
 * The live-node derivation remains the fallback for a node that has never
 * registered (there is nothing remembered to trust).
 *
 * Pure and exported so the choice is testable without standing up libp2p.
 */
export function reconnectAdvertiseAddrs(
  alreadyRegistered: readonly string[] | undefined,
  liveAddrs: readonly string[],
  ports: readonly number[] = AGENT_PORT_RANGE,
): string[] {
  if (alreadyRegistered && alreadyRegistered.length > 0) return [...alreadyRegistered];
  return filterDialableListenAddrs(liveAddrs, ports);
}

export const AGENT_PORT_RANGE_START = 24000;

/** Number of consecutive ports to try, starting at AGENT_PORT_RANGE_START. */
export const AGENT_PORT_RANGE_SIZE = 5;

/** The full list of candidate ports, e.g. [24000, 24001, 24002, 24003, 24004]. */
export const AGENT_PORT_RANGE: number[] = Array.from(
  { length: AGENT_PORT_RANGE_SIZE },
  (_, i) => AGENT_PORT_RANGE_START + i,
);

/** Human-readable description of the range, e.g. "24000-24004". */
export const AGENT_PORT_RANGE_LABEL =
  `${AGENT_PORT_RANGE_START}-${AGENT_PORT_RANGE_START + AGENT_PORT_RANGE_SIZE - 1}`;
