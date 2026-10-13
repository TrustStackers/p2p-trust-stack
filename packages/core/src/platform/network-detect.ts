/**
 * NetworkDetectModule — network profile detection and change tracking.
 *
 * Captures the agent's current network profile (LAN IPs, WAN IP, listen port)
 * and compares it against a stored profile to detect network changes.
 * Emits events when the network environment changes.
 *
 * This enables the user to know when they've switched networks (cellular,
 * home→work, etc.) and take manual action to re-register with bootstrap.
 */

import { networkInterfaces } from 'node:os';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A snapshot of the agent's network environment.
 */
export interface NetworkProfile {
  /** Public/WAN IP as seen by the bootstrap server (e.g., "203.0.113.5"). */
  wanIp?: string;
  /** Local interface IPs (e.g., ["192.168.1.10", "10.0.0.5"]). */
  lanIps: string[];
  /** The TCP port the agent is listening on. */
  listenPort: number;
  /** Full libp2p multiaddrs for reference. */
  libp2pAddrs: string[];
  /** Unix timestamp when this profile was captured. */
  capturedAt: number;
}

/**
 * Event payload emitted when the network profile changes.
 */
export interface NetworkChangeEvent {
  oldProfile: NetworkProfile;
  newProfile: NetworkProfile;
  /** What changed: 'wanIp', 'lanIps', 'listenPort', or 'all'. */
  changedFields: string[];
}

// ---------------------------------------------------------------------------
// OS-level LAN IP detection
// ---------------------------------------------------------------------------

/**
 * Detect local LAN IPv4 addresses from the OS network interfaces.
 *
 * Filters for IPv4 addresses in RFC1918 private ranges (10.x.x.x,
 * 172.16-31.x.x, 192.168.x.x) and excludes loopback (127.x.x.x) and
 * link-local (169.254.x.x) addresses.
 *
 * @returns Array of LAN IPv4 addresses, deduplicated and sorted.
 */
export function getLocalLanIps(): string[] {
  const ips = new Set<string>();
  const ifaces = networkInterfaces();

  for (const [, addrs] of Object.entries(ifaces)) {
    if (!addrs) continue;
    for (const addr of addrs) {
      // IPv4 only, skip internal/loopback
      if (addr.family !== 'IPv4' || addr.internal) continue;
      const ip = addr.address;

      // RFC1918 private ranges
      if (
        ip.startsWith('10.') ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
        ip.startsWith('192.168.')
      ) {
        ips.add(ip);
      }
    }
  }

  return Array.from(ips).sort();
}

/**
 * Extract LAN (RFC1918 private) IPs from libp2p multiaddrs.
 * Filters for /ip4/ addresses that are in private ranges.
 */
function extractLanIps(multiaddrs: string[]): string[] {
  const ips = new Set<string>();

  for (const addr of multiaddrs) {
    const match = addr.match(/\/ip4\/(\d+\.\d+\.\d+\.\d+)/);
    if (!match) continue;

    const ip = match[1];
    // Skip 0.0.0.0 (listen-all) and 127.x.x.x (loopback)
    if (ip === '0.0.0.0' || ip.startsWith('127.')) continue;

    // RFC1918 private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    if (ip.startsWith('10.') ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
        ip.startsWith('192.168.')) {
      ips.add(ip);
    }
  }

  return Array.from(ips);
}

/**
 * Extract the listen port from libp2p multiaddrs.
 */
function extractListenPort(multiaddrs: string[]): number {
  for (const addr of multiaddrs) {
    const match = addr.match(/\/tcp\/(\d+)/);
    if (match) return parseInt(match[1], 10);
  }
  return 0;
}

/**
 * Extract the WAN IP from a source address string.
 * E.g., "/ip4/203.0.113.5/tcp/4001" → "203.0.113.5"
 */
function extractWanIp(sourceAddr?: string): string | undefined {
  if (!sourceAddr) return undefined;
  const match = sourceAddr.match(/\/ip4\/(\d+\.\d+\.\d+\.\d+)/);
  return match ? match[1] : undefined;
}

/**
 * Is this advertised host a loopback address?
 *
 * A loopback advertised address is not a *location*: a peer that dials it reaches
 * its OWN machine, so publishing one never makes this node reachable. It is
 * therefore treated as "no advertised host configured" and the OS-detected LAN
 * IPs are used instead.
 *
 * This is not hypothetical. The utility server's setup wizard DEFAULTS
 * `advertisedHost` to `127.0.0.1`; `buildDialableMultiaddrs` then rewrote its only
 * listen address (`/ip4/0.0.0.0/tcp/4003`) to `/ip4/127.0.0.1/tcp/4003`, so every
 * remote agent's discovery address was undialable (field bug 2026-10-10 — a
 * co-admin agent could never connect to the utility server, so it never saw the
 * founding ceremony's pending approval).
 *
 * Pure and exported so the rule is testable without touching the OS interfaces.
 */
export function isLoopbackHost(host: string): boolean {
  // Accept the bracketed IPv6 form (`[::1]`) and surrounding whitespace.
  const h = host.trim().toLowerCase().replace(/^\[/, '').replace(/\]$/, '');
  return h === 'localhost'
    || h === '::1'
    || h === '0:0:0:0:0:0:0:1'
    || h.startsWith('127.');
}

/**
 * Build dialable multiaddrs from the local libp2p node's listen addresses.
 *
 * This replaces the wildcard `0.0.0.0` bind address with actual LAN IPs
 * detected from the OS network interfaces, and filters out relay circuit
 * addresses (`/p2p-circuit`) that should not be reported as direct-dial
 * endpoints (these are communicated separately via the bootstrap server's
 * `relayAddr` field).
 *
 * Why this matters: if a peer only reports `/ip4/0.0.0.0/tcp/{port}` (the
 * wildcard listen address that libp2p returns from `getMultiaddrs()`), no
 * other peer can dial it directly because `0.0.0.0` is not a routable
 * destination. Libp2p's dialer will fail on every direct attempt, and the
 * only remaining dialable address is the relay address — which forces all
 * connections through the relay, even for peers on the same LAN.
 *
 * By replacing the wildcard with the actual LAN IP(s) detected from the OS,
 * LAN peers can dial each other directly. Relay addresses are filtered out
 * because they belong in the `relayAddr` metadata field, not in the direct-
 * dial address list.
 *
 * @param multiaddrs — Raw multiaddr strings from `node.getMultiaddrs()`
 * @param advertisedHost — Operator-configured host to announce instead of the
 *   detected LAN IPs. Ignored when it is a loopback address (`isLoopbackHost`).
 * @returns Dialable multiaddrs with LAN IPs substituted and relay addrs filtered
 */
export function buildDialableMultiaddrs(multiaddrs: string[], advertisedHost?: string): string[] {
  // When an explicit advertised host is configured, prefer it over OS-detected
  // LAN IPs, so the peer's announced address matches the operator's configured
  // IP/hostname rather than an auto-detected interface address.
  //
  // A LOOPBACK host is NOT a configured location — see `isLoopbackHost` — so it is
  // ignored and the detected LAN IPs are used: announcing `127.0.0.1` only ever
  // sends every peer to its own machine, which is strictly worse than announcing
  // the interface address.
  const configuredHost = advertisedHost && !isLoopbackHost(advertisedHost)
    ? advertisedHost
    : undefined;
  const lanIps = configuredHost ? [configuredHost] : getLocalLanIps();
  const result: string[] = [];

  for (const addr of multiaddrs) {
    // Filter out relay circuit addresses — these are communicated via
    // the bootstrap server's relayAddr field, not as direct-dial addrs.
    if (addr.includes('/p2p-circuit')) continue;

    // Filter out WebSocket addresses in the relay namespace (e.g.
    // /tcp/{port}/ws/p2p/{id} — WebSocket relay variants). These are
    // not direct-dial addresses either.
    if (addr.includes('/p2p/') && addr.includes('/ws')) continue;

    // Replace 0.0.0.0 wildcard with actual LAN IPs
    if (addr.includes('/ip4/0.0.0.0/')) {
      for (const lanIp of lanIps) {
        result.push(addr.replace('/ip4/0.0.0.0/', `/ip4/${lanIp}/`));
      }
    } else {
      result.push(addr);
    }
  }

  // If all addresses were filtered out (e.g., no LAN IPs, only relay),
  // keep the originals as a fallback — at least the bootstrap server
  // can record the remoteAddr from the connection.
  if (result.length === 0) {
    return multiaddrs.filter(a => !a.includes('/p2p-circuit'));
  }

  return result;
}

// ---------------------------------------------------------------------------
// Profile comparison
// ---------------------------------------------------------------------------

/**
 * Compare two network profiles and determine what changed.
 * Returns an array of changed field names, or empty array if identical.
 */
function findChangedFields(oldProfile: NetworkProfile, newProfile: NetworkProfile): string[] {
  const changed: string[] = [];

  // Normalize WAN IP for comparison
  const oldWan = oldProfile.wanIp ?? '';
  const newWan = newProfile.wanIp ?? '';
  if (oldWan !== newWan) changed.push('wanIp');

  // Compare LAN IPs
  const oldLan = oldProfile.lanIps.sort().join(',');
  const newLan = newProfile.lanIps.sort().join(',');
  if (oldLan !== newLan) changed.push('lanIps');

  // Compare listen port
  if (oldProfile.listenPort !== newProfile.listenPort) changed.push('listenPort');

  return changed;
}

// ---------------------------------------------------------------------------
// NetworkDetectModule
// ---------------------------------------------------------------------------

export class NetworkDetectModule {
  private storedProfile: NetworkProfile | null = null;
  private currentProfile: NetworkProfile | null = null;
  private changeHandlers: Array<(event: NetworkChangeEvent) => void> = [];

  /**
   * Capture the current network profile from the agent's transport info.
   * Compares against the stored profile and emits change events if different.
   *
   * @param multiaddrs - The agent's current libp2p listen addresses
   * @param wanSourceAddr - The source address as seen by bootstrap server (optional)
   * @returns The current network profile
   */
  captureProfile(multiaddrs: string[], wanSourceAddr?: string): NetworkProfile {
    const profile: NetworkProfile = {
      wanIp: extractWanIp(wanSourceAddr),
      lanIps: extractLanIps(multiaddrs),
      listenPort: extractListenPort(multiaddrs),
      libp2pAddrs: multiaddrs,
      capturedAt: Math.floor(Date.now() / 1000),
    };

    if (this.storedProfile) {
      const changed = findChangedFields(this.storedProfile, profile);
      if (changed.length > 0) {
        const event: NetworkChangeEvent = {
          oldProfile: this.storedProfile,
          newProfile: profile,
          changedFields: changed,
        };
        for (const handler of this.changeHandlers) {
          handler(event);
        }
      }
    }

    // Update stored profile
    this.storedProfile = profile;
    this.currentProfile = profile;

    return profile;
  }

  /**
   * Get the current network profile.
   */
  getCurrentProfile(): NetworkProfile | undefined {
    return this.currentProfile ?? undefined;
  }

  /**
   * Get the stored (last-known) network profile.
   */
  getStoredProfile(): NetworkProfile | undefined {
    return this.storedProfile ?? undefined;
  }

  /**
   * Check if the network has changed since the last capture.
   * Compares current libp2p addresses against the stored profile.
   */
  isNetworkChanged(multiaddrs: string[], wanSourceAddr?: string): boolean {
    if (!this.storedProfile) return false;

    const current: NetworkProfile = {
      wanIp: extractWanIp(wanSourceAddr),
      lanIps: extractLanIps(multiaddrs),
      listenPort: extractListenPort(multiaddrs),
      libp2pAddrs: multiaddrs,
      capturedAt: Math.floor(Date.now() / 1000),
    };

    return findChangedFields(this.storedProfile, current).length > 0;
  }

  /**
   * Register a handler for network change events.
   */
  onNetworkChange(handler: (event: NetworkChangeEvent) => void): void {
    this.changeHandlers.push(handler);
  }

  /**
   * Clean up resources.
   */
  destroy(): void {
    this.storedProfile = null;
    this.currentProfile = null;
    this.changeHandlers = [];
  }
}