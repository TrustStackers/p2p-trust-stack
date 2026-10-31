// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * dial-candidates — ONE address-selection policy for every dial this stack makes.
 *
 * WHY THIS EXISTS
 * ---------------
 * Before this module the stack had TWO address-selection implementations that
 * disagreed, and neither ranked addresses by whether they could actually work:
 *
 *   1. The INITIAL connection (an agent joining a VTN, or a discovery-based
 *      recovery) put only `peer.multiaddrs` into the OOBI and let libp2p dial
 *      them with its default sorter.
 *   2. `ConnectivityModule.reconnectPeer()` (recovery) had its own inline
 *      direct → relay → last-known ladder, which was the only place a
 *      `/p2p-circuit` address was ever tried.
 *
 * So a FIRST cross-network join could not use the relay at all, and even when a
 * relay address was present libp2p's `defaultAddressSorter` ordered the list by
 * `loopbackAddressLast || publicAddressesFirst || circuitRelayAddressesLast ||
 * certifiedAddressesFirst || reliableTransportsFirst` — which for a typical
 * discovered utility server is exactly backwards:
 *
 *   peer.multiaddrs = [
 *     '/ip4/192.168.1.246/tcp/4001/p2p/<server>',              // LAN  — dead off-LAN
 *     '/ip4/24.5.6.7/tcp/52344/p2p/<server>',                  // NAT-mapped, dead everywhere
 *     '/dns/relay.…/tcp/4001/p2p/<relay>/p2p-circuit/p2p/<server>',  // the ONLY usable one
 *   ]
 *   defaultAddressSorter → [ 24.5.6.7:52344, relay, 192.168.1.246:4001 ]
 *
 * `publicAddressesFirst` ranks the NAT-mapped address ahead of the LAN one
 * (`isPrivate` is true for 192.168.x but false for 24.5.6.7), so the dial spends
 * its `addressDialTimeout` (6 s in the agent's node config) on an address
 * nothing listens on — and the relay, when it is reached at all, is last.
 * Measured against the real sorters (`@libp2p/utils` 7.x) on 2026-10-28.
 *
 * THE POLICY HERE
 * ---------------
 * Rank by "how likely is this address to actually work for the peer I am
 * dialing", not by "is this address publicly routable":
 *
 *   0. relay       — a `/p2p-circuit` address. Works from ANY network whenever
 *      the destination holds a reservation, which is the whole reason the
 *      bootstrap server is also a relay. FIRST, because it is the only entry
 *      that is not a guess about where the peer is.
 *   1. same-subnet — a direct address inside one of OUR OWN local subnets.
 *      RANKED SECOND, not first (field correction, 2026-10-29). A /24 match is
 *      NOT proof of shared L2: two routers on different WANs both hand out
 *      `192.168.1.x` by default, so a peer's LAN address can look local while
 *      being a different host — or nothing at all — on OUR lan. That is exactly
 *      the MBP2014 field log: the agent was `192.168.1.201`, the utility server
 *      advertised `192.168.1.28` on a different network, and the mis-ranked
 *      address was dialed FIRST on every attempt.
 *
 *      The cost of this correction is one relay round-trip for a same-LAN join
 *      in a relay-enabled deployment (a LAN-only rig has no relay candidate at
 *      all, so nothing changes there), and it buys a dial order that is right
 *      from every network. It still outranks every other direct scope.
 *   2. dns         — an operator-declared hostname. A deliberate public name
 *      (a port-forwarded or cloud-hosted server) is worth trying directly.
 *   3. lan         — a private address outside our subnets. Almost always
 *      unreachable, but cheap to try before the guesswork below.
 *   4. wan         — a bare public IP. Usually the bootstrap's OBSERVED
 *      remote address, i.e. a NAT-mapped ephemeral port — the least trustworthy
 *      entry in the list, which is why it ranks near the bottom.
 *   5. unknown     — unparseable, kept so nothing is silently dropped.
 *   6. loopback    — only ever correct for a peer on this same machine.
 *
 * If the relay ever needs to rank lower (e.g. a deployment where direct DNS
 * always works and the relay hop's latency matters), change
 * {@link DIAL_SCOPE_RANK} — it is the single place the order is expressed, and
 * both the explicit dial ladder and the libp2p `addressSorter` read it.
 *
 * Kept pure and dependency-free (no libp2p, no node APIs, no clock) so it is
 * cheap to unit test and safe to call from a status route.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** How reachable an address is likely to be, from the dialing peer's position. */
export type DialScope =
  | 'same-subnet'
  | 'relay'
  | 'dns'
  | 'lan'
  | 'wan'
  | 'unknown'
  | 'loopback';

/**
 * The dial order, as a rank per scope (LOWER is tried FIRST).
 *
 * Exported so a caller — or a test — can assert the policy itself rather than
 * reverse-engineering it from an ordered list.
 */
export const DIAL_SCOPE_RANK: Readonly<Record<DialScope, number>> = {
  relay: 0,
  'same-subnet': 1,
  dns: 2,
  lan: 3,
  wan: 4,
  unknown: 5,
  loopback: 6,
};

/** Where a candidate came from, so a caller can log/act on the distinction. */
export type DialCandidateSource = 'direct' | 'relay' | 'last-known';

/** One address to try, with the scope that produced its rank. */
export interface DialCandidate {
  /** The multiaddr string, exactly as it should be dialed. */
  addr: string;
  scope: DialScope;
  source: DialCandidateSource;
}

/** Everything {@link buildDialCandidates} needs. Every field but `peerId` is optional. */
export interface DialCandidateInput {
  /** The destination peer's libp2p peer ID (appended to the server relay prefix). */
  peerId: string;
  /** Direct addresses advertised for the peer (bootstrap directory / OOBI). */
  multiaddrs?: readonly string[];
  /**
   * The PER-PEER relay address from the bootstrap directory. Already carries the
   * destination peer ID (`<relay-prefix>/p2p/<peerId>`).
   */
  peerRelayAddr?: string;
  /**
   * The SERVER-LEVEL relay prefix, ending in `/p2p-circuit`
   * (`/dns/<relay-host>/tcp/<port>/p2p/<relayPeerId>/p2p-circuit`). The
   * destination peer ID is appended to build a dialable address.
   */
  serverRelayPrefix?: string;
  /**
   * This machine's own LAN IPs (`getLocalLanIps()`). Used to recognise a direct
   * address that is on OUR subnet. Omit to skip the `same-subnet` tier — the
   * policy degrades to `relay → dns → lan → wan`, which is still correct, only
   * slightly less fast for a same-LAN peer.
   */
  localLanIps?: readonly string[];
  /** Previously stored addresses, tried last. Never outranks a fresh one. */
  lastKnownMultiaddrs?: readonly string[];
}

// ---------------------------------------------------------------------------
// Address parsing helpers (pure)
// ---------------------------------------------------------------------------

/** The first host component of a multiaddr, e.g. `/ip4/1.2.3.4/…` → ip4 + 1.2.3.4. */
interface HostComponent {
  kind: 'ip4' | 'ip6' | 'dns';
  value: string;
}

const HOST_RE = /^\/(ip4|ip6|dns|dns4|dns6|dnsaddr)\/([^/]+)/;

function firstHostComponent(addr: string): HostComponent | undefined {
  const m = HOST_RE.exec(addr);
  if (!m) return undefined;
  const kind = m[1];
  // Strip an IPv6 zone index (`fe80::1%en0` → `fe80::1`): it is interface-local
  // and would make every comparison against another host fail.
  const value = m[2].split('%')[0];
  if (kind === 'ip4') return { kind: 'ip4', value };
  if (kind === 'ip6') return { kind: 'ip6', value };
  return { kind: 'dns', value };
}

/** Octets of a dotted-quad IPv4, or undefined when it is not one. */
function ipv4Octets(ip: string): number[] | undefined {
  const parts = ip.split('.');
  if (parts.length !== 4) return undefined;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined;
    const n = Number(part);
    if (n > 255) return undefined;
    octets.push(n);
  }
  return octets;
}

function isLoopbackIp(ip: string): boolean {
  if (ip === '::1') return true;
  const v4 = ipv4Octets(ip);
  return v4 ? v4[0] === 127 : false;
}

/**
 * Private / non-routable IPv4 and IPv6.
 *
 * `100.64.0.0/10` (carrier-grade NAT) is included as NOT public: it is the
 * address family a Starlink or mobile-carrier peer is handed, and no other host
 * can dial it. `@libp2p/utils`'s `isPrivateIp` agrees — but its
 * `publicAddressesFirst` sorter then ranks a genuinely routable address ahead of
 * a LAN one, which is the inversion this module exists to undo.
 */
function isPrivateIp(ip: string): boolean {
  if (ip.includes(':')) {
    const lower = ip.toLowerCase();
    if (lower === '::1') return true;
    if (lower.startsWith('fe80')) return true; // link-local
    if (/^f[cd]/.test(lower)) return true; // fc00::/7 unique-local
    return false;
  }
  const v4 = ipv4Octets(ip);
  if (!v4) return false;
  const [a, b] = v4;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true; // link-local
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  return false;
}

/**
 * Whether `ip` is on the same subnet as one of `localLanIps`.
 *
 * IPv4 compares the first three octets (a /24), IPv6 the first four hextets (a
 * /64) — the granularity a home/office LAN and a typical mobile carrier
 * allocation actually use. An IPv6 address with fewer than four explicit
 * hextets before its `::` is treated as NOT same-subnet rather than guessed at;
 * it still classifies as `lan`/`wan` and still outranks nothing important.
 */
function sharesSubnet(ip: string, localLanIps: readonly string[]): boolean {
  if (localLanIps.length === 0) return false;

  const v4 = ipv4Octets(ip);
  if (v4) {
    const prefix = `${v4[0]}.${v4[1]}.${v4[2]}.`;
    return localLanIps.some((local) => {
      const lv4 = ipv4Octets(local);
      if (!lv4) return false;
      return `${lv4[0]}.${lv4[1]}.${lv4[2]}.` === prefix;
    });
  }

  if (!ip.includes(':')) return false;
  const hextets = ipHextets(ip);
  if (!hextets) return false;
  return localLanIps.some((local) => {
    const lh = ipHextets(local);
    if (!lh) return false;
    return hextets.join(':') === lh.join(':');
  });
}

/** The first four hextets of an IPv6 address, or undefined when it has too few. */
function ipHextets(ip: string): string[] | undefined {
  const head = ip.split('::')[0];
  const parts = head.split(':').filter((h) => h.length > 0);
  if (parts.length < 4) return undefined;
  return parts.slice(0, 4).map((h) => h.toLowerCase());
}

// ---------------------------------------------------------------------------
// Classification + comparison
// ---------------------------------------------------------------------------

/**
 * Classify one address for a dialer sitting behind `localLanIps`.
 *
 * `relay` is tested FIRST: a circuit address also starts with `/dns/…` or
 * `/ip4/…`, so testing the host kind first would misclassify the relay as a
 * direct DNS/IP address — the exact mistake `isPrivate()`-style sorting makes.
 */
export function classifyDialAddr(addr: string, localLanIps: readonly string[] = []): DialScope {
  if (typeof addr !== 'string' || addr.length === 0) return 'unknown';
  if (addr.includes('/p2p-circuit')) return 'relay';

  const host = firstHostComponent(addr);
  if (!host) return 'unknown';

  if (host.kind === 'dns') {
    const lower = host.value.toLowerCase();
    if (lower === 'localhost' || lower.endsWith('.localhost')) return 'loopback';
    return 'dns';
  }

  if (isLoopbackIp(host.value)) return 'loopback';
  if (sharesSubnet(host.value, localLanIps)) return 'same-subnet';
  return isPrivateIp(host.value) ? 'lan' : 'wan';
}

/**
 * Compare two addresses by the policy in {@link DIAL_SCOPE_RANK}.
 *
 * Returns `-1 | 0 | 1`, so it is usable BOTH as the comparator for the explicit
 * candidate list AND (through {@link makeAddressSorter}) as libp2p's
 * `AddressSorter`. Same-scope addresses keep their relative order —
 * `Array.prototype.sort` is stable, and the caller feeds the list in source
 * order (per-peer relay before server-derived relay, advertised before
 * last-known).
 */
export function compareDialAddrs(
  a: string,
  b: string,
  localLanIps: readonly string[] = [],
): -1 | 0 | 1 {
  const ra = DIAL_SCOPE_RANK[classifyDialAddr(a, localLanIps)];
  const rb = DIAL_SCOPE_RANK[classifyDialAddr(b, localLanIps)];
  if (ra < rb) return -1;
  if (ra > rb) return 1;
  return 0;
}

/**
 * libp2p `AddressSorter` built from the same policy.
 *
 * Install it as `connectionManager.addressSorter` so a dial libp2p performs ON
 * ITS OWN — `Libp2pTransport.send()`'s `dialProtocol(peerId, …)` with no
 * explicit address list — also walks the addresses in our order instead of the
 * default sorter's (which puts a NAT-mapped public IP first and the relay last).
 * Without this, the explicit ladder below is defeated the moment a send falls
 * back to a peer-store dial.
 *
 * `localLanIps` is a plain array rather than a getter: it is captured when the
 * node is built, and a LAN address that has since gone stale is ranked `lan`
 * (still ahead of `wan`), so a network change can only cost a little order,
 * never correctness.
 */
export function makeAddressSorter(
  localLanIps: readonly string[] = [],
): (a: { multiaddr: { toString(): string } }, b: { multiaddr: { toString(): string } }) => -1 | 0 | 1 {
  return (a, b) => {
    try {
      return compareDialAddrs(a.multiaddr.toString(), b.multiaddr.toString(), localLanIps);
    } catch {
      // A throwing getter must never break a dial — treat it as a tie.
      return 0;
    }
  };
}

// ---------------------------------------------------------------------------
// Candidate list
// ---------------------------------------------------------------------------

/**
 * Build the ordered list of addresses to try for one destination peer.
 *
 * Ordering is {@link compareDialAddrs}; duplicates are removed, keeping the
 * FIRST occurrence so a per-peer relay address (which the bootstrap resolved
 * against its own dialable prefix) outranks the one we construct from the
 * server-level prefix. Empty and non-string entries are dropped.
 */
export function buildDialCandidates(input: DialCandidateInput): DialCandidate[] {
  const localLanIps = input.localLanIps ?? [];
  const peerId = typeof input.peerId === 'string' ? input.peerId : '';

  const collected: DialCandidate[] = [];
  const push = (addr: unknown, source: DialCandidateSource): void => {
    if (typeof addr !== 'string' || addr.length === 0) return;
    collected.push({ addr, scope: classifyDialAddr(addr, localLanIps), source });
  };

  // Direct first in source order, then relay, then last-known: the sort below is
  // stable, so this input order is what breaks ties inside a scope.
  for (const addr of input.multiaddrs ?? []) push(addr, 'direct');

  push(input.peerRelayAddr, 'relay');
  if (peerId && typeof input.serverRelayPrefix === 'string' && input.serverRelayPrefix.length > 0) {
    push(`${input.serverRelayPrefix}/p2p/${peerId}`, 'relay');
  }

  for (const addr of input.lastKnownMultiaddrs ?? []) push(addr, 'last-known');

  const seen = new Set<string>();
  const unique: DialCandidate[] = [];
  for (const candidate of collected) {
    if (seen.has(candidate.addr)) continue;
    seen.add(candidate.addr);
    unique.push(candidate);
  }

  return unique.sort((a, b) => compareDialAddrs(a.addr, b.addr, localLanIps));
}

/** The addresses of {@link buildDialCandidates}, in dial order. */
export function dialCandidateAddrs(candidates: readonly DialCandidate[]): string[] {
  return candidates.map((c) => c.addr);
}
