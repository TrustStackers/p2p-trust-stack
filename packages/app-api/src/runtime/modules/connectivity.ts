// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * ConnectivityModule — bootstrap server integration extracted from BaseAgent.
 *
 * Handles peer discovery, bootstrap registration, keepalive, and connection strategies.
 * This module is injected into BaseAgent during start() to keep the base class
 * focused on its core coordination responsibilities.
 *
 * Phase 8: Reconnection uses a clean 2-tier strategy:
 *   1. Try bootstrap-discovered direct addresses
 *   2. Dial via circuit relay through the bootstrap server (NAT traversal)
 *
 * Phase 9: Keepalive reuses the same TCP connection from registration (no second connection).
 * Network detection tracks LAN/WAN IP changes to alert the user.
 *
 * The previous LAN port sweep (24000-24004) has been removed — it was a hack
 * for pre-relay NAT traversal. mDNS is also not used (unreliable across networks).
 * The bootstrap server is the sole coordination mechanism.
 */

import type { Libp2p } from 'libp2p';
import { multiaddr } from '@multiformats/multiaddr';
import { BootstrapClient, type DiscoveredPeer } from '@p2p-trust-stack/core/transport/bootstrap-client.js';
import { loadBootstrapClientEnv, buildBootstrapUrls, type BootstrapClientEnv } from '@p2p-trust-stack/core/config/bootstrap-env.js';

import {
  NetworkDetectModule,
  type NetworkProfile,
  buildDialableMultiaddrs,
  getLocalLanIps,
} from '@p2p-trust-stack/core/platform/network-detect.js';
import {
  readRelayHealth,
  type RelayHealthSnapshot,
} from '@p2p-trust-stack/core/transport/relay-health.js';
import {
  buildDialCandidates,
  dialCandidateAddrs,
  type DialCandidate,
} from '@p2p-trust-stack/core/transport/dial-candidates.js';
import type { TspTransport } from '@p2p-trust-stack/core/transport/types.js';
import type { RelationshipStore } from '@p2p-trust-stack/core/relationship/store.js';

// ---------------------------------------------------------------------------
// Dial bounds
// ---------------------------------------------------------------------------

/** The TSP stream protocol negotiated on every connection. */
const TSP_PROTOCOL_ID = '/tsp/1.0.0';
/** Bound on a direct dial attempt, so one dead address cannot stall the ladder. */
const DIRECT_DIAL_TIMEOUT_MS = 10_000;
/** Bound on the relay HOP dial — a dead relay circuit must not hang recovery. */
const RELAY_DIAL_TIMEOUT_MS = 15_000;
/** Bound on the TSP stream open through a relay. */
const RELAY_STREAM_TIMEOUT_MS = 10_000;
/**
 * Delay before the single relay retry. The target's circuit-relay reservation is
 * created asynchronously during its own `register()` (see
 * `BootstrapClient.ensureRelayReservation()`), so an immediate HOP can lose that
 * race; 2 s covers it without making recovery slow.
 */
const RELAY_RETRY_DELAY_MS = 2_000;

/**
 * Ensure a dial target names the peer it is meant for.
 *
 * A multiaddr with no `/p2p/<peerId>` makes libp2p dial an UNIDENTIFIED peer: it
 * has nothing to check the handshake's peer ID against, so whatever answers at
 * that address is accepted as the peer. Every candidate reaching the ladder came
 * from an OOBI or the bootstrap directory and should already carry the peer ID —
 * this is the guard, not the common path.
 */
function withPeerId(addr: string, peerId: string): string {
  return addr.includes('/p2p/') ? addr : `${addr}/p2p/${peerId}`;
}

// ---------------------------------------------------------------------------
// ConnectivityModule
// ---------------------------------------------------------------------------

export class ConnectivityModule {
  private bootstrapClient?: BootstrapClient;
  private bootstrapRelayAddr?: string;
  private bootstrapConnected = false;
  private discoveredPeers: Map<string, DiscoveredPeer> = new Map();
  /** Peer designation sent to the bootstrap: user name, network/group, test flag. */
  private agentName?: string;
  private net?: string;
  private isTest = false;
  private networkDetect = new NetworkDetectModule();
  private clientSourceAddr?: string;  // WAN-facing IP as seen by bootstrap
  private libp2pNode?: Libp2p;         // Stored for auto-reconnect probe
  private onStatus?: (message: string) => void;  // Status callback for TUI
  private networkChangeHandlerRegistered = false;  // Track if network change auto-reconnect is wired

  /**
   * Connect to the bootstrap server, register this peer, and discover other peers.
   * Falls back gracefully if bootstrap is unavailable.
   *
   * After successful registration, starts the keepalive loop on the same TCP
   * connection (no second connection opened).
   */
  async connectToBootstrap(params: {
    libp2pNode: Libp2p;
    multiaddrs: string[];
    onStatus?: (message: string) => void;
    /** The agent's configured user name (bootstrap-facing). */
    agentName?: string;
    /** Network/group (namespace) the agent is joining, e.g. 'p2pts'. */
    net?: string;
    /** True when this is a test-suite agent (bootstrap TTL-prunes it). */
    test?: boolean;
    /**
     * Pre-loaded bootstrap client config (composition root injection).
     *
     * A CLIENT config — host + peer ID, no seed. The seed belongs to the bootstrap
     * server alone; this module only needs the address and the identity to expect.
     */
    bootstrapEnv?: BootstrapClientEnv;
    /** Explicit `.env` path. Defaults to `<cwd>/.env`. */
    bootstrapEnvPath?: string;
  }): Promise<void> {
    this.libp2pNode = params.libp2pNode;
    this.onStatus = params.onStatus;
    // Remember the designation so a later reRegisterWithBootstrap() re-sends it.
    this.agentName = params.agentName;
    this.net = params.net;
    this.isTest = params.test === true;

    // Resolve the bootstrap/relay identity + address from the component's `.env`
    // (through src/config/bootstrap-env.ts). There is no hardcoded default and no
    // `process.env` override anymore, so a missing/malformed config degrades to
    // LAN-only mode — the same behaviour as an unreachable server, and never a
    // silent wrong address.
    //
    // The CLIENT loader is used deliberately: an agent holds no seed, only the
    // address and the peer ID to expect.
    let bootstrapEnv = params.bootstrapEnv;
    if (!bootstrapEnv) {
      try {
        bootstrapEnv = loadBootstrapClientEnv(
          params.bootstrapEnvPath ? { path: params.bootstrapEnvPath } : {},
        );
      } catch (err) {
        this.bootstrapConnected = false;
        params.onStatus?.(
          `Bootstrap config unavailable (${err instanceof Error ? err.message : 'unknown'}) — ` +
          'continuing in LAN-only mode.',
        );
        return;
      }
    }
    const { tcpUrl, wsUrl } = buildBootstrapUrls(bootstrapEnv);
    this.bootstrapClient = new BootstrapClient(tcpUrl, wsUrl);

    // Wire up auto-reconnect status events.
    //
    // Relay statuses are deliberately kept SEPARATE from bootstrap status: a
    // lost circuit-relay reservation means "nobody across a WAN can reach this
    // peer", which is NOT the same as "the bootstrap server is down", and
    // clearing `bootstrapConnected` for it made the agent report — and act on —
    // a bootstrap outage that had not happened.
    this.bootstrapClient.onStatusChange((status, info) => {
      if (status === 'disconnected') {
        this.bootstrapConnected = false;
        this.onStatus?.(`[red]Bootstrap disconnected: ${info.message}[reset]`);
      } else if (status === 'reconnected') {
        this.bootstrapConnected = true;
        this.onStatus?.(`[green]Bootstrap reconnected: ${info.message}[reset]`);
      } else if (status === 'relay-degraded') {
        this.onStatus?.(
          `[yellow]Relay reachability impaired: ${info.message}[reset]`,
        );
      } else if (status === 'relay-restored') {
        this.onStatus?.(`[green]${info.message}[reset]`);
      }
    });

    // Wire up network change detection → immediate re-registration
    if (!this.networkChangeHandlerRegistered) {
      this.networkDetect.onNetworkChange(async (event) => {
        this.onStatus?.(`[yellow]Network change detected: ${event.changedFields.join(', ')} — Re-registering with bootstrap...[reset]`);
        if (this.libp2pNode) {
          try {
            await this.reRegisterWithBootstrap({
              libp2pNode: this.libp2pNode,
              multiaddrs: this.libp2pNode.getMultiaddrs().map(a => a.toString()),
              onStatus: this.onStatus,
            });
            this.onStatus?.(`[green]Auto re-registered after network change.[reset]`);
          } catch (err) {
            this.onStatus?.(`[red]Auto re-registration failed: ${err instanceof Error ? err.message : 'unknown'}[reset]`);
          }
        }
      });
      this.networkChangeHandlerRegistered = true;
    }

    // Replace wildcard 0.0.0.0 with actual LAN IPs and filter out relay
    // circuit addresses so peers on the same LAN can dial us directly.
    // Relay reachability is communicated separately via the bootstrap
    // server's relayAddr field.
    const dialableAddrs = buildDialableMultiaddrs(params.multiaddrs);
    params.onStatus?.(`Registering with LAN addrs: ${dialableAddrs.join(', ')}`);

    params.onStatus?.('Connecting to bootstrap server...');

    try {
      const result = await this.bootstrapClient.register(
        params.libp2pNode,
        dialableAddrs,
        'agent',
        undefined,
        undefined,
        { net: this.net, agentName: this.agentName, test: this.isTest || undefined },
      );

      this.bootstrapConnected = true;
      this.bootstrapRelayAddr = result.relayAddr;
      this.clientSourceAddr = result.clientSourceAddr;

      // Capture network profile (stores LAN/WAN IPs for change detection)
      if (result.clientSourceAddr) {
        this.networkDetect.captureProfile(params.multiaddrs, result.clientSourceAddr);
      }

      // Store discovered peers
      this.discoveredPeers.clear();
      for (const peer of result.connectedPeers) {
        this.discoveredPeers.set(peer.peerId, peer);

        // Patch the peer's addresses into the libp2p peer store so we can dial them
        if (peer.multiaddrs.length > 0) {
          try {
            await (params.libp2pNode.peerStore as any).patch(peer.peerId, {
              multiaddrs: peer.multiaddrs,
            });
          } catch {
            // Peer store patch may fail for some peer ID formats; ignore
          }
        }
      }

      // Start keepalive on the SAME TCP connection (no second connection)
      if (result.bootstrapConnection) {
        this.bootstrapClient.startKeepalive(params.libp2pNode);
        params.onStatus?.('Keepalive started (relay circuit active).');
        params.onStatus?.('Auto-reconnect enabled (exponential backoff).');
      }

      params.onStatus?.(
        `Connected to bootstrap server. Discovered ${result.connectedPeers.length} peers.` +
        (result.relayAddr ? ' (relay available)' : ''),
      );

      // Report whether we actually hold a circuit-relay reservation — this is
      // the piece that determines whether peers on a different WAN can reach
      // us via relay when direct dialing fails.
      params.onStatus?.(
        this.bootstrapClient.hasRelayReservation(params.libp2pNode)
          ? '[green]Circuit-relay reservation active — reachable via relay from other networks.[reset]'
          : '[yellow]No circuit-relay reservation yet — this peer may be unreachable from a different WAN until one is established.[reset]',
      );
    } catch (err) {
      // Bootstrap connection failed - log but continue in LAN-only mode

      params.onStatus?.(
        `Bootstrap server unavailable (${err instanceof Error ? err.message : 'unknown'}). ` +
        `Continuing in LAN-only mode.`,
      );
      this.bootstrapConnected = false;
    }
  }

  /**
   * Set the VTN key (namespace) this agent identifies itself by, and re-register
   * with the bootstrap so the change is visible immediately.
   *
   * WHY RE-REGISTER: `net` is the bootstrap-facing identity — it is what the
   * peer list shows beside the agent and what tells the network which VTN this
   * agent belongs to. Registration happens in `start()`, before the user has
   * picked a VTN, so the picker has to update the designation and push it.
   *
   * A no-op when the key is unchanged (the common "already on this VTN" case),
   * so re-picking the current VTN does not churn the bootstrap connection.
   */
  async setNet(
    net: string,
    params: { libp2pNode: Libp2p; multiaddrs: string[]; onStatus?: (message: string) => void },
  ): Promise<void> {
    const next = net.trim();
    if (!next) throw new Error('ConnectivityModule.setNet: a VTN key is required');
    if (this.net === next) return;
    this.net = next;
    await this.reRegisterWithBootstrap(params);
  }

  /** The VTN key this agent currently identifies itself by (undefined until chosen). */
  getNet(): string | undefined {
    return this.net;
  }

  /**
   * Re-register with the bootstrap server using fresh addresses.
   * Used when the user detects a network change and wants to update registration.
   */
  async reRegisterWithBootstrap(params: {
    libp2pNode: Libp2p;
    multiaddrs: string[];
    onStatus?: (message: string) => void;
  }): Promise<void> {
    if (!this.bootstrapClient) {
      params.onStatus?.('Not connected to bootstrap server. Cannot re-register.');
      return;
    }

    params.onStatus?.('Re-registering with bootstrap server...');

    // Stop existing keepalive before re-registering (auto-reconnect also cancelled)
    this.bootstrapClient.stopKeepalive();

    // Replace wildcard 0.0.0.0 with actual LAN IPs so peers on the same
    // LAN can dial us directly after re-registration.
    const dialableAddrs = buildDialableMultiaddrs(params.multiaddrs);

    try {
      const result = await this.bootstrapClient.register(
        params.libp2pNode,
        dialableAddrs,
        'agent',
        undefined,
        undefined,
        { net: this.net, agentName: this.agentName, test: this.isTest || undefined },
      );

      this.bootstrapConnected = true;
      this.bootstrapRelayAddr = result.relayAddr;
      this.clientSourceAddr = result.clientSourceAddr;

      // Update network profile
      if (result.clientSourceAddr) {
        this.networkDetect.captureProfile(params.multiaddrs, result.clientSourceAddr);
      }

      // Update discovered peers
      this.discoveredPeers.clear();
      for (const peer of result.connectedPeers) {
        this.discoveredPeers.set(peer.peerId, peer);

        if (peer.multiaddrs.length > 0) {
          try {
            await (params.libp2pNode.peerStore as any).patch(peer.peerId, {
              multiaddrs: peer.multiaddrs,
            });
          } catch {
            // Ignore peer store errors
          }
        }
      }

      // Restart keepalive on the new connection
      if (result.bootstrapConnection) {
        this.bootstrapClient.startKeepalive(params.libp2pNode);
        params.onStatus?.('Keepalive restarted (auto-reconnect enabled).');
      }

      params.onStatus?.(
        `Re-registered with bootstrap. Discovered ${result.connectedPeers.length} peers.` +
        (result.relayAddr ? ' (relay available)' : ''),
      );
    } catch (err) {
      params.onStatus?.(`Re-registration failed: ${err instanceof Error ? err.message : 'unknown'}`);
      this.bootstrapConnected = false;
    }
  }

  /**
   * Query the bootstrap server for the current peer list without re-registering.
   * Returns the list of discovered peers.
   */
  async refreshBootstrapPeers(params: {
    libp2pNode: Libp2p;
    onStatus?: (message: string) => void;
  }): Promise<DiscoveredPeer[]> {
    if (!this.bootstrapClient || !params.libp2pNode) {
      return [];
    }

    try {
      const result = await this.bootstrapClient.query(params.libp2pNode);

      // Update discovered peers map
      this.discoveredPeers.clear();
      for (const peer of result.connectedPeers) {
        this.discoveredPeers.set(peer.peerId, peer);

        // Patch addresses into peer store
        if (peer.multiaddrs.length > 0) {
          try {
            await (params.libp2pNode.peerStore as any).patch(peer.peerId, {
              multiaddrs: peer.multiaddrs,
            });
          } catch {
            // Ignore peer store errors
          }
        }
      }

      this.bootstrapRelayAddr = result.relayAddr;
      params.onStatus?.(`Refreshed bootstrap peers: ${result.connectedPeers.length} found.`);

      return result.connectedPeers;
    } catch (err) {
      params.onStatus?.(`Bootstrap query failed: ${err instanceof Error ? err.message : 'unknown'}`);
      return [];
    }
  }

  /** Check if the bootstrap server is connected. */
  isBootstrapConnected(): boolean {
    return this.bootstrapConnected;
  }

  /** Get the relay address through the bootstrap server (if available). */
  getBootstrapRelayAddr(): string | undefined {
    return this.bootstrapRelayAddr;
  }

  /**
   * LIVE circuit-relay grant view for this agent's node.
   *
   * Never a cached flag: it enumerates the connection manager on every call and
   * reads the relay's remaining `seconds` / `bytes` from each relayed
   * connection's `limits` getter. This is what lets the agent notice a relay
   * session that is ABOUT to expire rather than only reacting after it is cut.
   */
  getRelayHealth(): RelayHealthSnapshot {
    return readRelayHealth(this.libp2pNode, this.bootstrapClient?.getRelayPeerId() ?? null);
  }

  /** Whether this agent currently holds a relay reservation (inbound-reachable). */
  hasRelayReservation(): boolean {
    return this.bootstrapClient?.hasRelayReservation(this.libp2pNode) ?? false;
  }

  /** The relay's peer ID as resolved from the last successful bootstrap dial. */
  getRelayPeerId(): string | null {
    return this.bootstrapClient?.getRelayPeerId() ?? null;
  }

  /** Get the list of discovered peers from the bootstrap server. */
  getDiscoveredPeers(): DiscoveredPeer[] {
    return Array.from(this.discoveredPeers.values());
  }

  /** Get a specific discovered peer by libp2p peer ID. */
  getDiscoveredPeer(peerId: string): DiscoveredPeer | undefined {
    return this.discoveredPeers.get(peerId);
  }

  /** Get all discovered utility server peers. */
  getDiscoveredUtilityServers(): DiscoveredPeer[] {
    return Array.from(this.discoveredPeers.values()).filter(p => p.peerType === 'utility_server');
  }

  /** Get the current network profile. */
  getNetworkProfile(): NetworkProfile | undefined {
    return this.networkDetect.getCurrentProfile();
  }

  /** Check if the network has changed since last registration. */
  isNetworkChanged(multiaddrs: string[]): boolean {
    return this.networkDetect.isNetworkChanged(multiaddrs, this.clientSourceAddr);
  }

  /** Get the client's source address as seen by the bootstrap server. */
  getClientSourceAddr(): string | undefined {
    return this.clientSourceAddr;
  }

  /**
   * Reconnect to an already-established peer without requiring a fresh OOBI.
   *
   * Refreshes the bootstrap peer list, then walks ONE ordered address list
   * (`dialCandidatesFor()` → `dialPeerCandidates()`) built from the bootstrap
   * directory plus the last-known addresses:
   *
   *   1. relay        — a `/p2p-circuit` address (works from any network)
   *   2. same-subnet  — a direct address on OUR own LAN
   *   3. dns          — an operator-declared hostname
   *   4. lan / wan    — other direct addresses, then last-known
   *
   * The order is deliberate and is the fix for cross-network joins: libp2p's
   * default address sorter puts a NAT-mapped public IP first and the relay last,
   * so the dial budget was spent on addresses nothing listens on. See
   * dial-candidates.ts.
   *
   * The previous LAN port sweep has been removed — circuit relay is the
   * reliable fallback for internet connections.
   */
  async reconnectPeer(params: {
    transport: TspTransport;
    libp2pNode: Libp2p;
    store: RelationshipStore;
    localDid: string;
    remoteDid: string;
    recordRemoteTransport: { peerId: string; multiaddrs?: string[] };
    onStatus?: (message: string) => void;
  }): Promise<void> {
    const { peerId } = params.recordRemoteTransport;

    // Phase 11 fix: refresh the bootstrap peer list BEFORE attempting any
    // dials. The cached discoveredPeers may contain stale LAN addresses from
    // the last registration — if the target peer has since switched to a
    // different WAN/ISP, those old addresses will fail every direct dial
    // attempt, and the stale relayAddr may be missing or incorrect.
    //
    // A fresh query ensures we have the target's current WAN addresses and
    // relay address before trying any of the fallback tiers below.
    params.onStatus?.('Refreshing peer list from bootstrap server...');
    try {
      await this.refreshBootstrapPeers({
        libp2pNode: params.libp2pNode,
        onStatus: params.onStatus,
      });
    } catch {
      // Non-fatal: if the refresh fails, we still try with whatever cached
      // data we have (stale addresses are better than no addresses).
      params.onStatus?.('Bootstrap refresh failed, using cached peer data.');
    }

    // ONE ordered address list for this peer, and one dial ladder over it.
    //
    // This replaced an inline "all direct addresses, then relay, then
    // last-known" ladder that existed ONLY here — the join path had no relay
    // fallback at all, so a first cross-network join could never reach the
    // relay. Both paths now call dialCandidatesFor()/dialPeerCandidates().
    //
    // Ordering is the whole point: libp2p's default sorter ranks a NAT-mapped
    // public address ahead of the LAN one and pushes the relay to the end, so
    // the dial budget was spent on addresses nothing listens on. See
    // dial-candidates.ts for the measured evidence and the policy.
    const bootstrapPeer = this.discoveredPeers.get(peerId);
    const candidates = this.dialCandidatesFor({
      peerId,
      multiaddrs: bootstrapPeer?.multiaddrs,
      peerRelayAddr: bootstrapPeer?.relayAddr,
      lastKnownMultiaddrs: params.recordRemoteTransport.multiaddrs,
    });

    const dialled = await this.dialPeerCandidates({
      libp2pNode: params.libp2pNode,
      peerId,
      candidates,
      onStatus: params.onStatus,
    });

    if (dialled) {
      params.store.updateTransport(params.localDid, params.remoteDid, {
        peerId,
        // Store the WHOLE ordered list, not just the address that won: the peer
        // store then keeps every option, and the installed addressSorter picks
        // the best one on the next dial.
        multiaddrs: dialCandidateAddrs(candidates),
      });
      return;
    }

    throw new Error(
      `reconnectPeer: unable to reach ${params.remoteDid.slice(0, 12)}... ` +
      `Tried ${candidates.length} address(es): ${dialCandidateAddrs(candidates).join(', ') || 'none'}. ` +
      `Ensure both peers are registered with the bootstrap server.`,
    );
  }

  /**
   * The ordered dial-target list for one destination peer — the ONE place an
   * address list is built in this stack.
   *
   * The JOIN path calls this to seed an OOBI (so the very first RFI already
   * carries the relay address), and `reconnectPeer()` calls it to drive the
   * recovery ladder. Before this existed the two disagreed: the join used only
   * the bootstrap's `multiaddrs`, which never contain a `/p2p-circuit` address
   * because `buildDialableMultiaddrs()` filters them out — so a first
   * cross-network join had no relay to fall back to at all.
   *
   * The server-level relay prefix is supplied automatically from the bootstrap
   * registration, and this machine's LAN IPs let a same-subnet peer outrank the
   * relay. See dial-candidates.ts for the ranking rationale.
   */
  dialCandidatesFor(params: {
    peerId: string;
    multiaddrs?: readonly string[];
    peerRelayAddr?: string;
    lastKnownMultiaddrs?: readonly string[];
  }): DialCandidate[] {
    return buildDialCandidates({
      peerId: params.peerId,
      multiaddrs: params.multiaddrs,
      peerRelayAddr: params.peerRelayAddr,
      serverRelayPrefix: this.bootstrapRelayAddr,
      localLanIps: getLocalLanIps(),
      lastKnownMultiaddrs: params.lastKnownMultiaddrs,
    });
  }

  /**
   * Dial `peerId` through an ordered candidate list and report the address that
   * worked, or `undefined` when every candidate failed.
   *
   * The single dial implementation for BOTH the join path and recovery. Each
   * candidate is attempted in the order `buildDialCandidates()` produced, so the
   * relay is tried BEFORE a NAT-mapped public address instead of after it.
   *
   * Relay candidates get one retry after a short delay: the target's
   * circuit-relay reservation is established asynchronously during its own
   * `register()`, so an immediate HOP can lose a race a second attempt wins.
   * Never throws — the caller decides what an exhausted list means.
   */
  async dialPeerCandidates(params: {
    libp2pNode: Libp2p;
    peerId: string;
    candidates: readonly DialCandidate[];
    onStatus?: (message: string) => void;
  }): Promise<string | undefined> {
    const { libp2pNode, peerId, candidates, onStatus } = params;
    const short = peerId.slice(0, 12);
    if (candidates.length === 0) {
      onStatus?.(`No dial addresses known for ${short}...`);
      return undefined;
    }

    for (const candidate of candidates) {
      const label = `${candidate.scope}/${candidate.source}`;
      const isRelay = candidate.scope === 'relay';
      // A relay HOP that loses the reservation race is worth one retry; a dead
      // direct address is not (it would only burn the caller's time budget).
      const attempts = isRelay ? 2 : 1;

      for (let attempt = 1; attempt <= attempts; attempt++) {
        if (attempt > 1) {
          onStatus?.(`Retrying ${short}... via ${label} after the reservation race.`);
          await new Promise((resolve) => setTimeout(resolve, RELAY_RETRY_DELAY_MS));
        }
        onStatus?.(`Dialing ${short}... via ${label}: ${candidate.addr}`);
        try {
          if (isRelay) {
            await this.dialRelayAddr({ libp2pNode, relayAddr: candidate.addr });
          } else {
            // Dial THIS candidate, not "the peer".
            //
            // `dialProtocol(peerId, …)` hands libp2p the peer's WHOLE stored
            // address list and lets its dial queue pick, and the first dial that
            // completes at the transport level wins — including one that opens
            // and then immediately closes. libp2p returns that connection anyway
            // (its `dial-queue.ts` never checks `connection.status`), and
            // `openConnection` then throws
            // `ConnectionClosedError('Remote closed connection during opening')`,
            // aborting the ENTIRE call. So one bad address used to skip every
            // remaining candidate — relay included. That is the field failure of
            // 2026-10-29 on MBP2014, where the mis-ranked `192.168.1.28` (a
            // DIFFERENT network's LAN address that happens to share our /24)
            // aborted the dial before the relay was ever tried.
            //
            // Naming the address contains it: a bad candidate now costs one
            // candidate, and the ladder keeps walking. It also makes the
            // `onStatus` line above truthful — it always named the candidate, but
            // the call it described was a dial of the peer's whole address list.
            const stream = await (libp2pNode as any).dialProtocol(
              multiaddr(withPeerId(candidate.addr, peerId)),
              TSP_PROTOCOL_ID,
              { runOnLimitedConnection: true, signal: AbortSignal.timeout(DIRECT_DIAL_TIMEOUT_MS) },
            );
            try { await stream.close(); } catch { /* ignore */ }
          }
          onStatus?.(`Connected to ${short}... via ${label}.`);
          return candidate.addr;
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          onStatus?.(`${label} failed for ${short}...: ${message}`);
        }
      }
    }

    return undefined;
  }

  /**
   * Dial a `/p2p-circuit` address and open (then close) a TSP stream on it.
   *
   * Uses multiaddr() + dial() + connection.newStream() rather than
   * dialProtocol(multiaddrString): the dialProtocol API takes a PeerId + a
   * protocol string, not a full multiaddr containing `/p2p-circuit` components.
   * To dial through a relay we must:
   *   1. Parse the relay multiaddr
   *   2. dial() to establish the connection through the relay
   *   3. connection.newStream() to negotiate the TSP protocol
   *
   * A connection dialed through `/p2p-circuit` is ALWAYS "limited" in libp2p
   * (`connection.limits != null`), so `newStream()` throws
   * `LimitedConnectionError` unless `runOnLimitedConnection: true` is passed.
   *
   * The relay still rejects the HOP with `NO_RESERVATION` unless the *target*
   * peer holds a live reservation — see
   * `BootstrapClient.ensureRelayReservation()`.
   */
  private async dialRelayAddr(params: {
    libp2pNode: Libp2p;
    relayAddr: string;
  }): Promise<void> {
    const ma = multiaddr(params.relayAddr);
    const connection = await (params.libp2pNode as any).dial(ma, {
      signal: AbortSignal.timeout(RELAY_DIAL_TIMEOUT_MS),
    });
    const stream = await connection.newStream(TSP_PROTOCOL_ID, {
      signal: AbortSignal.timeout(RELAY_STREAM_TIMEOUT_MS),
      runOnLimitedConnection: true,
    });
    try { await stream.close(); } catch { /* ignore */ }
  }


  /** Clean up resources. */
  destroy(): void {
    this.bootstrapClient?.stopKeepalive();
    this.bootstrapClient = undefined;
    this.libp2pNode = undefined;
    this.discoveredPeers.clear();
    this.bootstrapConnected = false;
    this.networkDetect.destroy();
  }
}
