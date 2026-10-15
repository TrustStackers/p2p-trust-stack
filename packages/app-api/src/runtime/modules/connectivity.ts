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
import { peerIdFromString } from '@libp2p/peer-id';
import { BootstrapClient, type DiscoveredPeer } from '@p2p-trust-stack/core/transport/bootstrap-client.js';

import { NetworkDetectModule, type NetworkProfile, buildDialableMultiaddrs } from '@p2p-trust-stack/core/platform/network-detect.js';
import {
  readRelayHealth,
  type RelayHealthSnapshot,
} from '@p2p-trust-stack/core/transport/relay-health.js';
import type { TspTransport } from '@p2p-trust-stack/core/transport/types.js';
import type { RelationshipStore } from '@p2p-trust-stack/core/relationship/store.js';

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
  }): Promise<void> {
    this.libp2pNode = params.libp2pNode;
    this.onStatus = params.onStatus;
    // Remember the designation so a later reRegisterWithBootstrap() re-sends it.
    this.agentName = params.agentName;
    this.net = params.net;
    this.isTest = params.test === true;

    this.bootstrapClient = new BootstrapClient();

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
   * Phase 8: Clean 2-tier connection strategy via bootstrap server:
   *   1. Try bootstrap-discovered direct addresses
   *   2. Dial via circuit relay through the bootstrap server (NAT traversal)
   *   3. Last-known direct addresses as absolute fallback
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

    // Phase 11 fix: retry helper for relay dials. The target peer's circuit-
    // relay reservation may not be fully established on the bootstrap server
    // immediately after it re-registers (ensureRelayReservation() is async
    // and called during register()). A single retry after a short delay
    // covers this race condition without making reconnect take too long.
    const relayAddrSources: Array<{ label: string; getAddr: () => string | undefined }> = [];

    // Step 1: Try bootstrap-discovered direct addresses
    const bootstrapPeer = this.discoveredPeers.get(peerId);
    if (bootstrapPeer) {
      // If the peer has direct addresses, try those first
      if (bootstrapPeer.multiaddrs.length > 0) {
        params.onStatus?.('Reconnecting via bootstrap-discovered addresses...');
        try {
          params.store.updateTransport(params.localDid, params.remoteDid, {
            peerId,
            multiaddrs: bootstrapPeer.multiaddrs,
          });
          // Fix: dialProtocol() requires a real PeerId object (it calls the
          // internal isPeerId() guard) — passing a plain string throws
          // InvalidMultiaddrError immediately, before any network attempt is
          // even made. This previously caused every reconnect to skip straight
          // past "direct connection" with a misleading error.
          //
          // Second fix: runOnLimitedConnection: true is required whenever the
          // dial may resolve to a circuit-relay connection (which libp2p
          // always treats as "limited"). Without it, Connection.newStream()
          // (called internally by dialProtocol) throws
          // LimitedConnectionError('Cannot open protocol stream on limited
          // connection') even though the relayed connection itself opened
          // successfully — see libp2p-transport.ts's send() for the full
          // explanation. This applies here too since bootstrapPeer.multiaddrs
          // may include a /p2p-circuit address patched into the peer store.
          const stream = await (params.libp2pNode as any).dialProtocol(
            peerIdFromString(peerId),
            '/tsp/1.0.0',
            { runOnLimitedConnection: true },
          );
          params.onStatus?.('Reconnected via direct connection.');

          try { await stream.close(); } catch { /* ignore */ }
          return;
        } catch (err) {
          params.onStatus?.(`Direct connection failed (${err instanceof Error ? err.message : 'unknown'}), trying circuit relay...`);
        }

      }

      // Step 2a: Try relay address from bootstrap-discovered peer
      if (bootstrapPeer.relayAddr) {
        relayAddrSources.push({
          label: 'circuit relay',
          getAddr: () => bootstrapPeer.relayAddr,
        });
      }
    }

    // Step 2b: Try server-level relay address (construct from server relay prefix)
    //
    // this.bootstrapRelayAddr now arrives from the bootstrap server already
    // correctly ordered as `<relay-addr>/p2p/{relayPeerId}/p2p-circuit` (see
    // bootstrap-server.ts's relayAddr fix). Appending `/p2p/{destPeerId}`
    // after the trailing /p2p-circuit produces the standard dial-through-relay
    // shape: `<relay-addr>/p2p/{relayPeerId}/p2p-circuit/p2p/{destPeerId}`.
    // The `.replace()` here is defensive only — it strips a legacy/malformed
    // trailing `/p2p/{id}` if one is ever present (e.g. mid-rollout against
    // an old server build); on a correctly-shaped address ending in
    // /p2p-circuit it is a no-op since the regex only matches a trailing
    // /p2p/{id} segment, not /p2p-circuit.
    if (this.bootstrapRelayAddr) {
      relayAddrSources.push({
        label: 'server relay',
        getAddr: () => this.bootstrapRelayAddr!.replace(/\/p2p\/[^/]+$/, '') + `/p2p/${peerId}`,
      });
    }


    // Try each relay address source, with a single retry after a brief delay
    // to cover the race where the target peer's circuit-relay reservation
    // hasn't been fully established yet.
    for (const source of relayAddrSources) {
      for (let attempt = 0; attempt < 2; attempt++) {
        const relayAddr = source.getAddr();
        if (!relayAddr) continue;

        if (attempt === 1) {
          params.onStatus?.(`Retrying ${source.label} after brief delay (reservation may not be ready)...`);
          await new Promise(resolve => setTimeout(resolve, 2000));
        } else {
          params.onStatus?.(`Reconnecting via ${source.label}...`);
        }

        try {
          await this.dialViaRelay({
            libp2pNode: params.libp2pNode,
            store: params.store,
            localDid: params.localDid,
            remoteDid: params.remoteDid,
            peerId,
            relayAddr,
            onStatus: params.onStatus,
          });
          return;
        } catch {
          params.onStatus?.(`${source.label} attempt ${attempt + 1} failed.`);
        }
      }
    }

    // Step 2c: Try last-known direct addresses as absolute fallback
    const { multiaddrs } = params.recordRemoteTransport;
    if (multiaddrs && multiaddrs.length > 0) {
      params.onStatus?.('Trying last known addresses...');
      try {
        // Same PeerId-vs-string + runOnLimitedConnection fix as Step 1 above.
        const stream = await (params.libp2pNode as any).dialProtocol(
          peerIdFromString(peerId),
          '/tsp/1.0.0',
          { runOnLimitedConnection: true },
        );
        params.onStatus?.('Reconnected via last known addresses.');

        try { await stream.close(); } catch { /* ignore */ }
        return;
      } catch (err) {
        params.onStatus?.(`Last-known-address connection failed: ${err instanceof Error ? err.message : 'unknown'}`);
      }
    }


    throw new Error(
      `reconnectPeer: unable to reach ${params.remoteDid.slice(0, 12)}... ` +
      `Direct, relay, and last-known addresses all failed. ` +
      `Ensure both peers are registered with the bootstrap server.`,
    );
  }

  /**
   * Dial a peer through the bootstrap server's circuit relay.
   *
   * Uses multiaddr() + dial() + connection.newStream() instead of
   * dialProtocol(multiaddrString). The dialProtocol API expects a PeerId +
   * protocol string, not a full multiaddr containing /p2p-circuit components.
   * To dial through a relay, we must:
   *   1. Parse the relay multiaddr
   *   2. dial() to establish the connection through the relay
   *   3. connection.newStream() to negotiate the /tsp/1.0.0 protocol
   *
   * Fix: this previously called `libp2pNode.getProtocolStream(...)`, which is
   * not a real method on the libp2p API (it does not exist anywhere in
   * libp2p/@libp2p/interface) — every relay dial threw a TypeError and was
   * silently swallowed by the caller's try/catch as "Relay connection
   * failed.". The connection object returned by dial() already exposes
   * `.newStream(protocol)` directly, which is the correct, documented way to
   * open a new stream on an established connection.
   *
   * Note: even with this fixed, the relay dial will still be rejected by the
   * bootstrap server with NO_RESERVATION unless the *target* peer has an
   * active circuit-relay reservation — see BootstrapClient.ensureRelayReservation().
   */
  private async dialViaRelay(params: {
    libp2pNode: Libp2p;
    store: RelationshipStore;
    localDid: string;
    remoteDid: string;
    peerId: string;
    relayAddr: string;
    onStatus?: (message: string) => void;
  }): Promise<void> {
    params.onStatus?.(`Dialing via relay: ${params.relayAddr}`);

    // Parse the relay multiaddr and dial through it (bounded so a dead relay
    // circuit can't hang the reconnect flow indefinitely).
    const ma = multiaddr(params.relayAddr);
    const connection = await (params.libp2pNode as any).dial(ma, { signal: AbortSignal.timeout(15000) });

    // Open a stream on the /tsp/1.0.0 protocol through this relay connection.
    //
    // Bug fix: a connection dialed through /p2p-circuit is ALWAYS a "limited"
    // connection in libp2p (connection.limits != null). newStream() throws
    // LimitedConnectionError unless runOnLimitedConnection: true is passed —
    // this was silently swallowed by the caller's try/catch as a generic
    // "circuit relay attempt failed", masking the real cause.
    const stream = await connection.newStream('/tsp/1.0.0', {
      signal: AbortSignal.timeout(10000),
      runOnLimitedConnection: true,
    });


    params.onStatus?.('Reconnected via circuit relay.');

    // Update the store with relay address for future reference
    params.store.updateTransport(params.localDid, params.remoteDid, {
      peerId: params.peerId,
      multiaddrs: [params.relayAddr],
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
