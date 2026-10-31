// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `connectivity` domain — liveness, readiness, bootstrap/relay view, and the utility-server link.
 *
 * Wraps the existing runtime surface (`isBootstrapConnected`, `refreshBootstrapPeers`, `getConnectivityStatus`,
 * `configureUtilityServer`, …) with no new behaviour. The one addition is that state-changing operations
 * announce themselves on the bus, so a UI can replace its connection-check poll with a subscription
 * (design §3.5: `chat.html:201` polled every 10 s; that poll is deleted in P5).
 */
import { requireAgent, type DomainContext } from './context.js';
import { UtilityServerUnavailableError } from '../errors.js';
import {
  describeConnectivityFailure,
  type ConnectivityFailureKind,
} from '@p2p-trust-stack/core/transport/relay-health.js';
import {
  buildDialCandidates,
  dialCandidateAddrs,
} from '@p2p-trust-stack/core/transport/dial-candidates.js';
import { getLocalLanIps } from '@p2p-trust-stack/core/platform/network-detect.js';
import { encodeOobi } from '@p2p-trust-stack/core/relationship/oobi.js';
import type { DiscoveredPeer } from '@p2p-trust-stack/core/transport/bootstrap-client.js';
import type {
  BootstrapRefreshDto,
  BootstrapStatusDto,
  ConnectivityStatusDto,
  HealthDto,
  NetworkProfileDto,
  PushIdentityDto,
  ReadyDto,
  UtilityServerStatusDto,
  VtnOptionDto,
} from '../dto/connectivity.js';

export interface ConnectivityApi {
  /** Liveness. Never requires an active agent. */
  health(): Promise<HealthDto>;
  /** Readiness. Reports `{ ready: false, reason }` rather than throwing when not ready. */
  ready(): Promise<ReadyDto>;
  /** Bootstrap connectivity, with the convenience flags the UI gates on. */
  status(): Promise<BootstrapStatusDto>;
  /** Force a bootstrap peer refresh. Emits `connection.changed`. */
  refresh(): Promise<BootstrapRefreshDto>;
  /** Point this agent at a utility server by OOBI. Emits `connection.changed`. */
  connectUtility(utilityServerOobi: string): Promise<{ ok: true; connected: true }>;
  /** Utility-server link status. */
  utilityStatus(): Promise<UtilityServerStatusDto>;
  /**
   * The VTNs this agent could join, from the bootstrap peer directory.
   *
   * One entry per VTN key. Empty when no utility server is discovered, or when
   * the discovered ones have not bound a namespace yet — a server with no key
   * could not be matched against, so it is not offered.
   */
  vtns(): Promise<VtnOptionDto[]>;
  /**
   * Join a VTN: adopt its key (so this agent is identified by that network) and
   * dial the utility server that serves it. Emits `connection.changed`.
   *
   * Rejects with `UtilityServerUnavailableError` when no discovered server serves
   * that VTN, or when the handshake fails — the caller shows the standard
   * "utility server unreachable" message.
   */
  connectVtn(vtnKey: string): Promise<{ ok: true; connected: true; vtnKey: string }>;
  /** Push this identity's public state to the utility server. Emits `sync.completed` on success. */
  pushIdentity(): Promise<PushIdentityDto>;
  /** The running node's network profile, when known. */
  networkProfile(): Promise<NetworkProfileDto | undefined>;
  /**
   * Whether the machine's network has changed since the profile was captured.
   *
   * A **pull** form of the `network.changed` event: the dashboard gates a peer's connection label on it
   * ("INCOMPATIBLE" when the peer advertises LAN addresses that no longer match ours), and a synchronous
   * question is the right shape for a per-row label. Subscribe to `network.changed` for the push form.
   */
  networkChanged(): boolean;
  /**
   * A user-facing sentence explaining why an operation cannot proceed right now.
   *
   * The adapter used to import `describeConnectivityFailure` from `src/transport/relay-health.ts` and pass it a
   * `ConnectivityStatus` it had read itself. That was the last `src/` import in `web-server.ts` that was a
   * **presentation concern** rather than a shared type — "how do I describe the current connectivity state to a
   * person" is the layer's knowledge, so a caller now asks a question instead of assembling the answer from
   * pieces it had to reach for.
   *
   * Never throws. It is called on an ERROR path, so a status read that itself fails must not replace the
   * caller's 503 with a 500; the generic wording is the fallback (this mirrors `announceConnectionChanged`,
   * which also stays quiet rather than fabricating a status).
   *
   * `kind` selects the closing sentence: `'mutation'` (the default) promises the change is queued locally,
   * which is true for a write; `'connection'` drops that promise, because a failed JOIN has nothing queued
   * and the user needs to know to retry.
   */
  explainFailure(operation: string, kind?: ConnectivityFailureKind): Promise<string>;
}

/** How good a candidate a discovered utility server is, for picking one per VTN. */
function vtnCandidateRank(option: VtnOptionDto): number {
  // `reachableViaRelay` outranks `reachable`: a relay reservation is a fact the
  // bootstrap verified against its own relay, whereas `reachable` can be true on
  // the strength of a NAT-mapped address nothing listens on (see
  // `VtnOptionDto.reachableScope`). With several servers serving one key, the one
  // we can actually reach from another network should win.
  return (
    (option.connected ? 4 : 0) +
    (option.reachableViaRelay ? 2 : 0) +
    (option.reachable ? 1 : 0)
  );
}

/**
 * Collapse the discovered `utility_server` peers into the VTN list a user picks
 * from.
 *
 * ONE ENTRY PER VTN KEY, not per peer: several utility servers can serve the same
 * network, and the user is choosing a NETWORK to join. When more than one server
 * serves a key, the most reachable one wins (connected > reachable > otherwise) —
 * that is the peer most likely to complete the TSP handshake.
 *
 * A server is skipped when it has no key yet (it registered before the setup
 * wizard bound a namespace) or no DID (the strict 4-item OOBI cannot be built
 * without one). Both would be undialable, so offering them would only produce a
 * failure the user cannot act on.
 *
 * Exported for unit testing — it is pure, so it needs no running agent.
 */
export function groupVtnOptions(peers: readonly DiscoveredPeer[]): VtnOptionDto[] {
  const byKey = new Map<string, VtnOptionDto>();

  for (const peer of peers) {
    if (peer.peerType !== 'utility_server') continue;
    const vtnKey = (peer.net ?? '').trim();
    if (!vtnKey) continue;
    if (!peer.did) continue;

    const candidate: VtnOptionDto = {
      vtnKey,
      ...(peer.vtnName ? { vtnName: peer.vtnName } : {}),
      peerId: peer.peerId,
      did: peer.did,
      // `vid` is the permanent CESR Slot-A key (survives a did:scid:vh log roll);
      // `peerId` is only a fallback for a server that registered without a VID.
      vid: peer.vid || peer.peerId,
      multiaddrs: peer.multiaddrs,
      // Carried through so the JOIN can build a relay fallback. The server's own
      // advertised `multiaddrs` never contain a `/p2p-circuit` address —
      // `buildDialableMultiaddrs()` filters them out — so without this field the
      // join had no relay to fall back to and a cross-network join could not
      // succeed. See `VtnOptionDto.relayAddr`.
      ...(peer.relayAddr ? { relayAddr: peer.relayAddr } : {}),
      ...(peer.reachableViaRelay != null ? { reachableViaRelay: peer.reachableViaRelay } : {}),
      ...(peer.reachableScope ? { reachableScope: peer.reachableScope } : {}),
      reachable: peer.reachable,
      connected: peer.connected,
    };

    const existing = byKey.get(vtnKey);
    if (!existing || vtnCandidateRank(candidate) > vtnCandidateRank(existing)) {
      byKey.set(vtnKey, candidate);
    }
  }

  return [...byKey.values()].sort((a, b) => a.vtnKey.localeCompare(b.vtnKey));
}

/** Build the `connectivity` domain over a stack context. */
export function createConnectivityApi(ctx: DomainContext): ConnectivityApi {
  /**
   * Emit `connection.changed` from the live connectivity view.
   *
   * Only emitted when the agent exposes the layer-aware view — an agent implementation without
   * `getConnectivityStatus` (e.g. a test stub) simply does not announce. Emitting a fabricated status would
   * be worse than staying quiet.
   */
  function announceConnectionChanged(): void {
    const agent = ctx.getAgent();
    const status: ConnectivityStatusDto | undefined = agent?.getConnectivityStatus?.();
    if (!status) return;
    ctx.bus.emit('connection.changed', {
      layer: status.layer,
      bootstrapConnected: status.bootstrapConnected,
      utilityServerConnected: status.utilityServerConnected,
      degraded: status.degraded,
      at: Date.now(),
    });
  }

  return {
    async health(): Promise<HealthDto> {
      const agent = ctx.getAgent();
      return {
        status: 'ok',
        service: 'trust-app-api',
        time: new Date().toISOString(),
        agent: agent
          ? { active: true, name: agent.getName(), vid: agent.getVid().slice(0, 20) + '...' }
          : { active: false },
      };
    },

    async ready(): Promise<ReadyDto> {
      const agent = ctx.getAgent();
      if (!agent) return { ready: false, reason: 'no active VTA — log in first' };
      try {
        const rels = agent.listRelationships();
        // Utility-server (organization) relationships are infrastructure, not chat — exclude them.
        const human = rels.filter((r) => (r as { remoteSubjectKind?: string }).remoteSubjectKind !== 'organization');
        const bidirectional = human.filter(
          (r) => r.direction === 'bidirectional' && r.status === 'established',
        ).length;
        return {
          ready: true,
          agent: agent.getName(),
          relationshipCount: rels.length,
          chatReadyCount: bidirectional,
        };
      } catch (err) {
        return { ready: false, reason: `relationship store not ready: ${(err as Error).message ?? 'unknown error'}` };
      }
    },

    async status(): Promise<BootstrapStatusDto> {
      const agent = requireAgent(ctx, 'read bootstrap status');
      const connectivity = agent.getConnectivityStatus?.();
      return {
        connected: agent.isBootstrapConnected(),
        relayAddr: agent.getBootstrapRelayAddr(),
        discoveredPeers: agent.getDiscoveredPeers(),
        connectivity,
        layer: connectivity?.layer,
        bootstrapConnected: connectivity?.bootstrapConnected ?? agent.isBootstrapConnected(),
        utilityServerConnected: connectivity?.utilityServerConnected,
        relayExpiring: connectivity?.layer === 'relay-expiring',
        degraded: connectivity?.degraded,
        message: connectivity?.message,
      };
    },

    async refresh(): Promise<BootstrapRefreshDto> {
      const agent = requireAgent(ctx, 'refresh bootstrap peers');
      const peers = await agent.refreshBootstrapPeers();
      announceConnectionChanged();
      return { peers, count: peers.length };
    },

    async connectUtility(utilityServerOobi: string): Promise<{ ok: true; connected: true }> {
      const agent = requireAgent(ctx, 'connect to the utility server');
      if (!utilityServerOobi) throw new Error('utilityServerOobi is required');
      if (!agent.configureUtilityServer) {
        throw new UtilityServerUnavailableError('connect to the utility server');
      }
      await agent.configureUtilityServer({ utilityServerOobi });
      announceConnectionChanged();
      return { ok: true, connected: true };
    },

    async vtns(): Promise<VtnOptionDto[]> {
      const agent = requireAgent(ctx, 'list the VTNs available to join');
      return groupVtnOptions(agent.getDiscoveredPeers?.() ?? []);
    },

    async connectVtn(vtnKey: string): Promise<{ ok: true; connected: true; vtnKey: string }> {
      const agent = requireAgent(ctx, 'connect to a VTN');
      const wanted = vtnKey?.trim();
      if (!wanted) throw new Error('vtnKey is required');

      const option = groupVtnOptions(agent.getDiscoveredPeers?.() ?? [])
        .find((v) => v.vtnKey === wanted);
      // No discovered server serves this VTN. That is the SAME user-visible
      // condition as an unreachable server (the network cannot be joined right
      // now), so it reports the standard error rather than inventing a new one.
      if (!option) throw new UtilityServerUnavailableError(`join the VTN "${wanted}"`);
      if (!agent.configureUtilityServer) {
        throw new UtilityServerUnavailableError(`join the VTN "${wanted}"`);
      }

      // Adopt the key BEFORE the handshake: the agent must be identified by the
      // network it is joining, or the bootstrap directory keeps showing it under
      // whatever VTN it registered with at start() (which is none, on first run).
      if (agent.setNet) await agent.setNet(wanted);

      // The strict 4-item OOBI needs the server's real DID plus a VID (or its
      // peer ID as a fallback) — the same construction the auto-connect used.
      //
      // The `multiaddrs` slot carries the FULL ORDERED CANDIDATE LIST, not just
      // the server's advertised addresses. That list includes the relay address
      // (per-peer from the bootstrap, plus one derived from the server relay
      // prefix), which the server never advertises itself. Without it a first
      // cross-network join had nothing to dial: the advertised LAN address is
      // unroutable and the advertised NAT-mapped address has nothing listening on
      // it, so the handshake failed with "the relay connection to the utility
      // server could not be re-established" and never recovered.
      //
      // Ordering matters as much as membership — see dial-candidates.ts. libp2p's
      // default address sorter would try the NAT-mapped address first and the
      // relay last; the same policy is installed on the node as `addressSorter`,
      // so the dialer walks this list in this order.
      const candidates = buildDialCandidates({
        peerId: option.peerId,
        multiaddrs: option.multiaddrs,
        peerRelayAddr: option.relayAddr,
        serverRelayPrefix: agent.getBootstrapRelayAddr?.(),
        localLanIps: getLocalLanIps(),
      });
      const oobi = encodeOobi({
        cesrVid: option.vid,
        peerId: option.peerId,
        multiaddrs: dialCandidateAddrs(candidates),
        did: option.did,
      });
      await agent.configureUtilityServer({ utilityServerOobi: oobi });
      announceConnectionChanged();
      return { ok: true, connected: true, vtnKey: wanted };
    },

    async utilityStatus(): Promise<UtilityServerStatusDto> {
      const agent = requireAgent(ctx, 'read utility-server status');
      const did = agent.getUtilityServerDid ? agent.getUtilityServerDid() : null;
      return {
        connected: agent.isUtilityServerConnected ? agent.isUtilityServerConnected() : false,
        did,
        vid: did, // deprecated alias — same value, kept for wire compatibility
      };
    },

    async pushIdentity(): Promise<PushIdentityDto> {
      const agent = requireAgent(ctx, 'push identity to the utility server');
      if (!agent.pushIdentityToUtilityServer) {
        throw new UtilityServerUnavailableError('push identity');
      }
      // The push IS the sync, and it has a real lifecycle: started → completed | failed. Only `sync.completed`
      // was ever emitted, so a caller that got `{ ok: false }` back learned about the failure and nobody else did
      // — a subscriber watching the bus saw a sync begin and then silence.
      ctx.bus.emit('sync.started', { kind: 'identity-push', at: Date.now() });
      const ok = await agent.pushIdentityToUtilityServer();
      if (ok) {
        ctx.bus.emit('sync.completed', { kind: 'identity-push', at: Date.now() });
        return { ok: true };
      }
      const reason = agent.getProfileSyncStatus ? agent.getProfileSyncStatus().lastError : 'push not acknowledged';
      ctx.bus.emit('sync.failed', { kind: 'identity-push', reason: reason ?? 'push not acknowledged', at: Date.now() });
      return {
        ok: false,
        pending: true,
        error: reason,
      };
    },

    async networkProfile(): Promise<NetworkProfileDto | undefined> {
      const agent = requireAgent(ctx, 'read the network profile');
      return agent.getNetworkProfile?.();
    },

    networkChanged(): boolean {
      // Synchronous by design — see the interface note. `getAgent()` rather than `requireAgent` would hide a
      // missing agent behind `false`, which reads as "the network is fine"; a caller asking before activation
      // is a caller error.
      const agent = requireAgent(ctx, 'check whether the network changed');
      return agent.isNetworkChanged();
    },

    async explainFailure(operation: string, kind?: ConnectivityFailureKind): Promise<string> {
      const generic = `Utility server unavailable. Cannot ${operation} right now.`;
      // `getAgent()`, not `requireAgent()`: no active agent IS one of the conditions this explains, so throwing
      // here would replace the caller's own error with ours.
      const live = ctx.getAgent()?.getConnectivityStatus?.();
      return live ? describeConnectivityFailure(live, operation, kind) : generic;
    },
  };
}
