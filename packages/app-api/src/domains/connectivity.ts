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
import { describeConnectivityFailure } from '@p2p-trust-stack/core/transport/relay-health.js';
import type {
  BootstrapRefreshDto,
  BootstrapStatusDto,
  ConnectivityStatusDto,
  HealthDto,
  NetworkProfileDto,
  PushIdentityDto,
  ReadyDto,
  UtilityServerStatusDto,
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
   */
  explainFailure(operation: string): Promise<string>;
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

    async explainFailure(operation: string): Promise<string> {
      const generic = `Utility server unavailable. Cannot ${operation} right now.`;
      // `getAgent()`, not `requireAgent()`: no active agent IS one of the conditions this explains, so throwing
      // here would replace the caller's own error with ours.
      const live = ctx.getAgent()?.getConnectivityStatus?.();
      return live ? describeConnectivityFailure(live, operation) : generic;
    },
  };
}
