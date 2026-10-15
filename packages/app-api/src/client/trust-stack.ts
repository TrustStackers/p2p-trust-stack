// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `createAgentStack` — the single entry point an application calls.
 *
 * ```ts
 * const stack = await createAgentStack({ agent: { name: 'alice', passphrase: '…' } });
 * stack.on('connection.open', (e) => console.log('peer up', e.peerId));
 * await stack.start();
 * ```
 *
 * ## What this is (P2)
 *
 * The first working slice of the layer: the event bus, the `Host` seam, and two domains — `identity` and
 * `connectivity`. The remaining domains (`relationships`, `messaging`, `credentials`, `communities`,
 * `names`, `profiles`, `sync`, `contexts`) and capability scoping (`asContext`) arrive in P3/P4. The
 * interface deliberately grows a domain at a time rather than declaring all ten and throwing for eight.
 *
 * `didMethod` is **not** an option here yet: the runtime takes a `DidMethod` instance, not the string the
 * design sketches, so exposing a string would be an option that silently does nothing. Agents default to
 * `did:scid:vh` (the runtime's own default) until method selection is wired properly.
 *
 * ## Additive wiring
 *
 * `createAgentStack` subscribes the bus to the agent's **existing** runtime callbacks. It does not replace
 * them: the reference adapter keeps using the same callbacks it always did, so both paths work simultaneously
 * until P5 deletes the legacy one. Wiring is guarded per agent instance because the runtime *appends*
 * handlers (`BaseAgent.onConnectionEvent` pushes), so wiring the same instance twice would double every event.
 */
import { AgentRegistry } from '../runtime/agent-registry.js';
import type { AgentHandle } from '../runtime/handle.js';
import { createNodeHost } from '../host/node-host.js';
import type { Host } from '../host/types.js';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { createAgentEventsStore } from '../store/agent-events-store.js';
import { createAgentMessagesStore, type MessageStore } from '../store/message-store.js';
import { EventBus, type SubscribeOpts, type Subscription, type ReplayResult } from './events.js';
import type { StackEvent, StackEventPayloads } from '../events/catalog.js';
import { createIdentityApi, type IdentityApi } from '../domains/identity.js';
import { createConnectivityApi, type ConnectivityApi } from '../domains/connectivity.js';
import {
  createMessagingApi,
  recordInboundMessage,
  type MessagingApi,
  type MessagingDeps,
} from '../domains/messaging.js';
import { createRelationshipsApi, type RelationshipsApi } from '../domains/relationships.js';
import { createNamesApi, type NamesApi } from '../domains/names.js';
import { createProfilesApi, type ProfilesApi } from '../domains/profiles.js';
import { createCredentialsApi, type CredentialsApi } from '../domains/credentials.js';
import { createCommunitiesApi, type CommunitiesApi } from '../domains/communities.js';
import { createContextsApi, type ContextsApi } from '../domains/contexts.js';
import { createDelegationsApi, type DelegationsApi } from '../domains/delegations.js';
import { asContext, type ContextScopeOptions, type ScopedTrustStack } from './scope.js';
import type { DomainContext } from '../domains/context.js';

/** Semantic version of the API contract. A breaking change to any DTO or method signature bumps this. */
export const API_VERSION = '0.7.0';

export interface CreateAgentStackOpts {
  /**
   * P2PTS_HOME override — where this stack stores agents, keystores and databases.
   *
   * Defaults to the `P2PTS_HOME` environment variable, then to the platform default
   * (`~/Library/Application Support/P2PTS`, `~/.p2pts`, `%APPDATA%/P2PTS`). Pass it explicitly when
   * embedding: the default is convenient for a CLI, but a process hosting more than one stack
   * needs each one pinned, since the environment is process-wide. See
   * `@p2p-trust-stack/core/platform/p2pts-home.js` for the full contract.
   */
  home?: string;
  /** Host binding. Defaults to `NodeHost`. */
  host?: Host;
  /** Registry override — mainly for tests that need an isolated P2PTS_HOME. */
  registry?: AgentRegistry;
  /** Replay-buffer size for the in-memory bus. Default 1000. */
  eventBufferLimit?: number;
  /**
   * Adopt an agent the caller already created or unlocked, instead of creating one here.
   *
   * For a host that owns the agent lifecycle itself — the reference web adapter is the case that motivated
   * this: it keeps a mutable `agent` handle that `POST /api/activate` swaps, and it must be the *same* handle
   * the stack uses, or the two would drift and the layer would answer for a different identity than the
   * adapter. The caller then keeps the two in step with {@link TrustStack.adopt}.
   */
  adopt: AgentHandle;
  /** Not used when adopting. */
  agent?: undefined;
}

/** Create (or unlock) an agent from a config, then own it. */
export interface CreateAgentStackFromConfigOpts {
  home?: string;
  host?: Host;
  registry?: AgentRegistry;
  eventBufferLimit?: number;
  adopt?: undefined;
  /** The identity to create (if absent) or unlock. */
  agent: {
    name: string;
    passphrase: string;
    /** Network/namespace this agent joins. */
    net?: string;
    /**
     * Explicit libp2p listen port.
     *
     * Without this the runtime walks a small fixed range (24000-24004). Tests that start several agents
     * concurrently — `node --test` runs test FILES in parallel — exhaust that range and fail with
     * `EADDRINUSE`, so each file picks its own port.
     */
    port?: number;
  };
}

export type AnyCreateAgentStackOpts = CreateAgentStackOpts | CreateAgentStackFromConfigOpts;

export interface TrustStack {
  /** Semantic version of the API contract. */
  readonly version: string;
  /** The host this stack is bound to. */
  readonly host: Host;
  readonly identity: IdentityApi;
  readonly connectivity: ConnectivityApi;
  readonly messaging: MessagingApi;
  readonly relationships: RelationshipsApi;
  readonly names: NamesApi;
  readonly profiles: ProfilesApi;
  readonly credentials: CredentialsApi;
  /** Communities: the list, the detail view, and the founding/invitation ceremonies. */
  readonly communities: CommunitiesApi;
  /** Provisioned, revocable app contexts. */
  readonly contexts: ContextsApi;
  /**
   * Standing accountability/custody links between identities.
   *
   * The newest domain, and the one that replaced a lie: the TUI screen that manages these programmed to
   * `AgentHandle.createDelegation`/`listDelegations`, which nothing ever implemented — its list was always
   * empty and its Revoke key reported success without doing anything.
   */
  readonly delegations: DelegationsApi;

  /** Subscribe to a stack event, optionally replaying from a `since` cursor. */
  on<E extends StackEvent>(
    event: E,
    handler: (payload: StackEventPayloads[E]) => void,
    opts?: SubscribeOpts,
  ): Subscription;
  /** Subscribe for exactly one delivery. */
  once<E extends StackEvent>(
    event: E,
    handler: (payload: StackEventPayloads[E]) => void,
    opts?: SubscribeOpts,
  ): Subscription;
  /** Cancel a subscription. */
  off(sub: Subscription | undefined | null): void;
  /** Read retained events for a cursor without subscribing. */
  replay<E extends StackEvent>(
    event: E,
    opts: { since: number; filter?: Record<string, string | number | boolean>; limit?: number },
  ): ReturnType<EventBus['replay']>;
  /**
   * Read **durable** history from the `agent_events` outbox — it survives restarts and is not limited by the
   * in-memory window.
   *
   * Subscribe first, then read, so nothing is missed in between:
   * ```ts
   * const sub = stack.on('message.received', handler);
   * const { events } = await stack.replayDurable({ since: cursor });
   * ```
   */
  replayDurable(opts: {
    since: number;
    event?: StackEvent;
    filter?: Record<string, string | number | boolean>;
    limit?: number;
  }): Promise<ReplayResult>;
  /**
   * The cursor to resume from later.
   *
   * Reads the durable high-water mark when the outbox is attached, so a cursor taken now stays valid across a
   * restart. Do not use `replay().latestSeq` for this — a fresh process starts at 0 while the outbox may
   * already hold rows.
   */
  cursor(): Promise<number>;
  /**
   * A **deny-by-default** view of this stack for one provisioned app context.
   *
   * `allow` names the capabilities the context is granted; everything not named is refused, including every
   * method that is not explicitly classified. The context's liveness (revocation, expiry) is re-checked on every
   * call, so revoking it stops the app mid-session.
   *
   * The caller keeps `this` — the scoped object is what a third-party app is handed.
   */
  asContext(contextId: string, opts: ContextScopeOptions): ScopedTrustStack;

  /** Start the active agent (boots the libp2p node) and begin emitting events. */
  start(onStatus?: (message: string) => void): Promise<void>;
  /** Stop the active agent. */
  stop(): Promise<void>;
  /**
   * Point the stack at a different agent handle.
   *
   * For a host that owns the lifecycle: after it swaps its own active agent, it calls this so the layer
   * answers for the same identity. Re-points the durable outbox and transcript at that agent's database.
   */
  adopt(handle: AgentHandle): Promise<void>;
}

/** Build the stack. The agent is created or unlocked (or adopted) but NOT started — call `start()`. */
export async function createAgentStack(opts: AnyCreateAgentStackOpts): Promise<TrustStack> {
  const host = opts.host ?? createNodeHost({ home: opts.home, registry: opts.registry });
  // NOTE: `AgentRegistry`'s home is its **third** constructor parameter (see `host/node-host.ts`). Passing
  // it first silently targets the user's real P2PTS_HOME.
  const registry = opts.registry ?? new AgentRegistry(undefined, undefined, host.home);
  const bus = new EventBus({ bufferLimit: opts.eventBufferLimit });

  let agent: AgentHandle | null = null;
  const wired = new WeakSet<AgentHandle>();
  let storeDs: SqliteDataSource | null = null;
  let messageStore: MessageStore | null = null;

  /**
   * The inbound-message hook, late-bound.
   *
   * The bus wiring is installed before the domains exist (the agent must be wired as soon as it is created),
   * so the hook is read at delivery time rather than captured. That is what lets the runtime's `onMessage`
   * callback reach the `messaging` domain without a construction cycle.
   */
  let onInbound: ((msg: {
    remoteDid: string;
    body: Uint8Array;
    confidential: boolean;
    receivedAt: number;
  }) => void) | undefined;

  /**
   * Point the durable outbox at an agent's own database.
   *
   * Best-effort by design: if the database cannot be opened, the bus still delivers live and simply has no
   * durable history. A stack that refused to run because its outbox was unavailable would be worse than one
   * with a shorter memory — and the failure would surface as a total outage rather than a reduced guarantee.
   */
  async function attachStoreFor(agentName: string): Promise<void> {
    const previous = storeDs;
    storeDs = null;
    if (previous) await Promise.resolve(previous.close()).catch(() => { /* already closed */ });
    try {
      const ds = host.storageFor(agentName) as SqliteDataSource;
      storeDs = ds;
      messageStore = createAgentMessagesStore(ds);
      // Awaited: attaching seeds the bus's sequence counter from the outbox, so an emit that follows
      // immediately cannot reuse a sequence number that already exists.
      await bus.attachStore(createAgentEventsStore(ds));
    } catch {
      storeDs = null;
      messageStore = null;
      await bus.attachStore(undefined);
    }
  }

  const ctx: DomainContext = {
    host,
    registry,
    bus,
    getAgent: () => agent,
    setAgent: async (next) => {
      agent = next;
      if (next) {
        wireAgentToBus(next, bus, wired, () => onInbound);
        // A different agent means a different database, so the outbox must follow it.
        await attachStoreFor(next.getName());
      }
    },
  };

  const config = {
    name: opts.adopt ? opts.adopt.getName() : opts.agent.name,
    passphrase: opts.agent ? opts.agent.passphrase : '',
    ...(opts.agent?.net ? { net: opts.agent.net } : {}),
    ...(opts.agent?.port ? { port: opts.agent.port } : {}),
    ...(host.transport ? { transport: host.transport } : {}),
    ...(host.keystore ? { keystore: host.keystore } : {}),
  };

  // Create or unlock (or adopt), but do not start — `start()` owns that, so a caller can subscribe first and
  // therefore cannot miss the activation event.
  //
  // The lifecycle goes through the HOST, which owns `home` and the per-agent layout. This used to branch on
  // `registry.agentExists(...)` and call the runtime factories directly here, duplicating what the host now
  // provides — and leaving the stack holding a registry it otherwise had no use for.
  agent = opts.adopt
    ? opts.adopt
    : (host.agentExists(opts.agent.name)
      ? await host.unlockAgent(config)
      : await host.createAgent(config));
  wireAgentToBus(agent, bus, wired, () => onInbound);
  await attachStoreFor(agent.getName());

  // ── Domains ───────────────────────────────────────────────────────────────
  const messagingDeps: MessagingDeps = {
    dataSource: () => storeDs,
    store: () => messageStore,
  };
  const messaging = createMessagingApi(ctx, messagingDeps);

  // Now that the domain exists, point the inbound hook at it. Persisting an inbound message must never throw
  // into the runtime's dispatch loop — delivery to the app already happened.
  onInbound = (msg) => {
    void recordInboundMessage(ctx, messagingDeps, msg).catch(() => { /* transcript write failed */ });
  };

  // Named (rather than a bare returned literal) so `asContext` can hand the scoped view a reference to the full
  // stack: the caller keeps the unscoped object and the app receives the scoped one.
  const stack: TrustStack = {
    version: API_VERSION,
    host,
    identity: createIdentityApi(ctx),
    connectivity: createConnectivityApi(ctx),
    messaging,
    relationships: createRelationshipsApi(ctx),
    names: createNamesApi(ctx),
    profiles: createProfilesApi(ctx),
    credentials: createCredentialsApi(ctx, { dataSource: () => storeDs }),
    communities: createCommunitiesApi(ctx, { dataSource: () => storeDs }),
    contexts: createContextsApi(ctx, { home: () => host.home }),
    delegations: createDelegationsApi(ctx, { dataSource: () => storeDs }),

    asContext: (contextId, opts) => asContext(stack, contextId, opts),

    on: (event, handler, subOpts) => bus.on(event, handler, subOpts),
    once: (event, handler, subOpts) => bus.once(event, handler, subOpts),
    off: (sub) => bus.off(sub),
    replay: (event, replayOpts) => bus.replay(event, replayOpts),
    replayDurable: (replayOpts) => bus.replayDurable(replayOpts),
    cursor: () => bus.latestDurableSeq(),

    async start(onStatus) {
      const current = agent;
      if (!current) throw new Error('no active agent — create the stack with an agent config first');
      await current.start(onStatus);
    },

    async stop() {
      if (agent) await agent.stop();
      // Drain queued outbox writes before the database connection goes away.
      await bus.flush();
      const ds = storeDs;
      storeDs = null;
      if (ds) await Promise.resolve(ds.close()).catch(() => { /* already closed */ });
    },

    async adopt(handle) {
      agent = handle;
      wireAgentToBus(handle, bus, wired, () => onInbound);
      await attachStoreFor(handle.getName());
    },
  };

  return stack;
}

/**
 * Bridge the runtime's existing callbacks onto the bus.
 *
 * Additive by construction: the runtime keeps calling whatever else is registered. Guarded by a `WeakSet` so
 * re-wiring the same instance cannot double its events.
 *
 * Message and relationship wiring is deliberately absent here: their payload DTOs belong to the `messaging`
 * and `relationships` domains, which land in P3. Wiring them now would mean inventing P3's DTOs early.
 */
function wireAgentToBus(
  agent: AgentHandle,
  bus: EventBus,
  wired: WeakSet<AgentHandle>,
  getInbound: () => ((msg: {
    remoteDid: string;
    body: Uint8Array;
    confidential: boolean;
    receivedAt: number;
  }) => void) | undefined,
): void {
  if (wired.has(agent)) return;
  wired.add(agent);

  agent.onMessage((msg) => {
    getInbound()?.(msg);
  });

  // ── Relationship + ceremony callbacks ────────────────────────────────────
  // The runtime exposes these as five separate registration methods; the bus unifies them under
  // `relationship.ceremony` with `step` distinguishing the leg, so a subscriber follows a whole ceremony
  // with ONE subscription instead of five. Additive, like the rest of this wiring: the runtime keeps calling
  // whatever else is registered.
  agent.onRelationshipChange((record) => {
    bus.emit('relationship.changed', {
      peerDid: record.remoteDid,
      status: record.status,
      at: Date.now(),
    });
  });

  // A credential was delivered and persisted. This is the ONLY arrival signal — the receive participant is the
  // sole observer of a delivery, so without it a UI can only notice a new credential by polling the local table.
  //
  // A VIC additionally emits `invitation.received`, because that is what a VIC *is*: an invitation addressed to
  // this identity. Both events are in the catalogue and, until now, nothing emitted either.
  agent.onCredentialReceived?.((credential) => {
    const at = Date.now();
    bus.emit('credential.issued', { uuid: credential.uuid, vcType: credential.vcType, at });
    if (credential.vcType === 'vic') {
      bus.emit('invitation.received', {
        uuid: credential.uuid,
        communityUuid: credential.issuerIdentityUuid,
        at,
      });
    }
  });

  // A community arrived, or its governance changed. Both were previously discoverable only by polling —
  // `communities.html` repainted on a timer and `rules.html` re-read the pending list every 4 s.
  //
  // The `kind` is carried through rather than flattened to one event: a membership push means the community
  // LIST may have changed, while a governance push means the community's RULES changed (an approved change was
  // applied), which is what the Rules page's "current rules" box needs to re-read.
  agent.onCommunityChanged?.((community) => {
    bus.emit('community.changed', {
      communityUuid: community.communityUuid,
      kind: community.kind,
      at: Date.now(),
    });
  });

  // A governance-change proposal arrived. `governance.proposal` was in the catalogue with a payload type and,
  // until now, nothing emitted it.
  agent.onGovernanceProposal?.((proposal) => {
    bus.emit('governance.proposal', {
      proposalId: proposal.proposalId,
      communityUuid: proposal.communityUuid,
      at: Date.now(),
    });
  });

  // A founding ceremony advanced. This is the signal that did not exist: the community is not created until the
  // ceremony crystallizes, so `community.changed` cannot carry pre-crystallization progress — a co-signature
  // landing was observable only by polling the server's ceremony log.
  agent.onCeremonyEvent?.((event) => {
    bus.emit('ceremony.step', {
      threadId: event.threadId,
      step: event.step,
      communityUuid: event.communityUuid,
      at: Date.now(),
    });
  });

  const ceremony = (step: string, error?: string) => (remoteDid: string) => {
    bus.emit('relationship.ceremony', {
      peerDid: remoteDid,
      step,
      ...(error !== undefined ? { error } : {}),
      at: Date.now(),
    });
  };

  agent.onCeremonyPrompt?.(ceremony('prompt'));
  agent.onCeremonyAckChange?.(ceremony('ack'));
  agent.onCeremonyComplete?.(ceremony('complete'));
  agent.onCeremonyExpired?.(ceremony('expired'));
  agent.onCeremonyFailed?.((remoteDid, step, error) => {
    bus.emit('relationship.ceremony', {
      peerDid: remoteDid,
      step: 'failed',
      // `step` here is the ceremony leg that failed, which is exactly the detail a UI wants to show.
      error: `${step}: ${error}`,
      at: Date.now(),
    });
  });

  agent.onConnectionEvent((e) => {
    const at = e.timestamp;
    if (e.kind === 'open') {
      bus.emit('connection.open', {
        peerId: e.peerId,
        direction: e.direction,
        method: e.method,
        ...(e.remoteAddr !== undefined ? { remoteAddr: e.remoteAddr } : {}),
        at,
      });
    } else {
      bus.emit('connection.close', {
        peerId: e.peerId,
        direction: e.direction,
        method: e.method,
        at,
      });
    }
  });

  agent.onNetworkChange((changedFields) => {
    bus.emit('network.changed', { changedFields, at: Date.now() });
  });

  // The duplicate-connect notice. This was the ONE runtime callback with no bus event of its own, which forced
  // `agent-app/src/sse-bridge.ts` to hold the handle and subscribe directly — a documented hole in the boundary.
  // Declaring the event here is what lets that bridge become a pure bus consumer, and what gives a second client
  // (the TUI) any way to receive it at all.
  agent.onDuplicateConnectNotice?.((remoteDid, remoteName) => {
    bus.emit('duplicate.connect.notice', { peerDid: remoteDid, remoteName, at: Date.now() });
  });
}
