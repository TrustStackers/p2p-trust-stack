/**
 * Capability scope — `asContext()`, a **deny-by-default** view of the stack for one provisioned app context.
 *
 * ## What this is for
 *
 * A context is a revocable app scope: its own keypair and its own database, provisioned from the root identity
 * (`domains/contexts.ts`). This module is the other half — the *authority* half. A third-party app is handed
 * `asContext(stack, contextId, { allow: [...] })` and can only reach what its host named.
 *
 * ## Deny by default, in three separate senses
 *
 *   1. **No capability, no call.** `allow` is an explicit list. An empty or absent list grants nothing.
 *   2. **No classification, no call.** Every method of every exposed domain appears in `READ_METHODS` or
 *      `WRITE_METHODS`. A method that appears in neither is refused — so adding a method to a domain makes it
 *      denied until someone consciously classifies it, rather than silently granting it.
 *   3. **No liveness, no call.** The context is re-checked on EVERY call, not once at construction: a context
 *      that is revoked (its directory deleted) or that passes `expiresAt` stops working mid-session.
 *
 * ## Why the capability list comes from the CALLER
 *
 * It would be tidier to read the context's capabilities from storage, and that is deliberately not what happens.
 * `allowedKeyIds` is a **key** scope (which root DID verification methods the context may use), not a method
 * scope, and the F-021 / Y1 ruling pins the provision result's exact shape — so a stored per-context capability
 * list is a contract decision, not an oversight. Until that decision is made, the host states the scope and the
 * scoped object is the enforcement point. This is the standard capability pattern: the app never receives the
 * unscoped stack at all.
 *
 * ## What is NOT exposed, and why
 *
 * `host`, `version`, `start`, `stop`, `cursor` and the whole `contexts` domain are absent. A context is an
 * application, not an operator: it must not start or stop the agent, read the host's paths, or provision and
 * revoke other contexts. `identity.sign` is absent for a sharper reason — a context must not sign with the ROOT
 * key, which is exactly the isolation F-021 exists to protect.
 */
import { CapabilityError, StackError } from '../errors.js';
import type { TrustStack } from './trust-stack.js';
import type { ContextCapability, ContextScopeStateDto } from '../dto/contexts.js';
import { ContextManager } from '../runtime/context-manager.js';

/** Domains a scoped stack may expose. Everything else on `TrustStack` is deliberately unreachable. */
export type ScopedDomain =
  | 'identity'
  | 'connectivity'
  | 'relationships'
  | 'messaging'
  | 'profiles'
  | 'names'
  | 'credentials'
  | 'communities'
  | 'delegations';

/**
 * Method classification. `'read'` methods need `<domain>.read`; `'write'` need `<domain>.write`.
 *
 * This is an allow-list in the strict sense: a method missing from both maps is REFUSED. That is what makes the
 * scope robust to a domain gaining a method — the new one is denied until it is classified here, and
 * `test/trust_app_api/scope.test.ts` fails so the omission is noticed rather than shipped as an accidental grant.
 *
 * Deliberately absent (denied by omission, each for a reason):
 *   - `identity.sign` — signing with the ROOT key is precisely what a context must not do (F-021);
 *   - `identity.create` / `import` / `activate` / `deactivate` / `list` — host authority, not app authority;
 *   - `connectivity.refresh` / `connectUtility` / `pushIdentity` — host operations on the transport;
 *   - `contexts.*` — the registry is the host's, including `provision` and `revoke`.
 */
const READ_METHODS: Readonly<Record<ScopedDomain, readonly string[]>> = {
  identity: ['current', 'recoveryState', 'lookup'],
  connectivity: ['health', 'ready', 'status', 'utilityStatus', 'networkProfile', 'networkChanged', 'explainFailure'],
  relationships: ['oobi', 'list', 'get', 'ceremonyStatus', 'vrc', 'dtgVrc', 'graph', 'debug', 'duplicateNotice'],
  messaging: ['transcript', 'latest', 'unread'],
  profiles: ['list', 'claims', 'card', 'syncStatus'],
  names: ['resolve', 'list'],
  credentials: ['list', 'signatures', 'invitations', 'viewModels', 'verify'],
  delegations: ['list'],
  communities: [
    'list', 'detail', 'checkName', 'parents', 'adminCandidates',
    'governanceProposals', 'ceremonyLog', 'ceremonyLogThread', 'pendingCeremonies', 'ceremony',
    'governanceDocs',
  ],
};

const WRITE_METHODS: Readonly<Record<ScopedDomain, readonly string[]>> = {
  identity: [],
  connectivity: [],
  relationships: ['connect', 'connectDiscovered', 'disconnect', 'acknowledge', 'resetCeremony', 'verify', 'reconnect'],
  messaging: ['send', 'clear'],
  profiles: ['create', 'update', 'remove', 'addClaim', 'updateClaim', 'removeClaim'],
  names: ['register', 'revoke'],
  credentials: ['revoke', 'declineInvitation', 'acceptInvitation', 'issue'],
  delegations: ['create', 'revoke'],
  communities: ['invite', 'create', 'propose', 'approve', 'approveCeremony', 'resetCeremony'],
};

/**
 * Which capability each classification needs, per domain.
 *
 * An explicit map rather than a built string, so a domain with no write methods (`identity`, `connectivity`)
 * says so with `null` instead of advertising a capability that can never be exercised.
 */
const CAPABILITY: Readonly<Record<ScopedDomain, { read: ContextCapability; write: ContextCapability | null }>> = {
  identity: { read: 'identity.read', write: null },
  connectivity: { read: 'connectivity.read', write: null },
  relationships: { read: 'relationships.read', write: 'relationships.write' },
  messaging: { read: 'messaging.read', write: 'messaging.write' },
  profiles: { read: 'profiles.read', write: 'profiles.write' },
  names: { read: 'names.read', write: 'names.write' },
  credentials: { read: 'credentials.read', write: 'credentials.write' },
  communities: { read: 'communities.read', write: 'communities.write' },
  delegations: { read: 'delegations.read', write: 'delegations.write' },
};

/**
 * Methods that are deliberately NOT part of the context surface, with the reason.
 *
 * These are denied by omission in the sense that they appear in neither `READ_METHODS` nor `WRITE_METHODS` — but
 * they are listed here so the omission is a DECISION rather than an accident. The guard in
 * `test/trust_app_api/scope.test.ts` requires every declared domain method to be either classified or denied, so a
 * newly-added method fails that test until someone chooses one or the other.
 */
export const DENIED_METHODS: Readonly<Record<ScopedDomain, readonly string[]>> = {
  identity: [
    // A context must not sign with the ROOT key. This is the whole point of F-021's isolation: the root keypair
    // belongs to the host, and `revoke()` exists precisely to make a context's key unusable afterwards.
    'sign',
    // Host authority: creating, importing, activating or deactivating an agent is the operator's job, and
    // listing every identity in the home would expose identities that are not this context's business.
    'list', 'create', 'import', 'activate', 'deactivate',
  ],
  connectivity: [
    // Host operations on the transport: re-running bootstrap discovery, dialing the utility server and pushing
    // this identity to it. A context may OBSERVE connectivity (`health`/`ready`/`status`/`utilityStatus`) but
    // must not rewire the node it shares with the host.
    'refresh', 'connectUtility', 'pushIdentity',
  ],
  relationships: [],
  messaging: [],
  profiles: [],
  names: [],
  credentials: [],
  communities: [],
  delegations: [],
};

/** Exposed for the guard that asserts every domain method is classified. */
export const METHOD_CLASSIFICATION = {
  read: READ_METHODS,
  write: WRITE_METHODS,
  capability: CAPABILITY,
  denied: DENIED_METHODS,
} as const;

export interface ContextScopeOptions {
  /**
   * The capabilities this context may exercise.
   *
   * **DENY BY DEFAULT**: an absent or empty list grants nothing at all.
   */
  allow: readonly ContextCapability[];
}

/** A scoped view: the same domain shapes, every call gated. */
export type ScopedTrustStack = {
  readonly [D in ScopedDomain]: TrustStack[D];
} & {
  /** The context this view is scoped to. */
  readonly contextId: string;
  /** Live state, re-evaluated on every call rather than captured at construction. */
  state(): ContextScopeStateDto;
  /** Subscribe, with delivery gated on the context staying live. */
  on: TrustStack['on'];
  once: TrustStack['once'];
  off: TrustStack['off'];
};

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/** The domains a scoped stack exposes, in the order they are built. */
const SCOPED_DOMAINS: readonly ScopedDomain[] = [
  'identity', 'connectivity', 'relationships', 'messaging', 'profiles', 'names', 'credentials', 'communities',
];

/**
 * Build a deny-by-default view of `stack` for one provisioned context.
 *
 * @param stack     the full stack, which the caller keeps — the scoped object is what the app receives.
 * @param contextId the provisioned context to scope to.
 * @param opts      `allow` names the capabilities granted. Nothing else is reachable.
 */
export function asContext(
  stack: TrustStack,
  contextId: string,
  opts: ContextScopeOptions,
): ScopedTrustStack {
  if (!contextId || !contextId.trim()) {
    throw new StackError('invalid_context_id', 'asContext requires a contextId.');
  }
  const granted = new Set<ContextCapability>(opts?.allow ?? []);
  const home = stack.host.home;

  /**
   * Evaluate liveness NOW.
   *
   * Deliberately not cached: the whole value of a revocable context is that revoking it stops the app, and a
   * cached answer would let a revoked context keep working for the lifetime of the object.
   */
  const evaluate = (): ContextScopeStateDto => {
    const mgr = new ContextManager(contextId, home);
    // `exists()` is false once `revoke()` has deleted the directory — that IS revocation, observed.
    if (!mgr.exists()) {
      return { contextId, live: false, reason: 'revoked', capabilities: [...granted] };
    }
    if (mgr.isExpired()) {
      return { contextId, live: false, reason: 'expired', capabilities: [...granted] };
    }
    return { contextId, live: true, reason: 'active', capabilities: [...granted] };
  };

  /** Liveness + capability, in that order, with a message that says which one refused. */
  const assert = (domain: ScopedDomain, method: string): void => {
    const state = evaluate();
    if (!state.live) {
      throw new CapabilityError(
        `Context '${contextId}' is ${state.reason} — cannot call ${domain}.${method}().`,
      );
    }

    const read = READ_METHODS[domain] as readonly string[];
    const write = WRITE_METHODS[domain] as readonly string[];
    // Deny by omission: a method in NEITHER list is not classified, and an unclassified method is refused
    // rather than granted. That is what stops a newly-added domain method from being reachable by accident.
    const capability: ContextCapability | null =
      read.includes(method) ? CAPABILITY[domain].read
      : write.includes(method) ? CAPABILITY[domain].write
      : null;

    if (capability === null) {
      throw new CapabilityError(
        `${domain}.${method}() is not part of the context surface — a method that is neither classified ` +
        `read/write nor deliberately denied is refused by default.`,
      );
    }
    if (!granted.has(capability)) {
      throw new CapabilityError(
        `Context '${contextId}' was not granted '${capability}' — cannot call ${domain}.${method}().`,
      );
    }
  };

  /**
   * Wrap one domain so every call is gated.
   *
   * Methods are wrapped individually rather than the domain object being frozen: a caller could otherwise reach
   * an unwrapped method through a stale reference.
   */
  const scopeDomain = <D extends ScopedDomain>(domain: D): TrustStack[D] => {
    const source = stack[domain] as unknown as Record<string, unknown>;
    const wrapped: Record<string, unknown> = {};
    for (const key of Object.keys(source)) {
      const value = source[key];
      if (typeof value !== 'function') { wrapped[key] = value; continue; }
      wrapped[key] = (...args: unknown[]) => {
        try {
          assert(domain, key);
        } catch (err) {
          // REJECT — never throw synchronously. Every method on these domains returns a Promise, so a caller
          // writes `scoped.messaging.send(...).catch(...)`; a synchronous throw would bypass that handler and
          // escape as an uncaught exception instead of a refusal the caller can actually see.
          return Promise.reject(err);
        }
        return (value as (...a: unknown[]) => unknown).apply(source, args);
      };
    }
    return wrapped as unknown as TrustStack[D];
  };

  const scoped: Record<string, unknown> = {
    contextId,
    state: evaluate,
  };
  for (const domain of SCOPED_DOMAINS) scoped[domain] = scopeDomain(domain);

  // Events are gated on liveness at DELIVERY time, not subscription time: "revocation stops events" is only
  // true if the check happens when the event would otherwise be delivered.
  const guardHandler = <H>(handler: H): H => {
    if (typeof handler !== 'function') return handler;
    return ((...args: unknown[]) => {
      const state = evaluate();
      if (!state.live) return undefined;   // dropped, not thrown: an event arriving after revocation is expected
      return (handler as (...a: unknown[]) => unknown)(...args);
    }) as unknown as H;
  };

  scoped.on = (event: string, handler: unknown, o?: unknown) =>
    stack.on(event as never, guardHandler(handler) as never, o as never);
  scoped.once = (event: string, handler: unknown, o?: unknown) =>
    stack.once(event as never, guardHandler(handler) as never, o as never);
  scoped.off = (sub: unknown) => stack.off(sub as never);

  return scoped as unknown as ScopedTrustStack;
}

