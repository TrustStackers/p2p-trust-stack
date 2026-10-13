/**
 * `contexts` domain — provision, list, revoke and inspect scoped app contexts.
 *
 * A context is a **revocable app scope**: its own HKDF-derived keypair and its own database under
 * `P2PTS_HOME/contexts/<contextId>/`. The app never holds the root identity's keys.
 *
 * ## Why there is no SQL here
 *
 * The whole capability lives behind the typed handle (`provisionApp` / `revokeApp` / `listProvisionedApps`),
 * which the runtime already implemented. This domain adds no storage of its own — which is the point: a context's
 * isolation is a filesystem and keystore property, not a row.
 *
 * ## What this domain does NOT decide
 *
 * It does not decide what a context may DO. `allowedKeyIds` is a **key** scope (which root verification methods
 * the context may use), and the F-021 boundary pins the provision result's exact shape, so a stored per-context
 * capability list is a contract decision rather than an oversight. `client/scope.ts` therefore takes the
 * capability list from its CALLER and denies everything not named.
 */
import { requireAgent, type DomainContext } from './context.js';
import { StackError } from '../errors.js';
import { ContextManager } from '../runtime/context-manager.js';
import type { ContextDto, ProvisionedContextDto } from '../dto/contexts.js';

export interface ContextsDeps {
  /** Root data directory (P2PTS_HOME) — where the context registry lives. */
  home(): string;
}

export interface ContextsApi {
  /** Provision a new app context. The result carries PUBLIC identifiers only (audit F-021 / Y1). */
  provision(contextId: string, options?: {
    allowedKeyIds?: string[];
    expiresAt?: number;
    deviceLocal?: boolean;
  }): Promise<ProvisionedContextDto>;
  /** Every context provisioned under this home. */
  list(): Promise<ContextDto[]>;
  /** Revoke a context — its keystore, database and directory are DELETED. */
  revoke(contextId: string): Promise<void>;
  /** One context's stored metadata, or null when there is none. */
  get(contextId: string): Promise<ContextDto | null>;
  /** Whether a context has passed its `expiresAt`. False for a context that never expires or does not exist. */
  isExpired(contextId: string): Promise<boolean>;
}

export function createContextsApi(ctx: DomainContext, deps: ContextsDeps): ContextsApi {
  /** Read one context's metadata straight from disk (it lives in the context's own database). */
  const readMetadata = (contextId: string): ContextDto | null => {
    const mgr = new ContextManager(contextId, deps.home());
    const meta = mgr.getMetadata();
    return meta ? (meta as ContextDto) : null;
  };

  return {
    async provision(contextId, options) {
      const agent = requireAgent(ctx, 'provision a context');
      if (!contextId || !contextId.trim()) {
        throw new StackError('invalid_context_id', 'contextId is required.');
      }
      if (typeof agent.provisionApp !== 'function') {
        throw new StackError('not_supported', 'Context provisioning is not supported in this deployment mode.');
      }
      const bundle = await agent.provisionApp(contextId, options);
      return bundle as ProvisionedContextDto;
    },

    async list() {
      const agent = requireAgent(ctx, 'list contexts');
      // A deployment whose runtime has no context registry simply has no contexts — an empty list is a
      // legitimate, renderable answer rather than an error.
      if (typeof agent.listProvisionedApps !== 'function') return [];
      return agent.listProvisionedApps() as ContextDto[];
    },

    async revoke(contextId) {
      const agent = requireAgent(ctx, 'revoke a context');
      if (!contextId || !contextId.trim()) {
        throw new StackError('invalid_context_id', 'contextId is required.');
      }
      if (typeof agent.revokeApp !== 'function') {
        throw new StackError('not_supported', 'Context revocation is not supported in this deployment mode.');
      }
      await agent.revokeApp(contextId);
    },

    async get(contextId) {
      requireAgent(ctx, 'read a context');
      if (!contextId || !contextId.trim()) return null;
      return readMetadata(contextId);
    },

    async isExpired(contextId) {
      requireAgent(ctx, 'check a context');
      if (!contextId || !contextId.trim()) return false;
      // Same rule as `ContextManager.isExpired()`: second-resolution, and `>=` so a context is expired AT its
      // `expiresAt` rather than one second after it.
      const meta = readMetadata(contextId);
      if (!meta?.expiresAt) return false;
      return Math.floor(Date.now() / 1000) >= meta.expiresAt;
    },
  };
}
