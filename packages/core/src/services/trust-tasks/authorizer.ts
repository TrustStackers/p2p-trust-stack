/**
 * `guardAuthorizer` — the bridge from a `GovernanceGuard` to a ceremony `policy` step.
 *
 * The ceremony driver (`driver.ts`) expects a `CeremonyAuthorizer` — `authorize(action,
 * context) → PolicyResult`. `GovernanceGuard.authorize` takes a `PolicyQuery`
 * (`action`/`communityDid`/`actorDid`/`params`). This is the thin, reusable wrapper the
 * driver's doc-comment refers to, factored out so **every** policy-gated ceremony reads
 * the decision inputs the same way instead of each call site rebuilding a query.
 *
 * The ceremony context carries the inputs:
 *   - `communityDid` (required) — the governance DID the policy belongs to.
 *   - `actorDid`     (required) — who is asking.
 *   - `params`       (optional) — e.g. `{ kind, subjectDid }`.
 *   - `facts`        (optional) — caller-known facts that WIN over derived values.
 *
 * A missing `communityDid`/`actorDid` is a wiring error, not a policy decision, so it
 * fails closed WITH a named reason rather than silently denying with no explanation.
 */

import type { CeremonyAuthorizer } from './driver.js';
import type { PolicyAction, PolicyQuery, PolicyResult } from '../policy-engine.js';

/**
 * The minimum surface of a guard the authorizer needs. Kept structural (not
 * `import { GovernanceGuard }`) so this module stays free of the guard's DB/crypto
 * dependencies and is trivially testable with a stub.
 */
export interface AuthorizingGuard {
  authorize(query: PolicyQuery, extraFacts?: Record<string, unknown>): Promise<PolicyResult>;
}

/** The ceremony-context fields a policy gate reads. All optional; validated at use. */
export interface AuthorizerContext {
  communityDid?: unknown;
  actorDid?: unknown;
  params?: unknown;
  facts?: unknown;
}

/** Build a ceremony authorizer that evaluates `action` against `guard`. */
export function guardAuthorizer(guard: AuthorizingGuard): CeremonyAuthorizer {
  return {
    async authorize(action: string, context: Record<string, unknown>): Promise<PolicyResult> {
      const ctx = (context ?? {}) as AuthorizerContext;

      if (typeof ctx.communityDid !== 'string' || ctx.communityDid.length === 0) {
        return { allowed: false, reason: `policy step '${action}' has no communityDid in context` };
      }
      if (typeof ctx.actorDid !== 'string' || ctx.actorDid.length === 0) {
        return { allowed: false, reason: `policy step '${action}' has no actorDid in context` };
      }

      const query: PolicyQuery = {
        action: action as PolicyAction,
        communityDid: ctx.communityDid,
        actorDid: ctx.actorDid,
        ...(ctx.params !== null && typeof ctx.params === 'object'
          ? { params: ctx.params as Record<string, unknown> }
          : {}),
      };

      const facts =
        ctx.facts !== null && typeof ctx.facts === 'object'
          ? (ctx.facts as Record<string, unknown>)
          : undefined;

      return guard.authorize(query, facts);
    },
  };
}
