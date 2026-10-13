/**
 * gatePolicy — gate an action against a community's policy.
 *
 * Core helper (lives in `src/services`, NOT a route module): builds a stateless
 * `GovernanceGuard` + policy engine and evaluates `query` against the community's
 * stored policy bindings. Route layers import THIS; the utility server owns no
 * developer policy API of its own.
 *
 * `GovernanceGuard` and the engine are stateless and cheap; a hot path may build the
 * guard once and call `guard.authorize()` directly.
 */
import type { DataSource } from '../db/data-source.js';
import { GovernanceGuard } from './governance-guard.js';
import type { GovernanceResult } from './governance-guard.js';
import { createPolicyEngine } from './policy-engine-config.js';
import type { PolicyQuery } from './policy-engine.js';

const engine = createPolicyEngine();

export async function gatePolicy(
  db: DataSource,
  query: PolicyQuery,
  extraFacts?: Record<string, unknown>,
): Promise<GovernanceResult> {
  return new GovernanceGuard(db, engine).authorize(query, extraFacts);
}
