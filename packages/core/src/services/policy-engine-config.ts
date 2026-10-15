// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * PolicyEngine configuration — env-driven, with safe defaults.
 *
 * Follows the house pattern (`resolveMembershipPresentationPolicy`): a named env
 * constant, a resolver with an explicit fallback, and a warning when the value is
 * unrecognised. Call sites do not read `process.env` themselves.
 *
 * ## There is deliberately no `'off'`
 *
 * The membership-presentation resolver offers `off | warn | enforce`. This one has
 * no off value, and must not grow one. An off switch is exactly how the policy
 * layer gets silently bypassed — the bug class F-012 closed by making the engine a
 * *required* constructor argument on `GovernanceGuard`. An unrecognised value warns
 * and falls back to the default.
 *
 * ## What is configured here vs in the database
 *
 * The env var picks the **engine**. What a community may actually *do* is its policy
 * bindings (`community_policy_bindings`), edited per community at runtime. Moving
 * governance rules into env vars would put them back into code, which is the thing
 * this work removes.
 */

import type { PolicyEngine, UnknownFactPolicy } from './policy-engine.js';
import { UNKNOWN_FACT_POLICIES } from './policy-engine.js';
import { LocalPolicyEngine } from './local-policy-engine.js';
import { logger } from '../util/logger.js';

/** Selects the policy engine implementation. */
export const POLICY_ENGINE_ENV = 'TSP_POLICY_ENGINE';

/** What to do when a check reads a fact with no value for the request. */
export const POLICY_UNKNOWN_FACT_ENV = 'TSP_POLICY_UNKNOWN_FACT';

/**
 * The available engines.
 *
 * One entry today. Declared as a list so that adding a backend (Fork C's
 * `OpaSidecarPolicyEngine`) is additive rather than a rewrite of the resolver.
 */
export const POLICY_ENGINES = ['p2pts'] as const;
export type PolicyEngineKind = (typeof POLICY_ENGINES)[number];

export interface PolicyEngineConfig {
  /** The selected engine. */
  engine: PolicyEngineKind;
  /**
   * The baseline document `GovernanceGuard` falls back to when a community's own
   * `identities.role` is neither `vtc` nor `vtn`.
   *
   * Normally the community's role decides the baseline — this is only the last
   * resort, and exists so the old `defaultPolicy('vtc')`-for-everything behaviour
   * has a named, configurable replacement rather than a hard-coded literal.
   */
  defaultPolicyKind: 'vtc' | 'vtn';
  /** See `UnknownFactPolicy`. */
  unknownFact: UnknownFactPolicy;
}

export const DEFAULT_POLICY_ENGINE_CONFIG: PolicyEngineConfig = {
  engine: 'p2pts',
  defaultPolicyKind: 'vtc',
  unknownFact: 'deny',
};

/** Resolve the policy-engine configuration: env → validated value → safe default. */
export function resolvePolicyEngineConfig(
  env: Record<string, string | undefined> = process.env,
): PolicyEngineConfig {
  const rawEngine = (env[POLICY_ENGINE_ENV] ?? '').trim().toLowerCase();
  let engine: PolicyEngineKind = DEFAULT_POLICY_ENGINE_CONFIG.engine;
  if ((POLICY_ENGINES as readonly string[]).includes(rawEngine)) {
    engine = rawEngine as PolicyEngineKind;
  } else if (rawEngine.length > 0) {
    logger.warn(
      `[policy-engine] unrecognised ${POLICY_ENGINE_ENV}="${rawEngine}" — falling back to "${engine}"`,
    );
  }

  const rawUnknownFact = (env[POLICY_UNKNOWN_FACT_ENV] ?? '').trim().toLowerCase();
  let unknownFact: UnknownFactPolicy = DEFAULT_POLICY_ENGINE_CONFIG.unknownFact;
  if ((UNKNOWN_FACT_POLICIES as readonly string[]).includes(rawUnknownFact)) {
    unknownFact = rawUnknownFact as UnknownFactPolicy;
  } else if (rawUnknownFact.length > 0) {
    logger.warn(
      `[policy-engine] unrecognised ${POLICY_UNKNOWN_FACT_ENV}="${rawUnknownFact}" — falling back to "${unknownFact}"`,
    );
  }

  return { ...DEFAULT_POLICY_ENGINE_CONFIG, engine, unknownFact };
}

/**
 * The single construction point for a policy engine.
 *
 * Every call site used to be `new LocalPolicyEngine()`, so adding a constructor
 * option — or a second backend — meant finding and editing all of them. Call sites
 * now ask for an engine and receive whatever the configuration selects.
 */
export function createPolicyEngine(
  cfg: PolicyEngineConfig = resolvePolicyEngineConfig(),
): PolicyEngine {
  // One entry in POLICY_ENGINES today. A switch here (rather than at the call sites)
  // is what makes Fork C additive: `OpaSidecarPolicyEngine` would slot in beside it.
  return new LocalPolicyEngine({ unknownFact: cfg.unknownFact });
}