// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Policy fact catalogue — the vocabulary a policy document may read.
 *
 * ## Why this is a separate module
 *
 * A fact is *data* the policy reads, and the set of legal fact names has to live in
 * one place for three reasons:
 *
 *  1. **Validation.** An unknown fact name is a typo that would otherwise fail
 *     silently at decision time ("no value for this fact" → deny). It is rejected at
 *     POLICY-SAVE time instead, with the offending path named.
 *  2. **Cost control.** `factsReferencedBy()` walks a document to find which facts it
 *     actually reads, so the assembly side can resolve only those. A three-fact
 *     policy must not pay for thirteen.
 *  3. **Purity.** The derivation helpers here are pure functions of `PolicyData` and
 *     the query — no database access — so the catalogue is unit-testable without a
 *     DB. The reads that *populate* `PolicyData.facts` stay in `GovernanceGuard`.
 *
 * ## Two sources, documented precedence
 *
 * A fact resolves from `data.facts[name]` when present; otherwise it is derived from
 * the typed fields `GovernanceGuard` has always assembled (`governance.adminDids`,
 * `memberships`, `subjectIsCommunityMember`). The typed path is what keeps existing
 * policies working; the bag is how new facts are added without widening `PolicyData`
 * on every addition.
 */

import type { JsonPolicy, PolicyData, PolicyQuery } from './policy-engine.js';

/** The value shape a fact carries. Drives which check operators are legal. */
export type PolicyFactKind = 'boolean' | 'number' | 'string' | 'stringSet';

/**
 * Every fact a policy may reference, with its kind.
 *
 * Keep this list and the assembly side in step: adding a name here without a way to
 * populate it produces a policy that denies with `indeterminate: true` — safe, but
 * useless.
 */
export const POLICY_FACTS = {
  // ── actor / subject identity ────────────────────────────────────────────
  /** The actor is an admin (or founding_admin) of this community, or the community itself. */
  actor_is_admin: 'boolean',
  /** The actor's DID document is `active` (not deactivated/superseded). */
  actor_did_active: 'boolean',
  /** The subject already holds an ACTIVE membership in this community. */
  subject_is_active_member: 'boolean',
  /** The subject DID belongs to this community context (DidManager.isCommunityMember). */
  subject_is_community_member: 'boolean',
  /** The subject's membership row records personhood as asserted. */
  personhood_asserted: 'boolean',
  /** The subject holds a valid (issued, unrevoked) InvitationCredential. */
  subject_has_valid_vic: 'boolean',

  // ── delegation / grant ──────────────────────────────────────────────────
  /** The actor holds an unrevoked grant for this scope/permission. */
  has_grant: 'boolean',
  /** The actor holds an unrevoked, unexpired delegation for this dependency. */
  has_delegation: 'boolean',
  /** The actor's grant scopes, as a set. */
  actor_grants: 'stringSet',
  /** The actor's delegation scopes, as a set. */
  actor_delegations: 'stringSet',

  // ── counts and thresholds (numeric) ─────────────────────────────────────
  /** `governance.admin_threshold_m` — the M of the community's M-of-N admin quorum. */
  threshold_m: 'number',
  /** `governance.admin_threshold_n` — the N of the community's M-of-N admin quorum. */
  threshold_n: 'number',
  /** Number of approvals supplied with this request (compare against `threshold_m`). */
  approval_count: 'number',
  /** Number of admins/founding_admins in the community. */
  admin_count: 'number',
  /** Number of credentials this community has issued (quota checks). */
  issued_credential_count: 'number',
  /** Binding-supplied minimum approvals for a configurable rule (e.g. invite endorsement). */
  min_approvals: 'number',
  /** Number of distinct approvers a governance change requires (from a binding's scope). */
  required_approver_count: 'number',
  /** Number of ACTIVE members in the community. */
  active_member_count: 'number',

  // ── cross-community ─────────────────────────────────────────────────────
  /** Child kinds the parent VTN permits (`allowedChildKinds`). */
  parent_allowed_child_kinds: 'stringSet',
  /**
   * The requested child kind is permitted by the parent VTN.
   *
   * True when there is no parent, when the parent declares no `allowedChildKinds`, or
   * when the declared list includes the kind. The guard derives this from the parent's
   * document plus `query.params.child_kind`. It is a derived BOOLEAN rather than a
   * membership test on `parent_allowed_child_kinds` because the check grammar compares
   * a fact against a literal, and the requested kind is a query value, not a literal.
   */
  child_kind_allowed: 'boolean',
  /**
   * The requested credential kind is among the community's allowed claim types.
   * Derived from the community's `claim-type-allow` policy bindings + `query.params.kind`.
   */
  claim_type_allowed: 'boolean',
} as const satisfies Record<string, PolicyFactKind>;

/** A legal fact name. */
export type PolicyFactName = keyof typeof POLICY_FACTS;

/** True when `name` is a declared fact. */
export function isKnownFact(name: unknown): name is PolicyFactName {
  return typeof name === 'string' && Object.prototype.hasOwnProperty.call(POLICY_FACTS, name);
}

/** The declared kind of a fact, or undefined when unknown. */
export function factKind(name: string): PolicyFactKind | undefined {
  return isKnownFact(name) ? POLICY_FACTS[name] : undefined;
}

// ═══════════════════════════════════════════════════════════════════════════
// Strict coercion
//
// Policies arrive as JSON from a database column, so a "number" can be a string and
// a "boolean" can be 0/1. Coercion is deliberately narrow: anything that is not
// clearly the right shape yields `undefined` ("no value"), which the evaluator turns
// into a FAILED check plus `indeterminate` — never into a silently-passing one.
// ═══════════════════════════════════════════════════════════════════════════

/** Strict boolean: real booleans, plus 0/1 which SQLite hands back for INTEGER cols. */
export function asBoolean(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (value === 0 || value === 1) return value === 1;
  return undefined;
}

/** Strict number: finite numbers and numeric strings. */
export function asNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim().length > 0) {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

/** A set of strings, from a Set, or from an array of strings. */
export function asSet(value: unknown): Set<string> | undefined {
  if (value instanceof Set) return value as Set<string>;
  if (Array.isArray(value)) {
    return new Set(value.filter((v): v is string => typeof v === 'string'));
  }
  return undefined;
}

// ═══════════════════════════════════════════════════════════════════════════
// Resolution
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Resolve a fact to a value, or `undefined` when it has none for this query.
 *
 * `undefined` means **"cannot check"**, which is distinct from `false` ("checked and
 * false"). The evaluator keeps them apart: `false` fails the check normally, while
 * `undefined` fails it AND flags the result `indeterminate`. Collapsing the two is
 * how "I have no key for this actor" would be reported as "this actor is forged".
 *
 * Precedence: an explicitly supplied `data.facts[name]` wins, then the typed fields.
 *
 * @param name  the fact name (caller is expected to have validated it)
 * @param data  the assembled policy data
 * @param query the request, which supplies the actor/subject DIDs
 */
export function resolveFact(name: string, data: PolicyData, query: PolicyQuery): unknown {
  if (!isKnownFact(name)) return undefined;

  // 1. Explicitly supplied bag wins.
  if (data.facts && Object.prototype.hasOwnProperty.call(data.facts, name)) {
    return data.facts[name];
  }

  // 2. Derived from the typed fields the guard has always assembled.
  switch (name) {
    case 'actor_is_admin':
      // NB: DID-space comparison. `PolicyData` is DID-space throughout — see the
      // class doc on GovernanceGuard for what feeding UUIDs here cost once already.
      return data.governance.adminDids.includes(query.actorDid);
    case 'subject_is_active_member': {
      const subject = subjectDidOf(query);
      // No subject on this request means the fact has no value, not that it is false.
      if (subject === undefined) return undefined;
      return data.memberships.some((m) => m.did === subject && m.status === 'active');
    }
    case 'subject_is_community_member':
      return data.subjectIsCommunityMember;
    case 'threshold_m':
      return data.governance.thresholdM ?? undefined;
    case 'threshold_n':
      return data.governance.thresholdN ?? undefined;
    case 'admin_count':
      return data.governance.adminDids.length;
    default:
      // Declared in the catalogue but not assemblable yet (P3 populates these via
      // the `facts` bag). "Cannot check", not "false".
      return undefined;
  }
}

/** The subject DID for this query, if it supplied one. */
export function subjectDidOf(query: PolicyQuery): string | undefined {
  const v = query.params?.['subjectDid'];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

// ═══════════════════════════════════════════════════════════════════════════
// Introspection — which facts does a document actually read?
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Every fact name a document references.
 *
 * Used for (a) save-time validation and (b) resolving only what is needed. Returns
 * names, not kinds, and deliberately INCLUDES unknown names so a caller can report
 * them rather than silently skipping the check.
 */
export function factsReferencedBy(policy: JsonPolicy | unknown): Set<string> {
  const found = new Set<string>();

  /** Walk a check tree, recursing through `any`/`all`/`not`. */
  const walkCheck = (check: unknown): void => {
    if (check === null || typeof check !== 'object') return;
    const c = check as Record<string, unknown>;
    if (typeof c.fact === 'string') found.add(c.fact);
    if (typeof c.valueFact === 'string') found.add(c.valueFact);
    if (typeof c.subsetOf === 'string') found.add(c.subsetOf);
    for (const key of ['any', 'all']) {
      const kids = c[key];
      if (Array.isArray(kids)) kids.forEach(walkCheck);
    }
    if (c.not !== undefined) walkCheck(c.not);
  };

  if (policy === null || typeof policy !== 'object') return found;
  const p = policy as Record<string, unknown>;

  // An explicit declaration counts too, but never REPLACES the walk: a declared-but-
  // unread fact is harmless, an undeclared-but-read one is not.
  if (Array.isArray(p.facts)) {
    for (const f of p.facts) if (typeof f === 'string') found.add(f);
  }

  if (Array.isArray(p.rules)) {
    for (const rule of p.rules) {
      if (rule === null || typeof rule !== 'object') continue;
      const r = rule as Record<string, unknown>;
      if (Array.isArray(r.require)) r.require.forEach(walkCheck);
    }
  }

  return found;
}