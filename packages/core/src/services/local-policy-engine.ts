/**
 * LocalPolicyEngine — the in-process structured-policy interpreter.
 *
 * Replaces `JsonPolicyEngine` (Fork A). Same `PolicyEngine` contract, a wider
 * document: rules carry a `when` selector, a `require` check list and a full
 * `decision`, with priority ordering, per-rule `enabled`, six check operators and
 * the trusttasks.org decision vocabulary.
 *
 * There is exactly ONE document version: `engine: 'p2pts'`. An earlier
 * `engine: 'json-policy'` document (the pre-P1 shape, with an `allow` condition tree
 * and `default: 'allow' | 'deny'`) was removed once it was established that nothing
 * in production ever wrote one — `defaultPolicy()` and `createVtc` both emit the
 * current document, so the old read path had no producer. Input that does not match
 * the current shape is simply "unrecognised" and denies.
 *
 * ## Deny short-circuits, and that is deliberate
 *
 * Once the matching rules are known:
 *
 *   1. if ANY matching rule decides `deny`, the answer is deny;
 *   2. otherwise the highest-priority matching rule wins;
 *   3. otherwise the document's `default`.
 *
 * Rule 1 is what makes "stricter but not more permissive" true for free when a VTC's
 * policy is composed with its parent VTN's: a child cannot out-rank a parent's deny
 * by claiming a higher priority. Without it, `priority` would be an escape hatch.
 *
 * ## "Cannot check" is not "checked and false"
 *
 * A check whose fact has no value for this request fails AND sets
 * `indeterminate: true`. The answer is still a denial (fail-closed), but the caller
 * can tell the two apart.
 */

import type {
  PolicyEngine,
  PolicyQuery,
  PolicyData,
  PolicyResult,
  JsonPolicyV2,
  PolicyCheck,
  PolicyCheckOp,
  PolicyDecision,
  UnknownFactPolicy,
} from './policy-engine.js';
import { defaultPolicy, POLICY_ACTIONS, PolicyFactError } from './policy-engine.js';
import { resolveFact, asBoolean, asNumber, asSet, isKnownFact } from './policy-facts.js';

/** A rule flattened out of the document. */
interface NormalizedRule {
  id: string;
  when?: { action?: string; kind?: string };
  require?: PolicyCheck[];
  decision?: PolicyDecision;
  priority: number;
  enabled: boolean;
}

interface NormalizedPolicy {
  version: number;
  defaultDecision: PolicyDecision;
  rules: NormalizedRule[];
  /** False when the document is not a recognisable policy at all. */
  recognized: boolean;
}

const OP_FNS: Record<PolicyCheckOp, (a: number, b: number) => boolean> = {
  lt: (a, b) => a < b,
  lte: (a, b) => a <= b,
  eq: (a, b) => a === b,
  gte: (a, b) => a >= b,
  gt: (a, b) => a > b,
};

/** The outcome of one check: did it pass, and could it be determined at all. */
interface CheckOutcome {
  pass: boolean;
  indeterminate: boolean;
}

/** Options for `LocalPolicyEngine`. */
export interface LocalPolicyEngineOptions {
  /** See `UnknownFactPolicy`. Defaults to `'deny'`. */
  unknownFact?: UnknownFactPolicy;
}

export class LocalPolicyEngine implements PolicyEngine {
  private readonly unknownFact: UnknownFactPolicy;

  constructor(options: LocalPolicyEngineOptions = {}) {
    this.unknownFact = options.unknownFact ?? 'deny';
  }

  /**
   * The refusal produced when a check cannot be determined — a fact the document
   * references has no value for this request.
   *
   * Under the default `'deny'` this is an ordinary indeterminate failure. Under
   * `'error'` it throws, so a mis-assembled fact surfaces as a crash instead of a
   * denial an operator would read as "the policy is refusing me". One helper, so the
   * choice cannot drift between the nine places a check can come up undecided.
   */
  private undetermined(reason: string): CheckOutcome {
    if (this.unknownFact === 'error') throw new PolicyFactError(reason);
    return { pass: false, indeterminate: true };
  }

  evaluate(query: PolicyQuery, data: PolicyData): PolicyResult {
    const policy = normalizePolicy(data.policy);

    // An unrecognised document (no engine, no rules — the metadata-only shape the
    // agent-side vtc/store.ts writes) must NOT throw. It has no rules, so it falls
    // through to the default decision, which is deny unless the document says
    // otherwise. The old engine would have crashed here on `policy.rules.filter`.
    if (!policy.recognized) {
      return {
        allowed: false,
        reason: 'policy document not recognised (no rules); denying by default',
        decision: { decision: 'deny', explanation: 'unrecognised policy document' },
        policyVersion: policy.version,
      };
    }

    // A whole v2 document can be suspended without deleting it.
    if ((data.policy as JsonPolicyV2 | undefined)?.enabled === false) {
      return {
        allowed: false,
        reason: 'policy document is disabled; denying by default',
        decision: { decision: 'deny', explanation: 'policy disabled' },
        policyVersion: policy.version,
      };
    }

    return this.evaluateV2(query, data, policy);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Evaluation
  // ═══════════════════════════════════════════════════════════════════════

  private evaluateV2(query: PolicyQuery, data: PolicyData, policy: NormalizedPolicy): PolicyResult {
    // Selector match first, then priority order (descending). Stable by id, so two
    // rules at the same priority always resolve the same way — a policy must not
    // decide differently run to run.
    const selected = policy.rules
      .filter((r) => r.enabled && ruleSelects(r, query))
      .sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id));

    const matchedRules: string[] = [];
    let indeterminate = false;

    for (const rule of selected) {
      const outcome = this.evalRequire(rule.require ?? [], query, data);
      if (!outcome.pass) {
        // A failed rule may still have been undeterminable; carry that to the result.
        if (outcome.indeterminate) indeterminate = true;
        continue;
      }
      matchedRules.push(rule.id);

      // Rule 1: deny short-circuits, regardless of priority. See the class doc.
      if (rule.decision?.decision === 'deny') {
        return {
          allowed: false,
          reason: rule.decision.explanation ?? `denied by rule '${rule.id}'`,
          matchedRules: [...matchedRules],
          decision: rule.decision,
          policyVersion: 2,
        };
      }
    }

    // Rule 2: the highest-priority matching non-deny rule wins.
    for (const rule of selected) {
      if (!matchedRules.includes(rule.id)) continue;
      const decision = rule.decision ?? ({ decision: 'deny' } as PolicyDecision);
      return {
        allowed: decision.decision === 'allow',
        reason:
          decision.explanation ??
          (decision.decision === 'allow'
            ? undefined
            : `rule '${rule.id}' decided ${decision.decision}`),
        matchedRules,
        decision,
        ...(indeterminate ? { indeterminate: true } : {}),
        policyVersion: 2,
      };
    }

    // Rule 3: nothing matched — the document default.
    return {
      allowed: policy.defaultDecision.decision === 'allow',
      reason:
        policy.defaultDecision.explanation ?? `no matching rule for action '${query.action}'`,
      decision: policy.defaultDecision,
      ...(indeterminate ? { indeterminate: true } : {}),
      policyVersion: 2,
    };
  }

  /** A rule's `require` list, implicitly ANDed. */
  private evalRequire(checks: PolicyCheck[], query: PolicyQuery, data: PolicyData): CheckOutcome {
    let indeterminate = false;
    for (const check of checks) {
      const outcome = this.evalCheck(check, query, data);
      if (outcome.indeterminate) indeterminate = true;
      if (!outcome.pass) return { pass: false, indeterminate };
    }
    return { pass: true, indeterminate };
  }

  /**
   * One check.
   *
   * A malformed check (no operator at all) fails AND is flagged indeterminate: it is
   * a document bug, and `validatePolicy()` rejects it at save time, so reaching here
   * means a hand-edited row. Failing closed with a signal beats guessing.
   */
  private evalCheck(check: PolicyCheck, query: PolicyQuery, data: PolicyData): CheckOutcome {
    // ── grouping ────────────────────────────────────────────────────────
    if (check.all !== undefined) return this.evalRequire(check.all, query, data);
    if (check.any !== undefined) {
      let indeterminate = false;
      for (const sub of check.any) {
        const outcome = this.evalCheck(sub, query, data);
        if (outcome.pass) return { pass: true, indeterminate: false };
        if (outcome.indeterminate) indeterminate = true;
      }
      return { pass: false, indeterminate };
    }
    if (check.not !== undefined) {
      const inner = this.evalCheck(check.not, query, data);
      // Negating an undeterminable check stays undeterminable: "not unknown" is not true.
      return { pass: !inner.pass && !inner.indeterminate, indeterminate: inner.indeterminate };
    }

    if (typeof check.fact !== 'string') {
      return this.undetermined('policy check has no `fact` name');
    }

    // ── boolean equality ────────────────────────────────────────────────
    if (check.is !== undefined) {
      const value = asBoolean(resolveFact(check.fact, data, query));
      if (value === undefined) return this.undetermined(noValue(check.fact, query));
      return { pass: value === check.is, indeterminate: false };
    }

    // ── numeric comparison (vs a literal, or vs another fact) ───────────
    if (check.op !== undefined) {
      const fn = OP_FNS[check.op];
      if (!fn) return this.undetermined(`unknown operator '${String(check.op)}'`);

      const left = asNumber(resolveFact(check.fact, data, query));
      if (left === undefined) return this.undetermined(noValue(check.fact, query));

      const right =
        typeof check.valueFact === 'string'
          ? asNumber(resolveFact(check.valueFact, data, query))
          : asNumber(check.value);
      if (right === undefined) {
        return this.undetermined(
          typeof check.valueFact === 'string' ? noValue(check.valueFact, query) : 'comparison value is not a number',
        );
      }

      return { pass: fn(left, right), indeterminate: false };
    }

    // ── collection containment ──────────────────────────────────────────
    if (check.includes !== undefined) {
      const set = asSet(resolveFact(check.fact, data, query));
      if (set === undefined) return this.undetermined(noValue(check.fact, query));
      const needle = typeof check.includes === 'string' ? check.includes : String(check.includes);
      return { pass: set.has(needle), indeterminate: false };
    }

    // ── collection subset ───────────────────────────────────────────────
    if (check.subsetOf !== undefined) {
      const left = asSet(resolveFact(check.fact, data, query));
      if (left === undefined) return this.undetermined(noValue(check.fact, query));
      const right = asSet(resolveFact(check.subsetOf, data, query));
      if (right === undefined) return this.undetermined(noValue(check.subsetOf, query));
      for (const v of left) if (!right.has(v)) return { pass: false, indeterminate: false };
      return { pass: true, indeterminate: false };
    }

    return this.undetermined('policy check has no recognised operator');
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Validation — what makes a document acceptable at SAVE time
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Validate a policy document before it is persisted.
   *
   * This gates `PATCH /communities/:uuid/governance`: a document that would otherwise
   * fail silently at decision time is instead rejected at save time.
   *
   * Rejects, with a path in the reason: an unknown engine, a bad `default`, duplicate
   * rule ids, an unknown action, an unknown FACT name (the highest-value check — it
   * turns a silent deny-at-decision-time into a 400 at save time), and a check with
   * no operator.
   */
  validatePolicy(policy: unknown): PolicyResult {
    if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
      return { allowed: false, reason: 'policy must be a JSON object' };
    }
    const p = policy as Record<string, unknown>;

    if (p.engine === 'p2pts') return this.validateV2(p);
    return {
      allowed: false,
      reason: `unsupported engine '${String(p.engine)}' (expected 'p2pts')`,
    };
  }

  private validateV2(p: Record<string, unknown>): PolicyResult {
    const dflt = p.default as Record<string, unknown> | undefined;
    if (dflt === null || typeof dflt !== 'object') {
      return { allowed: false, reason: 'policy.default must be a decision object' };
    }
    if (!isDecisionKind(dflt.decision)) {
      return {
        allowed: false,
        reason: `policy.default.decision must be one of allow|deny|requireStepUp|requireConsent (got '${String(dflt.decision)}')`,
      };
    }
    if (p.appliesTo !== undefined) {
      if (!Array.isArray(p.appliesTo) || p.appliesTo.some((v) => typeof v !== 'string')) {
        return { allowed: false, reason: 'policy.appliesTo must be an array of strings' };
      }
    }
    if (!Array.isArray(p.rules)) return { allowed: false, reason: 'policy.rules must be an array' };

    const seen = new Set<string>();
    for (let i = 0; i < p.rules.length; i++) {
      const rule = p.rules[i] as Record<string, unknown> | null;
      if (rule === null || typeof rule !== 'object') {
        return { allowed: false, reason: `rules[${i}] must be an object` };
      }
      if (typeof rule.id !== 'string' || !rule.id) {
        return { allowed: false, reason: `rules[${i}]: missing string id` };
      }
      if (seen.has(rule.id)) return { allowed: false, reason: `rules[${i}]: duplicate id '${rule.id}'` };
      seen.add(rule.id);

      const decision = rule.decision as Record<string, unknown> | undefined;
      if (decision === null || typeof decision !== 'object') {
        return { allowed: false, reason: `rules[${i}] ('${rule.id}'): missing decision` };
      }
      if (!isDecisionKind(decision.decision)) {
        return {
          allowed: false,
          reason: `rules[${i}] ('${rule.id}'): decision must be one of allow|deny|requireStepUp|requireConsent (got '${String(decision.decision)}')`,
        };
      }
      if (decision.decision === 'requireConsent') {
        const rc = decision.requireConsent as Record<string, unknown> | undefined;
        if (rc === null || typeof rc !== 'object' || typeof rc.approverSet !== 'string') {
          return {
            allowed: false,
            reason: `rules[${i}] ('${rule.id}'): requireConsent needs { approverSet }`,
          };
        }
      }

      const when = rule.when as Record<string, unknown> | undefined;
      if (when !== undefined) {
        if (when === null || typeof when !== 'object') {
          return { allowed: false, reason: `rules[${i}] ('${rule.id}'): when must be an object` };
        }
        if (when.action !== undefined && !isKnownAction(when.action)) {
          return {
            allowed: false,
            reason: `rules[${i}] ('${rule.id}').when.action: unknown action '${String(when.action)}'`,
          };
        }
      }

      if (rule.require !== undefined) {
        if (!Array.isArray(rule.require)) {
          return { allowed: false, reason: `rules[${i}] ('${rule.id}'): require must be an array` };
        }
        const bad = validateChecks(rule.require, `rules[${i}] ('${rule.id}').require`);
        if (bad) return bad;
      }

      if (rule.priority !== undefined) {
        const pr = rule.priority;
        if (typeof pr !== 'number' || pr < 0 || pr > 1000) {
          return { allowed: false, reason: `rules[${i}] ('${rule.id}'): priority must be 0–1000` };
        }
      }
    }
    return { allowed: true };
  }

  defaultPolicy(kind: 'vtc' | 'vtn'): JsonPolicyV2 {
    return defaultPolicy(kind);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Module-level helpers
// ═══════════════════════════════════════════════════════════════════════════

/** Returned for anything that is not a recognisable policy document. */
const UNRECOGNIZED: NormalizedPolicy = {
  version: 0,
  defaultDecision: { decision: 'deny', explanation: 'unrecognised policy document' },
  rules: [],
  recognized: false,
};

/**
 * The message used when a fact a document references has no value for the request.
 *
 * Names the fact AND the action, because the usual cause is an assembly gap for one
 * specific action — not a globally missing fact.
 */
function noValue(fact: string, query: PolicyQuery): string {
  return `fact '${fact}' has no value for action '${query.action}'`;
}

/**
 * Flatten a document into one rule shape.
 *
 * Anything unrecognised — `null`, a string, an array, the metadata-only object the
 * agent-side `vtc/store.ts` writes when the server supplied no document, or a retired
 * `engine: 'json-policy'` document — yields `recognized: false` and NO rules, so the
 * caller denies by default. This is the deliberate difference from the old engine,
 * which did `policy.rules.filter(...)` and threw a TypeError on exactly that shape.
 */
export function normalizePolicy(policy: unknown): NormalizedPolicy {
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) return UNRECOGNIZED;
  const p = policy as Record<string, unknown>;

  if (p.engine === 'p2pts') {
    const rules = Array.isArray(p.rules) ? p.rules : [];
    const dflt = p.default as Record<string, unknown> | undefined;
    const defaultDecision: PolicyDecision =
      dflt !== null && typeof dflt === 'object' && isDecisionKind(dflt.decision)
        ? (dflt as unknown as PolicyDecision)
        : { decision: 'deny', explanation: 'missing or invalid default' };

    return {
      version: 2,
      defaultDecision,
      recognized: true,
      rules: rules
        .filter((r): r is Record<string, unknown> => r !== null && typeof r === 'object')
        .map((r) => ({
          id: typeof r.id === 'string' ? r.id : 'unnamed',
          when: r.when as { action?: string; kind?: string } | undefined,
          require: Array.isArray(r.require) ? (r.require as PolicyCheck[]) : undefined,
          decision: r.decision as PolicyDecision | undefined,
          priority: typeof r.priority === 'number' ? r.priority : 0,
          enabled: r.enabled === undefined ? true : r.enabled !== false,
        })),
    };
  }

  return UNRECOGNIZED;
}

/**
 * Does this rule's selector apply to the query?
 *
 * A rule with no `when` at all matches every action — that is how a document states
 * an unconditional rule. An omitted `when.action` means "every action" and an omitted
 * `when.kind` means "every credential kind".
 */
function ruleSelects(rule: NormalizedRule, query: PolicyQuery): boolean {
  const kind = query.params?.['kind'];
  const when = rule.when ?? {};
  if (when.action !== undefined && when.action !== query.action) return false;
  if (when.kind !== undefined && when.kind !== kind) return false;
  return true;
}

function isDecisionKind(v: unknown): v is PolicyDecision['decision'] {
  return v === 'allow' || v === 'deny' || v === 'requireStepUp' || v === 'requireConsent';
}

function isKnownAction(v: unknown): boolean {
  return typeof v === 'string' && (POLICY_ACTIONS as readonly string[]).includes(v);
}

/**
 * Validate a v2 `require` list. Returns a failure result, or null when acceptable.
 *
 * The fact-name check is the valuable one: an unknown fact would otherwise fail
 * silently at decision time (no value → deny + `indeterminate`), which reads to an
 * operator as "the policy is refusing me" rather than "the policy has a typo".
 */
function validateChecks(checks: unknown[], path: string): PolicyResult | null {
  for (let i = 0; i < checks.length; i++) {
    const at = `${path}[${i}]`;
    const check = checks[i];
    if (check === null || typeof check !== 'object') {
      return { allowed: false, reason: `${at} must be an object` };
    }
    const c = check as Record<string, unknown>;

    // Grouping recurses.
    if (c.any !== undefined || c.all !== undefined) {
      const kids = c.any !== undefined ? c.any : c.all;
      if (!Array.isArray(kids)) {
        return { allowed: false, reason: `${at}: any/all must be an array` };
      }
      const bad = validateChecks(kids, c.any !== undefined ? `${at}.any` : `${at}.all`);
      if (bad) return bad;
      continue;
    }
    if (c.not !== undefined) {
      const bad = validateChecks([c.not], `${at}.not`);
      if (bad) return bad;
      continue;
    }

    if (typeof c.fact !== 'string' || !isKnownFact(c.fact)) {
      return {
        allowed: false,
        reason: `${at}.fact: unknown fact '${String(c.fact)}' (see POLICY_FACTS in policy-facts.ts)`,
      };
    }

    const operators = ['is', 'op', 'includes', 'subsetOf'].filter((k) => c[k] !== undefined);
    if (operators.length === 0) {
      return { allowed: false, reason: `${at}: no operator (expected is|op|includes|subsetOf)` };
    }
    if (operators.length > 1) {
      return { allowed: false, reason: `${at}: exactly one operator expected, got ${operators.join(', ')}` };
    }

    if (c.op !== undefined) {
      if (!(typeof c.op === 'string' && Object.prototype.hasOwnProperty.call(OP_FNS, c.op))) {
        return { allowed: false, reason: `${at}.op: unknown operator '${String(c.op)}'` };
      }
      if (c.value === undefined && c.valueFact === undefined) {
        return { allowed: false, reason: `${at}: 'op' needs a 'value' or a 'valueFact'` };
      }
      if (c.valueFact !== undefined && !isKnownFact(c.valueFact)) {
        return { allowed: false, reason: `${at}.valueFact: unknown fact '${String(c.valueFact)}'` };
      }
    }
    if (c.is !== undefined && typeof c.is !== 'boolean') {
      return { allowed: false, reason: `${at}.is: must be a boolean` };
    }
    if (c.subsetOf !== undefined && !isKnownFact(c.subsetOf)) {
      return { allowed: false, reason: `${at}.subsetOf: unknown fact '${String(c.subsetOf)}'` };
    }
  }
  return null;
}