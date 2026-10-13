/**
 * LocalPolicyEngine — the structured-policy interpreter.
 *
 * This file did not exist before P1: the engine shipped without a unit test, so its
 * only coverage was indirect through `governance-guard.test.ts`. What is pinned here:
 *
 *  1. **A retired pre-P1 document denies rather than being evaluated.** The engine
 *     serves exactly one document shape; the old `json-policy` read path was removed
 *     once it was established that nothing in production ever wrote one.
 *  2. **The six v2 operators**, including `valueFact` (comparing one fact against
 *     another — the `approval_count >= threshold_m` case) and collection operators.
 *  3. **Priority ordering and deny short-circuit.** The second is load-bearing for
 *     VTN∩VTC composition: a child must not out-rank a parent's deny.
 *  4. **"Cannot check" is not "checked and false"** — a check with no fact value fails
 *     AND flags `indeterminate`.
 *  5. **An unrecognised document does not throw.** `policy_rules` can hold a
 *     metadata-only shape with no `engine`/`rules`; the old engine threw a TypeError
 *     on it.
 *  6. **validatePolicy rejects at SAVE time** what would otherwise fail silently at
 *     decision time — most importantly an unknown fact name.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/services/policy-engine.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LocalPolicyEngine } from '../../src/services/local-policy-engine.js';
import { defaultPolicy } from '../../src/services/policy-engine.js';
import type { PolicyQuery, PolicyData, JsonPolicy } from '../../src/services/policy-engine.js';
import { isKnownFact, factsReferencedBy } from '../../src/services/policy-facts.js';

const ADMIN = 'did:scid:vh:admin';
const OUTSIDER = 'did:scid:vh:outsider';
const SUBJECT = 'did:scid:vh:subject';

const engine = new LocalPolicyEngine();

/** Minimal PolicyData with the three facts the guard assembles today. */
function data(policy: JsonPolicy, over: Partial<PolicyData> = {}): PolicyData {
  return {
    policy,
    governance: { adminDids: [ADMIN], thresholdM: 2, thresholdN: 3 },
    memberships: [{ did: SUBJECT, status: 'pending' }],
    subjectIsCommunityMember: false,
    ...over,
  };
}

function query(over: Partial<PolicyQuery> = {}): PolicyQuery {
  return {
    action: 'issue_credential',
    communityDid: 'did:scid:vh:club',
    actorDid: ADMIN,
    params: { kind: 'MembershipCredential', subjectDid: SUBJECT },
    ...over,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. A retired pre-P1 document denies (it is no longer evaluated)
// ═══════════════════════════════════════════════════════════════════════════

test('a retired `json-policy` document denies instead of being evaluated', () => {
  // The pre-P1 shape. Nothing in production ever wrote one: `defaultPolicy()` and
  // `createVtc` both emit the current document, so the old read path had no producer
  // and was removed. Such a row now falls through to "unrecognised" and denies.
  const retired = {
    engine: 'json-policy',
    version: '1',
    default: 'deny',
    rules: [
      {
        id: 'vmc-issue',
        action: 'issue_credential',
        kind: 'MembershipCredential',
        allow: { all: [{ actor_is_admin: true }, { not: { subject_is_active_member: true } }] },
      },
    ],
  } as unknown as JsonPolicy;

  const r = engine.evaluate(query(), data(retired));
  assert.equal(r.allowed, false, 'a retired document must not grant access');
  assert.match(String(r.reason), /not recognised/);
  assert.equal(r.policyVersion, 0);
});

test('validatePolicy rejects a retired `json-policy` document at save time', () => {
  const retired = { engine: 'json-policy', version: '1', default: 'deny', rules: [] };
  const r = engine.validatePolicy(retired);
  assert.equal(r.allowed, false);
  assert.match(String(r.reason), /unsupported engine/);
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Unrecognised documents must not throw
// ═══════════════════════════════════════════════════════════════════════════

test('an unrecognised document denies instead of throwing', () => {
  // The metadata-only shape the agent-side vtc/store.ts writes: no engine, no rules.
  // The old engine did `policy.rules.filter(...)` and threw a TypeError here.
  const metadataOnly = {
    name: 'Some VTC', role: 'vtc', adminUuids: ['u1'], threshold: 2, source: 'remote',
  } as unknown as JsonPolicy;

  const r = engine.evaluate(query(), data(metadataOnly));
  assert.equal(r.allowed, false);
  assert.match(String(r.reason), /not recognised/);
  assert.equal(r.policyVersion, 0);
});

test('null / array / string policies deny instead of throwing', () => {
  for (const bad of [null, [], 'nope', 42]) {
    const r = engine.evaluate(query(), data(bad as unknown as JsonPolicy));
    assert.equal(r.allowed, false, `policy ${JSON.stringify(bad)} must deny`);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. v2 — the six operators
// ═══════════════════════════════════════════════════════════════════════════

/** A v2 document with one rule, parameterised by its `require` list. */
function v2(require_: unknown[], extra: Record<string, unknown> = {}): JsonPolicy {
  return {
    engine: 'p2pts',
    version: '2',
    default: { decision: 'deny', explanation: 'no rule matched' },
    rules: [
      { id: 'r', when: { action: 'issue_credential' }, require: require_, decision: { decision: 'allow' }, ...extra },
    ],
  } as unknown as JsonPolicy;
}

test('v2 op `is`: boolean equality', () => {
  assert.equal(engine.evaluate(query(), data(v2([{ fact: 'actor_is_admin', is: true }]))).allowed, true);
  assert.equal(engine.evaluate(query(), data(v2([{ fact: 'actor_is_admin', is: false }]))).allowed, false);
  assert.equal(
    engine.evaluate(query({ actorDid: OUTSIDER }), data(v2([{ fact: 'actor_is_admin', is: true }]))).allowed,
    false,
  );
});

test('v2 op `op` against a literal', () => {
  // thresholdM is 2 in the fixture data.
  assert.equal(engine.evaluate(query(), data(v2([{ fact: 'threshold_m', op: 'lte', value: 2 }]))).allowed, true);
  assert.equal(engine.evaluate(query(), data(v2([{ fact: 'threshold_m', op: 'gt', value: 2 }]))).allowed, false);
});

test('v2 op `op` against ANOTHER fact (approval_count >= threshold_m)', () => {
  const withApprovals = (n: number): PolicyData =>
    data(v2([{ fact: 'approval_count', op: 'gte', valueFact: 'threshold_m' }]), {
      facts: { approval_count: n },
    });

  assert.equal(engine.evaluate(query(), withApprovals(2)).allowed, true, '2 >= 2');
  assert.equal(engine.evaluate(query(), withApprovals(3)).allowed, true, '3 >= 2');
  assert.equal(engine.evaluate(query(), withApprovals(1)).allowed, false, '1 >= 2 is false');
});

test('v2 op `includes` on a set fact', () => {
  const withScopes = (scopes: string[]): PolicyData =>
    data(v2([{ fact: 'actor_grants', includes: 'scope:alpha' }]), { facts: { actor_grants: scopes } });

  assert.equal(engine.evaluate(query(), withScopes(['scope:alpha'])).allowed, true);
  assert.equal(engine.evaluate(query(), withScopes(['scope:beta'])).allowed, false);
  assert.equal(engine.evaluate(query(), withScopes([])).allowed, false);
});

test('v2 op `subsetOf`', () => {
  const withSets = (mine: string[], allowed: string[]): PolicyData =>
    data(v2([{ fact: 'actor_grants', subsetOf: 'parent_allowed_child_kinds' }]), {
      facts: { actor_grants: mine, parent_allowed_child_kinds: allowed },
    });

  assert.equal(engine.evaluate(query(), withSets(['a'], ['a', 'b'])).allowed, true);
  assert.equal(engine.evaluate(query(), withSets(['a', 'z'], ['a', 'b'])).allowed, false);
  assert.equal(engine.evaluate(query(), withSets([], ['a'])).allowed, true, 'empty ⊆ anything');
});

test('v2 grouping: all / any / not', () => {
  const admin = { fact: 'actor_is_admin', is: true };
  const active = { fact: 'subject_is_active_member', is: true };

  assert.equal(engine.evaluate(query(), data(v2([{ all: [admin, { not: active }] }]))).allowed, true);
  assert.equal(
    engine.evaluate(query(), data(v2([{ all: [admin, active] }]))).allowed,
    false,
    'all: an active subject fails',
  );
  assert.equal(engine.evaluate(query(), data(v2([{ any: [active, admin] }]))).allowed, true, 'any: admin passes');
  assert.equal(
    engine.evaluate(query(), data(v2([{ any: [active, { fact: 'actor_did_active', is: true }] }]))).allowed,
    false,
  );
});

test('v2: `require: []` matches on the selector alone', () => {
  assert.equal(engine.evaluate(query(), data(v2([]))).allowed, true);
});

test('v2: the `kind` selector discriminates', () => {
  // Build the rule WITH a kind selector — the `v2()` helper omits `kind`, so it
  // matches every kind and cannot test this.
  const policy = {
    engine: 'p2pts',
    version: '2',
    default: { decision: 'deny' },
    rules: [
      {
        id: 'vmc-only',
        when: { action: 'issue_credential', kind: 'MembershipCredential' },
        require: [{ fact: 'actor_is_admin', is: true }],
        decision: { decision: 'allow' },
      },
    ],
  } as unknown as JsonPolicy;

  assert.equal(
    engine.evaluate(query(), data(policy)).allowed,
    true,
    'the matching kind must pass',
  );
  assert.equal(
    engine.evaluate(query({ params: { kind: 'EndorsementCredential', subjectDid: SUBJECT } }), data(policy)).allowed,
    false,
    'a different kind must not match a kind-scoped rule',
  );
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. Priority, deny short-circuit, enabled
// ═══════════════════════════════════════════════════════════════════════════

/** Two matching rules; the higher priority wins. */
function twoRules(a: Record<string, unknown>, b: Record<string, unknown>): JsonPolicy {
  return {
    engine: 'p2pts',
    version: '2',
    default: { decision: 'deny' },
    rules: [
      { id: 'a', when: { action: 'issue_credential' }, require: [], decision: { decision: 'allow' }, ...a },
      { id: 'b', when: { action: 'issue_credential' }, require: [], decision: { decision: 'deny' }, ...b },
    ],
  } as unknown as JsonPolicy;
}

test('v2: a deny short-circuits even a HIGHER-priority allow', () => {
  // This is the property VTN∩VTC composition depends on: a child cannot out-rank its
  // parent's deny by claiming a larger priority. If this ever inverts, composition
  // silently becomes permissive.
  const r = engine.evaluate(query(), data(twoRules({ priority: 1000 }, { priority: 0 })));
  assert.equal(r.allowed, false, 'deny wins over a higher-priority allow');
  assert.deepEqual(r.matchedRules, ['a', 'b']);
});

test('v2: without a deny, the highest priority wins', () => {
  const policy = {
    engine: 'p2pts',
    version: '2',
    default: { decision: 'deny' },
    rules: [
      { id: 'deny-low', when: { action: 'add_admin' }, require: [], decision: { decision: 'deny' } },
      { id: 'allow-high', when: { action: 'issue_credential' }, require: [], decision: { decision: 'allow' }, priority: 10 },
      { id: 'allow-low', when: { action: 'issue_credential' }, require: [], decision: { decision: 'allow' }, priority: 1 },
    ],
  } as unknown as JsonPolicy;
  const r = engine.evaluate(query(), data(policy));
  assert.equal(r.allowed, true);
  assert.deepEqual(r.matchedRules, ['allow-high', 'allow-low']);
});

test('v2: `enabled: false` on a rule removes it from evaluation', () => {
  const policy = {
    engine: 'p2pts',
    version: '2',
    default: { decision: 'deny' },
    rules: [
      { id: 'off', when: { action: 'issue_credential' }, require: [], decision: { decision: 'allow' }, enabled: false },
    ],
  } as unknown as JsonPolicy;
  assert.equal(engine.evaluate(query(), data(policy)).allowed, false);
});

test('v2: `enabled: false` on the DOCUMENT suspends everything', () => {
  const policy = { ...(v2([]) as object), enabled: false } as unknown as JsonPolicy;
  const r = engine.evaluate(query(), data(policy));
  assert.equal(r.allowed, false);
  assert.match(String(r.reason), /disabled/);
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. "Cannot check" is not "checked and false"
// ═══════════════════════════════════════════════════════════════════════════

test('v2: a fact with no value fails AND flags indeterminate', () => {
  // `issued_credential_count` is declared but nothing populates it yet (P3).
  const policy = v2([{ fact: 'issued_credential_count', op: 'lt', value: 500 }]);
  const r = engine.evaluate(query(), data(policy));
  assert.equal(r.allowed, false, 'fail-closed');
  assert.equal(r.indeterminate, true, 'but distinguishable from "checked and false"');
});

test('v2: a fact that IS false does not set indeterminate', () => {
  const policy = v2([{ fact: 'actor_is_admin', is: true }]);
  const r = engine.evaluate(query({ actorDid: OUTSIDER }), data(policy));
  assert.equal(r.allowed, false);
  assert.equal(r.indeterminate, undefined, 'this is a definite no, not an unknown');
});

test('v2: negating an undeterminable check stays undeterminable', () => {
  // "not unknown" is not true — otherwise `not` would turn a missing fact into an allow.
  const policy = v2([{ not: { fact: 'issued_credential_count', op: 'lt', value: 500 } }]);
  const r = engine.evaluate(query(), data(policy));
  assert.equal(r.allowed, false);
  assert.equal(r.indeterminate, true);
});

test('v2: a dateless query makes subject_is_active_member indeterminate, not false', () => {
  const policy = v2([{ fact: 'subject_is_active_member', is: false }]);
  const noSubject = query({ params: { kind: 'MembershipCredential' } }); // no subjectDid
  const r = engine.evaluate(noSubject, data(policy));
  assert.equal(r.allowed, false);
  assert.equal(r.indeterminate, true);
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. validatePolicy — reject at SAVE time what would fail silently at decision time
// ═══════════════════════════════════════════════════════════════════════════

test('validate: accepts the documents the server itself writes', () => {
  // The property that matters: `defaultPolicy()` emits what `validatePolicy()`
  // accepts. A validator stricter than the producer would reject the very document
  // the server writes at community creation.
  assert.equal(engine.validatePolicy(defaultPolicy('vtc')).allowed, true, 'the VTC baseline must round-trip');
  assert.equal(engine.validatePolicy(defaultPolicy('vtn')).allowed, true, 'the VTN baseline must round-trip');
});

test('validate: rejects an unknown engine', () => {
  const r = engine.validatePolicy({ engine: 'rego', rules: [] });
  assert.equal(r.allowed, false);
  assert.match(String(r.reason), /unsupported engine/);
});

test('validate: rejects an unknown FACT name, naming the path', () => {
  // The highest-value check in the file: without it this typo would deny silently at
  // decision time and read to an operator as "the policy is refusing me".
  const policy = {
    engine: 'p2pts',
    version: '2',
    default: { decision: 'deny' },
    rules: [
      {
        id: 'typo',
        when: { action: 'add_admin' },
        require: [{ fact: 'actor_is_adminn', is: true }],
        decision: { decision: 'allow' },
      },
    ],
  };
  const r = engine.validatePolicy(policy);
  assert.equal(r.allowed, false);
  assert.match(String(r.reason), /unknown fact 'actor_is_adminn'/);
  assert.match(String(r.reason), /require\[0\]/, 'the path must be reported');
});

test('validate: rejects an unknown action, a duplicate id, and a bad operator', () => {
  const base = { engine: 'p2pts', version: '2', default: { decision: 'deny' } };

  const badAction = engine.validatePolicy({
    ...base,
    rules: [{ id: 'r', when: { action: 'not_an_action' }, require: [], decision: { decision: 'allow' } }],
  });
  assert.equal(badAction.allowed, false);
  assert.match(String(badAction.reason), /unknown action/);

  const dup = engine.validatePolicy({
    ...base,
    rules: [
      { id: 'same', when: { action: 'add_admin' }, require: [], decision: { decision: 'allow' } },
      { id: 'same', when: { action: 'add_admin' }, require: [], decision: { decision: 'deny' } },
    ],
  });
  assert.equal(dup.allowed, false);
  assert.match(String(dup.reason), /duplicate id/);

  const badOp = engine.validatePolicy({
    ...base,
    rules: [
      {
        id: 'r',
        when: { action: 'add_admin' },
        require: [{ fact: 'threshold_m', op: 'approximately', value: 2 }],
        decision: { decision: 'allow' },
      },
    ],
  });
  assert.equal(badOp.allowed, false);
  assert.match(String(badOp.reason), /unknown operator/);
});

test('validate: rejects a requireConsent decision with no approverSet', () => {
  const r = engine.validatePolicy({
    engine: 'p2pts',
    version: '2',
    default: { decision: 'deny' },
    rules: [
      { id: 'r', when: { action: 'add_admin' }, require: [], decision: { decision: 'requireConsent' } },
    ],
  });
  assert.equal(r.allowed, false);
  assert.match(String(r.reason), /requireConsent needs/);
});

test('validate: rejects a bad decision value', () => {
  const r = engine.validatePolicy({
    engine: 'p2pts',
    version: '2',
    default: { decision: 'maybe' },
    rules: [],
  });
  assert.equal(r.allowed, false);
  assert.match(String(r.reason), /policy.default.decision/);
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. defaultPolicy — v2, and VTC ≠ VTN
// ═══════════════════════════════════════════════════════════════════════════

test('defaultPolicy emits v2 and validates', () => {
  const p = defaultPolicy('vtc');
  assert.equal(p.engine, 'p2pts');
  assert.equal(p.version, '2');
  assert.equal(p.default.decision, 'deny');
  assert.equal(engine.validatePolicy(p).allowed, true);
});

test('defaultPolicy: VTN grants affiliate actions, VTC does not', () => {
  // The `kind` argument used to be ignored, and GovernanceGuard passed 'vtc' for both
  // roles. `affiliateVtc` is driven from the VTN routes, so affiliation is a
  // parent-side action — a VTC must not be able to affiliate itself.
  const vtcIds = defaultPolicy('vtc').rules.map((r) => r.id);
  const vtnIds = defaultPolicy('vtn').rules.map((r) => r.id);

  assert.ok(vtnIds.includes('affiliate-vtc'), 'a VTN accepts child communities');
  assert.ok(vtnIds.includes('unaffiliate-vtc'), 'a VTN removes child communities');
  assert.ok(!vtcIds.includes('affiliate-vtc'), 'a VTC cannot affiliate itself into a network');
  assert.ok(!vtcIds.includes('unaffiliate-vtc'));

  for (const id of ['vmc-issue', 'approve-membership', 'update-governance']) {
    assert.ok(vtcIds.includes(id), `VTC baseline must keep '${id}'`);
    assert.ok(vtnIds.includes(id), `VTN baseline must keep '${id}'`);
  }
});

test('defaultPolicy: `appliesTo` records the role it was built for', () => {
  assert.deepEqual(defaultPolicy('vtc').appliesTo, ['vtc']);
  assert.deepEqual(defaultPolicy('vtn').appliesTo, ['vtn']);
  assert.equal(defaultPolicy('vtc').role, 'vtc');
  assert.equal(defaultPolicy('vtn').role, 'vtn');
});

test('defaultPolicy: it only reads facts the guard can actually assemble today', () => {
  // A rule referencing an unpopulated fact would deny (fail-closed) but make the
  // default policy useless. This is the guard against adding one by accident.
  //
  // Kept in step with `GovernanceGuard`: P3 added `approval_count`, `admin_count` and
  // `child_kind_allowed` when it moved the crystallization and parent-child decisions
  // out of TypeScript and into this document.
  const assembled = new Set([
    'actor_is_admin',
    'subject_is_active_member',
    'subject_is_community_member',
    'threshold_m',
    'threshold_n',
    'admin_count',
    'approval_count',
    'child_kind_allowed',
  ]);
  for (const policy of [defaultPolicy('vtc'), defaultPolicy('vtn')]) {
    for (const fact of factsReferencedBy(policy)) {
      assert.ok(assembled.has(fact), `default policy reads '${fact}', which is not assembled yet`);
    }
  }
});

test('defaultPolicy: the VMC rule still excludes an already-active member', () => {
  assert.equal(
    engine.evaluate(query(), data(defaultPolicy('vtc'))).allowed,
    true,
    'an admin issuing to a pending member is allowed',
  );
  const active = engine.evaluate(
    query(),
    data(defaultPolicy('vtc'), { memberships: [{ did: SUBJECT, status: 'active' }] }),
  );
  assert.equal(active.allowed, false, 're-issuing to an active member is denied');
});

test('defaultPolicy: a non-admin is denied under the VTC baseline', () => {
  const r = engine.evaluate(query({ actorDid: OUTSIDER }), data(defaultPolicy('vtc')));
  assert.equal(r.allowed, false);
});

// ═══════════════════════════════════════════════════════════════════════════
// 8. Fact catalogue
// ═══════════════════════════════════════════════════════════════════════════

test('factsReferencedBy finds every fact a document reads, including nested ones', () => {
  // Recursion through `all`/`not` matters: a fact that only appears inside a group
  // still has to be resolved, or the check silently reads "no value".
  const grouped = v2([
    { all: [{ fact: 'actor_is_admin', is: true }, { not: { fact: 'subject_is_active_member', is: true } }] },
  ]);
  assert.deepEqual([...factsReferencedBy(grouped)].sort(), ['actor_is_admin', 'subject_is_active_member']);

  const v2doc = v2([
    { fact: 'actor_grants', subsetOf: 'parent_allowed_child_kinds' },
    { any: [{ fact: 'threshold_m', op: 'gte', valueFact: 'threshold_n' }] },
  ]);
  assert.deepEqual(
    [...factsReferencedBy(v2doc)].sort(),
    ['actor_grants', 'parent_allowed_child_kinds', 'threshold_m', 'threshold_n'],
  );
});

test('isKnownFact recognises the catalogue and nothing else', () => {
  assert.equal(isKnownFact('actor_is_admin'), true);
  assert.equal(isKnownFact('threshold_m'), true);
  assert.equal(isKnownFact('actor_is_adminn'), false);
  assert.equal(isKnownFact(''), false);
  assert.equal(isKnownFact(undefined), false);
});