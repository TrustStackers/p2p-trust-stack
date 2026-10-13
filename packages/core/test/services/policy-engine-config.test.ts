/**
 * P2 — PolicyEngine configuration, and the baseline-kind decision.
 *
 * Two things are pinned here, both of them properties rather than values:
 *
 *  1. **There is no way to switch the policy engine off.** An unrecognised
 *     `TSP_POLICY_ENGINE` warns and falls back to the default; it never produces a
 *     guard without an engine. This is the same bug class F-012 closed by making the
 *     engine a *required* constructor argument — an off switch is how the policy
 *     layer gets silently bypassed.
 *  2. **A community's own role decides its baseline, not a hard-coded `'vtc'`.** A
 *     VTN and a VTC have genuinely different baselines, so a VTN falling back to the
 *     VTC document silently loses `affiliate_vtc`/`unaffiliate_vtc`.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/services/policy-engine-config.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  POLICY_ENGINE_ENV,
  POLICY_UNKNOWN_FACT_ENV,
  DEFAULT_POLICY_ENGINE_CONFIG,
  POLICY_ENGINES,
  resolvePolicyEngineConfig,
  createPolicyEngine,
} from '../../src/services/policy-engine-config.js';
import { defaultPolicy, PolicyFactError } from '../../src/services/policy-engine.js';
import { resolveBaselineKind } from '../../src/services/governance-guard.js';
import type { PolicyData, PolicyQuery } from '../../src/services/policy-engine.js';

const MEMBERSHIP = 'MembershipCredential';

function query(): PolicyQuery {
  return {
    action: 'issue_credential',
    communityDid: 'did:scid:vh:club',
    actorDid: 'did:scid:vh:admin',
    params: { kind: MEMBERSHIP, subjectDid: 'did:scid:vh:subject' },
  };
}

/** Data whose `adminDids` does NOT contain the actor, so `actor_is_admin` is false. */
function data(): PolicyData {
  return {
    policy: defaultPolicy('vtc'),
    governance: { adminDids: ['did:scid:vh:somebody-else'], thresholdM: 2, thresholdN: 3 },
    memberships: [],
    subjectIsCommunityMember: false,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Resolution — env → validated value → safe default
// ═══════════════════════════════════════════════════════════════════════════

test('config: an empty environment yields the documented defaults', () => {
  const cfg = resolvePolicyEngineConfig({});
  assert.deepEqual(cfg, DEFAULT_POLICY_ENGINE_CONFIG);
  assert.equal(cfg.engine, 'p2pts');
  assert.equal(cfg.unknownFact, 'deny');
});

test('config: an unknown engine value falls back rather than failing', () => {
  const cfg = resolvePolicyEngineConfig({ [POLICY_ENGINE_ENV]: 'rego' });
  assert.equal(cfg.engine, DEFAULT_POLICY_ENGINE_CONFIG.engine);
});

test('config: there is no `off` — the policy layer cannot be switched off by env', () => {
  // The whole point. `off` is not a recognised value, so it resolves to the default
  // engine: a guard is still constructed, and still decides.
  for (const attempt of ['off', 'none', 'disabled', 'false', '0']) {
    const cfg = resolvePolicyEngineConfig({ [POLICY_ENGINE_ENV]: attempt });
    assert.equal(
      cfg.engine,
      DEFAULT_POLICY_ENGINE_CONFIG.engine,
      `"${attempt}" must not disable the engine`,
    );
    assert.ok(
      (POLICY_ENGINES as readonly string[]).includes(cfg.engine),
      'the resolved engine must always be a real implementation',
    );
  }
});

test('config: engine selection is case- and whitespace-insensitive', () => {
  assert.equal(resolvePolicyEngineConfig({ [POLICY_ENGINE_ENV]: '  P2PTS  ' }).engine, 'p2pts');
});
test('config: the unknown-fact policy resolves, and rejects nonsense', () => {
  assert.equal(resolvePolicyEngineConfig({ [POLICY_UNKNOWN_FACT_ENV]: 'error' }).unknownFact, 'error');
  assert.equal(resolvePolicyEngineConfig({ [POLICY_UNKNOWN_FACT_ENV]: 'DENY' }).unknownFact, 'deny');
  assert.equal(
    resolvePolicyEngineConfig({ [POLICY_UNKNOWN_FACT_ENV]: 'panic' }).unknownFact,
    'deny',
    'an unrecognised value falls back to the fail-closed default',
  );
});



// ═══════════════════════════════════════════════════════════════════════════
// 2. createPolicyEngine — the single construction point
// ═══════════════════════════════════════════════════════════════════════════

test('createPolicyEngine: returns a working engine that validates its own baseline', () => {
  const engine = createPolicyEngine();
  assert.equal(engine.validatePolicy(defaultPolicy('vtc')).allowed, true);
  assert.equal(engine.validatePolicy(defaultPolicy('vtn')).allowed, true);
});

test('createPolicyEngine: the default engine DENIES an undeterminable check', () => {
  // `issued_credential_count` is a real catalogue fact with no derivation yet, so it
  // has no value for this request. It is the ONLY check, deliberately: a check that
  // fails on its own terms (a determinate `false`) short-circuits before reaching an
  // undeterminable one, and a determinate failure must NOT be labelled indeterminate.
  const engine = createPolicyEngine({ ...DEFAULT_POLICY_ENGINE_CONFIG });
  const probe = {
    ...defaultPolicy('vtc'),
    rules: [
      {
        id: 'probe',
        when: { action: 'issue_credential' },
        require: [{ fact: 'issued_credential_count', op: 'lt', value: 10 }],
        decision: { decision: 'allow' },
      },
    ],
  };
  const r = engine.evaluate(query(), { ...data(), policy: probe });
  assert.equal(r.allowed, false, 'fail closed');
  assert.equal(r.indeterminate, true, 'and say so, rather than looking like a plain deny');
});

test('createPolicyEngine: a DETERMINATE failure is not labelled indeterminate', () => {
  // The counterpart to the test above. `actor_is_admin` is determinate here — the
  // actor is simply not an admin — so the denial is a plain one. Conflating the two
  // would make "I have no key for this actor" indistinguishable from "this actor is
  // not an admin", which is the distinction the whole indeterminate channel exists for.
  const engine = createPolicyEngine({ ...DEFAULT_POLICY_ENGINE_CONFIG });
  const probe = {
    ...defaultPolicy('vtc'),
    rules: [
      {
        id: 'probe',
        when: { action: 'issue_credential' },
        require: [{ fact: 'actor_is_admin', is: true }],
        decision: { decision: 'allow' },
      },
    ],
  };
  const r = engine.evaluate(query(), { ...data(), policy: probe });
  assert.equal(r.allowed, false);
  assert.equal(r.indeterminate, undefined, 'a determinate denial is not indeterminate');
});

test('createPolicyEngine({unknownFact: "error"}) THROWS on an undeterminable check', () => {
  const engine = createPolicyEngine({ ...DEFAULT_POLICY_ENGINE_CONFIG, unknownFact: 'error' });
  const probe = {
    ...defaultPolicy('vtc'),
    rules: [
      {
        id: 'probe',
        when: { action: 'issue_credential' },
        require: [{ fact: 'issued_credential_count', op: 'lt', value: 10 }],
        decision: { decision: 'allow' },
      },
    ],
  };
  assert.throws(
    () => engine.evaluate(query(), { ...data(), policy: probe }),
    PolicyFactError,
    'a mis-assembled fact must fail loudly in development, not read as "the policy refuses me"',
  );
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. resolveBaselineKind — the vtc-for-vtn defect
// ═══════════════════════════════════════════════════════════════════════════

test('baselineKind: a community\'s own role is authoritative', () => {
  // The defect: this used to be `defaultPolicy('vtc')` unconditionally, so a VTN with
  // no stored document was governed by a VTC baseline — which deliberately omits
  // `affiliate_vtc`/`unaffiliate_vtc`.
  assert.equal(resolveBaselineKind('vtn', 'vtc'), 'vtn', 'a VTN must not fall back to the VTC baseline');
  assert.equal(resolveBaselineKind('vtc', 'vtn'), 'vtc', 'nor a VTC to the VTN baseline');
});

test('baselineKind: a non-community role uses the configured fallback', () => {
  // e.g. a `vta` identity that somehow carries a governance row.
  assert.equal(resolveBaselineKind('vta', 'vtn'), 'vtn');
  assert.equal(resolveBaselineKind('vta', 'vtc'), 'vtc');
  assert.equal(resolveBaselineKind(null, 'vtc'), 'vtc');
  assert.equal(resolveBaselineKind(undefined, 'vtn'), 'vtn');
});

test('baselineKind: the two baselines actually differ (so the choice has teeth)', () => {
  const vtc = defaultPolicy('vtc');
  const vtn = defaultPolicy('vtn');
  assert.equal(vtc.rules.some((r) => r.id === 'affiliate-vtc'), false, 'a VTC cannot affiliate itself');
  assert.equal(vtn.rules.some((r) => r.id === 'affiliate-vtc'), true, 'a VTN accepts children');
  assert.notDeepEqual(vtc.rules.map((r) => r.id), vtn.rules.map((r) => r.id));
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. What createVtc persists
// ═══════════════════════════════════════════════════════════════════════════

test('createVtc: the persisted baseline declares the `p2pts` engine', () => {
  // The P2 requirement. `createVtc` stores `defaultPolicy(kind)` in
  // `governance.policy_rules`, and `GovernanceGuard` dispatches on `engine`. A
  // document that lost this field would be "unrecognised" everywhere and deny every
  // request — so the field is asserted rather than assumed.
  for (const kind of ['vtc', 'vtn'] as const) {
    const p = defaultPolicy(kind);
    assert.equal(p.engine, 'p2pts', `the ${kind} baseline must declare its engine`);
    assert.equal(p.version, '2');
    assert.deepEqual(p.appliesTo, [kind]);
    assert.equal(p.role, kind);
    assert.equal(
      createPolicyEngine().validatePolicy(p).allowed,
      true,
      'and must round-trip through validation, or the server rejects its own document',
    );
  }
});