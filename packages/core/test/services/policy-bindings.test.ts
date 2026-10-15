// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Phase A — modular policy bindings.
 *
 * Tier 2 (`community_policy_bindings`) resolves catalog rule templates
 * (`trust_task_templates`, family='rule') into the rules the engine evaluates, and
 * supplies binding parameter facts. `GovernanceGuard` prefers these over the legacy
 * `governance.policy_rules` document when a community has bindings.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/services/policy-bindings.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import * as identitiesRepo from '../../src/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '../../src/db/repositories/did-documents-repo.js';
import * as membershipsRepo from '../../src/db/repositories/memberships-repo.js';
import * as governanceRepo from '../../src/db/repositories/governance-repo.js';
import { GovernanceGuard } from '../../src/services/governance-guard.js';
import { LocalPolicyEngine } from '../../src/services/local-policy-engine.js';
import { defaultPolicy } from '../../src/services/policy-engine.js';
import { resolveCommunityRules, ruleIdFromType } from '../../src/services/policy-bindings.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();
const CLUB_DID = 'did:scid:vh:club';
const ADMIN_DID = 'did:scid:vh:admin';

async function makeAppDb(): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

async function seedIdentity(
  db: SqliteDataSource,
  opts: { did: string; role: 'vta' | 'vtc' | 'vtn'; name: string },
): Promise<string> {
  const uuid = await identitiesRepo.create(db, { realDid: opts.did, role: opts.role, name: opts.name });
  await didDocumentsRepo.create(db, {
    identityUuid: uuid, did: opts.did, method: opts.did.split(':')[1] ?? 'scid', isPrimary: true,
  });
  return uuid;
}

/** A VTC with one active `founding_admin` and the default baseline policy. */
async function seedClub(db: SqliteDataSource): Promise<{ vtcUuid: string; adminUuid: string }> {
  const vtcUuid = await seedIdentity(db, { did: CLUB_DID, role: 'vtc', name: 'Chess Club' });
  const adminUuid = await seedIdentity(db, { did: ADMIN_DID, role: 'vta', name: 'Club Admin' });
  await membershipsRepo.create(db, {
    memberIdentityUuid: adminUuid, communityIdentityUuid: vtcUuid, role: 'founding_admin', status: 'active',
  });
  await governanceRepo.create(db, {
    communityIdentityUuid: vtcUuid, adminThresholdM: 1, adminThresholdN: 1,
    policyRules: JSON.stringify(defaultPolicy('vtc')),
  });
  return { vtcUuid, adminUuid };
}

/** Insert one binding row. */
async function bind(
  db: SqliteDataSource,
  communityUuid: string,
  ruleType: string,
  opts: { enabled?: boolean; params?: unknown } = {},
): Promise<void> {
  await db.run(
    `INSERT INTO community_policy_bindings
       (uuid, community_identity_uuid, rule_type, enabled, params, updated_at)
     VALUES (?, ?, ?, ?, ?, 0)`,
    randomUUID(), communityUuid, ruleType,
    opts.enabled === false ? 0 : 1,
    opts.params === undefined ? null : JSON.stringify(opts.params),
  );
}

// ── Resolver ────────────────────────────────────────────────────────────────

test('ruleIdFromType derives a stable slug', () => {
  assert.equal(ruleIdFromType('task:p2pts:rule:update-governance:0.1'), 'update-governance');
  assert.equal(ruleIdFromType('not-a-rule-type'), 'not-a-rule-type');
});

test('no bindings → an empty rule set (no fallback source)', async () => {
  const db = await makeAppDb();
  const { vtcUuid } = await seedClub(db);
  const resolved = await resolveCommunityRules(db, vtcUuid);
  assert.deepEqual(resolved, { rules: [], facts: {} });
});

test('a binding resolves to an atomic rule + parameter facts (default overlaid by the binding)', async () => {
  const db = await makeAppDb();
  const { vtcUuid } = await seedClub(db);
  await bind(db, vtcUuid, 'task:p2pts:rule:vic-issue:0.1', { params: { min_approvals: 3 } });

  const resolved = await resolveCommunityRules(db, vtcUuid);
  assert.ok(resolved, 'bindings exist, so the resolver must not fall back');
  assert.equal(resolved.rules.length, 1);
  assert.equal(resolved.rules[0].id, 'vic-issue');
  assert.equal(resolved.rules[0].decision.decision, 'allow');
  // The template default is 1; the binding overrides it to 3.
  assert.equal(resolved.facts.min_approvals, 3);
});

test('a disabled binding contributes no rule (but bindings still govern)', async () => {
  const db = await makeAppDb();
  const { vtcUuid } = await seedClub(db);
  await bind(db, vtcUuid, 'task:p2pts:rule:update-governance:0.1', { enabled: false });

  const resolved = await resolveCommunityRules(db, vtcUuid);
  assert.ok(resolved);
  assert.equal(resolved.rules.length, 0);
});

test('a dangling binding (unknown rule type) is ignored, not guessed', async () => {
  const db = await makeAppDb();
  const { vtcUuid } = await seedClub(db);
  await bind(db, vtcUuid, 'task:p2pts:rule:does-not-exist:0.1');

  const resolved = await resolveCommunityRules(db, vtcUuid);
  assert.ok(resolved);
  assert.equal(resolved.rules.length, 0);
});

// ── Guard integration (bindings override the blob) ────────────────────────────

test('bindings are the SOLE rule source (an unbound action is denied)', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  const { vtcUuid } = await seedClub(db);

  // No bindings → no rules → the policy default (deny) applies. There is no
  // document fallback any more.
  const before = await guard.authorize({
    action: 'approve_membership', communityDid: CLUB_DID, actorDid: ADMIN_DID,
  });
  assert.equal(before.allowed, false, 'no rules means denied, not a document fallback');

  // Bind ONLY update-governance; approve_membership still matches no rule → deny.
  await bind(db, vtcUuid, 'task:p2pts:rule:update-governance:0.1');
  const after = await guard.authorize({
    action: 'approve_membership', communityDid: CLUB_DID, actorDid: ADMIN_DID,
  });
  assert.equal(after.allowed, false);

  // The bound rule itself is honored.
  const gov = await guard.authorize({
    action: 'update_governance', communityDid: CLUB_DID, actorDid: ADMIN_DID,
  });
  assert.equal(gov.allowed, true, gov.reason);
});

test('adding the matching binding restores the action (bindings are the rule source)', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  const { vtcUuid } = await seedClub(db);

  await bind(db, vtcUuid, 'task:p2pts:rule:update-governance:0.1');
  await bind(db, vtcUuid, 'task:p2pts:rule:approve-membership:0.1');

  const allowed = await guard.authorize({
    action: 'approve_membership', communityDid: CLUB_DID, actorDid: ADMIN_DID,
  });
  assert.equal(allowed.allowed, true, allowed.reason);
});

