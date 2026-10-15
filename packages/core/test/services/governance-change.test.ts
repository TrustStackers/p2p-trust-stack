// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Phase B — governance-change core: consent scope resolution, proposal hashing, and
 * the durable proposal/approval store.
 *
 * Run:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/services/governance-change.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { TX_SCHEMA_SQL, applyTxSchemaAdditions } from '../../src/tx/schema.js';
import { GovernanceChangeStore } from '../../src/tx/governance-change-store.js';
import { resolveRequiredApprovers, computeChangeProposalHash } from '../../src/services/governance-change.js';

async function makeStore(): Promise<{ ds: SqliteDataSource; store: GovernanceChangeStore }> {
  const ds = new SqliteDataSource(':memory:');
  await ds.exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(ds);
  return { ds, store: new GovernanceChangeStore(ds) };
}

// ── scope resolution ──────────────────────────────────────────────────────────

test('resolveRequiredApprovers: admins (default) requires every admin', () => {
  const r = resolveRequiredApprovers({ scope: 'admins' }, { adminUuids: ['a', 'b'], memberUuids: ['a', 'b', 'c'] });
  assert.equal(r.requiredCount, 2);
  assert.deepEqual(r.eligibleUuids, ['a', 'b']);
});

test('resolveRequiredApprovers: all_members requires every active member', () => {
  const r = resolveRequiredApprovers({ scope: 'all_members' }, { adminUuids: ['a'], memberUuids: ['a', 'b', 'c'] });
  assert.equal(r.requiredCount, 3);
  assert.deepEqual(r.eligibleUuids, ['a', 'b', 'c']);
});

test('resolveRequiredApprovers: members = minApprovals (clamped to the roster)', () => {
  const ctx = { adminUuids: [], memberUuids: ['a', 'b', 'c'] };
  assert.equal(resolveRequiredApprovers({ scope: 'members', minApprovals: 2 }, ctx).requiredCount, 2);
  assert.equal(resolveRequiredApprovers({ scope: 'members', minApprovals: 9 }, ctx).requiredCount, 3);
  assert.equal(resolveRequiredApprovers({ scope: 'members' }, ctx).requiredCount, 1); // default 1
});

// ── proposal hash ─────────────────────────────────────────────────────────────

test('computeChangeProposalHash: deterministic, order-insensitive on the eligible set, change-sensitive', () => {
  const base = {
    proposalId: 'p', communityUuid: 'c', proposerUuid: 'u',
    change: { adminThresholdM: 2 }, scope: 'admins' as const,
    requiredApproverUuids: ['a', 'b'], expiresAt: 123,
  };
  const h1 = computeChangeProposalHash(base);
  assert.equal(computeChangeProposalHash({ ...base, requiredApproverUuids: ['b', 'a'] }), h1);
  assert.notEqual(computeChangeProposalHash({ ...base, change: { adminThresholdM: 3 } }), h1);
  assert.notEqual(computeChangeProposalHash({ ...base, scope: 'all_members' }), h1);
});

// ── durable store ─────────────────────────────────────────────────────────────

test('GovernanceChangeStore: create → approve → count → crystallize', async () => {
  const { store } = await makeStore();

  await store.createProposal({
    proposalId: 'p1', communityUuid: 'c1', communityDid: 'did:x', proposerUuid: 'alice',
    change: { adminThresholdM: 2 }, scope: 'admins', requiredApproverCount: 2,
    requiredApproverUuids: ['alice', 'bob'], proposalHash: 'H', expiresAt: Date.now() + 10_000,
  });

  assert.equal((await store.getProposal('p1'))?.status, 'pending');
  assert.equal((await store.listPendingForApprover('bob')).length, 1, 'bob is eligible');
  assert.equal((await store.listPendingForApprover('carol')).length, 0, 'carol is not');

  assert.equal(await store.recordApproval('p1', 'alice', 'sigA'), true);
  assert.equal(await store.recordApproval('p1', 'alice', 'sigA'), false, 'duplicate suppressed by UNIQUE');
  assert.equal(await store.countApprovals('p1'), 1);

  await store.updateStatus('p1', 'crystallized');
  assert.equal((await store.getProposal('p1'))?.status, 'crystallized');
  assert.equal((await store.listPending()).length, 0, 'crystallized proposals are no longer pending');
});

test('GovernanceChangeStore: two different approvers each count once', async () => {
  const { store } = await makeStore();
  await store.createProposal({
    proposalId: 'p2', communityUuid: 'c1', communityDid: 'did:x', proposerUuid: 'alice',
    change: {}, scope: 'admins', requiredApproverCount: 2,
    requiredApproverUuids: ['alice', 'bob'], proposalHash: 'H2', expiresAt: Date.now() + 10_000,
  });
  await store.recordApproval('p2', 'alice', 's1');
  await store.recordApproval('p2', 'bob', 's2');
  assert.equal(await store.countApprovals('p2'), 2);
});
