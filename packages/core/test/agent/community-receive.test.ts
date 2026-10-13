/**
 * The **community arrival signal** — what lets the Communities page stop polling.
 *
 * `VtcReceiveParticipant` is the only thing that observes a community record arriving (a `vtc-membership`
 * push) or its governance changing (a `governance` push). Without the `onPersisted` hook, an observer could
 * only discover either by asking — which is what `communities.html` and `rules.html` did on a 4 s timer.
 *
 * The guard matters as much as the hook: `prepare()` votes 'no' on ANY throw, so an observer that threw would
 * abort a 2PC transaction whose community row has already been written — turning a successful delivery into a
 * refusal. That is the exact defect the credential signal shipped with and had to fix, so it is pinned here.
 *
 * Run:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/agent/community-receive.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { TX_SCHEMA_SQL, applyTxSchemaAdditions } from '../../src/tx/schema.js';
import { runMigrations } from '../../src/db/migrate.js';
import { VtcReceiveParticipant } from '../../src/tx/vtc-receive-participant.js';
import type { PersistedCommunityEvent } from '../../src/tx/vtc-receive-participant.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

/** A participant over the REAL application schema, so `upsertCommunity` has its tables. */
async function makeParticipant(onPersisted?: (c: PersistedCommunityEvent) => void) {
  const appDb = new SqliteDataSource(':memory:');
  runMigrations(appDb.getRawDb(), MIGRATIONS_DIR);
  const txDb = new SqliteDataSource(':memory:');
  await txDb.exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(txDb);
  return { appDb, txDb, participant: new VtcReceiveParticipant('peer:agent', appDb, txDb, onPersisted) };
}

/** Minimal well-formed membership push: one community, no governance row, no members. */
const MEMBERSHIP = {
  community: { uuid: 'c1', did: 'did:scid:vh:club', name: 'Club', role: 'vtc' },
  governance: null,
  memberships: [],
};

const GOVERNANCE = {
  communityUuid: 'c1',
  communityName: 'Club',
  adminThresholdM: 2,
  adminThresholdN: 3,
  parentCommunityUuid: null,
  allowedClaimTypes: [],
  vtcGovernanceDigest: null,
  updatedAt: 1,
};

test('a persisted community is ANNOUNCED, tagged as a membership push', async () => {
  const announced: PersistedCommunityEvent[] = [];
  const { participant } = await makeParticipant((c) => announced.push(c));

  const vote = await participant.prepare('tx-1', [
    { op: 'exchange:vtc-membership', params: { ...MEMBERSHIP } } as never,
  ]);

  assert.equal(vote, 'yes');
  assert.deepEqual(announced, [{ communityUuid: 'c1', kind: 'membership' }]);
});

test('a governance push is ANNOUNCED separately, because it means different things to a UI', async () => {
  // `membership` = the community list may have changed; `governance` = that community's RULES changed
  // (an approved change was applied). A page re-reads different endpoints for each.
  const announced: PersistedCommunityEvent[] = [];
  const { participant } = await makeParticipant((c) => announced.push(c));

  const vote = await participant.prepare('tx-2', [
    { op: 'exchange:governance', params: { ...GOVERNANCE } } as never,
  ]);

  assert.equal(vote, 'yes');
  assert.deepEqual(announced, [{ communityUuid: 'c1', kind: 'governance' }]);
});

test('a THROWING observer cannot abort the transaction that already wrote the community', async () => {
  const { appDb, participant } = await makeParticipant(() => {
    throw new Error('observer exploded');
  });

  const vote = await participant.prepare('tx-3', [
    { op: 'exchange:vtc-membership', params: { ...MEMBERSHIP } } as never,
  ]);

  assert.equal(vote, 'yes', 'the vote must not be decided by a side effect');
  const row = await appDb.get<{ uuid: string }>('SELECT uuid FROM identities WHERE uuid = ?', 'c1');
  assert.ok(row, 'the community is still written');
});

test('a REFUSED push announces nothing', async () => {
  const announced: PersistedCommunityEvent[] = [];
  const { participant } = await makeParticipant((c) => announced.push(c));

  // No params at all — the participant refuses before it can persist anything.
  const vote = await participant.prepare('tx-4', [
    { op: 'exchange:vtc-membership', params: undefined } as never,
  ]);

  assert.equal(vote, 'no');
  assert.deepEqual(announced, [], 'a refusal is not an arrival');
});

test('an ignored op announces nothing', async () => {
  const announced: PersistedCommunityEvent[] = [];
  const { participant } = await makeParticipant((c) => announced.push(c));

  const vote = await participant.prepare('tx-5', [
    { op: 'exchange:something-else', params: {} } as never,
  ]);

  assert.equal(vote, 'yes', 'an unclaimed op is a no-op, not a failure');
  assert.deepEqual(announced, []);
});
