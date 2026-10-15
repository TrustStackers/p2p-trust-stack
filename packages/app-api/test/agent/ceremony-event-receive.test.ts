// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `CeremonyEventReceiveParticipant` — the agent side of the server's ceremony-PROGRESS nudge.
 *
 * This is the signal that did not exist: a founding ceremony is driven server-side, and the community does not
 * exist until the ceremony CRYSTALLIZES, so `community.changed` cannot carry progress before that. A co-admin's
 * co-signature was therefore observable only by polling the server's ceremony log — which is what
 * `communities.html` did every 4 s.
 *
 * Two things are pinned here beyond the announcement itself:
 *
 *   1. **The participant must exist even though it persists nothing.** The coordinator votes `'no'` when NO
 *      participant claims an operation, so omitting this class would make the server's nudge delivery fail
 *      outright rather than be a harmless no-op.
 *   2. **A throwing observer must not abort the transaction.** `prepare()` votes 'no' on any throw, so an
 *      unguarded observer would turn an accepted nudge into a refusal. Same defect class as the credential and
 *      community signals.
 *
 * Run:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/agent/ceremony-event-receive.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { TX_SCHEMA_SQL, applyTxSchemaAdditions } from '@p2p-trust-stack/core/tx/schema.js';
import { CeremonyEventReceiveParticipant } from '../../src/runtime/tx/ceremony-event-receive-participant.js';
import type { PersistedCeremonyEvent } from '../../src/runtime/tx/ceremony-event-receive-participant.js';

async function makeParticipant(onPersisted?: (e: PersistedCeremonyEvent) => void) {
  const appDb = new SqliteDataSource(':memory:');
  const txDb = new SqliteDataSource(':memory:');
  await txDb.exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(txDb);
  return { txDb, participant: new CeremonyEventReceiveParticipant('peer:agent', appDb, txDb, onPersisted) };
}

const NUDGE = { threadId: 'cer-1', step: 'co-sign:1', communityUuid: null, at: 1 };

test('only exchange:ceremony-event is claimed — it must not swallow another participant\'s op', async () => {
  const { participant } = await makeParticipant();
  assert.equal(participant.handlesOperation({ op: 'exchange:ceremony-event' } as never), true);
  // `governance-events` is a neighbouring NAME and a different thing: a server↔server replication topic.
  assert.equal(participant.handlesOperation({ op: 'exchange:governance-events' } as never), false);
  assert.equal(participant.handlesOperation({ op: 'exchange:vtc-membership' } as never), false);
  assert.equal(participant.handlesOperation({ op: 'exchange:governance-proposal' } as never), false);
});

test('a ceremony nudge is ANNOUNCED, and persists nothing (it carries no content)', async () => {
  const announced: PersistedCeremonyEvent[] = [];
  const { txDb, participant } = await makeParticipant((e) => announced.push(e));

  const vote = await participant.prepare('tx-1', [
    { op: 'exchange:ceremony-event', params: { ...NUDGE } } as never,
  ]);

  assert.equal(vote, 'yes');
  assert.deepEqual(announced, [{ threadId: 'cer-1', step: 'co-sign:1', communityUuid: null }]);

  // No APPLICATION row: the nudge is a reference, and the agent re-reads its own log endpoint. The only thing
  // written is the participant's own 2PC state (the tx schema's other tables are untouched).
  const counts = await txDb.get<{ c: number }>(
    `SELECT (SELECT COUNT(*) FROM ceremony_proposals)
          + (SELECT COUNT(*) FROM ceremony_approvals)
          + (SELECT COUNT(*) FROM governance_change_proposals)
          + (SELECT COUNT(*) FROM vrc_ceremonies) AS c`,
  );
  assert.equal(counts?.c, 0, 'the ceremony nudge writes no application table');
});

test('a nudge that names no thread is REFUSED rather than voted yes on nothing', async () => {
  const announced: PersistedCeremonyEvent[] = [];
  const { participant } = await makeParticipant((e) => announced.push(e));

  const vote = await participant.prepare('tx-2', [
    { op: 'exchange:ceremony-event', params: { step: 'co-sign:1' } } as never,
  ]);

  assert.equal(vote, 'no');
  assert.deepEqual(announced, [], 'a refusal is not an arrival');
});

test('a THROWING observer cannot abort the nudge transaction', async () => {
  // `prepare()` votes 'no' on any throw, so an unguarded observer would turn an accepted nudge into a refusal —
  // the same defect the credential and community signals each had to fix.
  const { participant } = await makeParticipant(() => {
    throw new Error('observer exploded');
  });

  const vote = await participant.prepare('tx-3', [
    { op: 'exchange:ceremony-event', params: { ...NUDGE } } as never,
  ]);

  assert.equal(vote, 'yes', 'the vote must not be decided by a side effect');
});

test('an ignored op announces nothing', async () => {
  const announced: PersistedCeremonyEvent[] = [];
  const { participant } = await makeParticipant((e) => announced.push(e));

  const vote = await participant.prepare('tx-4', [{ op: 'exchange:something-else', params: {} } as never]);

  assert.equal(vote, 'yes', 'an unclaimed op is a no-op, not a failure');
  assert.deepEqual(announced, []);
});
