// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for transaction-layer ISOLATION (G5a): per-agent tx database + outbox
 * ownership.
 *
 * Several agents launched from the same working directory used to share one
 * `data/tx/tx-coordinator.db` — one transaction log, one `tx_participant_state`
 * and one `tx_outbox`. Two concrete faults followed:
 *
 *  1. `DurableOutbox.drain()` selected EVERY undelivered row, so on reconnect an
 *     agent tried to deliver entries belonging to a DIFFERENT agent through its
 *     own transport;
 *  2. the reconnect promotion `UPDATE tx_outbox SET state='delivered' WHERE
 *     state='sent' AND destination LIKE 'server:%'` promoted every agent's rows,
 *     so an entry that was never sent was marked delivered and never retried.
 *
 * Both are fixed by (a) the per-agent database path and (b) an `owner` column,
 * scoped with `COALESCE(owner,'') = COALESCE(?,'')` (NULL matches NULL, so
 * pre-existing unowned rows keep behaving as before).
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tx/outbox-owner.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { TX_SCHEMA_SQL, applyTxSchemaAdditions } from '@p2p-trust-stack/core/tx/schema.js';
import {
  ConnectionWatch,
  DurableOutbox,
  markServerEntriesDelivered,
} from '@p2p-trust-stack/core/tx/index.js';
import { agentTxDbPath } from '../../src/runtime/tx/bootstrap.js';

const PAYLOAD = { protocol: 'exchange:identity', payload: [{ did: 'did:x' }] };

async function makeTxDb(): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(':memory:');
  await ds.exec(TX_SCHEMA_SQL);
  // The `owner` column is additive: tx_outbox already exists in every deployed
  // database, and CREATE TABLE IF NOT EXISTS never alters one.
  await applyTxSchemaAdditions(ds);
  return ds;
}

async function stateOf(ds: SqliteDataSource, destination: string, owner: string | null) {
  const rows = await ds.all<{ entry_id: string; state: string }>(
    `SELECT entry_id, state FROM tx_outbox
      WHERE destination = ? AND COALESCE(owner, '') = COALESCE(?, '')`,
    destination, owner,
  );
  return rows;
}

test('applyTxSchemaAdditions: adds tx_outbox.owner idempotently', async () => {
  const ds = await makeTxDb();
  const cols = await ds.all<{ name: string }>('PRAGMA table_info(tx_outbox)');
  assert.ok(cols.some((c) => c.name === 'owner'), 'owner column present after the addition');

  const again = await applyTxSchemaAdditions(ds);
  assert.deepEqual(again, [], 'a second application is a no-op');
  await ds.close();
});

test("DurableOutbox: drain() delivers ONLY this owner's entries", async () => {
  const ds = await makeTxDb();
  const watch = new ConnectionWatch();
  const sentByAlice: string[] = [];
  const sentByBob: string[] = [];

  const alice = new DurableOutbox(
    ds, async (dest) => { sentByAlice.push(dest); return true; }, watch, { owner: 'alice' },
  );
  const bob = new DurableOutbox(
    ds, async (dest) => { sentByBob.push(dest); return true; }, watch, { owner: 'bob' },
  );

  // Offline: both enqueue, nothing is sent, both rows stay 'pending'.
  watch.set('down');
  await alice.enqueue('server:us-1', PAYLOAD);
  await bob.enqueue('server:us-1', PAYLOAD);
  assert.equal(sentByAlice.length, 0);
  assert.equal(sentByBob.length, 0);

  // Reconnect: alice drains. Bob's entry must be left alone.
  watch.set('up');
  await alice.drain();

  assert.deepEqual(sentByAlice, ['server:us-1'], 'alice delivers her own entry');
  assert.deepEqual(sentByBob, [], "alice must NOT deliver bob's entry");
  assert.equal((await stateOf(ds, 'server:us-1', 'bob'))[0].state, 'pending', "bob's entry is untouched");

  // Bob drains his own, and only his.
  await bob.drain();
  assert.deepEqual(sentByBob, ['server:us-1']);

  await ds.close();
});

test("markServerEntriesDelivered: promotes only the given owner's server rows", async () => {
  const ds = await makeTxDb();
  const watch = new ConnectionWatch();
  watch.set('up');

  const alice = new DurableOutbox(ds, async () => true, watch, { owner: 'alice' });
  const bob = new DurableOutbox(ds, async () => true, watch, { owner: 'bob' });

  // Both pushes succeeded against the server → both rows are 'sent', not yet
  // promoted (the promotion happens on the reconnect path).
  await alice.enqueue('server:us-1', PAYLOAD);
  await bob.enqueue('server:us-1', PAYLOAD);
  assert.equal((await stateOf(ds, 'server:us-1', 'alice'))[0].state, 'sent');
  assert.equal((await stateOf(ds, 'server:us-1', 'bob'))[0].state, 'sent');

  await markServerEntriesDelivered(ds, 'alice');

  assert.equal((await stateOf(ds, 'server:us-1', 'alice'))[0].state, 'delivered', "alice's row is promoted");
  assert.equal(
    (await stateOf(ds, 'server:us-1', 'bob'))[0].state, 'sent',
    "bob's row must NOT be marked delivered by alice's reconnect",
  );

  await ds.close();
});

test('agentTxDbPath: one database per agent, inside the agent VTA directory', () => {
  const base = '/tmp/p2pts-home';
  // The tx DB now lives INSIDE the agent's own VTA directory
  // (P2PTS_HOME/vta/<agentKey>/), not in the application source tree.
  assert.equal(agentTxDbPath('alice', base), join(base, 'vta', 'alice', 'tx-coordinator.db'));
  assert.notEqual(agentTxDbPath('alice', base), agentTxDbPath('bob', base), 'agents must not share a database');

  // AGENT_NAME is operator-supplied and becomes a path segment, so the result
  // must never contain a traversal or current-dir segment.
  const escaped = agentTxDbPath('../../etc', base);
  const segments = escaped.split('/');
  assert.ok(!segments.includes('..'), 'no traversal segment');
  assert.ok(!escaped.includes('/etc/'), 'the escape attempt does not land in /etc');
  assert.ok(!agentTxDbPath('a b', base).includes(' '), 'no whitespace in the path segment');
  assert.equal(agentTxDbPath('', base), join(base, 'vta', 'default', 'tx-coordinator.db'), 'empty name falls back');
  assert.equal(agentTxDbPath('.hidden', base), join(base, 'vta', '_hidden', 'tx-coordinator.db'), 'no leading dot');
});
