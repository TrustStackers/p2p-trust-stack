// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * H7 / decision D-4a — inbound 2PC dedup keyed on `(txId, messageId)`.
 *
 * `DurableInbox` existed, was exported, and was never constructed: a replayed
 * inbound 2PC message was re-executed instead of being deduped, and the operations
 * it carries (mint VRC, store_remote_vrc, exchange:identity) are not idempotent in
 * general — so a replay could double-apply.
 *
 * The reason it could not simply be switched on is the reason these tests lead with
 * it: one `txId` legitimately carries SEVERAL distinct messages. Keying on `txId`
 * alone would classify the `tx_commit` as a replay of the `tx_prepare` and silently
 * strand the reservation, which is worse than the bug it fixes. The key is therefore
 * `(txId, messageId)`, and the test that matters most is the one asserting a commit
 * is NOT swallowed as a replay of a prepare under the same txId.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tx/inbox-dedup.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { TX_SCHEMA_SQL } from '../../src/tx/schema.js';
import { DurableInbox, withInboundDedup, inboxKeyFor } from '../../src/tx/index.js';
import type { TxWireMessage } from '../../src/tx/index.js';

async function makeTxDb(): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(':memory:');
  await ds.exec(TX_SCHEMA_SQL);
  return ds;
}

/** A handler that counts invocations and always votes yes. */
function countingHandler() {
  const seen: string[] = [];
  const handler = async (msg: TxWireMessage): Promise<TxWireMessage | null> => {
    seen.push(`${msg.kind}:${(msg as { messageId?: string }).messageId ?? 'none'}`);
    if (msg.kind === 'tx_prepare') {
      return { kind: 'tx_prepare_result', txId: msg.txId, vote: 'yes' };
    }
    return { kind: 'tx_commit_result', txId: msg.txId, ok: true };
  };
  return { handler, seen };
}

const PREPARE: TxWireMessage = {
  kind: 'tx_prepare',
  txId: 'tx-1',
  operations: [{ participantId: 'p1', op: 'name_register', params: {} }],
  messageId: 'msg-prepare',
} as TxWireMessage;

test('DurableInbox.handleOnce: returns the caller\'s own result, and never re-runs on a replay', async () => {
  const ds = await makeTxDb();
  const inbox = new DurableInbox(ds); // no construction-time handler: handleOnce supplies it

  let runs = 0;
  const first = await inbox.handleOnce('probe-key', async () => {
    runs++;
    return { kind: 'tx_commit_result', txId: 'tx-9', ok: true } as TxWireMessage;
  });
  assert.equal(first.duplicate, false);
  assert.equal(first.result?.kind, 'tx_commit_result', 'the closure result is handed back');
  assert.equal(runs, 1);

  const replay = await inbox.handleOnce('probe-key', async () => {
    runs++;
    return null;
  });
  assert.equal(replay.duplicate, true);
  assert.equal(replay.result, null);
  assert.equal(runs, 1, 'the closure is not invoked for a duplicate');

  await ds.close();
});

test('inboxKeyFor: (txId, messageId) when present, null when absent', () => {
  assert.equal(
    inboxKeyFor({ txId: 'tx-1', messageId: 'm1' }),
    'tx:tx-1:m1',
    'the key pairs the transaction with the individual message',
  );
  assert.equal(inboxKeyFor({ txId: 'tx-1' }), null, 'no messageId means no dedup key');
  // Distinct messages of one transaction MUST produce distinct keys — the whole point.
  assert.notEqual(
    inboxKeyFor({ txId: 'tx-1', messageId: 'm1' }),
    inboxKeyFor({ txId: 'tx-1', messageId: 'm2' }),
  );
});

test('a replayed message is deduped: the handler runs once, the replay gets no response', async () => {
  const ds = await makeTxDb();
  const { handler, seen } = countingHandler();
  const inbound = withInboundDedup(handler, ds);

  const first = await inbound(PREPARE, 'corr-1');
  assert.equal(first?.kind, 'tx_prepare_result', 'the first delivery is handled normally');
  assert.deepEqual(seen, ['tx_prepare:msg-prepare']);

  // The byte-identical replay — what recover() or the outbox retry produces.
  const replay = await inbound(PREPARE, 'corr-1');
  assert.equal(replay, null, 'a duplicate yields NO response and is not re-applied');
  assert.deepEqual(seen, ['tx_prepare:msg-prepare'], 'the handler did NOT run a second time');

  await ds.close();
});

test('CRITICAL: a DIFFERENT message of the same txId is not swallowed as a replay', async () => {
  const ds = await makeTxDb();
  const { handler, seen } = countingHandler();
  const inbound = withInboundDedup(handler, ds);

  const prepared = await inbound(PREPARE, 'corr-1');
  assert.equal(prepared?.kind, 'tx_prepare_result');

  // Same txId, different messageId: the commit MUST go through. A txId-keyed inbox
  // would have suppressed this and stranded the reservation.
  const commit: TxWireMessage = { kind: 'tx_commit', txId: 'tx-1', messageId: 'msg-commit' };
  const committed = await inbound(commit, 'corr-2');

  assert.equal(committed?.kind, 'tx_commit_result', 'the commit is delivered, not deduped away');
  assert.deepEqual(seen, ['tx_prepare:msg-prepare', 'tx_commit:msg-commit']);

  // And the commit's own replay IS deduped.
  assert.equal(await inbound(commit, 'corr-2'), null);
  assert.equal(seen.length, 2, 'exactly two handler invocations: one prepare, one commit');

  await ds.close();
});

test('a message with no messageId passes through — no identity, no dedup', async () => {
  const ds = await makeTxDb();
  const { handler, seen } = countingHandler();
  const inbound = withInboundDedup(handler, ds);

  const legacy: TxWireMessage = { kind: 'tx_commit', txId: 'tx-2' };
  await inbound(legacy, 'corr-3');
  await inbound(legacy, 'corr-3');

  assert.deepEqual(seen, ['tx_commit:none', 'tx_commit:none'], 'a pre-H7 peer is never dropped');

  // Nothing was written to tx_inbox either — absence of identity is not a key.
  const rows = await ds.all<{ idempotency_key: string }>('SELECT idempotency_key FROM tx_inbox');
  assert.equal(rows.length, 0);

  await ds.close();
});

test('dedup is DURABLE: a fresh inbox over the same database still suppresses', async () => {
  const ds = await makeTxDb();
  const first = countingHandler();
  await withInboundDedup(first.handler, ds)(PREPARE, 'corr-1');
  assert.equal(first.seen.length, 1);

  // Simulate a restart: new objects, same storage. This is what the crash-recovery
  // and outbox-retry replays actually face.
  const second = countingHandler();
  const replayResponse = await withInboundDedup(second.handler, ds)(
    PREPARE,
    'corr-1',
  );

  assert.equal(replayResponse, null, 'the replay is still recognised after a restart');
  assert.equal(second.seen.length, 0, 'the restarted handler is not invoked either');

  await ds.close();
});
