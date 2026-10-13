/**
 * F-028 — a repeated idempotency key must not acknowledge a DIFFERENT document.
 *
 * The finding: *"a repeated idempotency key is absorbed and acknowledged as success"*,
 * with the prescribed direction *"return the original result on a repeated key; do not
 * acknowledge a different document as success."*
 *
 * The mechanism was `DurableInbox`: it returned the *existing receipt* for any repeat of
 * a key, without ever comparing what was being delivered. So a second, different
 * document under the same key was answered "already delivered" — a claim that was simply
 * untrue, and one the sender had no way to detect.
 *
 * The fix records a fingerprint (a digest of the document) with the key:
 *
 *   same key + same fingerprint  → duplicate (the original delivery stands)
 *   same key + DIFFERENT         → conflict  (handler not run, not acknowledged)
 *   missing fingerprint (either) → treated as the same, never a conflict
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tx/inbox-fingerprint.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { TX_SCHEMA_SQL } from '../../src/tx/schema.js';
import { DurableInbox, inboxFingerprintFor } from '../../src/tx/index.js';

async function makeTxDb(): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(':memory:');
  await ds.exec(TX_SCHEMA_SQL);
  return ds;
}

test('F-028: a repeat under the same key with a DIFFERENT document is a CONFLICT, not a success', async () => {
  const ds = await makeTxDb();
  let ran = 0;
  const inbox = new DurableInbox(ds);

  // First delivery of a document.
  const first = await inbox.handleOnce('key-1', async () => { ran++; return 'applied-A'; }, { fingerprint: 'doc-A' });
  assert.deepEqual(first, { duplicate: false, conflict: false, result: 'applied-A' });

  // The SAME document again: a genuine replay → duplicate, handler not re-run.
  const replay = await inbox.handleOnce('key-1', async () => { ran++; return 'applied-A'; }, { fingerprint: 'doc-A' });
  assert.deepEqual(replay, { duplicate: true, conflict: false, result: null });
  assert.equal(ran, 1);

  // A DIFFERENT document under the same key: the audit's finding. It must NOT be
  // acknowledged as success, and must not be applied.
  const conflict = await inbox.handleOnce('key-1', async () => { ran++; return 'applied-B'; }, { fingerprint: 'doc-B' });
  assert.equal(conflict.conflict, true, 'a different document under a delivered key is a conflict');
  assert.equal(conflict.duplicate, false, 'it is not a replay');
  assert.equal(conflict.result, null);
  assert.equal(ran, 1, 'the handler must NOT run for a conflicting document');

  // And the original record survives: the original document still dedups afterwards.
  const afterConflict = await inbox.handleOnce('key-1', async () => { ran++; return 'applied-A'; }, { fingerprint: 'doc-A' });
  assert.equal(afterConflict.duplicate, true, 'a conflict must not overwrite the original record');
  assert.equal(ran, 1);

  await ds.close();
});

test('F-028: legacy rows with no fingerprint are never treated as a conflict', async () => {
  const ds = await makeTxDb();
  const inbox = new DurableInbox(ds);

  // A row written by a pre-F-028 build (payload_digest NULL), then a fingerprinted
  // repeat. Declaring a conflict from absent information would reject legitimate
  // replays of everything delivered before the upgrade — so it must dedup.
  await inbox.handleOnce('legacy-key', async () => 'x');
  const replay = await inbox.handleOnce('legacy-key', async () => 'x', { fingerprint: 'doc-A' });
  assert.equal(replay.duplicate, true);
  assert.equal(replay.conflict, false);

  await ds.close();
});

test('F-028: the identity of a delivered document EXCLUDES the proof (a re-signed retry is the same document)', () => {
  const base = { kind: 'tx_prepare', txId: 'tx-1', messageId: 'm1', operations: [{ op: 'name_register', params: { name: 'alice' } }] };
  const same = { ...base };
  const changedParams = { ...base, operations: [{ op: 'name_register', params: { name: 'mallory' } }] };
  const reSigned = { ...base, proof: { actor: 'Dx', issuedAt: 99, expiresAt: 999, signature: 'zzz' } };

  assert.equal(inboxFingerprintFor(base), inboxFingerprintFor(same), 'identical content → identical fingerprint');
  assert.notEqual(inboxFingerprintFor(base), inboxFingerprintFor(changedParams), 'different operations → different document');
  assert.equal(
    inboxFingerprintFor(base), inboxFingerprintFor(reSigned),
    'a retry re-signed with a fresh proof is the SAME document, not a conflict',
  );
});
