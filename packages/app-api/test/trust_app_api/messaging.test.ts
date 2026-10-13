/**
 * `messaging` domain tests — the durable transcript.
 *
 * The headline assertion is the one the old design could not make: **a transcript survives an agent switch**.
 * The in-memory `ChatLog` documented its own limitation ("an agent logout (or an agent switch) drops every
 * session"), so this is the behaviour change P3 exists to deliver.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/trust_app_api/messaging.test.ts
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createAgentStack, createAgentMessagesStore, StackError, type TrustStack } from '../../src/index.js';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';

const HOMES: string[] = [];
const STACKS: TrustStack[] = [];

const PASS = 'correct horse battery';

after(async () => {
  for (const s of STACKS) {
    try { await s.stop(); } catch { /* not started */ }
  }
  for (const h of HOMES) rmSync(h, { recursive: true, force: true });
});

async function makeStack(agentName = 'chatter', reuseHome?: string): Promise<{ stack: TrustStack; home: string }> {
  const home = reuseHome ?? mkdtempSync(join(tmpdir(), 'api-messaging-'));
  if (!reuseHome) HOMES.push(home);
  const stack = await createAgentStack({ home, agent: { name: agentName, passphrase: PASS, port: 24014 } });
  assert.equal(stack.host.home, home, 'isolated home — must never touch the real P2PTS_HOME');
  STACKS.push(stack);
  return { stack, home };
}

/**
 * Seed transcript entries straight into the durable store.
 *
 * Inbound entries normally arrive through the runtime's `onMessage` callback, which needs a live peer; the
 * store is the same object the domain reads, so seeding it exercises the real read path without a network.
 */
async function seed(stack: TrustStack, peerDid: string, entries: Array<[string, 'me' | 'peer']>) {
  const name = (await stack.identity.current()).name;
  assert.ok(name, 'seed() needs an active agent');
  const ds = stack.host.storageFor(name) as SqliteDataSource;
  const store = createAgentMessagesStore(ds);
  for (const [text, side] of entries) {
    await store.append(peerDid, { agentName: side === 'me' ? name : 'Peer', text, side });
  }
  await ds.close();
}

test('the messaging domain is present on the stack', async () => {
  const { stack } = await makeStack();
  assert.equal(typeof stack.messaging.send, 'function');
  assert.equal(typeof stack.messaging.transcript, 'function');
  assert.equal(typeof stack.messaging.unread, 'function');
  assert.equal(typeof stack.messaging.clear, 'function');
});

test('send() refuses a peer with no relationship, with a reason rather than a timeout', async () => {
  const { stack } = await makeStack();
  await assert.rejects(
    () => stack.messaging.send('did:scid:vh:1:znobody', 'hello'),
    (err: unknown) => err instanceof StackError && (err as StackError).code === 'not_ready',
  );
});

test('transcript() on an unknown peer is empty, not an error', async () => {
  const { stack } = await makeStack();
  const t = await stack.messaging.transcript('did:scid:vh:1:znobody');
  assert.deepEqual(t.entries, []);
  assert.equal(t.cursor, 0);
  assert.equal(t.localName, 'chatter');
  assert.equal(t.peerName, null, 'an unknown peer has no resolvable name');
});

test('unread() is zero on a fresh agent', async () => {
  const { stack } = await makeStack();
  assert.deepEqual(await stack.messaging.unread(), { unread: 0, senders: 0, latestReceivedAt: 0 });
});

test('clear() on an unknown peer reports zero cleared', async () => {
  const { stack } = await makeStack();
  const result = await stack.messaging.clear('did:scid:vh:1:znobody');
  assert.deepEqual(result, { ok: true, peerVid: 'did:scid:vh:1:znobody', cleared: 0 });
});

test('every messaging call fails closed once the agent is deactivated', async () => {
  const { stack } = await makeStack('leaver');
  await stack.identity.deactivate();

  await assert.rejects(() => stack.messaging.transcript('did:x'), /No active VTA/);
  await assert.rejects(() => stack.messaging.unread(), /No active VTA/);
  await assert.rejects(() => stack.messaging.clear('did:x'), /No active VTA/);
  await assert.rejects(() => stack.messaging.send('did:x', 'hi'), /No active VTA/);
});

test('transcript() reads the durable store, in order, with a monotonic cursor', async () => {
  const { stack } = await makeStack();
  const peer = 'did:scid:vh:1:zpeer';
  await seed(stack, peer, [['first', 'me'], ['second', 'peer'], ['third', 'me']]);

  const t = await stack.messaging.transcript(peer);
  assert.deepEqual(t.entries.map((e) => e.text), ['first', 'second', 'third']);
  assert.deepEqual(t.entries.map((e) => e.side), ['me', 'peer', 'me']);
  assert.ok(t.cursor > 0);

  // Times must be strictly increasing — a UI derives a stable DOM id from them.
  const times = t.entries.map((e) => e.time);
  for (let i = 1; i < times.length; i++) assert.ok(times[i] > times[i - 1], 'times are strictly increasing');
});

test('unread() counts inbound entries only, with distinct senders', async () => {
  const { stack } = await makeStack();
  await seed(stack, 'did:scid:vh:1:za', [['a1', 'peer'], ['a2', 'me'], ['a3', 'peer']]);
  await seed(stack, 'did:scid:vh:1:zb', [['b1', 'peer']]);

  const all = await stack.messaging.unread();
  assert.equal(all.unread, 3, 'only the three inbound entries');
  assert.equal(all.senders, 2, 'two distinct peers');
  assert.ok(all.latestReceivedAt > 0);

  const t = await stack.messaging.transcript('did:scid:vh:1:za');
  // Cursor at the LAST inbound entry of 'a' (a3): only 'b' remains after it.
  const sinceA3 = await stack.messaging.unread({ since: t.entries[2].time });
  assert.equal(sinceA3.unread, 1, 'the cursor excludes earlier inbound entries');

  const sinceA1 = await stack.messaging.unread({ since: t.entries[0].time });
  assert.equal(sinceA1.unread, 2, 'later inbound entries from both peers are counted');
});

test('clear() drops ONE peer and reports the count, leaving others intact', async () => {
  const { stack } = await makeStack();
  await seed(stack, 'did:scid:vh:1:za', [['a1', 'me'], ['a2', 'peer']]);
  await seed(stack, 'did:scid:vh:1:zb', [['b1', 'me']]);

  const cleared = await stack.messaging.clear('did:scid:vh:1:za');
  assert.equal(cleared.cleared, 2);
  assert.deepEqual((await stack.messaging.transcript('did:scid:vh:1:za')).entries, []);
  assert.deepEqual(
    (await stack.messaging.transcript('did:scid:vh:1:zb')).entries.map((e) => e.text),
    ['b1'],
    'the other peer is untouched',
  );
});

test('a transcript SURVIVES an agent deactivate + reactivate (the P3 exit criterion)', async () => {
  const { stack } = await makeStack('survivor');
  const peer = 'did:scid:vh:1:zsurvivor-peer';
  await seed(stack, peer, [['before the switch', 'me'], ['and a reply', 'peer']]);

  const before = await stack.messaging.transcript(peer);
  assert.equal(before.entries.length, 2);

  // Deactivate (drops the agent, closes the store's connection) then reactivate the same identity.
  await stack.identity.deactivate();
  await stack.identity.activate({ name: 'survivor', passphrase: PASS });

  const after = await stack.messaging.transcript(peer);
  assert.deepEqual(
    after.entries.map((e) => e.text),
    ['before the switch', 'and a reply'],
    'the transcript outlived the agent — the in-memory ChatLog could not do this',
  );
});

test('a transcript survives a full process restart (a new stack over the same home)', async () => {
  const home = mkdtempSync(join(tmpdir(), 'api-messaging-restart-'));
  HOMES.push(home);
  const peer = 'did:scid:vh:1:zpersist';

  const first = await makeStack('persist', home);
  await seed(first.stack, peer, [['durable', 'me']]);
  await first.stack.stop();

  const second = await makeStack('persist', home);
  const after = await second.stack.messaging.transcript(peer);
  assert.deepEqual(after.entries.map((e) => e.text), ['durable']);
});
