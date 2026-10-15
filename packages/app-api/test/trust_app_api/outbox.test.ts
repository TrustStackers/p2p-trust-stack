// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Durable event outbox tests — decision D2.
 *
 * The outbox (`agent_events`) exists so the event log can be inspected, replayed, and debugged **on its
 * own**, separately from the message/state tables. These tests pin the property that motivated it: history
 * survives the process, and is not limited by the bus's in-memory window.
 *
 * The observable difference between the two readers is the point:
 *   - `replay()`        — the in-memory window (bounded, can report `truncated`)
 *   - `replayDurable()` — the outbox (bounded only by the database)
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/trust_app_api/outbox.test.ts
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createAgentStack, type TrustStack } from '../../src/index.js';

const HOMES: string[] = [];
const STACKS: TrustStack[] = [];

after(async () => {
  for (const s of STACKS) {
    try { await s.stop(); } catch { /* not started */ }
  }
  for (const h of HOMES) rmSync(h, { recursive: true, force: true });
});

function newHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'api-outbox-'));
  HOMES.push(home);
  return home;
}

async function makeStack(home: string, opts: { eventBufferLimit?: number } = {}) {
  const stack = await createAgentStack({
    home,
    eventBufferLimit: opts.eventBufferLimit,
    agent: { name: 'outboxer', passphrase: 'correct horse battery' },
  });
  assert.equal(stack.host.home, home, 'isolated home — must never touch the real P2PTS_HOME');
  STACKS.push(stack);
  return stack;
}

test('every emitted event is appended to the outbox and readable back', async () => {
  const home = newHome();
  const stack = await makeStack(home);

  await stack.identity.create({ name: 'alpha', passphrase: 'correct horse battery' });
  await stack.identity.create({ name: 'beta', passphrase: 'correct horse battery' });

  const { events, truncated } = await stack.replayDurable({ since: 0, event: 'identity.created' });
  assert.equal(truncated, false, 'a durable log has no window to fall short of');
  assert.deepEqual(events.map((e) => (e.payload as { name: string }).name), ['alpha', 'beta']);
  assert.deepEqual(events.map((e) => e.seq), [1, 2], 'sequence numbers are preserved');
  assert.ok(events.every((e) => e.at > 0), 'timestamps are recorded');
});

test('outbox history survives a restart (a NEW stack over the same home)', async () => {
  const home = newHome();

  const first = await makeStack(home);
  await first.identity.create({ name: 'gamma', passphrase: 'correct horse battery' });
  await first.stop();

  // A completely fresh stack, same P2PTS_HOME — the in-memory window is gone, the outbox is not.
  const second = await makeStack(home);
  const { events } = await second.replayDurable({ since: 0, event: 'identity.created' });
  assert.deepEqual(
    events.map((e) => (e.payload as { name: string }).name),
    ['gamma'],
    'the event recorded before the restart is still there',
  );
});

test('the outbox exceeds the in-memory window, and replay() reports the window honestly', async () => {
  const home = newHome();
  // A window of ONE makes the distinction observable without creating many agents.
  const stack = await makeStack(home, { eventBufferLimit: 1 });

  await stack.identity.create({ name: 'd1', passphrase: 'correct horse battery' });
  await stack.identity.create({ name: 'd2', passphrase: 'correct horse battery' });
  await stack.identity.create({ name: 'd3', passphrase: 'correct horse battery' });

  const inMemory = stack.replay('identity.created', { since: 0 });
  assert.equal(inMemory.events.length, 1, 'the window holds only the newest event');
  assert.equal(inMemory.truncated, true, 'and it says so rather than silently returning a partial history');

  const durable = await stack.replayDurable({ since: 0, event: 'identity.created' });
  assert.equal(durable.events.length, 3, 'the outbox has the whole history');
  assert.equal(durable.truncated, false);
});

test('replayDurable honours a cursor, an event name, and a limit', async () => {
  const home = newHome();
  const stack = await makeStack(home);

  await stack.identity.create({ name: 'e1', passphrase: 'correct horse battery' });
  await stack.identity.create({ name: 'e2', passphrase: 'correct horse battery' });
  const cursor = await stack.cursor();
  await stack.identity.create({ name: 'e3', passphrase: 'correct horse battery' });

  const afterCursor = await stack.replayDurable({ since: cursor, event: 'identity.created' });
  assert.deepEqual(afterCursor.events.map((e) => (e.payload as { name: string }).name), ['e3']);

  const limited = await stack.replayDurable({ since: 0, event: 'identity.created', limit: 2 });
  assert.equal(limited.events.length, 2);

  const other = await stack.replayDurable({ since: 0, event: 'message.sent' });
  assert.deepEqual(other.events, [], 'an event name with no rows reads empty, not everything');
});

test('a subscription registered before reading history sees nothing twice', async () => {
  const home = newHome();
  const stack = await makeStack(home);

  await stack.identity.create({ name: 'f1', passphrase: 'correct horse battery' });
  const cursor = await stack.cursor();

  // The documented pattern: subscribe FIRST, then read history from a cursor — so a live event arriving in
  // between is not lost. Nothing else happens here, so the two must not double-count.
  const live: string[] = [];
  stack.on('identity.created', (p) => live.push(p.name));
  const history = await stack.replayDurable({ since: cursor, event: 'identity.created' });

  assert.deepEqual(history.events, [], 'the cursor is past the only event');
  assert.deepEqual(live, [], 'and nothing was re-delivered');
});

test('cursor() is durable: a fresh stack over the same home resumes past old events', async () => {
  const home = newHome();

  const first = await makeStack(home);
  await first.identity.create({ name: 'g1', passphrase: 'correct horse battery' });
  const cursor = await first.cursor();
  await first.stop();

  // A new process would start its in-memory counter at 0 — the cursor must still be meaningful.
  const second = await makeStack(home);
  assert.ok(cursor >= 1, 'the cursor reflects the outbox, not the fresh in-memory counter');
  const { events } = await second.replayDurable({ since: cursor, event: 'identity.created' });
  assert.deepEqual(events, [], 'nothing is replayed past a durable cursor');

  await second.identity.create({ name: 'g2', passphrase: 'correct horse battery' });
  const { events: after } = await second.replayDurable({ since: cursor, event: 'identity.created' });
  assert.deepEqual(after.map((e) => (e.payload as { name: string }).name), ['g2']);
});
