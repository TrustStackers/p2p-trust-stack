/**
 * Tests for ChatLog — the per-peer, in-memory chat transcript.
 *
 * Covers:
 *   - append: records an entry keyed by the agent login name, time, and text
 *   - append: time defaults to now, and is bumped on collision (unique, monotonic)
 *   - list: returns a copy of that peer's session only
 *   - clear: drops ONE peer's session and leaves other peers untouched
 *   - clear: a subsequent append starts a fresh list of entries
 *   - clearAll: drops every session (agent logout / agent switch)
 *   - the per-session entry cap drops the OLDEST entries first
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/agent/chat-log.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ChatLog } from '../../src/runtime/chat-log.js';

const PEER_A = 'did:scid:vh:zPeerA';
const PEER_B = 'did:scid:vh:zPeerB';

// ---------------------------------------------------------------------------
// append
// ---------------------------------------------------------------------------

test('ChatLog.append: stores agentName + time + text, keyed per peer', () => {
  const log = new ChatLog();
  const entry = log.append(PEER_A, { agentName: 'alice', text: 'hello bob', side: 'me' });

  assert.equal(entry.agentName, 'alice');
  assert.equal(entry.text, 'hello bob');
  assert.equal(entry.side, 'me');
  assert.equal(typeof entry.time, 'number');
  assert.ok(entry.time > 0, 'time must be populated');

  assert.deepEqual(log.list(PEER_A), [entry]);
  assert.equal(log.size(PEER_A), 1);
  assert.equal(log.size(PEER_B), 0, 'other peers must be unaffected');
});

test('ChatLog.append: keeps received and sent entries in one per-peer list', () => {
  const log = new ChatLog();
  log.append(PEER_A, { agentName: 'alice', text: 'hi', side: 'me', time: 1000 });
  log.append(PEER_A, { agentName: 'bob', text: 'hi yourself', side: 'peer', time: 2000, confidential: true });

  const entries = log.list(PEER_A);
  assert.equal(entries.length, 2);
  assert.deepEqual(entries.map(e => e.side), ['me', 'peer']);
  assert.deepEqual(entries.map(e => e.agentName), ['alice', 'bob']);
  assert.equal(entries[1].confidential, true);
  assert.equal(entries[0].confidential, undefined, 'plain entries must not carry the flag');
});

test('ChatLog.append: time is unique and strictly increasing per session', () => {
  const log = new ChatLog();
  const a = log.append(PEER_A, { agentName: 'alice', text: 'one', side: 'me', time: 5000 });
  const b = log.append(PEER_A, { agentName: 'alice', text: 'two', side: 'me', time: 5000 });
  const c = log.append(PEER_A, { agentName: 'bob', text: 'three', side: 'peer', time: 4000 });

  assert.equal(a.time, 5000);
  assert.equal(b.time, 5001, 'colliding timestamp must be bumped so DOM ids stay unique');
  assert.equal(c.time, 5002, 'a stale/earlier timestamp must not move time backwards');
});

test('ChatLog.append: a second peer gets an independent time sequence', () => {
  const log = new ChatLog();
  log.append(PEER_A, { agentName: 'alice', text: 'a1', side: 'me', time: 10_000 });
  const b1 = log.append(PEER_B, { agentName: 'carol', text: 'b1', side: 'peer', time: 1000 });

  assert.equal(b1.time, 1000, 'PEER_A history must not affect PEER_B ordering');
  assert.equal(log.size(PEER_A), 1);
  assert.equal(log.size(PEER_B), 1);
});

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

test('ChatLog.list: returns a copy, so a caller cannot mutate stored history', () => {
  const log = new ChatLog();
  log.append(PEER_A, { agentName: 'alice', text: 'original', side: 'me' });

  const copy = log.list(PEER_A);
  copy[0].text = 'tampered';
  copy.push({ agentName: 'x', time: 1, text: 'injected', side: 'peer' });

  assert.equal(log.list(PEER_A).length, 1);
  assert.equal(log.list(PEER_A)[0].text, 'original');
});

test('ChatLog.list: unknown peer returns an empty list', () => {
  assert.deepEqual(new ChatLog().list(PEER_A), []);
});

// ---------------------------------------------------------------------------
// clear — scoped to ONE peer (the chat UI's "Clear History" button)
// ---------------------------------------------------------------------------

test('ChatLog.clear: clears only the requested peer and leaves others intact', () => {
  const log = new ChatLog();
  log.append(PEER_A, { agentName: 'alice', text: 'a1', side: 'me' });
  log.append(PEER_A, { agentName: 'bob', text: 'a2', side: 'peer' });
  log.append(PEER_B, { agentName: 'carol', text: 'b1', side: 'me' });

  const cleared = log.clear(PEER_A);

  assert.equal(cleared, 2, 'clear must report how many entries were discarded');
  assert.equal(log.size(PEER_A), 0);
  assert.deepEqual(log.list(PEER_A), []);
  assert.equal(log.size(PEER_B), 1, 'PEER_B history must be unaffected');
  assert.equal(log.list(PEER_B)[0].text, 'b1');
  assert.equal(log.sessionCount(), 1);
});

test('ChatLog.clear: new text after a clear creates a NEW list of entries', () => {
  const log = new ChatLog();
  log.append(PEER_A, { agentName: 'alice', text: 'before', side: 'me' });
  log.clear(PEER_A);

  const fresh = log.append(PEER_A, { agentName: 'alice', text: 'after', side: 'me' });
  assert.deepEqual(log.list(PEER_A), [fresh]);
  assert.equal(log.list(PEER_A)[0].text, 'after');
});

test('ChatLog.clear: clearing an unknown / already-cleared peer is a no-op', () => {
  const log = new ChatLog();
  assert.equal(log.clear(PEER_A), 0);
  log.append(PEER_A, { agentName: 'alice', text: 'x', side: 'me' });
  assert.equal(log.clear(PEER_A), 1);
  assert.equal(log.clear(PEER_A), 0, 'second clear must not report phantom entries');
});

// ---------------------------------------------------------------------------
// clearAll — agent logout / agent switch
// ---------------------------------------------------------------------------

test('ChatLog.clearAll: drops every session (logout loses all chat history)', () => {
  const log = new ChatLog();
  log.append(PEER_A, { agentName: 'alice', text: 'a1', side: 'me' });
  log.append(PEER_B, { agentName: 'carol', text: 'b1', side: 'peer' });

  log.clearAll();

  assert.equal(log.sessionCount(), 0);
  assert.deepEqual(log.list(PEER_A), []);
  assert.deepEqual(log.list(PEER_B), []);
});

// ---------------------------------------------------------------------------
// Bounded growth
// ---------------------------------------------------------------------------

test('ChatLog.append: caps a session and drops the OLDEST entries first', () => {
  const log = new ChatLog();
  const cap = ChatLog.MAX_ENTRIES_PER_SESSION;
  for (let i = 0; i < cap + 10; i++) {
    log.append(PEER_A, { agentName: 'alice', text: `msg-${i}`, side: 'me', time: i + 1 });
  }

  const entries = log.list(PEER_A);
  assert.equal(entries.length, cap);
  assert.equal(entries[0].text, 'msg-10', 'oldest entries are evicted');
  assert.equal(entries[cap - 1].text, `msg-${cap + 9}`, 'newest entry is retained');
});
