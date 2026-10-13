/**
 * Event bus tests — the subscription model that replaces broadcast-SSE + timer polling.
 *
 * These are pure unit tests: no agent, no libp2p, no database. The bus is the piece every later domain
 * depends on, so its guarantees are pinned before anything is built on top of it.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/trust_app_api/events.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventBus } from '../../src/client/events.js';
import { STACK_EVENTS, matchesFilter } from '../../src/events/catalog.js';

const msg = (peerDid: string, bytes = 1) => ({ peerDid, confidential: false, bytes, at: Date.now() });

test('emit assigns a strictly increasing sequence number', () => {
  const bus = new EventBus();
  assert.equal(bus.latestSeq, 0);
  assert.equal(bus.emit('message.sent', msg('did:a')), 1);
  assert.equal(bus.emit('message.sent', msg('did:b')), 2);
  assert.equal(bus.latestSeq, 2);
});

test('emit rejects a name that is not in the closed catalogue', () => {
  const bus = new EventBus();
  assert.throws(
    () => (bus as unknown as { emit(e: string, p: unknown): number }).emit('message.exploded', {}),
    /unknown stack event/,
  );
});

test('delivery is per-event: subscribers only receive their own event', () => {
  const bus = new EventBus();
  const sent: string[] = [];
  const received: string[] = [];
  bus.on('message.sent', (p) => sent.push(p.peerDid));
  bus.on('message.received', (p) => received.push(p.peerDid));

  bus.emit('message.sent', msg('did:a'));
  bus.emit('message.received', msg('did:b'));

  assert.deepEqual(sent, ['did:a']);
  assert.deepEqual(received, ['did:b']);
});

test('filter delivers only matching payloads (no all-to-all fan-out)', () => {
  const bus = new EventBus();
  const seen: string[] = [];
  bus.on('message.sent', (p) => seen.push(p.peerDid), { filter: { peerDid: 'did:a' } });

  bus.emit('message.sent', msg('did:a'));
  bus.emit('message.sent', msg('did:b'));
  bus.emit('message.sent', msg('did:a'));

  assert.deepEqual(seen, ['did:a', 'did:a']);
});

test('unsubscribe stops delivery; unsubscribe() is idempotent', () => {
  const bus = new EventBus();
  let n = 0;
  const sub = bus.on('message.sent', () => n++);

  bus.emit('message.sent', msg('did:a'));
  sub.unsubscribe();
  sub.unsubscribe(); // idempotent
  bus.emit('message.sent', msg('did:a'));

  assert.equal(n, 1);
  assert.equal(bus.listenerCount('message.sent'), 0);
});

test('once delivers exactly one event', () => {
  const bus = new EventBus();
  let n = 0;
  bus.once('message.sent', () => n++);
  bus.emit('message.sent', msg('did:a'));
  bus.emit('message.sent', msg('did:a'));
  assert.equal(n, 1);
  assert.equal(bus.listenerCount(), 0);
});

test('since replays missed events before going live, in order', () => {
  const bus = new EventBus();
  bus.emit('message.sent', msg('did:a'));   // seq 1
  bus.emit('message.sent', msg('did:b'));   // seq 2
  const cursor = bus.latestSeq;             // = 2

  bus.emit('message.sent', msg('did:c'));   // seq 3 — missed by the subscriber

  const seen: string[] = [];
  bus.on('message.sent', (p) => seen.push(p.peerDid), { since: cursor });
  bus.emit('message.sent', msg('did:d'));   // seq 4 — live

  assert.deepEqual(seen, ['did:c', 'did:d'], 'replay first, then live');
});

test('since + filter replays only matching events', () => {
  const bus = new EventBus();
  bus.emit('message.sent', msg('did:a'));
  bus.emit('message.sent', msg('did:b'));

  const seen: string[] = [];
  bus.on('message.sent', (p) => seen.push(p.peerDid), { since: 0, filter: { peerDid: 'did:b' } });

  assert.deepEqual(seen, ['did:b']);
});

test('replay() reads retained events without subscribing', () => {
  const bus = new EventBus();
  bus.emit('connection.open', { peerId: 'p1', direction: 'inbound', method: 'tcp', at: 1 });
  bus.emit('connection.open', { peerId: 'p2', direction: 'inbound', method: 'tcp', at: 2 });

  const { events, truncated } = bus.replay('connection.open', { since: 0 });
  assert.equal(events.length, 2);
  assert.deepEqual(events.map((e) => e.seq), [1, 2]);
  assert.equal(truncated, false);
  assert.equal(bus.listenerCount(), 0, 'replay must not subscribe');
});

test('replay() reports truncation when the cursor predates the retained window', () => {
  const bus = new EventBus({ bufferLimit: 2 });
  for (let i = 0; i < 5; i++) bus.emit('message.sent', msg('did:a'));

  assert.equal(bus.latestSeq, 5);
  assert.equal(bus.oldestSeq, 4, 'only the last two are retained');

  const fresh = bus.replay('message.sent', { since: 3 });
  assert.equal(fresh.truncated, false, 'cursor is inside the window');

  const stale = bus.replay('message.sent', { since: 0 });
  assert.equal(stale.truncated, true, 'cursor predates the window — history is incomplete');
  assert.equal(stale.events.length, 2);
});

test('replay() honours limit', () => {
  const bus = new EventBus();
  for (let i = 0; i < 4; i++) bus.emit('message.sent', msg('did:a'));
  const { events } = bus.replay('message.sent', { since: 0, limit: 2 });
  assert.equal(events.length, 2);
});

test('a throwing handler cannot break the emitter or starve other subscribers', () => {
  const errors: Array<{ event: string; id: number }> = [];
  const bus = new EventBus({
    onHandlerError: (_err, event, id) => errors.push({ event, id }),
  });

  const delivered: string[] = [];
  bus.on('message.sent', () => {
    throw new Error('boom');
  });
  bus.on('message.sent', (p) => delivered.push(p.peerDid));

  assert.doesNotThrow(() => bus.emit('message.sent', msg('did:a')));
  assert.deepEqual(delivered, ['did:a'], 'the healthy subscriber still received it');
  assert.equal(errors.length, 1);
  assert.equal(errors[0].event, 'message.sent');
});

test('unsubscribing a later subscriber mid-delivery takes effect without corrupting the snapshot', () => {
  const bus = new EventBus();
  const seen: string[] = [];
  let other: { unsubscribe(): void };
  bus.on('message.sent', () => {
    seen.push('first');
    other.unsubscribe(); // unsubscribe a subscriber that has not been visited yet
  });
  other = bus.on('message.sent', () => seen.push('second'));

  bus.emit('message.sent', msg('did:a'));

  assert.deepEqual(seen, ['first'], 'the mid-flight unsubscribe took effect');
  assert.equal(bus.listenerCount('message.sent'), 1);
});

test('clear() drops subscriptions and retained events', () => {
  const bus = new EventBus();
  bus.on('message.sent', () => {});
  bus.emit('message.sent', msg('did:a'));

  bus.clear();

  assert.equal(bus.listenerCount(), 0);
  assert.deepEqual(bus.replay('message.sent', { since: 0 }).events, []);
});

test('the catalogue is closed, unique, and every name is namespaced', () => {
  assert.equal(new Set(STACK_EVENTS).size, STACK_EVENTS.length, 'no duplicate event names');
  for (const e of STACK_EVENTS) {
    assert.match(e, /^[a-z]+(\.[a-z]+)*$/, `event name not namespaced: ${e}`);
  }
});

test('matchesFilter requires every key to match exactly', () => {
  const payload = { peerDid: 'did:a', bytes: 3 };
  assert.equal(matchesFilter(payload, undefined), true);
  assert.equal(matchesFilter(payload, {}), true);
  assert.equal(matchesFilter(payload, { peerDid: 'did:a' }), true);
  assert.equal(matchesFilter(payload, { peerDid: 'did:a', bytes: 3 }), true);
  assert.equal(matchesFilter(payload, { peerDid: 'did:b' }), false);
  assert.equal(matchesFilter(payload, { peerDid: 'did:a', bytes: 4 }), false);
  assert.equal(matchesFilter(null, { peerDid: 'did:a' }), false);
});

