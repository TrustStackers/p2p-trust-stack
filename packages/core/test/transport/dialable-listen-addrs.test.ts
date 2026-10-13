/**
 * Advertising only DIALABLE addresses (2026-09-25 field churn).
 *
 * `node.getMultiaddrs()` returns listen AND observed addresses; for a NAT'd agent the
 * observed one is an ephemeral SOURCE port where nothing listens. Advertising it made peers
 * dial `connect ECONNREFUSED 192.168.1.246:60981` on a 5s loop instead of the agent's real
 * listen address.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/transport/dialable-listen-addrs.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  filterDialableListenAddrs,
  reconnectAdvertiseAddrs,
  AGENT_PORT_RANGE,
} from '../../src/transport/port-range.js';

test('keeps listen addresses; drops observed/ephemeral ports and out-of-range ones', () => {
  const addrs = [
    '/ip4/10.0.0.5/tcp/24000',                     // listen — keep
    '/ip4/10.0.0.5/tcp/24000/p2p/12D3KooWX',       // listen + peer id — keep
    '/ip6/::1/tcp/24004',                          // listen, top of range — keep
    '/ip4/192.168.1.246/tcp/60981',                // observed (field log) — drop
    '/ip4/192.168.1.246/tcp/60950/p2p/12D3KooWY',  // observed — drop
    '/ip4/10.0.0.5/tcp/24005',                     // just outside the range — drop
    '/ip4/10.0.0.5/udp/24000',                     // no tcp — drop
  ];

  assert.deepEqual(filterDialableListenAddrs(addrs), [
    '/ip4/10.0.0.5/tcp/24000',
    '/ip4/10.0.0.5/tcp/24000/p2p/12D3KooWX',
    '/ip6/::1/tcp/24004',
  ]);
});

test('the range is the one agents actually bind', () => {
  assert.deepEqual(AGENT_PORT_RANGE, [24000, 24001, 24002, 24003, 24004]);
});

test('an empty / observed-only list yields nothing to advertise (never a dead port)', () => {
  assert.deepEqual(filterDialableListenAddrs([]), []);
  assert.deepEqual(filterDialableListenAddrs(['/ip4/192.168.1.246/tcp/60981']), []);
});

// ---------------------------------------------------------------------------
// Reconnect re-advertisement (2026-10-10 field bug)
// ---------------------------------------------------------------------------

test('reconnect re-advertises the addresses ALREADY registered, not a re-derivation', () => {
  // The utility server: it listens on 4003, which is OUTSIDE the AGENT range — so
  // re-deriving the address set drops every one of its addresses, and the bootstrap
  // is left publishing only the NAT source port it observed. That is how a co-admin
  // agent ended up unable to reach the utility server at all.
  const registered = ['/ip4/192.168.1.27/tcp/4003/p2p/12D3KooWSrv'];
  const live = [
    '/ip4/0.0.0.0/tcp/4003',            // its listen address
    '/ip4/137.119.78.102/tcp/59478',    // observed NAT source port (nothing listens)
  ];

  assert.deepEqual(reconnectAdvertiseAddrs(registered, live), registered);

  // …and this is the re-derivation it replaces — NOTHING to advertise:
  assert.deepEqual(filterDialableListenAddrs(live), []);
});

test('reconnect falls back to the live derivation when nothing was registered yet', () => {
  const live = ['/ip4/10.0.0.5/tcp/24000', '/ip4/192.168.1.246/tcp/60981'];

  assert.deepEqual(reconnectAdvertiseAddrs(undefined, live), ['/ip4/10.0.0.5/tcp/24000']);
  assert.deepEqual(reconnectAdvertiseAddrs([], live), ['/ip4/10.0.0.5/tcp/24000']);
});

test('reconnect returns a copy, so a caller cannot mutate the remembered set', () => {
  const registered = ['/ip4/10.0.0.5/tcp/24000'];

  const out = reconnectAdvertiseAddrs(registered, []);
  out.push('/ip4/198.51.100.9/tcp/1');

  assert.deepEqual(registered, ['/ip4/10.0.0.5/tcp/24000']);
});
