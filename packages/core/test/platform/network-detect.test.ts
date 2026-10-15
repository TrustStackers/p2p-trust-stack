// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Advertised-address hardening (2026-10-10 field bug).
 *
 * The utility server's setup wizard DEFAULTS `advertisedHost` to `127.0.0.1`. A
 * loopback advertised address is not a location — a peer that dials it reaches its
 * OWN machine — so it must never become a node's published dialable address. That
 * is how a co-admin agent ended up unable to reach the utility server at all (and
 * therefore never saw the founding ceremony's pending approval).
 *
 * `buildDialableMultiaddrs` therefore treats a loopback `advertisedHost` as "not
 * configured" and falls back to the OS-detected LAN IPs.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/platform/network-detect.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildDialableMultiaddrs, isLoopbackHost } from '../../src/platform/network-detect.js';

// ---------------------------------------------------------------------------
// isLoopbackHost
// ---------------------------------------------------------------------------

test('isLoopbackHost recognises every loopback spelling', () => {
  for (const host of ['127.0.0.1', '127.0.0.2', ' 127.0.0.1 ', 'localhost', 'LOCALHOST', '::1', '[::1]', '0:0:0:0:0:0:0:1']) {
    assert.equal(isLoopbackHost(host), true, `${JSON.stringify(host)} must be loopback`);
  }
});

test('isLoopbackHost rejects addresses a peer can actually dial', () => {
  for (const host of ['192.168.1.27', '10.0.0.5', 'mediator.example.com', '203.0.113.5', '172.28.32.1']) {
    assert.equal(isLoopbackHost(host), false, `${JSON.stringify(host)} is NOT loopback`);
  }
});

// ---------------------------------------------------------------------------
// buildDialableMultiaddrs
// ---------------------------------------------------------------------------

test('a real advertised host replaces the wildcard listen address', () => {
  const out = buildDialableMultiaddrs(['/ip4/0.0.0.0/tcp/4003'], '192.168.1.27');
  assert.deepEqual(out, ['/ip4/192.168.1.27/tcp/4003']);
});

test('a LOOPBACK advertised host is ignored — never published as the only address', () => {
  // With the old behaviour this returned exactly ['/ip4/127.0.0.1/tcp/4003'], which
  // no other machine can dial.
  const out = buildDialableMultiaddrs(['/ip4/0.0.0.0/tcp/4003'], '127.0.0.1');

  assert.equal(
    out.some((a) => a.includes('/ip4/127.')),
    false,
    `a loopback address must never be advertised (got ${JSON.stringify(out)})`,
  );
});

test('a non-wildcard listen address passes through untouched', () => {
  const out = buildDialableMultiaddrs(['/ip4/10.1.2.3/tcp/24000'], '192.168.1.27');
  assert.deepEqual(out, ['/ip4/10.1.2.3/tcp/24000']);
});

test('relay circuit addresses are never advertised as direct-dial endpoints', () => {
  const out = buildDialableMultiaddrs(
    ['/dns/mediator.example.com/tcp/4001/p2p/12D3Relay/p2p-circuit/p2p/12D3Peer'],
    '192.168.1.27',
  );
  assert.deepEqual(out, []);
});
