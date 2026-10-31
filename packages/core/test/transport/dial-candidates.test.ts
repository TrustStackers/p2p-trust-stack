// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Unit tests for the shared address-selection policy.
 *
 * These pin the ONE thing the cross-network join bug turned on: the dial order
 * for a discovered peer. The regression under test is the real
 * `@libp2p/utils` `defaultAddressSorter`, which ranks a NAT-mapped public
 * address ahead of the LAN one and pushes the relay to the end — see the module
 * header for the measured output.
 *
 * Pure module, no libp2p node and no network: every case is a string in,
 * ordering out.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  DIAL_SCOPE_RANK,
  buildDialCandidates,
  classifyDialAddr,
  compareDialAddrs,
  dialCandidateAddrs,
  makeAddressSorter,
} from '../../src/transport/dial-candidates.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SERVER = '12D3KooWSrvPeerIdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const RELAY = '12D3KooWRelayPeerIdBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

const LAN_ADDR = `/ip4/192.168.1.246/tcp/4001/p2p/${SERVER}`;
const NAT_ADDR = `/ip4/24.5.6.7/tcp/52344/p2p/${SERVER}`;
const RELAY_PREFIX = `/dns/relay.truststackers.com/tcp/4001/p2p/${RELAY}/p2p-circuit`;
const RELAY_ADDR = `${RELAY_PREFIX}/p2p/${SERVER}`;

// ---------------------------------------------------------------------------
// classifyDialAddr
// ---------------------------------------------------------------------------

describe('classifyDialAddr', () => {
  it('classifies a /p2p-circuit address as relay, whatever its host kind', () => {
    assert.equal(classifyDialAddr(RELAY_ADDR), 'relay');
    assert.equal(classifyDialAddr(`/ip4/24.5.6.7/tcp/4001/p2p/${RELAY}/p2p-circuit/p2p/${SERVER}`), 'relay');
  });

  it('classifies a direct address on our own subnet as same-subnet', () => {
    assert.equal(classifyDialAddr(LAN_ADDR, ['192.168.1.5']), 'same-subnet');
  });

  it('classifies a private address on a DIFFERENT subnet as lan', () => {
    // The Starlink case: we are 192.168.0.x, the server is 192.168.1.x.
    assert.equal(classifyDialAddr(LAN_ADDR, ['192.168.0.24']), 'lan');
  });

  it('classifies a public IP as wan', () => {
    assert.equal(classifyDialAddr(NAT_ADDR), 'wan');
  });

  it('classifies CGNAT (100.64/10) as lan, not wan', () => {
    assert.equal(classifyDialAddr(`/ip4/100.64.1.7/tcp/4001/p2p/${SERVER}`), 'lan');
  });

  it('classifies a hostname as dns', () => {
    assert.equal(classifyDialAddr(`/dns/server.example.com/tcp/4001/p2p/${SERVER}`), 'dns');
  });

  it('classifies loopback forms as loopback', () => {
    assert.equal(classifyDialAddr(`/ip4/127.0.0.1/tcp/4001/p2p/${SERVER}`), 'loopback');
    assert.equal(classifyDialAddr(`/ip6/::1/tcp/4001/p2p/${SERVER}`), 'loopback');
    assert.equal(classifyDialAddr(`/dns/localhost/tcp/4001/p2p/${SERVER}`), 'loopback');
  });

  it('degrades unparseable input to unknown rather than throwing', () => {
    assert.equal(classifyDialAddr(''), 'unknown');
    assert.equal(classifyDialAddr('not-a-multiaddr'), 'unknown');
    assert.equal(classifyDialAddr('/unix/var/run/x.sock'), 'unknown');
  });

  it('does not treat an absent localLanIps list as "everything is same-subnet"', () => {
    assert.equal(classifyDialAddr(LAN_ADDR, []), 'lan');
  });
});

// ---------------------------------------------------------------------------
// DIAL_SCOPE_RANK / compareDialAddrs
// ---------------------------------------------------------------------------

describe('DIAL_SCOPE_RANK', () => {
  it('ranks relay first, above every direct scope', () => {
    assert.ok(DIAL_SCOPE_RANK.relay < DIAL_SCOPE_RANK['same-subnet']);
    assert.ok(DIAL_SCOPE_RANK.relay < DIAL_SCOPE_RANK.dns);
    assert.ok(DIAL_SCOPE_RANK.relay < DIAL_SCOPE_RANK.lan);
    assert.ok(DIAL_SCOPE_RANK.relay < DIAL_SCOPE_RANK.wan);
    assert.ok(DIAL_SCOPE_RANK['same-subnet'] < DIAL_SCOPE_RANK.dns);
    assert.ok(DIAL_SCOPE_RANK.wan < DIAL_SCOPE_RANK.unknown);
    assert.ok(DIAL_SCOPE_RANK.unknown < DIAL_SCOPE_RANK.loopback);
  });
});

describe('compareDialAddrs', () => {
  it('returns -1 | 0 | 1 only', () => {
    const cmp = compareDialAddrs(RELAY_ADDR, NAT_ADDR);
    assert.ok(cmp === -1 || cmp === 0 || cmp === 1);
    assert.equal(cmp, -1, 'relay must sort before a NAT-mapped public IP');
  });

  it('is a tie for two addresses in the same scope', () => {
    assert.equal(compareDialAddrs(LAN_ADDR, `/ip4/10.0.0.9/tcp/4001/p2p/${SERVER}`), 0);
  });
});

// ---------------------------------------------------------------------------
// buildDialCandidates
// ---------------------------------------------------------------------------

describe('buildDialCandidates', () => {
  it('REGRESSION: puts the relay ahead of a NAT-mapped public IP and an off-subnet LAN IP', () => {
    // This is the exact address set a discovered utility server yields, and the
    // exact case libp2p's default sorter gets backwards.
    const candidates = buildDialCandidates({
      peerId: SERVER,
      multiaddrs: [LAN_ADDR, NAT_ADDR],
      peerRelayAddr: RELAY_ADDR,
      localLanIps: ['192.168.0.24'], // Starlink: different subnet from the server
    });

    assert.deepEqual(dialCandidateAddrs(candidates), [RELAY_ADDR, LAN_ADDR, NAT_ADDR]);
    assert.deepEqual(candidates.map((c) => c.scope), ['relay', 'lan', 'wan']);
  });

  it('still prefers a same-subnet LAN address over every OTHER direct address', () => {
    const candidates = buildDialCandidates({
      peerId: SERVER,
      multiaddrs: [LAN_ADDR, NAT_ADDR],
      peerRelayAddr: RELAY_ADDR,
      localLanIps: ['192.168.1.5'],
    });

    // The relay leads (see the module header: a /24 match is not proof of shared
    // L2), but the same-subnet address still beats the NAT-mapped one.
    assert.deepEqual(dialCandidateAddrs(candidates), [RELAY_ADDR, LAN_ADDR, NAT_ADDR]);
  });

  it('REGRESSION (MBP2014, 2026-10-29): two networks sharing 192.168.1.0/24 no longer dial each other first', () => {
    // The field case, exactly: the agent was 192.168.1.201 on one router, and the
    // utility server advertised 192.168.1.28 from ANOTHER router on a different
    // WAN. `classifyDialAddr` cannot tell that apart from a genuine same-LAN peer
    // — which is the whole point: the order must not depend on the distinction.
    // The relay leads, so the cross-network join reaches the one address that can
    // work before spending the attempt on a host that is not there.
    const candidates = buildDialCandidates({
      peerId: SERVER,
      multiaddrs: ['/ip4/192.168.1.28/tcp/4003/p2p/' + SERVER, NAT_ADDR],
      peerRelayAddr: RELAY_ADDR,
      localLanIps: ['192.168.1.201'],
    });

    assert.deepEqual(dialCandidateAddrs(candidates), [
      RELAY_ADDR,
      `/ip4/192.168.1.28/tcp/4003/p2p/${SERVER}`,
      NAT_ADDR,
    ]);
    assert.equal(candidates[1].scope, 'same-subnet', 'the /24 match is still reported as such');
  });

  it('derives a relay address from the server-level prefix, appending the peer ID', () => {
    const candidates = buildDialCandidates({
      peerId: SERVER,
      multiaddrs: [],
      serverRelayPrefix: RELAY_PREFIX,
    });

    assert.deepEqual(dialCandidateAddrs(candidates), [`${RELAY_PREFIX}/p2p/${SERVER}`]);
    assert.equal(candidates[0].source, 'relay');
  });

  it('de-duplicates the per-peer and server-derived relay address, keeping the first', () => {
    const candidates = buildDialCandidates({
      peerId: SERVER,
      peerRelayAddr: RELAY_ADDR,
      serverRelayPrefix: RELAY_PREFIX,
    });

    assert.equal(candidates.length, 1);
    assert.equal(candidates[0].addr, RELAY_ADDR);
  });

  it('never lets a last-known address outrank a fresh one', () => {
    const stale = `/ip4/192.168.9.9/tcp/4001/p2p/${SERVER}`;
    const candidates = buildDialCandidates({
      peerId: SERVER,
      multiaddrs: [LAN_ADDR],
      peerRelayAddr: RELAY_ADDR,
      lastKnownMultiaddrs: [stale],
      localLanIps: ['192.168.0.24'],
    });

    assert.deepEqual(dialCandidateAddrs(candidates), [RELAY_ADDR, LAN_ADDR, stale]);
    assert.equal(candidates[2].source, 'last-known');
  });

  it('drops empty, non-string and duplicate entries without throwing', () => {
    const candidates = buildDialCandidates({
      peerId: SERVER,
      multiaddrs: [LAN_ADDR, '', LAN_ADDR, undefined as unknown as string, 'garbage-no-host'],
    });

    assert.deepEqual(dialCandidateAddrs(candidates), [LAN_ADDR, 'garbage-no-host']);
  });

  it('omits the server-derived relay when no prefix is supplied', () => {
    const candidates = buildDialCandidates({ peerId: SERVER, multiaddrs: [LAN_ADDR] });
    assert.deepEqual(dialCandidateAddrs(candidates), [LAN_ADDR]);
  });
});

// ---------------------------------------------------------------------------
// makeAddressSorter — the libp2p hook
// ---------------------------------------------------------------------------

describe('makeAddressSorter', () => {
  const ma = (addr: string) => ({ multiaddr: { toString: () => addr } });

  it('orders a libp2p address list by the same policy as the explicit ladder', () => {
    const sorter = makeAddressSorter(['192.168.0.24']);
    const sorted = [LAN_ADDR, NAT_ADDR, RELAY_ADDR].sort((a, b) => sorter(ma(a), ma(b)));
    assert.deepEqual(sorted, [RELAY_ADDR, LAN_ADDR, NAT_ADDR]);
  });

  it('is a tie when a multiaddr getter throws, so a dial is never broken', () => {
    const sorter = makeAddressSorter([]);
    const throwing = { multiaddr: { toString: () => { throw new Error('boom'); } } };
    assert.equal(sorter(throwing, ma(RELAY_ADDR)), 0);
  });
});
