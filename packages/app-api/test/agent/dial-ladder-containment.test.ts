// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The dial ladder must name the address it dials, and contain a bad candidate.
 *
 * Field failure, MBP2014, 2026-10-29. `dialPeerCandidates` reported
 * `Dialing <peer>… via same-subnet/direct: /ip4/192.168.1.28/tcp/4003/…` — but
 * for a direct candidate it actually called `dialProtocol(peerId, …)`, handing
 * libp2p the peer's WHOLE address list and letting its dial queue pick. The
 * first dial to complete at the transport level wins, including one that opens
 * and then immediately closes; libp2p returns that connection anyway and
 * `openConnection` throws `Remote closed connection during opening`, aborting the
 * ENTIRE call — so every remaining candidate, relay included, was skipped.
 *
 * Two things are pinned here:
 *   1. the dial target IS the candidate address (with the peer ID, so a foreign
 *      host at that address cannot be accepted as the peer);
 *   2. a candidate that fails costs one candidate, and the ladder keeps walking.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test \
 *     test/agent/dial-ladder-containment.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ConnectivityModule } from '../../src/runtime/modules/connectivity.js';
import { buildDialCandidates } from '@p2p-trust-stack/core/transport/dial-candidates.js';
import type { Libp2p } from 'libp2p';

const SERVER = '12D3KooWServerPeerIdForTheLadderTestAAAAAAAAAAAAAAA';
const RELAY = '12D3KooWRelayPeerIdForTheLadderTestBBBBBBBBBBBBBBB';

/** The field address set: a /24-coincident LAN address, a relay, a NAT-mapped IP. */
const COINCIDENT_LAN = `/ip4/192.168.1.28/tcp/4003/p2p/${SERVER}`;
const RELAY_ADDR = `/dns/relay.truststackers.com/tcp/4001/p2p/${RELAY}/p2p-circuit/p2p/${SERVER}`;
const NAT_ADDR = `/ip4/137.119.78.102/tcp/58166/p2p/${SERVER}`;

/** Records every dial target and answers with whatever the test decides. */
class StubNode {
  public dialed: string[] = [];
  private readonly verdict: (target: string) => Error | 'ok';

  constructor(verdict: (target: string) => Error | 'ok') {
    this.verdict = verdict;
  }

  private record(target: { toString(): string }): Error | 'ok' {
    const addr = target.toString();
    this.dialed.push(addr);
    return this.verdict(addr);
  }

  async dialProtocol(target: { toString(): string }): Promise<{ close(): Promise<void> }> {
    const verdict = this.record(target);
    if (verdict instanceof Error) throw verdict;
    return { close: async () => {} };
  }

  async dial(target: { toString(): string }): Promise<{ newStream(): Promise<{ close(): Promise<void> }> }> {
    const verdict = this.record(target);
    if (verdict instanceof Error) throw verdict;
    return { newStream: async () => ({ close: async () => {} }) };
  }
}

function makeCandidates() {
  return buildDialCandidates({
    peerId: SERVER,
    multiaddrs: [COINCIDENT_LAN, NAT_ADDR],
    peerRelayAddr: RELAY_ADDR,
    localLanIps: ['192.168.1.201'], // MBP2014's LAN — same /24, different network
  });
}

test('dialPeerCandidates: dials the CANDIDATE address, not the bare peer ID', async () => {
  const node = new StubNode(() => 'ok');
  const statuses: string[] = [];

  const won = await new ConnectivityModule().dialPeerCandidates({
    libp2pNode: node as unknown as Libp2p,
    peerId: SERVER,
    candidates: makeCandidates(),
    onStatus: (m) => statuses.push(m),
  });

  // The relay leads the order now, and it is dialed by its own address.
  assert.equal(won, RELAY_ADDR, 'the relay candidate must be the one that won');
  assert.deepEqual(node.dialed, [RELAY_ADDR], 'exactly the candidate address must be dialed');
  assert.notEqual(node.dialed[0], SERVER, 'the bare peer ID must never be the dial target');
  assert.ok(
    statuses.some((s) => s.includes('Connected') && s.includes('relay')),
    'the status line must name the candidate that worked',
  );
});

test('dialPeerCandidates: the /24-coincident address is never dialed once the relay works', async () => {
  const node = new StubNode(() => 'ok');

  const won = await new ConnectivityModule().dialPeerCandidates({
    libp2pNode: node as unknown as Libp2p,
    peerId: SERVER,
    candidates: makeCandidates(),
  });

  // The field failure needed TWO things to go wrong: the coincident address had
  // to be dialed first, and its failure had to abort the call. Correcting the
  // order removes the first; the assertion below is that the address which
  // aborted the field dial is not touched at all.
  assert.equal(won, RELAY_ADDR);
  assert.deepEqual(
    node.dialed,
    [RELAY_ADDR],
    'the mis-ranked 192.168.1.28 must not be dialed while the relay is available',
  );
});

test('dialPeerCandidates: a failed candidate does not abort the ladder — the next one is tried', async () => {
  const node = new StubNode((target) =>
    target === RELAY_ADDR
      ? new Error('failed to connect via relay with status NO_RESERVATION')
      : 'ok',
  );
  const statuses: string[] = [];

  const won = await new ConnectivityModule().dialPeerCandidates({
    libp2pNode: node as unknown as Libp2p,
    peerId: SERVER,
    candidates: makeCandidates(),
    onStatus: (m) => statuses.push(m),
  });

  assert.equal(won, COINCIDENT_LAN, 'the ladder must walk past a failed candidate');
  // The relay is retried once (reservation race), then the direct candidates follow.
  assert.deepEqual(node.dialed, [RELAY_ADDR, RELAY_ADDR, COINCIDENT_LAN]);
  assert.ok(
    statuses.some((s) => s.includes('failed') && s.includes('NO_RESERVATION')),
    'the failure must be reported against the candidate that caused it',
  );
});

test('dialPeerCandidates: a connect-then-close direct candidate is contained, not fatal', async () => {
  const node = new StubNode((target) =>
    target === COINCIDENT_LAN
      ? new Error('Remote closed connection during opening')
      : target === RELAY_ADDR
        ? new Error('relay down')
        : 'ok',
  );

  const won = await new ConnectivityModule().dialPeerCandidates({
    libp2pNode: node as unknown as Libp2p,
    peerId: SERVER,
    candidates: makeCandidates(),
  });

  // The exact error that aborted the whole dial in the field is now just one
  // failed candidate: the NAT-mapped address is still reached afterwards.
  assert.equal(won, NAT_ADDR);
  assert.deepEqual(node.dialed, [RELAY_ADDR, RELAY_ADDR, COINCIDENT_LAN, NAT_ADDR]);
});

test('dialPeerCandidates: appends the peer ID to a candidate that lacks one', async () => {
  const node = new StubNode(() => 'ok');
  const bare = { addr: '/ip4/192.168.1.28/tcp/4003', scope: 'same-subnet' as const, source: 'direct' as const };

  await new ConnectivityModule().dialPeerCandidates({
    libp2pNode: node as unknown as Libp2p,
    peerId: SERVER,
    candidates: [bare],
  });

  assert.deepEqual(
    node.dialed,
    [`/ip4/192.168.1.28/tcp/4003/p2p/${SERVER}`],
    'a peer-less address must be completed, so the handshake is checked against the expected peer',
  );
});

test('dialPeerCandidates: returns undefined once every candidate has failed', async () => {
  const node = new StubNode(() => new Error('ECONNREFUSED'));

  const won = await new ConnectivityModule().dialPeerCandidates({
    libp2pNode: node as unknown as Libp2p,
    peerId: SERVER,
    candidates: makeCandidates(),
  });

  assert.equal(won, undefined, 'an exhausted ladder resolves undefined, never throws');
  // The relay gets one retry after the reservation race; each direct candidate gets one attempt.
  assert.deepEqual(node.dialed, [RELAY_ADDR, RELAY_ADDR, COINCIDENT_LAN, NAT_ADDR]);
});

test('dialPeerCandidates: no candidates is a no-op, not a throw', async () => {
  const node = new StubNode(() => 'ok');

  const won = await new ConnectivityModule().dialPeerCandidates({
    libp2pNode: node as unknown as Libp2p,
    peerId: SERVER,
    candidates: [],
  });

  assert.equal(won, undefined);
  assert.deepEqual(node.dialed, []);
});

