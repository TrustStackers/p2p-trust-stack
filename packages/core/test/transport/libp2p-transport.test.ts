// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Integration tests for Libp2pTransport.
 *
 * Spins up two real libp2p nodes in-process on 127.0.0.1 with dynamic ports
 * (no mDNS — direct multiaddr dial), wraps each in a Libp2pTransport, and
 * verifies bidirectional message delivery.
 *
 * Run with:
 *   node --test --experimental-strip-types test/transport/libp2p-transport.test.ts
 */

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createLibp2p, type Libp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { identify } from '@libp2p/identify';
import { Libp2pTransport } from '../../src/transport/index.js';
import type { TransportAddress } from '../../src/transport/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeNode(): Promise<Libp2p> {
  return createLibp2p({
    addresses: { listen: ['/ip4/127.0.0.1/tcp/0'] },
    transports: [tcp()],
    streamMuxers: [yamux()],
    connectionEncrypters: [noise()],
    services: { identify: identify() },
  });
}

function firstMultiaddr(node: Libp2p): string {
  const addrs = node.getMultiaddrs();
  if (addrs.length === 0) throw new Error('Node has no multiaddrs');
  return addrs[0].toString();
}

function waitForMessage(
  transport: Libp2pTransport,
): Promise<{ message: Uint8Array; fromAddr: TransportAddress }> {
  return new Promise((resolve) => {
    transport.onMessage((message, fromAddr) => {
      resolve({ message, fromAddr });
    });
  });
}

// ---------------------------------------------------------------------------
// Test state
// ---------------------------------------------------------------------------

let nodeA: Libp2p;
let nodeB: Libp2p;
let transportA: Libp2pTransport;
let transportB: Libp2pTransport;

before(async () => {
  nodeA = await makeNode();
  nodeB = await makeNode();
  transportA = new Libp2pTransport(nodeA);
  transportB = new Libp2pTransport(nodeB);
  await transportA.start();
  await transportB.start();
});

after(async () => {
  await transportA.stop();
  await transportB.stop();
  await nodeA.stop();
  await nodeB.stop();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('A sends a message to B — B receives exact bytes and correct peerId', async () => {
  const payload = new TextEncoder().encode('hello from A');

  const received = waitForMessage(transportB);

  const addrB: TransportAddress = {
    peerId: nodeB.peerId.toString(),
    multiaddrs: [firstMultiaddr(nodeB)],
  };
  await transportA.send(payload, addrB);

  const { message, fromAddr } = await received;

  assert.deepEqual(
    new Uint8Array(message),
    payload,
    'payload bytes must match exactly',
  );
  assert.equal(
    fromAddr.peerId,
    nodeA.peerId.toString(),
    'fromAddr.peerId must be A\'s peer ID',
  );
});

test('invalidatePeer drops the cached connection and the next send re-dials successfully', async () => {
  // Establish a connection A → B, then invalidate it as the request-timeout path
  // does. The point is that invalidation must not strand the peer: the very next
  // send has to work, otherwise dropping a silently-dead connection would be a
  // new failure rather than the fix for one.
  const addrB: TransportAddress = {
    peerId: nodeB.peerId.toString(),
    multiaddrs: [firstMultiaddr(nodeB)],
  };

  const firstReceived = waitForMessage(transportB);
  await transportA.send(new TextEncoder().encode('before invalidation'), addrB);
  await firstReceived;
  assert.ok(
    nodeA.getConnections(nodeB.peerId).length > 0,
    'connection must exist before invalidation',
  );

  await transportA.invalidatePeer(nodeB.peerId.toString(), 'test invalidation');
  assert.equal(
    nodeA.getConnections(nodeB.peerId).length,
    0,
    'invalidatePeer must close the cached connection',
  );

  const afterReceived = waitForMessage(transportB);
  await transportA.send(new TextEncoder().encode('after invalidation'), addrB);
  const { message } = await afterReceived;
  assert.deepEqual(
    new Uint8Array(message),
    new TextEncoder().encode('after invalidation'),
    'a send after invalidation must re-dial and deliver',
  );
});

test('invalidatePeer tolerates an unparseable peer id (never throws)', async () => {
  await assert.doesNotReject(() => transportA.invalidatePeer('not-a-peer-id'));
});

test('B sends a message to A — A receives exact bytes and correct peerId', async () => {
  const payload = new TextEncoder().encode('hello from B');

  const received = waitForMessage(transportA);

  const addrA: TransportAddress = {
    peerId: nodeA.peerId.toString(),
    multiaddrs: [firstMultiaddr(nodeA)],
  };
  await transportB.send(payload, addrA);

  const { message, fromAddr } = await received;

  assert.deepEqual(
    new Uint8Array(message),
    payload,
    'payload bytes must match exactly',
  );
  assert.equal(
    fromAddr.peerId,
    nodeB.peerId.toString(),
    'fromAddr.peerId must be B\'s peer ID',
  );
});

test('send delivers arbitrary binary data unchanged', async () => {
  // A buffer with all byte values 0-255 to confirm no text encoding corruption
  const payload = new Uint8Array(256);
  for (let i = 0; i < 256; i++) payload[i] = i;

  const received = waitForMessage(transportB);

  const addrB: TransportAddress = {
    peerId: nodeB.peerId.toString(),
    multiaddrs: [firstMultiaddr(nodeB)],
  };
  await transportA.send(payload, addrB);

  const { message } = await received;
  assert.deepEqual(
    new Uint8Array(message),
    payload,
    'binary payload must survive transport unchanged',
  );
});

test('onMessage handler replacement — only the latest handler fires', async () => {
  let firstFired = false;
  let secondPayload: Uint8Array | null = null;

  // Register first handler
  transportB.onMessage(() => {
    firstFired = true;
  });

  // Replace with second handler
  const secondReceived = new Promise<Uint8Array>((resolve) => {
    transportB.onMessage((msg) => {
      secondPayload = msg;
      resolve(msg);
    });
  });

  const payload = new TextEncoder().encode('handler replacement test');
  const addrB: TransportAddress = {
    peerId: nodeB.peerId.toString(),
    multiaddrs: [firstMultiaddr(nodeB)],
  };
  await transportA.send(payload, addrB);
  await secondReceived;

  assert.equal(firstFired, false, 'replaced handler must not fire');
  assert.deepEqual(
    new Uint8Array(secondPayload!),
    payload,
    'active handler must receive the message',
  );
});
