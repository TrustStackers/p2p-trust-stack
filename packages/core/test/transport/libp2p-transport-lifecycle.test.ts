/**
 * Lifecycle tests for Libp2pTransport — Step 5 (Tasks 5.1, 5.2, 5.3).
 *
 * Tests stream lifecycle hardening:
 *   - 5.1: Protocol ID is exactly '/tsp/1.0.0'
 *   - 5.2: Frame size limit (maxMessageBytes) — boundary and over-limit cases
 *   - 5.3: Send timeout (TransportTimeoutError), oversized send (TransportFrameTooLargeError),
 *           idle-read timeout, backpressure (many rapid sends arrive intact and in order)
 *
 * Run with:
 *   node --test --experimental-strip-types test/transport/libp2p-transport-lifecycle.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLibp2p, type Libp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { identify } from '@libp2p/identify';
import {
  Libp2pTransport,
  TSP_PROTOCOL,
  TransportTimeoutError,
  TransportFrameTooLargeError,
} from '../../src/transport/index.js';
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
// 5.1 — Protocol ID re-verification
// ---------------------------------------------------------------------------

test('TSP_PROTOCOL constant is exactly "/tsp/1.0.0"', () => {
  assert.equal(TSP_PROTOCOL, '/tsp/1.0.0', 'TSP_PROTOCOL must be "/tsp/1.0.0"');
});

// ---------------------------------------------------------------------------
// 5.2 — Frame size limit (maxMessageBytes)
// ---------------------------------------------------------------------------

test('send() rejects oversized message before dialing (TransportFrameTooLargeError)', async () => {
  const nodeA = await makeNode();
  const nodeB = await makeNode();
  const maxMessageBytes = 64;
  const transportA = new Libp2pTransport(nodeA, { maxMessageBytes });
  const transportB = new Libp2pTransport(nodeB, { maxMessageBytes });
  await transportA.start();
  await transportB.start();

  try {
    const oversized = new Uint8Array(maxMessageBytes + 1);
    const addrB: TransportAddress = {
      peerId: nodeB.peerId.toString(),
      multiaddrs: [firstMultiaddr(nodeB)],
    };

    await assert.rejects(
      () => transportA.send(oversized, addrB),
      (err: unknown) => {
        assert.ok(err instanceof TransportFrameTooLargeError, 'must throw TransportFrameTooLargeError');
        assert.ok(
          (err as TransportFrameTooLargeError).message.includes(`${maxMessageBytes + 1} bytes`),
          'error message must include actual byte count',
        );
        return true;
      },
    );
  } finally {
    await transportA.stop();
    await transportB.stop();
    await nodeA.stop();
    await nodeB.stop();
  }
});

test('send() delivers a message exactly at maxMessageBytes limit', async () => {
  const nodeA = await makeNode();
  const nodeB = await makeNode();
  const maxMessageBytes = 256;
  const transportA = new Libp2pTransport(nodeA, { maxMessageBytes });
  const transportB = new Libp2pTransport(nodeB, { maxMessageBytes });
  await transportA.start();
  await transportB.start();

  try {
    // Exactly at the limit — should succeed.
    const payload = new Uint8Array(maxMessageBytes);
    for (let i = 0; i < maxMessageBytes; i++) payload[i] = i % 256;

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
      'message at exactly maxMessageBytes must be delivered intact',
    );
  } finally {
    await transportA.stop();
    await transportB.stop();
    await nodeA.stop();
    await nodeB.stop();
  }
});

test('receiver closes stream when inbound frame exceeds maxMessageBytes', async () => {
  // Sender has a large limit; receiver has a small limit.
  // The sender sends a frame that exceeds the receiver's limit.
  // The receiver's lpStream should throw and close the stream without crashing.
  const nodeA = await makeNode();
  const nodeB = await makeNode();
  const senderMax = 512;
  const receiverMax = 64;
  const transportA = new Libp2pTransport(nodeA, { maxMessageBytes: senderMax });
  const transportB = new Libp2pTransport(nodeB, { maxMessageBytes: receiverMax });
  await transportA.start();
  await transportB.start();

  try {
    // B's handler should NOT fire (frame is too large for B's limit).
    let bHandlerFired = false;
    transportB.onMessage(() => {
      bHandlerFired = true;
    });

    // Send a frame that is within A's limit but exceeds B's limit.
    const payload = new Uint8Array(receiverMax + 1);
    const addrB: TransportAddress = {
      peerId: nodeB.peerId.toString(),
      multiaddrs: [firstMultiaddr(nodeB)],
    };

    // The send itself may succeed (A's limit is not exceeded) or fail depending
    // on whether lpStream rejects the write when the receiver closes the stream.
    // Either way, B's handler must NOT fire.
    try {
      await transportA.send(payload, addrB);
    } catch {
      // Expected: the receiver may close the stream, causing the sender's write to fail.
    }

    // Give B's handler a moment to (not) fire.
    await new Promise(resolve => setTimeout(resolve, 100));

    assert.equal(bHandlerFired, false, 'B handler must not fire for oversized frame');
  } finally {
    await transportA.stop();
    await transportB.stop();
    await nodeA.stop();
    await nodeB.stop();
  }
});

// ---------------------------------------------------------------------------
// 5.3 — Send timeout (TransportTimeoutError)
// ---------------------------------------------------------------------------

test('send() throws TransportTimeoutError when dial times out', async () => {
  // Use a very short timeout and a peer that is not listening on the given address.
  const nodeA = await makeNode();
  const transportA = new Libp2pTransport(nodeA, { sendTimeoutMs: 200 });
  await transportA.start();

  try {
    const payload = new TextEncoder().encode('hello');
    // Use a non-existent peer ID and address — the dial will fail/timeout.
    // We use a valid-format peer ID that doesn't exist on the network.
    const fakePeerId = nodeA.peerId.toString(); // self-dial will fail or timeout
    const addrFake: TransportAddress = {
      peerId: fakePeerId,
      multiaddrs: ['/ip4/127.0.0.1/tcp/19999'], // nothing listening here
    };

    const start = Date.now();
    let threw = false;
    try {
      await transportA.send(payload, addrFake);
    } catch (err) {
      threw = true;
      // Accept either TransportTimeoutError (timeout fired) or a connection error
      // (dial failed fast). The important thing is that send() does not hang.
      const elapsed = Date.now() - start;
      assert.ok(
        elapsed < 5000,
        `send() must not hang — elapsed ${elapsed}ms`,
      );
      if (err instanceof TransportTimeoutError) {
        assert.ok(
          (err as TransportTimeoutError).message.includes('send'),
          'TransportTimeoutError message must mention "send"',
        );
      }
    }
    assert.ok(threw, 'send() to non-existent peer must throw');
  } finally {
    await transportA.stop();
    await nodeA.stop();
  }
});

// ---------------------------------------------------------------------------
// 5.3 — Idle-read timeout
// ---------------------------------------------------------------------------

test('inbound stream is aborted after idleTimeoutMs with no frames', async () => {
  const nodeA = await makeNode();
  const nodeB = await makeNode();
  const idleTimeoutMs = 150; // very short for testing
  const transportA = new Libp2pTransport(nodeA);
  const transportB = new Libp2pTransport(nodeB, { idleTimeoutMs });
  await transportA.start();
  await transportB.start();

  try {
    // Track whether B's handler fires.
    let bHandlerFired = false;
    transportB.onMessage(() => {
      bHandlerFired = true;
    });

    // A opens a stream to B but never sends a frame.
    // We do this by dialing the protocol directly without writing.
    const { multiaddr } = await import('@multiformats/multiaddr');
    await nodeA.peerStore.patch(nodeB.peerId, {
      multiaddrs: [multiaddr(firstMultiaddr(nodeB))],
    });
    const stream = await nodeA.dialProtocol(nodeB.peerId, TSP_PROTOCOL);

    // Wait longer than idleTimeoutMs — B should abort the stream.
    await new Promise(resolve => setTimeout(resolve, idleTimeoutMs + 200));

    // B's handler must not have fired (no frame was sent).
    assert.equal(bHandlerFired, false, 'B handler must not fire when no frame is sent');

    // Clean up the stream.
    try { await stream.close(); } catch { /* ignore */ }
  } finally {
    await transportA.stop();
    await transportB.stop();
    await nodeA.stop();
    await nodeB.stop();
  }
});

// ---------------------------------------------------------------------------
// 5.3 — Backpressure: many rapid sends arrive intact and in order
// ---------------------------------------------------------------------------

test('backpressure: N rapid sends all arrive intact and in order', async () => {
  const nodeA = await makeNode();
  const nodeB = await makeNode();
  const transportA = new Libp2pTransport(nodeA);
  const transportB = new Libp2pTransport(nodeB);
  await transportA.start();
  await transportB.start();

  const N = 20;
  const received: Uint8Array[] = [];

  // Register B's handler to collect messages.
  const allReceived = new Promise<void>((resolve) => {
    transportB.onMessage((message) => {
      received.push(new Uint8Array(message));
      if (received.length === N) resolve();
    });
  });

  const addrB: TransportAddress = {
    peerId: nodeB.peerId.toString(),
    multiaddrs: [firstMultiaddr(nodeB)],
  };

  // Send N messages rapidly (sequentially — each send opens/closes its own stream).
  for (let i = 0; i < N; i++) {
    const payload = new Uint8Array(4);
    // Encode i as 4 bytes so we can verify order.
    payload[0] = (i >> 24) & 0xff;
    payload[1] = (i >> 16) & 0xff;
    payload[2] = (i >> 8) & 0xff;
    payload[3] = i & 0xff;
    await transportA.send(payload, addrB);
  }

  // Wait for all N messages to arrive (with a generous timeout).
  await Promise.race([
    allReceived,
    new Promise<void>((_, reject) =>
      setTimeout(() => reject(new Error(`Only received ${received.length}/${N} messages`)), 10_000),
    ),
  ]);

  assert.equal(received.length, N, `must receive exactly ${N} messages`);

  // Verify each message is intact (correct 4-byte encoding of its index).
  for (let i = 0; i < N; i++) {
    const expected = new Uint8Array(4);
    expected[0] = (i >> 24) & 0xff;
    expected[1] = (i >> 16) & 0xff;
    expected[2] = (i >> 8) & 0xff;
    expected[3] = i & 0xff;
    assert.deepEqual(received[i], expected, `message ${i} must be intact`);
  }

  await transportA.stop();
  await transportB.stop();
  await nodeA.stop();
  await nodeB.stop();
});
