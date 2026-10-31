// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Dispatch-containment tests for Libp2pTransport.
 *
 * WHY: `onMessage()` handlers are written as `async`, and the transport used to
 * call the handler bare — no `await`, no `.catch()`. A rejection inside a handler
 * was therefore an UNHANDLED REJECTION, and Node's default
 * (`--unhandled-rejections=throw`) escalated it to a fatal error.
 *
 * Field failure, 2026-10-29: a transient YugabyteDB error
 * (`XX000` / `tserver_shared_mem.cc`: "Timed out waiting kResponseSent, state:
 * kProcessingRequest") was thrown out of the utility server's TSP bridge handler
 * and TERMINATED the process — the log ended with the Node version banner and a
 * shell prompt. Every agent delivery queued behind it stalled.
 *
 * These tests assert the containment contract at the transport boundary:
 *   1. a REJECTING async handler does not produce an unhandledRejection;
 *   2. a handler that throws SYNCHRONOUSLY is contained the same way;
 *   3. the read loop survives both and keeps dispatching later frames.
 *
 * Run with:
 *   node --conditions=development --experimental-strip-types --loader ./test-loader.mjs \
 *     --test packages/core/test/transport/libp2p-transport-dispatch.test.ts
 */

import { test } from 'node:test';
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

/** The exact error the field log carried. */
const YB_RPC_TIMEOUT =
  'Timed out waiting kResponseSent, state: kProcessingRequest';

/** Poll until `predicate()` holds, or fail after `timeoutMs`. */
async function waitFor(predicate: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error('waitFor: condition not met within timeout');
}

// ---------------------------------------------------------------------------
// Containment
// ---------------------------------------------------------------------------

test('a rejecting or throwing onMessage handler cannot escape the transport', async () => {
  const nodeA = await makeNode();
  const nodeB = await makeNode();
  const transportA = new Libp2pTransport(nodeA);
  const transportB = new Libp2pTransport(nodeB);
  await transportA.start();
  await transportB.start();

  const seen: string[] = [];
  const unhandled: unknown[] = [];
  const onUnhandled = (reason: unknown): void => {
    unhandled.push(reason);
  };
  process.on('unhandledRejection', onUnhandled);

  try {
    // A NON-async handler, so both failure mechanisms are exercised through the
    // same registration:
    //   'reject'     → returns a rejected promise (the async-handler shape that
    //                  killed the utility server);
    //   'throw-sync' → throws before returning anything at all.
    transportB.onMessage((message) => {
      const text = new TextDecoder().decode(message);
      seen.push(text);
      if (text === 'reject') return Promise.reject(new Error(YB_RPC_TIMEOUT));
      if (text === 'throw-sync') throw new Error(YB_RPC_TIMEOUT);
      return undefined;
    });

    const addrB: TransportAddress = {
      peerId: nodeB.peerId.toString(),
      multiaddrs: [firstMultiaddr(nodeB)],
    };
    const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

    await transportA.send(enc('reject'), addrB);
    await transportA.send(enc('throw-sync'), addrB);
    // The frame AFTER both failures must still arrive: containment must not cost
    // the read loop its liveness.
    await transportA.send(enc('after'), addrB);

    await waitFor(() => seen.length >= 3);

    assert.deepEqual(
      seen,
      ['reject', 'throw-sync', 'after'],
      'every frame must reach the handler, including the one after two failures',
    );

    // Give the rejection handlers a macrotask turn before asserting.
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(
      unhandled.length,
      0,
      'handler failures must be contained by the transport, not surface as ' +
        `unhandledRejection (saw ${unhandled.length})`,
    );
  } finally {
    process.off('unhandledRejection', onUnhandled);
    await transportA.stop().catch(() => {});
    await transportB.stop().catch(() => {});
    await nodeA.stop();
    await nodeB.stop();
  }
});

test('a handler that rejects on EVERY frame does not degrade later frames', async () => {
  const nodeA = await makeNode();
  const nodeB = await makeNode();
  const transportA = new Libp2pTransport(nodeA);
  const transportB = new Libp2pTransport(nodeB);
  await transportA.start();
  await transportB.start();

  let dispatches = 0;
  try {
    // The realistic shape: an async handler whose awaited work fails every time
    // while the dependency is down (a stalled tablet server in the field log).
    transportB.onMessage(async () => {
      dispatches++;
      await Promise.resolve();
      throw new Error(YB_RPC_TIMEOUT);
    });

    const addrB: TransportAddress = {
      peerId: nodeB.peerId.toString(),
      multiaddrs: [firstMultiaddr(nodeB)],
    };
    const frame = new TextEncoder().encode('x');
    for (let i = 0; i < 10; i++) await transportA.send(frame, addrB);

    await waitFor(() => dispatches >= 10);
    assert.equal(dispatches, 10, 'a sustained failure must not stall the read loop');
  } finally {
    await transportA.stop().catch(() => {});
    await transportB.stop().catch(() => {});
    await nodeA.stop();
    await nodeB.stop();
  }
});
