// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests: TspClientModule request-timeout hook.
 *
 * The hook exists because a request that times out with NO response is the only
 * evidence that a write did not arrive: a half-open / black-holed connection
 * accepts the bytes silently, so `sendFn` resolves and the peer never sees the
 * frame. Without dropping that cached connection (invalidateConnection) the next
 * request reuses it and fails identically — the field behaviour where one lost
 * `tx_commit` was followed by every later request to the same peer timing out at
 * 30s.
 *
 * No libp2p and no timers: a short per-request timeout drives the real path.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/agent/tsp-client-timeout.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { TspClientModule } from '../../src/runtime/modules/tsp-client.js';
import { decodeProtocolMessage, encodeProtocolMessage } from '@p2p-trust-stack/core/tsp-handlers/types.js';

const PEER_DID = 'did:scid:vh:1:zPeerThatNeverAnswers';

test('fires the request-timeout hook with the peer that never answered', async () => {
  const client = new TspClientModule();
  // The send "succeeds": this is exactly the silent-black-hole case.
  client.init(async () => { /* written, never delivered */ });

  const timedOutFor: string[] = [];
  client.setRequestTimeoutHook((did) => timedOutFor.push(did));

  await assert.rejects(
    () => client.request(PEER_DID, 'tx_commit', { ops: [] }, 25),
    /TSP request 'tx_commit' timed out after 25ms/,
  );

  assert.deepEqual(timedOutFor, [PEER_DID]);
  client.destroy();
});

test('does not fire the hook when a correlated response arrives', async () => {
  const client = new TspClientModule();
  let correlationId: string | undefined;
  client.init(async (_remoteDid: string, body: Uint8Array) => {
    correlationId = decodeProtocolMessage(body).correlationId;
  });

  const timedOutFor: string[] = [];
  client.setRequestTimeoutHook((did) => timedOutFor.push(did));

  const pending = client.request(PEER_DID, 'tx_prepare', { ops: [] }, 25);

  // Answer the pending request the way the bridge's inbound path does.
  assert.ok(correlationId, 'the outbound request must carry a correlationId');
  await client.handleIncoming(
    encodeProtocolMessage({ protocol: 'tx_prepare_result', correlationId, payload: { vote: 'yes' } }),
  );

  const response = await pending;
  assert.equal(response.protocol, 'tx_prepare_result');
  assert.deepEqual(timedOutFor, [], 'a matched response must not trigger invalidation');
  client.destroy();
});

test('a throwing hook cannot mask the timeout the caller sees', async () => {
  const client = new TspClientModule();
  client.init(async () => { /* no response */ });
  client.setRequestTimeoutHook(() => {
    throw new Error('invalidation blew up');
  });

  await assert.rejects(
    () => client.request(PEER_DID, 'tx_query', {}, 25),
    /TSP request 'tx_query' timed out after 25ms/,
  );
  client.destroy();
});

test('destroy() clears pending requests without firing the hook', async () => {
  const client = new TspClientModule();
  client.init(async () => { /* no response */ });

  const timedOutFor: string[] = [];
  client.setRequestTimeoutHook((did) => timedOutFor.push(did));

  const pending = client.request(PEER_DID, 'tx_inquiry', {}, 5_000);
  client.destroy();

  await assert.rejects(() => pending, /shutting down/);
  assert.deepEqual(timedOutFor, [], 'shutdown is not a connection failure');
});
