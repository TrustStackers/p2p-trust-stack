// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * TspBridge.connect() — the outbound-pending relationship must not be a dead end.
 *
 * Field bug, MBP2014, 2026-10-29. `sendRfi` writes its outbound-pending row
 * BEFORE the send (so an immediately-arriving RFA can be matched), and that send
 * then failed with `Remote closed connection during opening`. The row survived.
 * Because `TspBridge.connect()` read an outbound-pending row as "a handshake is
 * in progress" and only WAITED for it, and because `sendRfi` cannot run again
 * while the row exists (`insertOutbound` throws `already exists`), the agent
 * could never re-send. Its log showed ONE `[RM:sendRfi]` line followed by five
 * identical 30 s `timed out waiting for bidirectional relationship` errors — on a
 * machine whose bootstrap connection, relay reservation and peer discovery were
 * all demonstrably healthy. It recovered only when the app was restarted and
 * `pruneStaleOutbound`'s 5-minute window had elapsed.
 *
 * Two fixes are pinned here:
 *   - `RelationshipManager.sendRfi` rolls the row back when the send fails
 *     (pinned in `packages/core/test/relationship/manager.test.ts`).
 *   - `TspBridge.connect` treats a row OLDER than one handshake window as dead
 *     and re-drives the handshake instead of waiting on it — the tests below.
 *
 * The two controls matter as much as the fix: a row YOUNGER than the window may
 * genuinely be in flight, and re-sending then would duplicate the RFI.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test \
 *     test/agent/tsp-bridge-pending-retry.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { TspBridge } from '../../src/runtime/modules/tsp-bridge.js';
import type { TspClientModule } from '../../src/runtime/modules/tsp-client.js';
import type { RelationshipManager } from '@p2p-trust-stack/core/relationship/manager.js';
import type { RelationshipRecord } from '@p2p-trust-stack/core/relationship/types.js';
import { encodeOobi } from '@p2p-trust-stack/core/relationship/oobi.js';
import { cesrEncode, CESR_CODES } from '@p2p-trust-stack/core/crypto/cesr.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SERVER_DID = 'did:scid:vh:1:test-utility-server';
const SERVER_PEER_ID = '12D3KooWServerForTest';

/** A strict 4-item OOBI, the shape the real connect path requires. */
const SERVER_OOBI = encodeOobi({
  cesrVid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, new Uint8Array(32)),
  peerId: SERVER_PEER_ID,
  multiaddrs: ['/ip4/127.0.0.1/tcp/4003'],
  did: SERVER_DID,
});

/**
 * The record the failed handshake leaves behind: outbound, pending, and
 * `ageSeconds` old. `created_at` is unix SECONDS in the store, so the fixture
 * uses seconds too.
 */
function pendingRecord(ageSeconds: number): RelationshipRecord {
  return {
    localDid: 'did:peer:4:local',
    remoteDid: SERVER_DID,
    direction: 'outbound',
    status: 'pending',
    createdAt: Math.floor(Date.now() / 1000) - ageSeconds,
  } as RelationshipRecord;
}

/** The completed handshake the reconnect path is waiting for. */
function establishedRecord(): RelationshipRecord {
  return {
    ...pendingRecord(0),
    direction: 'bidirectional',
    status: 'established',
  } as RelationshipRecord;
}

interface StubHooks {
  /** Current relationship row, read by both connect() and its wait loop. */
  getRecord: () => RelationshipRecord | undefined;
  /** Called by the re-drive path with the DID it is clearing. */
  onRemove?: (did: string) => void;
  /** Called when the handshake is (re-)driven. Throw to fail the send. */
  onSendRfi?: () => void;
}

/** A TspBridge over a stub manager, so no libp2p node or database is needed. */
function makeBridge(hooks: StubHooks): TspBridge {
  const manager = {
    getRelationship: () => hooks.getRecord(),
    removeRelationship: (did: string) => hooks.onRemove?.(did),
    sendRfi: async () => {
      hooks.onSendRfi?.();
    },
    updateRemoteSubjectKind: () => {},
  } as unknown as RelationshipManager;

  const tspClient = {
    init: () => {},
    setRequestTimeoutHook: () => {},
  } as unknown as TspClientModule;

  const bridge = new TspBridge();
  bridge.init({ manager, tspClient, utilityServerOobi: SERVER_OOBI });
  return bridge;
}

// ---------------------------------------------------------------------------
// The fix
// ---------------------------------------------------------------------------

test('TspBridge.connect: an outbound-pending row past the handshake window is re-driven, not waited on', async () => {
  let record: RelationshipRecord | undefined = pendingRecord(120);
  const removed: string[] = [];
  let rfiSends = 0;

  const bridge = makeBridge({
    getRecord: () => record,
    onRemove: (did) => {
      removed.push(did);
      record = undefined;
    },
    onSendRfi: () => {
      rfiSends += 1;
      record = establishedRecord();
    },
  });

  const did = await bridge.connect();

  assert.equal(did, SERVER_DID, 'connect must resolve the server DID');
  assert.deepEqual(removed, [SERVER_DID], 'the dead row must be cleared exactly once');
  assert.equal(rfiSends, 1, 'the handshake must be re-driven, not waited on');
  assert.equal(bridge.isConnected(), true, 'the bridge must report connected after the re-drive');
  assert.equal(bridge.getUtilityServerDid(), SERVER_DID);
});

test('TspBridge.connect: a re-drive that fails surfaces the send error, not a 30 s timeout', async () => {
  let record: RelationshipRecord | undefined = pendingRecord(120);

  const bridge = makeBridge({
    getRecord: () => record,
    onRemove: () => {
      record = undefined;
    },
    onSendRfi: () => {
      throw new Error('Remote closed connection during opening');
    },
  });

  // The point: the caller learns WHY, immediately. Before the fix this burned a
  // full 30 s and reported a generic "timed out waiting for bidirectional
  // relationship", which is what made the field log unreadable.
  await assert.rejects(
    () => bridge.connect(),
    /Remote closed connection during opening/,
    'the transport failure must reach the caller',
  );
});

// ---------------------------------------------------------------------------
// Controls — the fix must NOT duplicate a handshake that is genuinely in flight
// ---------------------------------------------------------------------------

test('TspBridge.connect: a FRESH pending row is waited for, never cleared or re-sent', async () => {
  let record: RelationshipRecord | undefined = pendingRecord(0);
  const removed: string[] = [];
  let rfiSends = 0;

  const bridge = makeBridge({
    getRecord: () => record,
    onRemove: (did) => {
      removed.push(did);
      record = undefined;
    },
    onSendRfi: () => {
      rfiSends += 1;
    },
  });

  // The RFA arrives while connect() is waiting.
  const rfa = setTimeout(() => {
    record = establishedRecord();
  }, 300);

  try {
    const did = await bridge.connect();
    assert.equal(did, SERVER_DID, 'connect must resolve once the RFA lands');
  } finally {
    clearTimeout(rfa);
  }

  assert.deepEqual(removed, [], 'a row younger than the window must not be cleared');
  assert.equal(rfiSends, 0, 'a row younger than the window must not be re-sent');
});

test('TspBridge.connect: an already-established relationship short-circuits (no RFI, no clearing)', async () => {
  const removed: string[] = [];
  let rfiSends = 0;

  const bridge = makeBridge({
    getRecord: () => establishedRecord(),
    onRemove: (did) => removed.push(did),
    onSendRfi: () => {
      rfiSends += 1;
    },
  });

  const did = await bridge.connect();

  assert.equal(did, SERVER_DID);
  assert.deepEqual(removed, [], 'an established relationship must never be cleared');
  assert.equal(rfiSends, 0, 'an established relationship must not re-send an RFI');
});

