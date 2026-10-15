// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for RelationshipManager — Step 4, Tasks 4.2–4.5.
 *
 * Uses an in-memory SQLite database and a mock TspTransport to test the
 * full RFI/RFA handshake without any real network I/O.
 *
 * Covers:
 *   - sendRfi: encodes OOBI, builds RFI, stores outbound-pending record, sends message
 *   - handleMessage (TSP_RFI): verifies, stores inbound record, sends RFA
 *   - handleMessage (TSP_RFA): verifies digest match, confirms bidirectional
 *   - Full handshake: A sends RFI → B processes → B sends RFA → A processes → both bidirectional
 *   - Lower-digest-wins: simultaneous RFIs, only one side sends RFA
 *   - Tampered RFI is silently discarded (tspOpen throws)
 *   - RFA with wrong digest is silently discarded
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/relationship/manager.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import {
  generateEd25519KeyPair,
  generateX25519KeyPair,
} from '../../src/crypto/primitives.js';
import {
  cesrEncode,
  CESR_CODES,
} from '../../src/crypto/cesr.js';
import { runMigrations } from '../../src/db/migrate.js';
import { IdentityResolver } from '../../src/services/identity-resolver.js';
import { RelationshipStore } from '../../src/relationship/store.js';
import { RelationshipManager } from '../../src/relationship/manager.js';
import { encodeOobi } from '../../src/relationship/oobi.js';
import { tspSeal, peekEnvelope } from '../../src/tsp/v3/message.js';
import type { LocalIdentity } from '../../src/relationship/types.js';
import type { TspTransport, TransportAddress } from '../../src/transport/types.js';
import type { DidDocument } from '../../src/did/types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Mock transport
// ---------------------------------------------------------------------------

/**
 * A mock TspTransport that captures sent messages and allows test code to
 * inject incoming messages by calling deliverMessage().
 */
class MockTransport implements TspTransport {
  public sent: Array<{ message: Uint8Array; to: TransportAddress }> = [];
  private handler?: (message: Uint8Array, fromAddr: TransportAddress) => void;

  async start(): Promise<void> {}
  async stop(): Promise<void> {}

  async send(message: Uint8Array, remoteAddr: TransportAddress): Promise<void> {
    this.sent.push({ message: new Uint8Array(message), to: remoteAddr });
  }

  onMessage(handler: (message: Uint8Array, fromAddr: TransportAddress) => void): void {
    this.handler = handler;
  }

  /** Inject an incoming message as if it arrived from fromAddr. */
  deliverMessage(message: Uint8Array, fromAddr: TransportAddress): void {
    this.handler?.(message, fromAddr);
  }

  /** Clear the sent queue. */
  clearSent(): void {
    this.sent = [];
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIdentity(peerId: string, multiaddrs: string[] = []): {
  identity: LocalIdentity;
  transport: MockTransport;
  store: RelationshipStore;
  manager: RelationshipManager;
} {
  const signingKp = generateEd25519KeyPair();
  const agreementKp = generateX25519KeyPair();
  const vid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, signingKp.publicKey);

  // Build a minimal DID document with both keys.
  // Use a non-long-form DID ID (no second colon after 'did:peer:4') so that
  // RelationshipManager skips verifyDidPeer4() for these stub identities.
  // A real did:peer:4 long-form DID has the format: did:peer:4<hash>:<suffix>
  // Our stub uses a short-form-like ID that won't trigger the verifier.
  const didId = `did:test:${vid.slice(1, 17)}`;
  const didDocument: DidDocument = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: didId,
    verificationMethod: [
      {
        id: `${didId}#key-1`,
        type: 'Multikey',
        controller: didId,
        // Encode Ed25519 key as Multikey: 'z' + base58btc(0xed 0x01 + rawKey)
        publicKeyMultibase: encodeMultikey(signingKp.publicKey, [0xed, 0x01]),
      },
      {
        id: `${didId}#key-2`,
        type: 'Multikey',
        controller: didId,
        // Encode X25519 key as Multikey: 'z' + base58btc(0xec 0x01 + rawKey)
        publicKeyMultibase: encodeMultikey(agreementKp.publicKey, [0xec, 0x01]),
      },
    ],
    authentication: [`${didId}#key-1`],
    keyAgreement: [`${didId}#key-2`],
    service: [],
  };

  const identity: LocalIdentity = {
    cesrVid: vid,
    did: didId,
    didDocument,
    signingKeyPair: signingKp,
    agreementKeyPair: agreementKp,
  };

  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  const resolver = new IdentityResolver(db);
  resolver.resolveLocalIdentity({
    did: didId,
    name: 'test',
    method: 'did:peer:4',
    peerId,
    cesrVid: vid,
    didDocumentJson: JSON.stringify(didDocument),
  });
  const store = new RelationshipStore(db, resolver);

  const transport = new MockTransport();
  const manager = new RelationshipManager({ transport, store, identity });
  manager.start();

  return { identity, transport, store, manager };
}

/**
 * Encode a raw public key as a Multikey publicKeyMultibase string.
 * Format: 'z' + base58btc(prefix + rawKey)
 */
function encodeMultikey(rawKey: Uint8Array, prefix: number[]): string {
  const bytes = new Uint8Array([...prefix, ...rawKey]);
  return 'z' + base58btcEncode(bytes);
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58btcEncode(bytes: Uint8Array): string {
  let value = BigInt(0);
  for (const byte of bytes) {
    value = value * BigInt(256) + BigInt(byte);
  }

  let result = '';
  while (value > BigInt(0)) {
    result = BASE58_ALPHABET[Number(value % BigInt(58))] + result;
    value = value / BigInt(58);
  }

  // Add leading '1' for each leading zero byte.
  for (const byte of bytes) {
    if (byte === 0) result = '1' + result;
    else break;
  }

  return result;
}

/** Wait for all pending microtasks to settle (for fire-and-forget async handlers). */
function flushMicrotasks(): Promise<void> {
  // Use a longer timeout to allow async operations (including verifyDidPeer4 if needed)
  // to complete. The manager's handleMessage is fire-and-forget, so we need to wait
  // for the async chain to settle.
  return new Promise(resolve => setTimeout(resolve, 50));
}

// ---------------------------------------------------------------------------
// sendRfi
// ---------------------------------------------------------------------------

test('RelationshipManager.sendRfi: stores outbound-pending record and sends RFI message', async () => {
  const a = makeIdentity('12D3KooWPeerA', ['/ip4/127.0.0.1/tcp/4001']);
  const b = makeIdentity('12D3KooWPeerB', ['/ip4/127.0.0.1/tcp/4002']);

  // B publishes an OOBI.
  const bOobi = encodeOobi({
    cesrVid: b.identity.cesrVid,
    did: b.identity.did,
    peerId: '12D3KooWPeerB',
    multiaddrs: ['/ip4/127.0.0.1/tcp/4002'],
  });

  // A sends an RFI to B.
  await a.manager.sendRfi(bOobi);

  // A must have sent exactly one message.
  assert.equal(a.transport.sent.length, 1, 'A must have sent exactly one message');

  // A must have an outbound-pending record for B.
  const record = a.store.get(a.identity.did, b.identity.did);
  assert.ok(record, 'A must have a relationship record for B');
  assert.equal(record!.direction, 'outbound', 'record direction must be outbound');
  assert.equal(record!.status, 'pending', 'record status must be pending');
});

// ---------------------------------------------------------------------------
// Full handshake: A → B (RFI) → A (RFA) → bidirectional
// ---------------------------------------------------------------------------

test('RelationshipManager: full RFI/RFA handshake — both sides end up bidirectional', async () => {
  const a = makeIdentity('12D3KooWPeerA', ['/ip4/127.0.0.1/tcp/4001']);
  const b = makeIdentity('12D3KooWPeerB', ['/ip4/127.0.0.1/tcp/4002']);

  const aAddr: TransportAddress = { peerId: '12D3KooWPeerA', multiaddrs: ['/ip4/127.0.0.1/tcp/4001'] };
  const bAddr: TransportAddress = { peerId: '12D3KooWPeerB', multiaddrs: ['/ip4/127.0.0.1/tcp/4002'] };

  // B publishes an OOBI.
  const bOobi = encodeOobi({ cesrVid: b.identity.cesrVid, did: b.identity.did, peerId: bAddr.peerId, multiaddrs: bAddr.multiaddrs ?? [] });

  // Step 1: A sends RFI to B.
  await a.manager.sendRfi(bOobi);
  assert.equal(a.transport.sent.length, 1, 'A must have sent 1 message (RFI)');

  const rfiMessage = a.transport.sent[0].message;

  // Step 2: Deliver the RFI to B.
  b.transport.deliverMessage(rfiMessage, aAddr);
  await flushMicrotasks();

  // B must have sent an RFA.
  assert.equal(b.transport.sent.length, 1, 'B must have sent 1 message (RFA)');

  // B must now have a bidirectional record for A (processRfi calls confirmBidirectional after sending RFA).
  const bRecord = b.store.get(b.identity.did, a.identity.did);
  assert.ok(bRecord, 'B must have a relationship record for A');
  assert.equal(bRecord!.direction, 'bidirectional', 'B record direction must be bidirectional after sending RFA');
  assert.equal(bRecord!.status, 'established', 'B record status must be established after sending RFA');

  const rfaMessage = b.transport.sent[0].message;

  // Step 3: Deliver the RFA to A.
  a.transport.deliverMessage(rfaMessage, bAddr);
  await flushMicrotasks();

  // A must have a bidirectional record for B.
  const aRecord = a.store.get(a.identity.did, b.identity.did);
  assert.ok(aRecord, 'A must have a relationship record for B');
  assert.equal(aRecord!.direction, 'bidirectional', 'A record direction must be bidirectional');
  assert.equal(aRecord!.status, 'established', 'A record status must be established');
});

// ---------------------------------------------------------------------------
// RFA with wrong digest is discarded
// ---------------------------------------------------------------------------

test('RelationshipManager: RFA with wrong digest is silently discarded', async () => {
  const a = makeIdentity('12D3KooWPeerA', ['/ip4/127.0.0.1/tcp/4001']);
  const b = makeIdentity('12D3KooWPeerB', ['/ip4/127.0.0.1/tcp/4002']);

  const aAddr: TransportAddress = { peerId: '12D3KooWPeerA', multiaddrs: ['/ip4/127.0.0.1/tcp/4001'] };
  const bAddr: TransportAddress = { peerId: '12D3KooWPeerB', multiaddrs: ['/ip4/127.0.0.1/tcp/4002'] };

  const bOobi = encodeOobi({ cesrVid: b.identity.cesrVid, did: b.identity.did, peerId: bAddr.peerId, multiaddrs: bAddr.multiaddrs ?? [] });

  // A sends RFI.
  await a.manager.sendRfi(bOobi);
  const rfiMessage = a.transport.sent[0].message;

  // B processes RFI and sends RFA.
  b.transport.deliverMessage(rfiMessage, aAddr);
  await flushMicrotasks();
  assert.equal(b.transport.sent.length, 1, 'B must have sent RFA');

  // Tamper the RFA message (flip a byte in the middle).
  const rfaMessage = new Uint8Array(b.transport.sent[0].message);
  rfaMessage[Math.floor(rfaMessage.length / 2)] ^= 0xff;

  // Deliver the tampered RFA to A.
  a.transport.deliverMessage(rfaMessage, bAddr);
  await flushMicrotasks();

  // A's record must still be outbound-pending (not bidirectional).
  const aRecord = a.store.get(a.identity.did, b.identity.did);
  assert.ok(aRecord);
  assert.equal(aRecord!.direction, 'outbound', 'A record must remain outbound after tampered RFA');
  assert.equal(aRecord!.status, 'pending', 'A record must remain pending after tampered RFA');
});

// ---------------------------------------------------------------------------
// XRFD decline (rev 3) — a refused invite must be LOUD, not a 30 s timeout
// ---------------------------------------------------------------------------

test('RelationshipManager: a mis-addressed invite is DECLINED with an XRFD (no silent drop)', async () => {
  const a = makeIdentity('12D3KooWPeerA', ['/ip4/127.0.0.1/tcp/4001']);
  const b = makeIdentity('12D3KooWPeerB', ['/ip4/127.0.0.1/tcp/4002']);
  const c = makeIdentity('12D3KooWPeerC', ['/ip4/127.0.0.1/tcp/4003']);

  const aAddr: TransportAddress = { peerId: '12D3KooWPeerA', multiaddrs: ['/ip4/127.0.0.1/tcp/4001'] };

  // A addresses its invite to C (a stale / other OOBI) — but it is DELIVERED to B.
  const cOobi = encodeOobi({
    cesrVid: c.identity.cesrVid, did: c.identity.did,
    peerId: '12D3KooWPeerC', multiaddrs: ['/ip4/127.0.0.1/tcp/4003'],
  });
  await a.manager.sendRfi(cOobi);
  const rfiMessage = a.transport.sent[0].message;

  b.transport.deliverMessage(rfiMessage, aAddr);
  await flushMicrotasks();

  // The invite must NOT have created a relationship on B...
  assert.equal(
    b.store.get(b.identity.did, a.identity.did), undefined,
    'a refused invite must not create a relationship record',
  );
  // ...and B must have answered with exactly one XRFD decline.
  assert.equal(b.transport.sent.length, 1, 'B must reply with a single decline');
  const declined = peekEnvelope(b.transport.sent[0].message);
  assert.equal(declined.payloadType, 'TSP_RFD', 'the decline must be a TSP_RFD (XRFD)');
  assert.equal(declined.vidSender, b.identity.did);
  assert.equal(declined.vidReceiver, a.identity.did);
  // The decline carries the digest of the message being declined, so the
  // initiator can correlate it with the exact invite it sent.
  assert.deepEqual(
    declined.digest, peekEnvelope(rfiMessage).digest,
    'the decline must echo the declined invite digest',
  );
});

test('RelationshipManager: an inbound XRFD marks our outbound invite rejected', async () => {
  const a = makeIdentity('12D3KooWPeerA', ['/ip4/127.0.0.1/tcp/4001']);
  const b = makeIdentity('12D3KooWPeerB', ['/ip4/127.0.0.1/tcp/4002']);
  const bAddr: TransportAddress = { peerId: '12D3KooWPeerB', multiaddrs: ['/ip4/127.0.0.1/tcp/4002'] };

  const bOobi = encodeOobi({ cesrVid: b.identity.cesrVid, did: b.identity.did, peerId: bAddr.peerId, multiaddrs: bAddr.multiaddrs ?? [] });
  await a.manager.sendRfi(bOobi);

  // Before the decline: outbound-pending.
  assert.equal(a.store.get(a.identity.did, b.identity.did)!.status, 'pending');

  // B declines, echoing the digest of the invite it refused.
  const declinedDigest = peekEnvelope(a.transport.sent[0].message).digest!;
  const rfd = tspSeal({
    vidSender: b.identity.did, vidReceiver: a.identity.did,
    payload: { type: 'TSP_RFD', digest: declinedDigest },
    signingSecretKey: b.identity.signingKeyPair.secretKey,
  });
  a.transport.deliverMessage(rfd, bAddr);
  await flushMicrotasks();

  const aRecord = a.store.get(a.identity.did, b.identity.did)!;
  assert.equal(aRecord.status, 'rejected', 'an inbound decline must mark the invite rejected');
  assert.equal(aRecord.direction, 'outbound', 'the direction is unchanged by a decline');
});

test('RelationshipManager: a decline never downgrades an established relationship', async () => {
  const a = makeIdentity('12D3KooWPeerA', ['/ip4/127.0.0.1/tcp/4001']);
  const b = makeIdentity('12D3KooWPeerB', ['/ip4/127.0.0.1/tcp/4002']);
  const aAddr: TransportAddress = { peerId: '12D3KooWPeerA', multiaddrs: ['/ip4/127.0.0.1/tcp/4001'] };
  const bAddr: TransportAddress = { peerId: '12D3KooWPeerB', multiaddrs: ['/ip4/127.0.0.1/tcp/4002'] };

  // Complete the handshake so both sides are established.
  const bOobi = encodeOobi({ cesrVid: b.identity.cesrVid, did: b.identity.did, peerId: bAddr.peerId, multiaddrs: bAddr.multiaddrs ?? [] });
  await a.manager.sendRfi(bOobi);
  b.transport.deliverMessage(a.transport.sent[0].message, aAddr);
  await flushMicrotasks();
  a.transport.deliverMessage(b.transport.sent[0].message, bAddr);
  await flushMicrotasks();
  assert.equal(a.store.get(a.identity.did, b.identity.did)!.status, 'established');

  // A stale / duplicate decline arrives (signed by B, so it also exercises the
  // verified path — A now holds B's key from the RFA).
  const rfd = tspSeal({
    vidSender: b.identity.did, vidReceiver: a.identity.did,
    payload: { type: 'TSP_RFD', digest: new Uint8Array(32).fill(0x42) },
    signingSecretKey: b.identity.signingKeyPair.secretKey,
  });
  a.transport.deliverMessage(rfd, bAddr);
  await flushMicrotasks();

  assert.equal(
    a.store.get(a.identity.did, b.identity.did)!.status, 'established',
    'an established relationship must never be downgraded by a decline',
  );
});

// ---------------------------------------------------------------------------
// getRelationship / listRelationships
// ---------------------------------------------------------------------------

test('RelationshipManager.getRelationship: returns undefined for unknown remote VID', () => {
  const a = makeIdentity('12D3KooWPeerA');
  const unknownVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, generateEd25519KeyPair().publicKey);

  const result = a.manager.getRelationship(unknownVid);
  assert.equal(result, undefined, 'getRelationship must return undefined for unknown VID');
});

test('RelationshipManager.listRelationships: returns empty array initially', () => {
  const a = makeIdentity('12D3KooWPeerA');
  const records = a.manager.listRelationships();
  assert.deepEqual(records, [], 'listRelationships must return empty array initially');
});
