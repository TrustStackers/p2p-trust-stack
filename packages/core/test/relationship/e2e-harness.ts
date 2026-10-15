// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Shared harness for the Direct Mode end-to-end tests.
 *
 * Extracted from `e2e-direct-mode.test.ts` so a second e2e file can drive the
 * same real libp2p + real did:peer:4 + real RelationshipManager stack without
 * forking ~150 lines of duplicated setup. The extracted helpers are the ones
 * the existing suite used, unchanged; `startPair()`, `collectGenMessages()` and
 * `bodyOfSize()` are new and additive — nothing in the existing tests changes
 * behaviour.
 *
 * Why this exists: the `--E#####` Big-counter defect silently dropped every
 * payload above ~10.7 KB while all codec-level tests passed, because every live
 * body in the suite was 13-26 bytes. Large-body regression coverage has to run
 * through *this* stack (transport + relationship manager), not the codec alone.
 */

import { DatabaseSync } from 'node:sqlite';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createLibp2p, type Libp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { identify } from '@libp2p/identify';

import { createDidPeer4 } from '../../src/did/create.js';
import { resolveDidPeer4 } from '../../src/did/resolve.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { runMigrations } from '../../src/db/migrate.js';
import { IdentityResolver } from '../../src/services/identity-resolver.js';
import { Libp2pTransport } from '../../src/transport/index.js';
import { RelationshipStore } from '../../src/relationship/store.js';
import { RelationshipManager } from '../../src/relationship/manager.js';
import { encodeOobi } from '../../src/relationship/oobi.js';
import type { LocalIdentity } from '../../src/relationship/types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/** A loopback-only libp2p node: TCP + yamux + noise + identify. */
export async function makeLibp2pNode(): Promise<Libp2p> {
  return createLibp2p({
    addresses: { listen: ['/ip4/127.0.0.1/tcp/0'] },
    transports: [tcp()],
    streamMuxers: [yamux()],
    connectionEncrypters: [noise()],
    services: { identify: identify() },
  });
}

/** First listen multiaddr of a node (throws when the node is not listening). */
export function firstMultiaddr(node: Libp2p): string {
  const addrs = node.getMultiaddrs();
  if (addrs.length === 0) throw new Error('Node has no multiaddrs');
  return addrs[0].toString();
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/**
 * Build a LocalIdentity from a createDidPeer4 result.
 *
 * The VID is the CESR-encoded Ed25519 public key (used in TSP envelopes). The
 * didDocument has its `id` field populated with the long-form DID.
 *
 * `extraMultiaddrs` inflates the published service endpoint — the large-payload
 * suite uses it to produce a *legitimately* large inline DID document. Padding
 * the JSON instead would break `didMethod.verify`, because a long-form
 * did:peer:4 hash commits to the document body; extra service endpoints are
 * part of the document and so hash consistently.
 */
export async function makeLocalIdentity(
  node: Libp2p,
  extraMultiaddrs = 0,
): Promise<LocalIdentity> {
  const peerId = node.peerId.toString();
  const multiaddrs = node.getMultiaddrs().map(a => a.toString());
  for (let i = 0; i < extraMultiaddrs; i++) {
    multiaddrs.push(`/ip4/127.0.0.1/tcp/${20000 + i}/p2p/${peerId}`);
  }

  const result = await createDidPeer4({ peerId, multiaddrs });

  // Resolve the DID to get the document with the `id` field populated.
  const resolvedDoc = await resolveDidPeer4(result.did);

  const vid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, result.signingKeyPair.publicKey);

  return {
    cesrVid: vid,
    did: result.did,
    didDocument: resolvedDoc,
    signingKeyPair: result.signingKeyPair,
    agreementKeyPair: result.agreementKeyPair,
    // Carry the post-quantum key pairs through: `createDidPeer4` now PUBLISHES
    // #key-mldsa / #key-kem, and a peer that publishes `#key-kem` will be sealed
    // to under the hybrid KEM — so the local identity must hold the matching
    // secret or it cannot open its own confidential traffic.
    mlDsa65KeyPair: result.mlDsa65KeyPair,
    hybridKemKeyPair: result.hybridKemKeyPair,
  };
}

/** Create a RelationshipStore wired to a resolver + the migrated schema. */
export function makeStore(identity: LocalIdentity, peerId: string): RelationshipStore {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  const resolver = new IdentityResolver(db);
  resolver.resolveLocalIdentity({
    did: identity.did,
    name: 'e2e',
    method: 'did:peer:4',
    peerId,
    cesrVid: identity.cesrVid,
    didDocumentJson: JSON.stringify(identity.didDocument),
  });
  return new RelationshipStore(db, resolver);
}

// ---------------------------------------------------------------------------
// Waiting
// ---------------------------------------------------------------------------

/**
 * Poll until the relationship record for (localDid, remoteDid) is bidirectional,
 * or throw after a timeout.
 */
export async function waitForBidirectional(
  store: RelationshipStore,
  localDid: string,
  remoteDid: string,
  timeoutMs = 5000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const record = store.get(localDid, remoteDid);
    if (record?.direction === 'bidirectional') return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`waitForBidirectional: timed out after ${timeoutMs}ms`);
}

/**
 * Wait for a TSP_GEN message to arrive via onGenMessage, or throw after timeout.
 *
 * NOTE: `onGenMessage` is a single-slot registration (it replaces any previous
 * handler), so a test may only await one message this way. Use
 * {@link collectGenMessages} when a test expects several.
 */
export function waitForGenMessage(
  manager: RelationshipManager,
  timeoutMs = 5000,
): Promise<{ remoteDid: string; body: Uint8Array }> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`waitForGenMessage: timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    manager.onGenMessage((remoteDid, body) => {
      clearTimeout(timer);
      resolve({ remoteDid, body });
    });
  });
}

/** A received application message, as recorded by {@link collectGenMessages}. */
export interface ReceivedGenMessage {
  remoteDid: string;
  body: Uint8Array;
  confidential: boolean;
}

/** A persistent inbound-message collector. */
export interface GenMessageCollector {
  received: ReceivedGenMessage[];
  /** Resolve once `n` messages have arrived, or throw after `timeoutMs`. */
  waitForCount: (n: number, timeoutMs?: number) => Promise<void>;
}

/**
 * Register a persistent collector for inbound TSP_GEN messages plus a
 * `waitForCount(n)` helper. Unlike {@link waitForGenMessage} this survives
 * multiple messages, which is what the large-payload cases need.
 */
export function collectGenMessages(manager: RelationshipManager): GenMessageCollector {
  const received: ReceivedGenMessage[] = [];
  manager.onGenMessage((remoteDid, body, confidential) => {
    received.push({ remoteDid, body, confidential });
  });

  return {
    received,
    waitForCount: async (n, timeoutMs = 10_000) => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (received.length >= n) return;
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      throw new Error(
        `collectGenMessages.waitForCount: timed out after ${timeoutMs}ms ` +
        `waiting for ${n} message(s), got ${received.length}`,
      );
    },
  };
}

/**
 * A deterministic byte body of exactly `chars` ASCII bytes.
 *
 * Deliberately not all-identical bytes: a decoder that mis-slices at a fixed
 * offset often still yields a same-length body, which a `length` check would
 * miss but `deepEqual` catches.
 */
export function bodyOfSize(chars: number, seed = 0): Uint8Array {
  const out = new Uint8Array(chars);
  for (let i = 0; i < chars; i++) out[i] = 32 + ((i * 7 + seed) % 95);
  return out;
}

// ---------------------------------------------------------------------------
// The two-node pair
// ---------------------------------------------------------------------------

/** Two running nodes + managers, plus a `connect()` that completes the handshake. */
export interface E2ePair {
  nodeA: Libp2p;
  nodeB: Libp2p;
  identityA: LocalIdentity;
  identityB: LocalIdentity;
  transportA: Libp2pTransport;
  transportB: Libp2pTransport;
  storeA: RelationshipStore;
  storeB: RelationshipStore;
  managerA: RelationshipManager;
  managerB: RelationshipManager;
  /** Inbound messages, collected from the moment the pair starts. */
  receivedByA: GenMessageCollector;
  receivedByB: GenMessageCollector;
  /** Exchange OOBI out of band, send the RFI, wait for bidirectional on both sides. */
  connect: () => Promise<void>;
  /** Stop both transports and both nodes. Safe to call from a `finally`. */
  stop: () => Promise<void>;
}

/**
 * Start a fully wired agent pair.
 *
 * `aExtraMultiaddrs` inflates A's published DID document (see
 * {@link makeLocalIdentity}) so the RFI A sends carries a large inline
 * document. B always starts with a normal-sized document.
 */
export async function startPair(opts: { aExtraMultiaddrs?: number } = {}): Promise<E2ePair> {
  const nodeA = await makeLibp2pNode();
  const nodeB = await makeLibp2pNode();
  await nodeA.start();
  await nodeB.start();

  const identityA = await makeLocalIdentity(nodeA, opts.aExtraMultiaddrs ?? 0);
  const identityB = await makeLocalIdentity(nodeB);

  const transportA = new Libp2pTransport(nodeA);
  const transportB = new Libp2pTransport(nodeB);
  await transportA.start();
  await transportB.start();

  const storeA = makeStore(identityA, nodeA.peerId.toString());
  const storeB = makeStore(identityB, nodeB.peerId.toString());

  const managerA = new RelationshipManager({ transport: transportA, store: storeA, identity: identityA });
  const managerB = new RelationshipManager({ transport: transportB, store: storeB, identity: identityB });
  const receivedByA = collectGenMessages(managerA);
  const receivedByB = collectGenMessages(managerB);
  managerA.start();
  managerB.start();

  return {
    nodeA, nodeB,
    identityA, identityB,
    transportA, transportB,
    storeA, storeB,
    managerA, managerB,
    receivedByA, receivedByB,

    connect: async () => {
      const oobiB = encodeOobi({
        cesrVid: identityB.cesrVid,
        did: identityB.did,
        peerId: nodeB.peerId.toString(),
        multiaddrs: nodeB.getMultiaddrs().map(a => a.toString()),
      });
      await managerA.sendRfi(oobiB);
      await waitForBidirectional(storeA, identityA.did, identityB.did);
      await waitForBidirectional(storeB, identityB.did, identityA.did);
    },

    stop: async () => {
      await transportA.stop();
      await transportB.stop();
      await nodeA.stop();
      await nodeB.stop();
    },
  };
}
