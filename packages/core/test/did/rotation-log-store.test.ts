/**
 * Tests for RotationLogStore — Step 11, Task 11.6.
 *
 * Covers:
 *   - Constructor initialisation
 *   - appendEntry / getLog round-trip
 *   - appendEntry throws on duplicate (did, version)
 *   - getLatestEntry
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/did/rotation-log-store.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

import { runMigrations } from '../../src/db/migrate.js';
import { IdentityResolver } from '../../src/services/identity-resolver.js';
import { generateEd25519KeyPair, signEd25519 } from '../../src/crypto/primitives.js';
import { buildDidPeer4Document } from '../../src/did/create.js';
import { computeRotationEntryDigest, computeNextKeyCommitments } from '../../src/did/rotation-codec.js';
import { RotationLogStore } from '../../src/did/rotation-log-store.js';
import type { RotationLogEntry } from '../../src/did/rotation-types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeStore(): { db: DatabaseSync; resolver: IdentityResolver; store: RotationLogStore } {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  const resolver = new IdentityResolver(db);
  const store = new RotationLogStore(db, resolver);
  return { db, resolver, store };
}

/** Register an identity via the resolver so lookupByDid succeeds for rotation log tests. */
function ensureIdentity(resolver: IdentityResolver, did: string, didDocument?: object): void {
  if (resolver.lookupByDid(did)) {
    return;
  }
  resolver.resolveRemoteIdentity({
    did,
    method: 'peer4',
    didDocumentJson: didDocument ? JSON.stringify(didDocument) : undefined,
    isPrimary: true,
    recordedByNode: 'test',
  });
}

function makeGenesisEntry(did: string): RotationLogEntry {
  const signingKeyPair = generateEd25519KeyPair();
  const nextKeyPair = generateEd25519KeyPair();
  const doc = buildDidPeer4Document(signingKeyPair.publicKey, generateEd25519KeyPair().publicKey);
  const docWithId = { ...doc, id: did };

  const unsigned = {
    version: 0,
    didDocument: docWithId,
    prevHash: null as Uint8Array | null,
    nextKeyCommitments: computeNextKeyCommitments([nextKeyPair.publicKey]),
    createdAt: 1700000000,
  };
  const digest = computeRotationEntryDigest(unsigned);
  const signature = signEd25519(digest, signingKeyPair.secretKey);

  return { ...unsigned, digest, signature, witnessAttestations: [] };
}

function makeNextEntry(prev: RotationLogEntry, did: string): RotationLogEntry {
  const signingKeyPair = generateEd25519KeyPair();
  const nextKeyPair = generateEd25519KeyPair();
  const doc = buildDidPeer4Document(signingKeyPair.publicKey, generateEd25519KeyPair().publicKey);
  const docWithId = { ...doc, id: did };

  const unsigned = {
    version: prev.version + 1,
    didDocument: docWithId,
    prevHash: prev.digest as Uint8Array | null,
    nextKeyCommitments: computeNextKeyCommitments([nextKeyPair.publicKey]),
    createdAt: prev.createdAt + 100,
  };
  const digest = computeRotationEntryDigest(unsigned);
  const signature = signEd25519(digest, signingKeyPair.secretKey);

  return { ...unsigned, digest, signature, witnessAttestations: [] };
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

test('RotationLogStore: constructor initialises without error', () => {
  const { store } = makeStore();
  assert.ok(store, 'store must be created');
});

// ---------------------------------------------------------------------------
// appendEntry / getLog
// ---------------------------------------------------------------------------

test('RotationLogStore.appendEntry / getLog: round-trips a genesis entry', () => {
  const { resolver, store } = makeStore();
  const did = 'did:webvh-rotating:abc123';
  const entry = makeGenesisEntry(did);

  ensureIdentity(resolver, did, entry.didDocument);
  store.appendEntry(did, entry);
  const log = store.getLog(did);

  assert.equal(log.length, 1);
  assert.equal(log[0].version, 0);
  assert.deepEqual(log[0].didDocument, entry.didDocument);
  assert.equal(log[0].prevHash, null);
  assert.deepEqual(log[0].nextKeyCommitments, entry.nextKeyCommitments);
  assert.deepEqual(log[0].digest, entry.digest);
  assert.deepEqual(log[0].signature, entry.signature);
  assert.equal(log[0].createdAt, entry.createdAt);
  assert.deepEqual(log[0].witnessAttestations, []);
});

test('RotationLogStore.getLog: returns entries ordered by version ascending', () => {
  const { resolver, store } = makeStore();
  const did = 'did:webvh-rotating:multi';
  const entry0 = makeGenesisEntry(did);
  const entry1 = makeNextEntry(entry0, did);
  const entry2 = makeNextEntry(entry1, did);

  ensureIdentity(resolver, did, entry0.didDocument);

  store.appendEntry(did, entry2);
  store.appendEntry(did, entry0);
  store.appendEntry(did, entry1);

  const log = store.getLog(did);
  assert.equal(log.length, 3);
  assert.equal(log[0].version, 0);
  assert.equal(log[1].version, 1);
  assert.equal(log[2].version, 2);
});

test('RotationLogStore.getLog: returns empty array for unknown did', () => {
  const { store } = makeStore();
  assert.deepEqual(store.getLog('did:webvh-rotating:nonexistent'), []);
});

// ---------------------------------------------------------------------------
// appendEntry — duplicate rejection
// ---------------------------------------------------------------------------

test('RotationLogStore.appendEntry: throws on duplicate (did, version)', () => {
  const { resolver, store } = makeStore();
  const did = 'did:webvh-rotating:dup';
  const entry = makeGenesisEntry(did);

  ensureIdentity(resolver, did, entry.didDocument);
  store.appendEntry(did, entry);
  assert.throws(() => store.appendEntry(did, entry));
});

// ---------------------------------------------------------------------------
// getLatestEntry
// ---------------------------------------------------------------------------

test('RotationLogStore.getLatestEntry: returns the highest-version entry', () => {
  const { resolver, store } = makeStore();
  const did = 'did:webvh-rotating:latest';
  const entry0 = makeGenesisEntry(did);
  const entry1 = makeNextEntry(entry0, did);

  ensureIdentity(resolver, did, entry0.didDocument);
  store.appendEntry(did, entry0);
  store.appendEntry(did, entry1);

  const latest = store.getLatestEntry(did);
  assert.ok(latest);
  assert.equal(latest!.version, 1);
  assert.deepEqual(latest!.digest, entry1.digest);
});

test('RotationLogStore.getLatestEntry: returns undefined when no entries exist', () => {
  const { store } = makeStore();
  assert.equal(store.getLatestEntry('did:webvh-rotating:none'), undefined);
});
