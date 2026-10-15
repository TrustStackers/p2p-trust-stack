// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for SqliteKeyStore.
 *
 * Covers:
 *   - store/retrieve round trip returns original key bytes
 *   - wrong passphrase throws (AES-GCM auth tag mismatch)
 *   - missing key throws
 *   - overwrite (upsert) works correctly
 *   - both ed25519 and x25519 key types
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/keystore/sqlite-keystore.test.ts
 */

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteKeyStore } from '../../src/keystore/sqlite-keystore.js';
import { generateEd25519KeyPair, ed25519ToX25519 } from '../../src/crypto/primitives.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeStore(): SqliteKeyStore {
  // Use in-memory SQLite for tests — no file cleanup needed
  return new SqliteKeyStore(':memory:');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('SqliteKeyStore: store and retrieve Ed25519 key pair round trip', async () => {
  const store = makeStore();
  after(() => store.close());

  const kp = generateEd25519KeyPair();
  const vid = 'did:peer:4zTestEd25519';
  const passphrase = 'correct-horse-battery-staple';

  await store.storeKeyPairAsync(vid, 'ed25519', kp, passphrase);
  const retrieved = await store.retrieveKeyPairAsync(vid, 'ed25519', passphrase);

  assert.deepEqual(retrieved.secretKey, kp.secretKey, 'retrieved secret key must match original');
  assert.deepEqual(retrieved.publicKey, kp.publicKey, 'retrieved public key must match original');
});

test('SqliteKeyStore: store and retrieve X25519 key pair round trip', async () => {
  const store = makeStore();
  after(() => store.close());

  const ed = generateEd25519KeyPair();
  const kp = ed25519ToX25519(ed.secretKey);
  const vid = 'did:peer:4zTestX25519';
  const passphrase = 'another-secure-passphrase';

  await store.storeKeyPairAsync(vid, 'x25519', kp, passphrase);
  const retrieved = await store.retrieveKeyPairAsync(vid, 'x25519', passphrase);

  assert.deepEqual(retrieved.secretKey, kp.secretKey, 'retrieved X25519 secret key must match original');
  assert.deepEqual(retrieved.publicKey, kp.publicKey, 'retrieved X25519 public key must match original');
});

test('SqliteKeyStore: wrong passphrase throws', async () => {
  const store = makeStore();
  after(() => store.close());

  const kp = generateEd25519KeyPair();
  const vid = 'did:peer:4zTestWrongPass';

  await store.storeKeyPairAsync(vid, 'ed25519', kp, 'correct-passphrase');

  await assert.rejects(
    () => store.retrieveKeyPairAsync(vid, 'ed25519', 'wrong-passphrase'),
    /decryption failed/,
    'wrong passphrase must throw a decryption error',
  );
});

test('SqliteKeyStore: missing key throws', async () => {
  const store = makeStore();
  after(() => store.close());

  await assert.rejects(
    () => store.retrieveKeyPairAsync('did:peer:4zNonExistent', 'ed25519', 'any-passphrase'),
    /no key found/,
    'missing key must throw a not-found error',
  );
});

test('SqliteKeyStore: overwrite (upsert) replaces the existing entry', async () => {
  const store = makeStore();
  after(() => store.close());

  const kp1 = generateEd25519KeyPair();
  const kp2 = generateEd25519KeyPair();
  const vid = 'did:peer:4zTestUpsert';
  const passphrase = 'upsert-passphrase';

  await store.storeKeyPairAsync(vid, 'ed25519', kp1, passphrase);
  await store.storeKeyPairAsync(vid, 'ed25519', kp2, passphrase);

  const retrieved = await store.retrieveKeyPairAsync(vid, 'ed25519', passphrase);
  assert.deepEqual(retrieved.secretKey, kp2.secretKey, 'upsert must replace the secret key with the new one');
  assert.deepEqual(retrieved.publicKey, kp2.publicKey, 'upsert must replace the public key with the new one');
});

test('SqliteKeyStore: ed25519 and x25519 keys for the same VID are stored independently', async () => {
  const store = makeStore();
  after(() => store.close());

  const ed = generateEd25519KeyPair();
  const x = ed25519ToX25519(ed.secretKey);
  const vid = 'did:peer:4zTestBothKeys';
  const passphrase = 'shared-passphrase';

  await store.storeKeyPairAsync(vid, 'ed25519', ed, passphrase);
  await store.storeKeyPairAsync(vid, 'x25519', x, passphrase);

  const retrievedEd = await store.retrieveKeyPairAsync(vid, 'ed25519', passphrase);
  const retrievedX = await store.retrieveKeyPairAsync(vid, 'x25519', passphrase);

  assert.deepEqual(retrievedEd.secretKey, ed.secretKey, 'ed25519 secret key must be stored independently');
  assert.deepEqual(retrievedX.secretKey, x.secretKey, 'x25519 secret key must be stored independently');
  assert.notDeepEqual(retrievedEd.secretKey, retrievedX.secretKey, 'ed25519 and x25519 secret keys must differ');
});
