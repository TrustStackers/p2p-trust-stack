// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for the post-quantum crypto primitives (TSP Rev 3).
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/crypto/pqc.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateMlDsa65KeyPair,
  mlDsa65Sign,
  mlDsa65Verify,
  mlDsa65GetPublicKey,
  generateMlKem768X25519KeyPair,
  mlKem768X25519Encap,
  mlKem768X25519Decap,
  ML_DSA_65_SIG_BYTES,
  MLKEM768_X25519_ENC_BYTES,
  MLKEM768_X25519_SS_BYTES,
  MLKEM768_X25519_PK_BYTES,
  MLKEM768_X25519_SK_BYTES,
} from '../../src/crypto/pqc.js';

test('ML-DSA-65 sign/verify round trip', () => {
  const kp = generateMlDsa65KeyPair();
  const msg = new TextEncoder().encode('post-quantum hello');
  const sig = mlDsa65Sign(msg, kp.secretKey);
  assert.equal(sig.length, ML_DSA_65_SIG_BYTES);
  assert.equal(mlDsa65Verify(sig, msg, kp.publicKey), true);
});

test('ML-DSA-65 tampered signature fails verification', () => {
  const kp = generateMlDsa65KeyPair();
  const msg = new TextEncoder().encode('post-quantum hello');
  const sig = mlDsa65Sign(msg, kp.secretKey);
  const bad = new Uint8Array(sig);
  bad[0] ^= 0xff;
  assert.equal(mlDsa65Verify(bad, msg, kp.publicKey), false);
});

test('ML-DSA-65 getPublicKey recovers the public key from the secret key', () => {
  const kp = generateMlDsa65KeyPair();
  assert.deepEqual(mlDsa65GetPublicKey(kp.secretKey), kp.publicKey);
});

test('MLKEM768-X25519 hybrid encap/decap agree on the shared secret', () => {
  const kp = generateMlKem768X25519KeyPair();
  assert.equal(kp.publicKey.length, MLKEM768_X25519_PK_BYTES);
  assert.equal(kp.secretKey.length, MLKEM768_X25519_SK_BYTES);

  const { enc, sharedSecret } = mlKem768X25519Encap(kp.publicKey);
  assert.equal(enc.length, MLKEM768_X25519_ENC_BYTES);
  assert.equal(sharedSecret.length, MLKEM768_X25519_SS_BYTES);

  const recovered = mlKem768X25519Decap(enc, kp.secretKey);
  assert.deepEqual(recovered, sharedSecret);
});

test('MLKEM768-X25519 enc is 1120 bytes (1088 ML-KEM + 32 X25519)', () => {
  assert.equal(MLKEM768_X25519_ENC_BYTES, 1120);
  assert.equal(MLKEM768_X25519_SS_BYTES, 64);
});
