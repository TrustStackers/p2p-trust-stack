// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for the CESR 2.0 framing helpers (TSP v3 / Rev 3).
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/crypto/cesr-v2.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  NONCE_BYTES,
  encodeNonce,
  decodeNonce,
  encodeEnvelopeTag,
  encodePayloadTag,
  decodeCounter,
} from '../../src/crypto/cesr-v2.js';

function zeros(n: number): Uint8Array {
  return new Uint8Array(n);
}

// ---------------------------------------------------------------------------
// Nonce
// ---------------------------------------------------------------------------

test('encodeNonce produces a 24-char 0A Salt_128 primitive', () => {
  const encoded = encodeNonce(zeros(16));
  assert.equal(encoded.length, 24);
  assert.ok(encoded.startsWith('0A'));
});

test('encodeNonce/decodeNonce round trips 16 bytes', () => {
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = i * 7 + 3;
  assert.deepEqual(decodeNonce(encodeNonce(bytes)), bytes);
});

test('encodeNonce rejects non-16-byte input', () => {
  assert.throws(() => encodeNonce(zeros(15)), RangeError);
  assert.throws(() => encodeNonce(zeros(17)), RangeError);
  assert.throws(() => encodeNonce(zeros(24)), RangeError); // v2 used 24-byte nonces
});

test('decodeNonce rejects a non-Salt_128 primitive', () => {
  assert.throws(() => decodeNonce('IAAAAA'), SyntaxError);
  assert.throws(() => decodeNonce('4BAA'), SyntaxError);
});

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

test('encodeEnvelopeTag emits -E## signable-data counters', () => {
  assert.equal(encodeEnvelopeTag(0), '-EAA');
  assert.equal(encodeEnvelopeTag(4), '-EAE');
});

test('encodePayloadTag emits -Z## payload counters', () => {
  assert.equal(encodePayloadTag(0), '-ZAA');
  assert.equal(encodePayloadTag(2), '-ZAC');
});

test('decodeCounter round trips envelope and payload tags', () => {
  assert.deepEqual(decodeCounter('-EAE'), { code: '-E', count: 4 });
  assert.deepEqual(decodeCounter('-ZAC'), { code: '-Z', count: 2 });
  assert.deepEqual(decodeCounter('-ZAA'), { code: '-Z', count: 0 });
});

test('NONCE_BYTES is 16 (128-bit nonce)', () => {
  assert.equal(NONCE_BYTES, 16);
});
