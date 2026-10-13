/**
 * Tests for the TSP v3 field codecs (Rev 3 CESR 2.0 foundation).
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tsp/fields.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import {
  NULL_VID,
  encodeVid,
  decodeVid,
  isNullVid,
  encodeDigestSha256,
  encodeDigestBlake2b,
  TSP_FIELD_CTL,
  TSP_FIELD_SCS,
  TSP_FIELD_HOP,
  TSP_FIELD_RFI,
  TSP_FIELD_RFA,
  TSP_FIELD_RFD,
  CESR_CODE_TABLE_V2,
  ML_DSA_65_SIGNATURE_CODE,
  MLKEM768_X25519_KEM_ID,
} from '../../src/tsp/fields.js';

function zeros(n: number): Uint8Array {
  return new Uint8Array(n);
}

// ---------------------------------------------------------------------------
// VID_String
// ---------------------------------------------------------------------------

test('encodeVid(empty) is the NULL VID 4BAA', () => {
  assert.equal(encodeVid(zeros(0)), '4BAA');
  assert.equal(NULL_VID, '4BAA');
  assert.equal(isNullVid('4BAA'), true);
  assert.equal(decodeVid('4BAA').length, 0);
});

test('encodeVid/decodeVid round trip for various byte lengths', () => {
  for (const n of [1, 2, 3, 5, 31, 32, 33, 64, 255]) {
    const bytes = new Uint8Array(n);
    for (let i = 0; i < n; i++) bytes[i] = i & 0xff;
    assert.deepEqual(decodeVid(encodeVid(bytes)), bytes, `round trip for ${n} bytes`);
  }
});

test('encodeVid of 32 bytes uses 5B lead-pad form (length % 3 === 2)', () => {
  assert.ok(encodeVid(zeros(0)).startsWith('4B'));   // 0 % 3 === 0 → lead 0
  assert.ok(encodeVid(zeros(32)).startsWith('5B'));  // 32 % 3 === 2 → lead 1
  assert.ok(encodeVid(zeros(34)).startsWith('6B'));  // 34 % 3 === 1 → lead 2
  assert.ok(encodeVid(zeros(33)).startsWith('4B'));  // 33 % 3 === 0 → lead 0
});

test('decodeVid rejects non-variable-length (fixed-code) primitives', () => {
  const ed25519Pub = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, zeros(32)); // "D..."
  assert.throws(() => decodeVid(ed25519Pub), SyntaxError);
});

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

test('encodeDigestSha256 emits the I code, encodeDigestBlake2b the F code', () => {
  const digest = zeros(32);
  assert.ok(encodeDigestSha256(digest).startsWith('I'));
  assert.ok(encodeDigestBlake2b(digest).startsWith('F'));
  assert.equal(encodeDigestSha256(digest).length, 44); // I + 43 chars
  assert.equal(encodeDigestBlake2b(digest).length, 44);
});

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

test('TSP v3 payload field type and code-table constants are correct', () => {
  assert.equal(TSP_FIELD_CTL, 'XCTL');
  assert.equal(TSP_FIELD_SCS, 'XSCS');
  assert.equal(TSP_FIELD_HOP, 'XHOP');
  assert.equal(TSP_FIELD_RFI, 'XRFI');
  assert.equal(TSP_FIELD_RFA, 'XRFA');
  assert.equal(TSP_FIELD_RFD, 'XRFD');
  assert.equal(CESR_CODE_TABLE_V2, '-_AAACAA');
  assert.equal(ML_DSA_65_SIGNATURE_CODE, '1AAQ');
  assert.equal(MLKEM768_X25519_KEM_ID, 0x647a);
});
