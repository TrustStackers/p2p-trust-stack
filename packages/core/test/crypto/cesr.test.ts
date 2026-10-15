// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for the CESR codec (backed by the cesr npm library).
 *
 * Covers:
 *   - Encode/decode round trip for every code type
 *   - Malformed / wrong-length input rejection
 *   - Group framing encode/decode round trip
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/crypto/cesr.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Matter } from 'cesr';
import {
  cesrEncode,
  cesrDecode,
  cesrEncodeGroup,
  cesrDecodeGroup,
  CESR_CODES,
} from '../../src/crypto/cesr.js';
import { CESR_BYTE_LENGTHS } from '../../src/crypto/codes.js';
import type { CesrCode } from '../../src/crypto/cesr.js';

// ---------------------------------------------------------------------------
// Wire-code translation (audit F-013)
//
// The audit reported this stack's "TSP" as project-defined — "two internal codes
// differ from the CESR wire table", group framing "-T##", and "no genus/version
// code ever emitted". Re-verified at HEAD: the version string IS emitted (an
// existing test in test/tsp/v3-message.test.ts pins `-E##` envelope + YTSP-AAC),
// framing uses the reference library's own counter, and the code difference is
// true of the INTERNAL NAMES only — `cesrEncode` translates to the library's wire
// codes before emitting and `cesrDecode` translates back.
//
// These tests pin that translation so the layer cannot silently break, and so a
// future reader does not "fix" a divergence that does not exist on the wire.
// ---------------------------------------------------------------------------

test('F-013: internal code names are TRANSLATED to the CESR wire codes on encode', () => {
  const x25519 = cesrEncode(CESR_CODES.X25519_PUBLIC_KEY, makeBytes(32));
  assert.equal(x25519[0], Matter.Code.X25519, 'emits the library code');
  assert.equal(x25519[0], 'C', 'which is "C"');
  assert.notEqual(x25519[0], CESR_CODES.X25519_PUBLIC_KEY, 'and NOT the internal name "X"');

  const digest = cesrEncode(CESR_CODES.SHA2_256_DIGEST, makeBytes(32));
  assert.equal(digest[0], Matter.Code.SHA2_256, 'emits the library code');
  assert.equal(digest[0], 'I', 'which is "I", not "E" (the lib\'s "E" is Blake3-256)');
  assert.notEqual(digest[0], CESR_CODES.SHA2_256_DIGEST, 'and NOT the internal name "E"');
});

test('F-013: decode maps the wire codes back to the internal names', () => {
  assert.equal(
    cesrDecode(cesrEncode(CESR_CODES.X25519_PUBLIC_KEY, makeBytes(32))).code,
    CESR_CODES.X25519_PUBLIC_KEY,
    'callers keep using internal names on the way back in',
  );
  assert.equal(
    cesrDecode(cesrEncode(CESR_CODES.SHA2_256_DIGEST, makeBytes(32))).code,
    CESR_CODES.SHA2_256_DIGEST,
  );
});

test('F-013: a 24-byte NONCE uses variable-length Bytes framing (deliberate, with a cost)', () => {
  // The library's '0A' is 16-byte Salt_128, so a 24-byte nonce cannot use it and is
  // emitted as Bytes_L0/L1/L2 instead. The doc in codes.ts records the choice. The
  // cost is worth naming: a spec-conformant reader sees an anonymous byte string
  // rather than something identifiable as a nonce — the one genuine residue of
  // F-013, and it is semantic, not framing.
  const nonce = cesrEncode(CESR_CODES.NONCE, makeBytes(24));
  assert.ok(
    ['4B', '5B', '6B'].includes(nonce.slice(0, 2)),
    `expected a Bytes_L variable-length code, got "${nonce.slice(0, 2)}"`,
  );
  assert.notEqual(nonce.slice(0, 2), CESR_CODES.NONCE, 'and not the internal "0A" form');
});

test('F-013: group framing is the reference library counter, round-tripping to internal codes', () => {
  const frame = cesrEncodeGroup([
    { code: CESR_CODES.SHA2_256_DIGEST, bytes: makeBytes(32) },
    { code: CESR_CODES.ED25519_PUBLIC_KEY, bytes: makeBytes(32) },
  ]);

  // GenericGroup counter, i.e. the framing the CESR table defines — not a
  // project-invented header.
  assert.ok(frame.startsWith('-T'), `expected a -T GenericGroup header, got "${frame.slice(0, 4)}"`);

  const items = cesrDecodeGroup(frame);
  assert.deepEqual(
    items.map((i) => i.code),
    [CESR_CODES.SHA2_256_DIGEST, CESR_CODES.ED25519_PUBLIC_KEY],
    'and decoding yields the internal codes again',
  );
});


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Create a Uint8Array of the given length filled with a repeating byte value. */
function makeBytes(length: number, fill = 0xab): Uint8Array {
  return new Uint8Array(length).fill(fill);
}

// ---------------------------------------------------------------------------
// Round-trip tests for every code type
// ---------------------------------------------------------------------------

const allCodes = Object.values(CESR_CODES) as CesrCode[];

// Codes whose wire representation changed when migrating to the cesr library:
//   'X' (X25519) → cesr lib uses 'C'; encoded string starts with 'C', not 'X'
//   'E' (SHA2_256_DIGEST) → cesr lib uses 'I'; encoded string starts with 'I', not 'E'
//   '0A' (NONCE, 24 bytes) → cesr lib's '0A' is Salt_128 (16 bytes); we encode
//        24-byte nonces as variable-length (4B/5B/6B), not fixed-length '0A'
//   '4B' (VARIABLE_BYTES) → tested separately below; skip in fixed-length loop
const CODES_WITH_CHANGED_WIRE_FORMAT = new Set<CesrCode>([
  CESR_CODES.X25519_PUBLIC_KEY,  // 'X' → cesr lib uses 'C'
  CESR_CODES.SHA2_256_DIGEST,    // 'E' → cesr lib uses 'I'
  CESR_CODES.NONCE,              // '0A' 24-byte → now variable-length
  CESR_CODES.VARIABLE_BYTES,     // '4B' → tested separately
]);

for (const code of allCodes) {
  const expectedLen = CESR_BYTE_LENGTHS[code];

  // Skip codes whose wire format changed in the cesr library migration
  if (CODES_WITH_CHANGED_WIRE_FORMAT.has(code)) continue;

  test(`cesrEncode/cesrDecode round trip: code "${code}" (${expectedLen} bytes)`, () => {
    const original = makeBytes(expectedLen);
    const encoded = cesrEncode(code, original);

    // Encoded string must start with the code
    assert.ok(
      encoded.startsWith(code),
      `encoded string must start with code "${code}"`,
    );

    const { code: decodedCode, bytes: decodedBytes } = cesrDecode(encoded);
    assert.equal(decodedCode, code, 'decoded code must match original');
    assert.deepEqual(decodedBytes, original, 'decoded bytes must match original');
  });
}

// X25519 public key: our CESR_CODES.X25519_PUBLIC_KEY is 'X' but the cesr library
// uses 'C'. cesrEncode('X', bytes) encodes using 'C' on the wire; cesrDecode
// returns code 'X' (our canonical name) with the correct bytes.
test('cesrEncode/cesrDecode round trip: X25519 public key (code "X" → wire "C")', () => {
  const original = makeBytes(32);
  const encoded = cesrEncode(CESR_CODES.X25519_PUBLIC_KEY, original);
  assert.ok(encoded.startsWith('C'), 'X25519 pubkey must use cesr lib code "C" on the wire');
  const { code: decodedCode, bytes: decodedBytes } = cesrDecode(encoded);
  assert.equal(decodedCode, CESR_CODES.X25519_PUBLIC_KEY, 'decoded code must be X25519_PUBLIC_KEY');
  assert.deepEqual(decodedBytes, original, 'decoded bytes must match original');
});

// NONCE (24 bytes): our CESR_CODES.NONCE is '0A' but the cesr library's '0A' is
// Salt_128 (16 bytes). We encode 24-byte nonces as variable-length (4B/5B/6B).
// cesrDecode returns code VARIABLE_BYTES for any variable-length item.
test('cesrEncode/cesrDecode round trip: NONCE (24 bytes → variable-length)', () => {
  const original = makeBytes(24);
  const encoded = cesrEncode(CESR_CODES.NONCE, original);
  // 24 bytes: 24 % 3 = 0 → Bytes_L0 → '4B'
  assert.ok(encoded.startsWith('4B'), 'NONCE (24 bytes) must encode as variable-length "4B"');
  const { code: decodedCode, bytes: decodedBytes } = cesrDecode(encoded);
  assert.equal(decodedCode, CESR_CODES.VARIABLE_BYTES, 'decoded code must be VARIABLE_BYTES');
  assert.deepEqual(decodedBytes, original, 'decoded bytes must match original');
});

// ---------------------------------------------------------------------------
// Wrong-length input rejection
// ---------------------------------------------------------------------------

test('cesrEncode: rejects bytes with wrong length', () => {
  const code = CESR_CODES.ED25519_SIGNATURE; // expects 64 bytes
  assert.throws(
    () => cesrEncode(code, makeBytes(32)), // wrong: 32 bytes
    RangeError,
    'cesrEncode must throw RangeError for wrong-length input',
  );
});

test('cesrEncode: rejects empty bytes for non-zero-length code', () => {
  assert.throws(
    () => cesrEncode(CESR_CODES.SHA2_256_DIGEST, new Uint8Array(0)),
    RangeError,
  );
});

// ---------------------------------------------------------------------------
// Malformed decode input
// ---------------------------------------------------------------------------

test('cesrDecode: rejects string with unknown code prefix', () => {
  assert.throws(
    () => cesrDecode('ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ'),
    SyntaxError,
    'cesrDecode must throw SyntaxError for unknown code',
  );
});

test('cesrDecode: rejects truncated base64 payload', () => {
  // Encode a valid value, then truncate the base64 part.
  // The cesr library throws a generic Error (not RangeError/SyntaxError) for
  // truncated input ("Could not parse frame from input"), so we accept any Error.
  const valid = cesrEncode(CESR_CODES.SHA2_256_DIGEST, makeBytes(32));
  const truncated = valid.slice(0, valid.length - 4);
  assert.throws(
    () => cesrDecode(truncated),
    // cesr library throws Error; our wrapper may also throw RangeError or SyntaxError
    (err) => err instanceof Error,
    'cesrDecode must throw for truncated payload',
  );
});

// ---------------------------------------------------------------------------
// Group framing
// ---------------------------------------------------------------------------

test('cesrEncodeGroup/cesrDecodeGroup: empty group round trips', () => {
  const encoded = cesrEncodeGroup([]);
  assert.ok(encoded.startsWith('-TAA'), 'empty group must start with "-TAA" (GenericGroup count=0)');
  const decoded = cesrDecodeGroup(encoded);
  assert.deepEqual(decoded, [], 'empty group must decode to empty array');
});

test('cesrEncodeGroup/cesrDecodeGroup: single item round trip', () => {
  const bytes = makeBytes(32, 0x42);
  const parts = [{ code: CESR_CODES.SHA2_256_DIGEST as CesrCode, bytes }];
  const encoded = cesrEncodeGroup(parts);
  const decoded = cesrDecodeGroup(encoded);
  assert.equal(decoded.length, 1, 'must decode exactly 1 item');
  assert.equal(decoded[0].code, CESR_CODES.SHA2_256_DIGEST);
  assert.deepEqual(decoded[0].bytes, bytes);
});

test('cesrEncodeGroup/cesrDecodeGroup: multiple items of different types', () => {
  const sigBytes = makeBytes(64, 0x01);
  const keyBytes = makeBytes(32, 0x02);
  const digestBytes = makeBytes(32, 0x03);

  const parts = [
    { code: CESR_CODES.ED25519_SIGNATURE as CesrCode, bytes: sigBytes },
    { code: CESR_CODES.ED25519_PUBLIC_KEY as CesrCode, bytes: keyBytes },
    { code: CESR_CODES.SHA2_256_DIGEST as CesrCode, bytes: digestBytes },
  ];

  const encoded = cesrEncodeGroup(parts);
  assert.ok(encoded.startsWith('-TAD'), 'group of 3 must start with "-TAD" (GenericGroup count=3)');

  const decoded = cesrDecodeGroup(encoded);
  assert.equal(decoded.length, 3, 'must decode exactly 3 items');

  assert.equal(decoded[0].code, CESR_CODES.ED25519_SIGNATURE);
  assert.deepEqual(decoded[0].bytes, sigBytes);

  assert.equal(decoded[1].code, CESR_CODES.ED25519_PUBLIC_KEY);
  assert.deepEqual(decoded[1].bytes, keyBytes);

  assert.equal(decoded[2].code, CESR_CODES.SHA2_256_DIGEST);
  assert.deepEqual(decoded[2].bytes, digestBytes);
});

test('cesrEncodeGroup/cesrDecodeGroup: both digest types in same group', () => {
  const sha = makeBytes(32, 0xaa);
  const b2b = makeBytes(32, 0xbb);

  const parts = [
    { code: CESR_CODES.SHA2_256_DIGEST as CesrCode, bytes: sha },
    { code: CESR_CODES.BLAKE2B_256_DIGEST as CesrCode, bytes: b2b },
  ];

  const encoded = cesrEncodeGroup(parts);
  const decoded = cesrDecodeGroup(encoded);

  assert.equal(decoded.length, 2);
  assert.equal(decoded[0].code, CESR_CODES.SHA2_256_DIGEST);
  assert.deepEqual(decoded[0].bytes, sha);
  assert.equal(decoded[1].code, CESR_CODES.BLAKE2B_256_DIGEST);
  assert.deepEqual(decoded[1].bytes, b2b);
});

test('cesrDecodeGroup: rejects string without group prefix', () => {
  assert.throws(
    () => cesrDecodeGroup('DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
    SyntaxError,
    'must throw SyntaxError when group prefix is missing',
  );
});

test('cesrDecodeGroup: rejects non-GenericGroup counter', () => {
  // '-G' is SealSourceCouples, not GenericGroup ('-T')
  assert.throws(
    () => cesrDecodeGroup('-GAA'),
    SyntaxError,
    'must throw SyntaxError for non-GenericGroup counter',
  );
});

test('cesrDecodeGroup: rejects invalid counter (old -G4. format)', () => {
  // Old custom format '-G4.' has invalid base64 '.' — Counter.peek throws
  assert.throws(
    () => cesrDecodeGroup('-G4.'),
    SyntaxError,
    'must throw SyntaxError for old -G4. format',
  );
});

// ---------------------------------------------------------------------------
// Encoding properties
// ---------------------------------------------------------------------------

test('cesrEncode: different byte values produce different encoded strings', () => {
  const a = cesrEncode(CESR_CODES.SHA2_256_DIGEST, makeBytes(32, 0x00));
  const b = cesrEncode(CESR_CODES.SHA2_256_DIGEST, makeBytes(32, 0xff));
  assert.notEqual(a, b, 'different bytes must produce different encoded strings');
});

test('cesrEncode: same bytes produce the same encoded string (deterministic)', () => {
  const bytes = makeBytes(32, 0x7f);
  const a = cesrEncode(CESR_CODES.SHA2_256_DIGEST, bytes);
  const b = cesrEncode(CESR_CODES.SHA2_256_DIGEST, bytes);
  assert.equal(a, b, 'encoding must be deterministic');
});

// ---------------------------------------------------------------------------
// VARIABLE_BYTES encode / decode
// ---------------------------------------------------------------------------

test('cesrEncode/cesrDecode: VARIABLE_BYTES empty payload round trips', () => {
  const empty = new Uint8Array(0);
  const encoded = cesrEncode(CESR_CODES.VARIABLE_BYTES, empty);
  assert.ok(encoded.startsWith('4B'), 'VARIABLE_BYTES must start with "4B"');
  const { code, bytes } = cesrDecode(encoded);
  assert.equal(code, CESR_CODES.VARIABLE_BYTES);
  assert.deepEqual(bytes, empty, 'empty payload must round trip');
});

test('cesrEncode/cesrDecode: VARIABLE_BYTES small payload round trips', () => {
  const payload = new TextEncoder().encode('hello TSP');
  const encoded = cesrEncode(CESR_CODES.VARIABLE_BYTES, payload);
  assert.ok(encoded.startsWith('4B'), 'VARIABLE_BYTES must start with "4B"');
  const { code, bytes } = cesrDecode(encoded);
  assert.equal(code, CESR_CODES.VARIABLE_BYTES);
  assert.deepEqual(bytes, payload, 'small payload must round trip');
});

test('cesrEncode/cesrDecode: VARIABLE_BYTES binary payload (all byte values 0-255) round trips', () => {
  const payload = new Uint8Array(256);
  for (let i = 0; i < 256; i++) payload[i] = i;
  const encoded = cesrEncode(CESR_CODES.VARIABLE_BYTES, payload);
  const { bytes } = cesrDecode(encoded);
  assert.deepEqual(bytes, payload, 'binary payload must round trip unchanged');
});

test('cesrEncode/cesrDecode: VARIABLE_BYTES large payload (10 KB) round trips', () => {
  const payload = new Uint8Array(10240).fill(0xab);
  const encoded = cesrEncode(CESR_CODES.VARIABLE_BYTES, payload);
  const { bytes } = cesrDecode(encoded);
  assert.deepEqual(bytes, payload, 'large payload must round trip unchanged');
});

test('cesrEncode/cesrDecode: VARIABLE_BYTES different payloads produce different encodings', () => {
  const a = cesrEncode(CESR_CODES.VARIABLE_BYTES, new TextEncoder().encode('hello'));
  const b = cesrEncode(CESR_CODES.VARIABLE_BYTES, new TextEncoder().encode('world'));
  assert.notEqual(a, b, 'different payloads must produce different encodings');
});

test('cesrEncodeGroup/cesrDecodeGroup: group with VARIABLE_BYTES item round trips', () => {
  const body = new TextEncoder().encode('variable body content');
  const digest = makeBytes(32, 0x55);

  const parts = [
    { code: CESR_CODES.SHA2_256_DIGEST as CesrCode, bytes: digest },
    { code: CESR_CODES.VARIABLE_BYTES as CesrCode, bytes: body },
  ];

  const encoded = cesrEncodeGroup(parts);
  assert.ok(encoded.startsWith('-TAC'), 'group of 2 must start with "-TAC" (GenericGroup count=2)');

  const decoded = cesrDecodeGroup(encoded);
  assert.equal(decoded.length, 2, 'must decode exactly 2 items');
  assert.equal(decoded[0].code, CESR_CODES.SHA2_256_DIGEST);
  assert.deepEqual(decoded[0].bytes, digest);
  assert.equal(decoded[1].code, CESR_CODES.VARIABLE_BYTES);
  assert.deepEqual(decoded[1].bytes, body, 'VARIABLE_BYTES body must survive group encode/decode');
});

test('cesrEncodeGroup/cesrDecodeGroup: group with multiple VARIABLE_BYTES items round trips', () => {
  const body1 = new TextEncoder().encode('first variable field');
  const body2 = new Uint8Array(100).fill(0xcc);

  const parts = [
    { code: CESR_CODES.VARIABLE_BYTES as CesrCode, bytes: body1 },
    { code: CESR_CODES.VARIABLE_BYTES as CesrCode, bytes: body2 },
  ];

  const encoded = cesrEncodeGroup(parts);
  const decoded = cesrDecodeGroup(encoded);

  assert.equal(decoded.length, 2);
  assert.deepEqual(decoded[0].bytes, body1);
  assert.deepEqual(decoded[1].bytes, body2);
});

test('cesrEncodeGroup/cesrDecodeGroup: mixed fixed and variable items round trip', () => {
  const sigBytes = makeBytes(64, 0x01);
  const keyBytes = makeBytes(32, 0x02);
  const varBytes = new TextEncoder().encode('inner CESR group payload');

  const parts = [
    { code: CESR_CODES.ED25519_SIGNATURE as CesrCode, bytes: sigBytes },
    { code: CESR_CODES.ED25519_PUBLIC_KEY as CesrCode, bytes: keyBytes },
    { code: CESR_CODES.VARIABLE_BYTES as CesrCode, bytes: varBytes },
  ];

  const encoded = cesrEncodeGroup(parts);
  assert.ok(encoded.startsWith('-TAD'), 'group of 3 must start with "-TAD" (GenericGroup count=3)');

  const decoded = cesrDecodeGroup(encoded);
  assert.equal(decoded.length, 3);
  assert.equal(decoded[0].code, CESR_CODES.ED25519_SIGNATURE);
  assert.deepEqual(decoded[0].bytes, sigBytes);
  assert.equal(decoded[1].code, CESR_CODES.ED25519_PUBLIC_KEY);
  assert.deepEqual(decoded[1].bytes, keyBytes);
  assert.equal(decoded[2].code, CESR_CODES.VARIABLE_BYTES);
  assert.deepEqual(decoded[2].bytes, varBytes);
});

test('cesrEncode: VARIABLE_BYTES encoded string uses a variable-length code (4B/5B/6B)', () => {
  // 'test' is 4 bytes: 4 % 3 = 1 → leadSize = 2 → Bytes_L2 → '6B'
  const payload = new TextEncoder().encode('test');
  const encoded = cesrEncode(CESR_CODES.VARIABLE_BYTES, payload);
  const prefix2 = encoded.slice(0, 2);
  assert.ok(
    prefix2 === '4B' || prefix2 === '5B' || prefix2 === '6B',
    `VARIABLE_BYTES must use a variable-length code (4B/5B/6B), got "${prefix2}"`,
  );
});

test('cesrEncode: VARIABLE_BYTES encoded string is valid base64url after the code', () => {
  const payload = new TextEncoder().encode('test');
  const encoded = cesrEncode(CESR_CODES.VARIABLE_BYTES, payload);
  const afterCode = encoded.slice(2); // skip 2-char code
  assert.ok(
    /^[A-Za-z0-9_-]+$/.test(afterCode),
    'payload after code must be valid base64url',
  );
});
