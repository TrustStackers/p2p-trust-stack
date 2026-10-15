// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for OOBI encoding/decoding — Step 4, Task 4.1.
 *
 * Covers:
 *   - Round-trip: encodeOobi → decodeOobi → deep-equal original
 *   - Starts with "-TAC" (3-item GenericGroup counter)
 *   - Empty multiaddrs array round-trips correctly
 *   - Malformed input throws SyntaxError
 *   - Different VIDs produce different encoded OOBIs
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/relationship/oobi.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateEd25519KeyPair,
} from '../../src/crypto/primitives.js';
import {
  cesrEncode,
  cesrEncodeGroup,
  CESR_CODES,
} from '../../src/crypto/cesr.js';
import {
  encodeOobi,
  decodeOobi,
  signOobi,
  verifyOobiSignature,
  oobiIntroductionBytes,
} from '../../src/relationship/oobi.js';
import { generateMlDsa65KeyPair } from '../../src/crypto/pqc.js';
import type { OobiPayload } from '../../src/relationship/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeVid(): string {
  const kp = generateEd25519KeyPair();
  return cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, kp.publicKey);
}

function makeOobi(overrides?: Partial<OobiPayload>): OobiPayload {
  return {
    cesrVid: makeVid(),
    peerId: '12D3KooWExamplePeerIdABCDEFGHIJKLMNOPQRSTUVWXYZ',
    multiaddrs: ['/ip4/127.0.0.1/tcp/4001', '/ip4/192.168.1.1/udp/4001/quic-v1'],
    did: 'did:scid:vh:1:zExampleDid',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

test('encodeOobi/decodeOobi: round trip — vid, peerId, multiaddrs preserved', () => {
  const oobi = makeOobi();
  const encoded = encodeOobi(oobi);
  const decoded = decodeOobi(encoded);

  assert.equal(decoded.cesrVid, oobi.cesrVid, 'vid must be preserved');
  assert.equal(decoded.peerId, oobi.peerId, 'peerId must be preserved');
  assert.deepEqual(decoded.multiaddrs, oobi.multiaddrs, 'multiaddrs must be preserved');
  assert.equal(decoded.did, oobi.did, 'did must be preserved');
});

test('encodeOobi/decodeOobi: empty multiaddrs array round-trips correctly', () => {
  const oobi = makeOobi({ multiaddrs: [] });
  const encoded = encodeOobi(oobi);
  const decoded = decodeOobi(encoded);

  assert.deepEqual(decoded.multiaddrs, [], 'empty multiaddrs must round-trip as empty array');
});

test('encodeOobi/decodeOobi: single multiaddr round-trips correctly', () => {
  const oobi = makeOobi({ multiaddrs: ['/ip4/10.0.0.1/tcp/9000'] });
  const encoded = encodeOobi(oobi);
  const decoded = decodeOobi(encoded);

  assert.deepEqual(decoded.multiaddrs, ['/ip4/10.0.0.1/tcp/9000']);
});

test('encodeOobi/decodeOobi: peerId with special characters round-trips correctly', () => {
  const oobi = makeOobi({ peerId: '12D3KooWABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnop' });
  const encoded = encodeOobi(oobi);
  const decoded = decodeOobi(encoded);

  assert.equal(decoded.peerId, oobi.peerId);
});

// ---------------------------------------------------------------------------
// Wire format properties
// ---------------------------------------------------------------------------

test('encodeOobi: encoded string starts with "-TAE" (4-item GenericGroup)', () => {
  // GenericGroup counter: '-T' + base64url(count), where base64url(4) = 'E'.
  const oobi = makeOobi();
  const encoded = encodeOobi(oobi);

  assert.ok(encoded.startsWith('-TAE'), `encoded OOBI must start with "-TAE" (4-item GenericGroup), got "${encoded.slice(0, 8)}"`);
});

test('encodeOobi: encoded string is ASCII-safe (CESR is base64url)', () => {
  const oobi = makeOobi();
  const encoded = encodeOobi(oobi);

  // All characters should be ASCII printable (base64url + '-' for counter prefix).
  assert.ok(/^[\x20-\x7E]+$/.test(encoded), 'encoded OOBI must be ASCII-safe');
});

test('encodeOobi: different VIDs produce different encoded OOBIs', () => {
  const oobi1 = makeOobi();
  const oobi2 = makeOobi(); // different VID (fresh key pair)

  const encoded1 = encodeOobi(oobi1);
  const encoded2 = encodeOobi(oobi2);

  assert.notEqual(encoded1, encoded2, 'different VIDs must produce different encoded OOBIs');
});

test('encodeOobi: same OOBI encoded twice produces identical strings (deterministic)', () => {
  const oobi = makeOobi();
  const encoded1 = encodeOobi(oobi);
  const encoded2 = encodeOobi(oobi);

  assert.equal(encoded1, encoded2, 'encodeOobi must be deterministic');
});

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

test('decodeOobi: malformed input throws SyntaxError', () => {
  assert.throws(
    () => decodeOobi('not-a-cesr-string'),
    SyntaxError,
    'malformed input must throw SyntaxError',
  );
});

test('decodeOobi: empty string throws SyntaxError', () => {
  assert.throws(
    () => decodeOobi(''),
    SyntaxError,
    'empty string must throw SyntaxError',
  );
});

test('decodeOobi: wrong item count throws SyntaxError', () => {
  // A 2-item group (not the strict 4) must throw.
  const twoItemGroup = cesrEncodeGroup([
    { code: CESR_CODES.ED25519_PUBLIC_KEY, bytes: new Uint8Array(32).fill(1) },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode('peerId') },
  ]);

  assert.throws(
    () => decodeOobi(twoItemGroup),
    SyntaxError,
    '2-item group must throw SyntaxError (expected 4 items)',
  );
});

test('decodeOobi: legacy 3-item OOBI is REJECTED (strict 4-item, no fallback)', () => {
  const legacyThreeItem = cesrEncodeGroup([
    { code: CESR_CODES.ED25519_PUBLIC_KEY, bytes: new Uint8Array(32).fill(7) },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode('peerId') },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode('[]') },
  ]);

  assert.throws(
    () => decodeOobi(legacyThreeItem),
    SyntaxError,
    '3-item frame must throw SyntaxError (the OOBI format is strictly 4 items)',
  );
});

test('encodeOobi: non-ED25519_PUBLIC_KEY vid throws TypeError', () => {
  // Construct a fake VID that is not an ED25519_PUBLIC_KEY CESR string.
  // Use a SHA2_256_DIGEST code instead.
  const fakeVid = cesrEncode(CESR_CODES.SHA2_256_DIGEST, new Uint8Array(32).fill(0xab));

  assert.throws(
    () => encodeOobi({ cesrVid: fakeVid, peerId: 'test', multiaddrs: [], did: 'did:scid:vh:1:zX' }),
    TypeError,
    'non-ED25519_PUBLIC_KEY vid must throw TypeError',
  );
});

// ---------------------------------------------------------------------------
// ML-DSA-65 signed introduction (G7e/G7f) — a 5th CESR item
// ---------------------------------------------------------------------------

test('the 4-item unsigned form is unchanged (already-issued OOBIs keep working)', () => {
  const oobi = makeOobi();
  const encoded = encodeOobi(oobi);
  const decoded = decodeOobi(encoded);

  assert.equal(decoded.mlDsa65Signature, undefined, 'no signature on an unsigned OOBI');
  assert.deepEqual({ ...decoded, mlDsa65Signature: undefined }, { ...oobi, mlDsa65Signature: undefined });
});

test('signOobi → encode → decode round-trips the ML-DSA-65 signature', () => {
  const { publicKey, secretKey } = generateMlDsa65KeyPair();
  const signed = signOobi(makeOobi(), secretKey);

  assert.equal(signed.mlDsa65Signature?.length, 3309, 'ML-DSA-65 signature is 3309 bytes');

  const decoded = decodeOobi(encodeOobi(signed));
  assert.deepEqual(decoded.mlDsa65Signature, signed.mlDsa65Signature, 'signature survives the frame');
  assert.equal(verifyOobiSignature(decoded, publicKey), true, 'and verifies');
});

test('verification covers the introduction: a tampered field fails', () => {
  const { publicKey, secretKey } = generateMlDsa65KeyPair();
  const oobi = makeOobi();
  const signed = signOobi(oobi, secretKey);

  // Attacker swaps the transport address but keeps the signature.
  const tampered: OobiPayload = { ...signed, peerId: '12D3KooWattackerSwappedPeerId' };
  assert.equal(verifyOobiSignature(tampered, publicKey), false, 'a swapped peerId must not verify');

  // And swapping the DID (the identity claim) fails too.
  assert.equal(
    verifyOobiSignature({ ...signed, did: 'did:scid:vh:1:zImpostor' }, publicKey),
    false,
    'a swapped DID must not verify',
  );

  // Sanity: the untouched one still verifies.
  assert.equal(verifyOobiSignature(signed, publicKey), true);
});

test('verification reports "unsigned" distinctly from "forged"', () => {
  const { publicKey } = generateMlDsa65KeyPair();
  assert.equal(verifyOobiSignature(makeOobi(), publicKey), false, 'unsigned → false, never a throw');

  const { publicKey: otherKey, secretKey: otherSecret } = generateMlDsa65KeyPair();
  assert.equal(
    verifyOobiSignature(signOobi(makeOobi(), otherSecret), publicKey),
    false,
    'signed by the wrong key → false',
  );
  assert.equal(
    verifyOobiSignature(signOobi(makeOobi(), otherSecret), otherKey),
    true,
    'control: the same signature verifies under its own key',
  );
});

test('the signature covers exactly the four-item body (not the whole 5-item frame)', () => {
  const { publicKey, secretKey } = generateMlDsa65KeyPair();
  const oobi = makeOobi();
  const signed = signOobi(oobi, secretKey);

  // The signed input is the 4-item frame, stable regardless of the signature.
  const bodyBytes = oobiIntroductionBytes(oobi);
  assert.deepEqual(
    bodyBytes,
    oobiIntroductionBytes(signed),
    'the signable bytes do not include the signature item',
  );
  assert.ok(bodyBytes.length > 0);
  assert.equal(verifyOobiSignature(signed, publicKey), true);
});

test('decodeOobi rejects a 3-item (legacy) or 6-item frame', () => {
  const oobi = makeOobi();
  const four = [
    { code: CESR_CODES.ED25519_PUBLIC_KEY, bytes: new Uint8Array(32).fill(1) },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode(oobi.peerId) },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode('[]') },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode(oobi.did) },
  ];
  assert.throws(() => decodeOobi(cesrEncodeGroup(four.slice(0, 3))), SyntaxError, '3 items');
  assert.throws(
    () => decodeOobi(cesrEncodeGroup([...four, { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode('x') }])),
    SyntaxError,
    '6 items',
  );
});

