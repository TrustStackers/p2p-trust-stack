/**
 * Conformance tests for TSP crypto primitives.
 *
 * Covers:
 *   - Ed25519 sign/verify round trip + tamper detection
 *   - SHA2-256 and Blake2b-256 against known test vectors
 *   - HKDF determinism
 *   - HPKE-Auth seal/open round trip
 *
 * Run with:
 *   node --test --experimental-strip-types test/crypto/primitives.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import {
  generateEd25519KeyPair,
  signEd25519,
  verifyEd25519,
  generateX25519KeyPair,
  ed25519ToX25519,
  sha256,
  blake2b256,
  hkdf,
  timingSafeEqualString,
  generateHpkeKeyPair,
  hpkeAuthSeal,
  hpkeAuthOpen,
} from '../../src/crypto/primitives.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

test('Ed25519: generateEd25519KeyPair returns 32-byte keys', () => {
  const kp = generateEd25519KeyPair();
  assert.equal(kp.secretKey.length, 32, 'secret key must be 32 bytes');
  assert.equal(kp.publicKey.length, 32, 'public key must be 32 bytes');
});

test('Ed25519: sign/verify round trip succeeds', () => {
  const kp = generateEd25519KeyPair();
  const message = new TextEncoder().encode('hello TSP');
  const sig = signEd25519(message, kp.secretKey);
  assert.equal(sig.length, 64, 'signature must be 64 bytes');
  assert.equal(verifyEd25519(sig, message, kp.publicKey), true, 'valid signature must verify');
});

test('Ed25519: tampered message fails verification', () => {
  const kp = generateEd25519KeyPair();
  const message = new TextEncoder().encode('hello TSP');
  const sig = signEd25519(message, kp.secretKey);
  const tampered = new TextEncoder().encode('hello TSP!');
  assert.equal(
    verifyEd25519(sig, tampered, kp.publicKey),
    false,
    'tampered message must not verify',
  );
});

test('Ed25519: tampered signature fails verification', () => {
  const kp = generateEd25519KeyPair();
  const message = new TextEncoder().encode('hello TSP');
  const sig = signEd25519(message, kp.secretKey);
  const badSig = new Uint8Array(sig);
  badSig[0] ^= 0xff; // flip bits in first byte
  assert.equal(
    verifyEd25519(badSig, message, kp.publicKey),
    false,
    'corrupted signature must not verify',
  );
});

test('Ed25519: wrong public key fails verification', () => {
  const kp1 = generateEd25519KeyPair();
  const kp2 = generateEd25519KeyPair();
  const message = new TextEncoder().encode('hello TSP');
  const sig = signEd25519(message, kp1.secretKey);
  assert.equal(
    verifyEd25519(sig, message, kp2.publicKey),
    false,
    'wrong public key must not verify',
  );
});

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

test('X25519: generateX25519KeyPair returns 32-byte keys', () => {
  const kp = generateX25519KeyPair();
  assert.equal(kp.secretKey.length, 32);
  assert.equal(kp.publicKey.length, 32);
});

test('ed25519ToX25519: converts Ed25519 secret key to X25519 key pair', () => {
  const edKp = generateEd25519KeyPair();
  const xKp = ed25519ToX25519(edKp.secretKey);
  assert.equal(xKp.secretKey.length, 32, 'X25519 secret key must be 32 bytes');
  assert.equal(xKp.publicKey.length, 32, 'X25519 public key must be 32 bytes');
  // Deterministic: same input → same output
  const xKp2 = ed25519ToX25519(edKp.secretKey);
  assert.deepEqual(xKp.secretKey, xKp2.secretKey, 'conversion must be deterministic');
  assert.deepEqual(xKp.publicKey, xKp2.publicKey, 'conversion must be deterministic');
});

// ---------------------------------------------------------------------------
// SHA2-256 — test vectors
// ---------------------------------------------------------------------------

test('SHA2-256: empty input matches RFC 6234 test vector', () => {
  // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  const expected = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const result = sha256(new Uint8Array(0));
  assert.equal(bytesToHex(result), expected, 'SHA-256 of empty input must match RFC vector');
});

test('SHA2-256: "abc" matches NIST test vector', () => {
  // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  // Verified against @noble/hashes output (FIPS 180-4 test vector)
  const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
  const result = sha256(new TextEncoder().encode('abc'));
  assert.equal(bytesToHex(result), expected, 'SHA-256 of "abc" must match NIST vector');
});

test('SHA2-256: output is 32 bytes', () => {
  assert.equal(sha256(new Uint8Array([1, 2, 3])).length, 32);
});

// ---------------------------------------------------------------------------
// Blake2b-256 — test vectors
//
// Vectors from the official Blake2 reference implementation:
//   https://github.com/nicowillis/blake2/blob/master/testvectors/blake2b-kat.txt
// ---------------------------------------------------------------------------

test('Blake2b-256: empty input matches reference vector', () => {
  // blake2b-256("") = 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
  const expected = '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8';
  const result = blake2b256(new Uint8Array(0));
  assert.equal(bytesToHex(result), expected, 'Blake2b-256 of empty input must match reference');
});

test('Blake2b-256: output is 32 bytes', () => {
  assert.equal(blake2b256(new Uint8Array([1, 2, 3])).length, 32);
});

test('Blake2b-256 and SHA2-256 produce different digests for the same input', () => {
  const data = new TextEncoder().encode('tsp digest test');
  const sha = sha256(data);
  const b2b = blake2b256(data);
  assert.notDeepEqual(sha, b2b, 'SHA-256 and Blake2b-256 must differ for the same input');
});

// ---------------------------------------------------------------------------
// HKDF
// ---------------------------------------------------------------------------

test('HKDF: same inputs produce the same output (deterministic)', () => {
  const ikm = new TextEncoder().encode('input key material');
  const salt = new TextEncoder().encode('salt');
  const info = new TextEncoder().encode('tsp-test');
  const out1 = hkdf(nobleSha256, ikm, salt, info, 32);
  const out2 = hkdf(nobleSha256, ikm, salt, info, 32);
  assert.deepEqual(out1, out2, 'HKDF must be deterministic');
  assert.equal(out1.length, 32, 'output must be 32 bytes');
});

test('HKDF: different info produces different output', () => {
  const ikm = new TextEncoder().encode('input key material');
  const salt = new TextEncoder().encode('salt');
  const out1 = hkdf(nobleSha256, ikm, salt, new TextEncoder().encode('context-a'), 32);
  const out2 = hkdf(nobleSha256, ikm, salt, new TextEncoder().encode('context-b'), 32);
  assert.notDeepEqual(out1, out2, 'different info must produce different output');
});

// ---------------------------------------------------------------------------
// HPKE-Auth
// ---------------------------------------------------------------------------

test('HPKE-Auth: seal/open round trip recovers plaintext', async () => {
  const recipientKp = await generateHpkeKeyPair();
  const senderKp = await generateHpkeKeyPair();
  const plaintext = new TextEncoder().encode('hello HPKE-Auth');

  const { enc, ciphertext } = await hpkeAuthSeal(
    recipientKp.publicKey,
    senderKp,
    plaintext,
  );

  const recovered = await hpkeAuthOpen(
    recipientKp,
    senderKp.publicKey,
    enc,
    ciphertext,
  );

  assert.deepEqual(
    recovered,
    plaintext,
    'decrypted plaintext must match original',
  );
});

test('HPKE-Auth: seal/open with AAD round trip succeeds', async () => {
  const recipientKp = await generateHpkeKeyPair();
  const senderKp = await generateHpkeKeyPair();
  const plaintext = new TextEncoder().encode('authenticated message');
  const aad = new TextEncoder().encode('additional authenticated data');

  const { enc, ciphertext } = await hpkeAuthSeal(
    recipientKp.publicKey,
    senderKp,
    plaintext,
    aad,
  );

  const recovered = await hpkeAuthOpen(
    recipientKp,
    senderKp.publicKey,
    enc,
    ciphertext,
    aad,
  );

  assert.deepEqual(recovered, plaintext, 'AAD round trip must recover plaintext');
});

test('HPKE-Auth: wrong sender key fails to open', async () => {
  const recipientKp = await generateHpkeKeyPair();
  const senderKp = await generateHpkeKeyPair();
  const wrongSenderKp = await generateHpkeKeyPair();
  const plaintext = new TextEncoder().encode('secret');

  const { enc, ciphertext } = await hpkeAuthSeal(
    recipientKp.publicKey,
    senderKp,
    plaintext,
  );

  await assert.rejects(
    () => hpkeAuthOpen(recipientKp, wrongSenderKp.publicKey, enc, ciphertext),
    'opening with wrong sender key must throw',
  );
});

test('HPKE-Auth: ciphertext differs from plaintext', async () => {
  const recipientKp = await generateHpkeKeyPair();
  const senderKp = await generateHpkeKeyPair();
  const plaintext = new TextEncoder().encode('hello');

  const { ciphertext } = await hpkeAuthSeal(recipientKp.publicKey, senderKp, plaintext);

  assert.notDeepEqual(ciphertext, plaintext, 'ciphertext must differ from plaintext');
});

// ---------------------------------------------------------------------------
// timingSafeEqualString (audit F-020)
// ---------------------------------------------------------------------------

test('timingSafeEqualString: equal strings match; any difference at all does not', () => {
  assert.equal(timingSafeEqualString('abc123', 'abc123'), true);
  assert.equal(timingSafeEqualString('abc123', 'abc124'), false, 'last-byte difference');
  assert.equal(timingSafeEqualString('zbc123', 'abc123'), false, 'first-byte difference');
  assert.equal(timingSafeEqualString('', ''), true);
});

test('timingSafeEqualString: unequal lengths return false instead of throwing', () => {
  // `crypto.timingSafeEqual` throws on length mismatch; hashing both sides first
  // is what makes this safe — and removes the length oracle too.
  assert.equal(timingSafeEqualString('abc', 'abcd'), false);
  assert.equal(timingSafeEqualString('a'.repeat(64), 'a'.repeat(63)), false);
  assert.equal(timingSafeEqualString('abc', ''), false);
});

test('timingSafeEqualString: non-strings are rejected rather than coerced', () => {
  assert.equal(timingSafeEqualString(undefined as unknown as string, 'a'), false);
  assert.equal(timingSafeEqualString('a', null as unknown as string), false);
});

test('timingSafeEqualString: an HMAC compared this way still accepts only the right MAC', () => {
  // The shape the session cookie uses.
  const secret = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
  const mac = createHmac('sha256', secret).update('identity:1700000000').digest('base64url');
  const wrong = createHmac('sha256', Buffer.from('f'.repeat(32), 'hex')).update('identity:1700000000').digest('base64url');

  assert.equal(timingSafeEqualString(mac, mac), true);
  assert.equal(timingSafeEqualString(mac, wrong), false);
  assert.equal(timingSafeEqualString(mac, mac.slice(0, -1)), false);
});

