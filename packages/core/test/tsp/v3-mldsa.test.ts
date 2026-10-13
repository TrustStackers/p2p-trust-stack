/**
 * Tests for ML-DSA-65 signature dispatch in the v3 message codec.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tsp/v3-mldsa.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateMlDsa65KeyPair } from '../../src/crypto/pqc.js';
import { tspSeal, tspOpen } from '../../src/tsp/v3/message.js';

const ALICE = 'did:peer:4zQmUL61Nc1F7ioiKxHNqwnJXX4srh';
const BOB = 'did:peer:4zQmZmA0sG7j1ewTjXjtdwujik33CE2cMbYSPagpMiYnt1A';

test('ML-DSA-65 signature round trip in the v3 codec', () => {
  const kp = generateMlDsa65KeyPair();
  const body = new TextEncoder().encode('pqc signed message');
  const sealed = tspSeal({ vidSender: ALICE, vidReceiver: BOB, payload: { type: 'TSP_GEN', body }, signingSecretKey: kp.secretKey });
  const str = new TextDecoder().decode(sealed);
  assert.ok(str.includes('1AAQ'), 'signature uses 1AAQ ML-DSA-65 code');

  const envelope = tspOpen({ message: sealed, senderPublicKey: kp.publicKey });
  assert.equal(envelope.payload.type, 'TSP_GEN');
  assert.deepEqual((envelope.payload as { body: Uint8Array }).body, body);
});

test('ML-DSA-65 tampered payload fails verification', () => {
  const kp = generateMlDsa65KeyPair();
  const sealed = tspSeal({ vidSender: ALICE, vidReceiver: BOB, payload: { type: 'TSP_GEN', body: new TextEncoder().encode('x') }, signingSecretKey: kp.secretKey });
  const bytes = new Uint8Array(sealed);
  bytes[6] ^= 0xff;
  assert.throws(() => tspOpen({ message: bytes, senderPublicKey: kp.publicKey }), /signature/i);
});

test('ML-DSA-65 wrong public key fails verification', () => {
  const kp = generateMlDsa65KeyPair();
  const other = generateMlDsa65KeyPair();
  const sealed = tspSeal({ vidSender: ALICE, vidReceiver: BOB, payload: { type: 'TSP_GEN', body: new TextEncoder().encode('x') }, signingSecretKey: kp.secretKey });
  assert.throws(() => tspOpen({ message: sealed, senderPublicKey: other.publicKey }), /signature/i);
});
