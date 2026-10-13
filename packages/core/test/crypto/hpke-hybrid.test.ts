/**
 * Tests for HPKE-Base over the MLKEM768-X25519 hybrid KEM (G7f, confidential).
 *
 * Confidential payloads are sealed with the HYBRID KEM when the peer publishes
 * `#key-kem`, and classically (DHKEM(X25519)) otherwise. Because the CESR
 * HPKE-Base cipher carries no KEM identifier, the receiver tries the expected KEM
 * and falls back to the other — which is only sound if the AEAD tag decides.
 * These tests pin exactly that property.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/crypto/hpke-hybrid.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateX25519KeyPair, importHpkeKeyPair, importHpkePublicKey, hpkeBaseSeal, hpkeBaseOpen } from '../../src/crypto/primitives.js';
import { generateMlKem768X25519KeyPair, MLKEM768_X25519_ENC_BYTES } from '../../src/crypto/pqc.js';
import { hpkeHybridSeal, hpkeHybridOpen } from '../../src/crypto/ml-kem-x25519.js';
import { tspSeal, tspOpen, TSP_HPKE_INFO, X25519_ENC_SIZE } from '../../src/tsp/v3/message.js';

const ALICE = 'did:peer:4zQmUL61Nc1F7ioiKxHNqwnJXX4srh';
const BOB = 'did:peer:4zQmZmA0sG7j1ewTjXjtdwujik33CE2cMbYSPagpMiYnt1A';
const INFO = TSP_HPKE_INFO;
const AAD = new TextEncoder().encode('confidential aad');
const BODY = new TextEncoder().encode('post-quantum confidential body');

test('hybrid seal/open round-trips with RAW key bytes (the #key-kem form)', async () => {
  const kp = generateMlKem768X25519KeyPair();
  const { enc, ciphertext } = await hpkeHybridSeal(kp.publicKey, BODY, INFO, AAD);

  assert.equal(enc.length, MLKEM768_X25519_ENC_BYTES, 'hybrid enc is 1120 bytes');
  assert.equal(enc.length, 1120);

  const opened = await hpkeHybridOpen(kp.secretKey, enc, ciphertext, INFO, AAD, kp.publicKey);
  assert.deepEqual(opened, BODY);
});

test('THE FALLBACK PREMISE: a hybrid cipher cannot be opened with the classical split', async () => {
  // 1120 + ciphertext is indistinguishable from "32-byte enc + long ciphertext"
  // by length alone, so a receiver that tries the wrong split must simply fail to
  // authenticate rather than silently produce garbage. That is what makes
  // processGen's try-expected-then-fallback sound.
  const kp = generateMlKem768X25519KeyPair();
  const { enc, ciphertext } = await hpkeHybridSeal(kp.publicKey, BODY, INFO, AAD);

  // Whole cipher text, exactly as it travels on the wire.
  const cipher = Buffer.concat([Buffer.from(enc), Buffer.from(ciphertext)]);

  // Classical interpretation: enc' = first 32 bytes, ct' = the rest.
  const classicalEnc = new Uint8Array(cipher.subarray(0, X25519_ENC_SIZE));
  const classicalCt = new Uint8Array(cipher.subarray(X25519_ENC_SIZE));
  const x = generateX25519KeyPair();
  const xKp = await importHpkeKeyPair(x);

  await assert.rejects(
    () => hpkeBaseOpen(xKp, classicalEnc, classicalCt, INFO, AAD),
    'the classical split of a hybrid cipher must NOT authenticate',
  );

  // …while the hybrid split does.
  const opened = await hpkeHybridOpen(kp.secretKey, enc, ciphertext, INFO, AAD, kp.publicKey);
  assert.deepEqual(opened, BODY);
});

test('a classical cipher cannot be opened with the hybrid KEM', async () => {
  const x = generateX25519KeyPair();
  const xPub = await importHpkePublicKey(x.publicKey);
  const { enc, ciphertext } = await hpkeBaseSeal(xPub, BODY, INFO, AAD);
  assert.equal(enc.length, X25519_ENC_SIZE);

  const kp = generateMlKem768X25519KeyPair();
  await assert.rejects(
    () => hpkeHybridOpen(kp.secretKey, enc, ciphertext, INFO, AAD, kp.publicKey),
    'a 32-byte enc cannot be a hybrid encapsulated key',
  );
});

test('TSP: a hybrid-sealed CONFIDENTIAL payload is decoded with hpkeEncSize = 1120', async () => {
  const { generateEd25519KeyPair } = await import('../../src/crypto/primitives.js');
  const senderEd = generateEd25519KeyPair();
  const recipientKem = generateMlKem768X25519KeyPair();

  const { enc, ciphertext } = await hpkeHybridSeal(recipientKem.publicKey, BODY, INFO, AAD);
  const sealed = tspSeal({
    vidSender: ALICE,
    vidReceiver: BOB,
    payload: { type: 'TSP_GEN_CONFIDENTIAL', enc, ciphertext },
    signingSecretKey: senderEd.secretKey,
  });

  // Correct KEM size → the payload decodes and opens.
  const envelope = tspOpen({
    message: sealed,
    senderPublicKey: senderEd.publicKey,
    hpkeEncSize: MLKEM768_X25519_ENC_BYTES,
  });
  assert.equal(envelope.payload.type, 'TSP_GEN_CONFIDENTIAL');
  const p = envelope.payload as { enc: Uint8Array; ciphertext: Uint8Array };
  assert.deepEqual(p.enc, enc);
  const opened = await hpkeHybridOpen(recipientKem.secretKey, p.enc, p.ciphertext, INFO, AAD, recipientKem.publicKey);
  assert.deepEqual(opened, BODY);

  // Wrong (default) KEM size → tspOpen assumes a 32-byte `enc` and decodes
  // structurally, but that split can NEVER open. Note deliberately what the guard
  // does and does not catch: it rejects a cipher too SHORT to hold the assumed
  // key, while a long hybrid cipher is indistinguishable by length from
  // "32-byte enc + long ciphertext" — which is precisely why the receiver tries
  // both KEMs and lets the AEAD tag decide instead of trusting a length heuristic.
  const wrong = tspOpen({ message: sealed, senderPublicKey: senderEd.publicKey });
  const wp = wrong.payload as { enc: Uint8Array; ciphertext: Uint8Array };
  assert.notDeepEqual(wp.enc, enc, 'the assumed split does not match the real encapsulated key');
  assert.equal(wp.enc.length, X25519_ENC_SIZE);
  await assert.rejects(
    () => hpkeHybridOpen(recipientKem.secretKey, wp.enc, wp.ciphertext, INFO, AAD, recipientKem.publicKey),
    'the wrongly-split cipher cannot be opened',
  );
});
