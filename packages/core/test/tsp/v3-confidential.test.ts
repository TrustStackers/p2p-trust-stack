// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for HPKE-Base confidential messages (TSP v3 / Rev 3).
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tsp/v3-confidential.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateEd25519KeyPair,
  generateX25519KeyPair,
  importHpkeKeyPair,
  importHpkePublicKey,
  hpkeBaseSeal,
  hpkeBaseOpen,
} from '../../src/crypto/primitives.js';
import { MLKEM768_X25519_ENC_BYTES } from '../../src/crypto/pqc.js';
import { encodeVid, NULL_VID } from '../../src/tsp/fields.js';
import { TSP_CURRENT_VERSION_STRING } from '../../src/tsp/version.js';
import { tspSeal, tspOpen, TSP_HPKE_INFO, X25519_ENC_SIZE } from '../../src/tsp/v3/message.js';

const ALICE = 'did:peer:4zQmUL61Nc1F7ioiKxHNqwnJXX4srh';
const BOB = 'did:peer:4zQmZmA0sG7j1ewTjXjtdwujik33CE2cMbYSPagpMiYnt1A';

/** Reconstruct the HPKE aad = CONCAT(TSP_Version, VID_sndr, VID_rcvr). */
function envelopeAad(vidSender: string, vidReceiver: string | null): Uint8Array {
  const vidSndr = encodeVid(new TextEncoder().encode(vidSender));
  const vidRcvr = vidReceiver ? encodeVid(new TextEncoder().encode(vidReceiver)) : NULL_VID;
  return new TextEncoder().encode(TSP_CURRENT_VERSION_STRING + vidSndr + vidRcvr);
}

test('hpkeBaseSeal/Open round trip with info + aad', async () => {
  const receiverX = generateX25519KeyPair();
  const receiverKp = await importHpkeKeyPair(receiverX);
  const receiverPk = await importHpkePublicKey(receiverX.publicKey);

  const plaintext = new TextEncoder().encode('secret hello');
  const info = TSP_HPKE_INFO;
  const aad = new TextEncoder().encode('some aad');

  const { enc, ciphertext } = await hpkeBaseSeal(receiverPk, plaintext, info, aad);
  const decrypted = await hpkeBaseOpen(receiverKp, enc, ciphertext, info, aad);
  assert.deepEqual(decrypted, plaintext);
});

test('hpkeBaseOpen with wrong aad fails', async () => {
  const receiverX = generateX25519KeyPair();
  const receiverKp = await importHpkeKeyPair(receiverX);
  const receiverPk = await importHpkePublicKey(receiverX.publicKey);

  const { enc, ciphertext } = await hpkeBaseSeal(receiverPk, new TextEncoder().encode('x'), TSP_HPKE_INFO, new TextEncoder().encode('aad1'));
  await assert.rejects(() => hpkeBaseOpen(receiverKp, enc, ciphertext, TSP_HPKE_INFO, new TextEncoder().encode('aad2')));
});

test('TSP_GEN_CONFIDENTIAL message round trip recovers plaintext', async () => {
  const senderEd = generateEd25519KeyPair();
  const receiverX = generateX25519KeyPair();
  const receiverKp = await importHpkeKeyPair(receiverX);
  const receiverPk = await importHpkePublicKey(receiverX.publicKey);

  const plaintext = new TextEncoder().encode('confidential v3 payload');
  const aad = envelopeAad(ALICE, BOB);
  const { enc, ciphertext } = await hpkeBaseSeal(receiverPk, plaintext, TSP_HPKE_INFO, aad);

  const sealed = tspSeal({
    vidSender: ALICE,
    vidReceiver: BOB,
    payload: { type: 'TSP_GEN_CONFIDENTIAL', enc, ciphertext },
    signingSecretKey: senderEd.secretKey,
  });
  const str = new TextDecoder().decode(sealed);
  assert.ok(str.startsWith('-E'), 'envelope starts with -E##');

  const envelope = tspOpen({ message: sealed, senderPublicKey: senderEd.publicKey });
  assert.equal(envelope.payload.type, 'TSP_GEN_CONFIDENTIAL');
  const p = envelope.payload as { enc: Uint8Array; ciphertext: Uint8Array };

  const decrypted = await hpkeBaseOpen(receiverKp, p.enc, p.ciphertext, TSP_HPKE_INFO, aad);
  assert.deepEqual(decrypted, plaintext);
});

test('confidential ciphertext tamper breaks decryption', async () => {
  const senderEd = generateEd25519KeyPair();
  const receiverX = generateX25519KeyPair();
  const receiverKp = await importHpkeKeyPair(receiverX);
  const receiverPk = await importHpkePublicKey(receiverX.publicKey);

  const aad = envelopeAad(ALICE, BOB);
  const { enc, ciphertext } = await hpkeBaseSeal(receiverPk, new TextEncoder().encode('x'), TSP_HPKE_INFO, aad);
  const sealed = tspSeal({ vidSender: ALICE, vidReceiver: BOB, payload: { type: 'TSP_GEN_CONFIDENTIAL', enc, ciphertext }, signingSecretKey: senderEd.secretKey });

  const envelope = tspOpen({ message: sealed, senderPublicKey: senderEd.publicKey });
  const p = envelope.payload as { enc: Uint8Array; ciphertext: Uint8Array };
  const tampered = new Uint8Array(p.ciphertext);
  tampered[0] ^= 0xff;

  await assert.rejects(() => hpkeBaseOpen(receiverKp, p.enc, tampered, TSP_HPKE_INFO, aad));
});

// ---------------------------------------------------------------------------
// KEM size negotiation + key-length diagnostics (G7)
// ---------------------------------------------------------------------------

test('tspOpen: a hybrid-KEM expectation on an X25519 message fails loudly, not silently', async () => {
  // The CESR HPKE-Base cipher carries no KEM identifier, so the split point must
  // come from the receiver. Before G7 the split was a hard-coded 32-byte slice
  // with no guard, so a mismatched KEM produced a wrong `enc` and a garbage
  // `ciphertext` instead of an error. Now the mismatch is named.
  const senderEd = generateEd25519KeyPair();
  const receiverX = generateX25519KeyPair();
  const receiverPk = await importHpkePublicKey(receiverX.publicKey);
  const { enc, ciphertext } = await hpkeBaseSeal(
    receiverPk,
    new TextEncoder().encode('x'),
    TSP_HPKE_INFO,
    envelopeAad(ALICE, BOB),
  );
  const sealed = tspSeal({
    vidSender: ALICE,
    vidReceiver: BOB,
    payload: { type: 'TSP_GEN_CONFIDENTIAL', enc, ciphertext },
    signingSecretKey: senderEd.secretKey,
  });

  // Default (X25519) opens fine.
  assert.equal(
    tspOpen({ message: sealed, senderPublicKey: senderEd.publicKey }).payload.type,
    'TSP_GEN_CONFIDENTIAL',
  );

  // Claiming the hybrid KEM (1120-byte enc) cannot fit in this cipher.
  assert.throws(
    () => tspOpen({
      message: sealed,
      senderPublicKey: senderEd.publicKey,
      hpkeEncSize: MLKEM768_X25519_ENC_BYTES,
    }),
    (err: Error) => {
      assert.ok(err instanceof SyntaxError);
      assert.match(err.message, /cannot hold a 1120-byte encapsulated key/);
      assert.match(err.message, /MLKEM768-X25519 = 1120/, 'tells the caller how to open it');
      return true;
    },
  );
});

test('tspOpen: an empty confidential ciphertext is rejected by the KEM guard', async () => {
  const senderEd = generateEd25519KeyPair();
  const sealed = tspSeal({
    vidSender: ALICE,
    vidReceiver: BOB,
    // enc is exactly X25519_ENC_SIZE and there is no ciphertext at all: the old
    // code returned enc=cipher, ciphertext=<empty> silently.
    payload: { type: 'TSP_GEN_CONFIDENTIAL', enc: new Uint8Array(X25519_ENC_SIZE), ciphertext: new Uint8Array(0) },
    signingSecretKey: senderEd.secretKey,
  });

  assert.throws(
    () => tspOpen({ message: sealed, senderPublicKey: senderEd.publicKey }),
    /cannot hold a 32-byte encapsulated key/,
  );
});

test('tspOpen: an unsupported sender key length names the supported algorithms', () => {
  const senderEd = generateEd25519KeyPair();
  const sealed = tspSeal({
    vidSender: ALICE,
    vidReceiver: BOB,
    payload: { type: 'TSP_GEN', body: new TextEncoder().encode('hi') },
    signingSecretKey: senderEd.secretKey,
  });

  assert.throws(
    // e.g. a rotated/next key or the wrong slot resolved from the DID document
    () => tspOpen({ message: sealed, senderPublicKey: new Uint8Array(5) }),
    (err: Error) => {
      assert.match(err.message, /unsupported public key length 5/);
      assert.match(err.message, /32 \(Ed25519\)/);
      assert.match(err.message, /1952 \(ML-DSA-65\)/);
      assert.match(err.message, /does not match the key it signs with/, 'points at the likely cause');
      return true;
    },
  );
});

