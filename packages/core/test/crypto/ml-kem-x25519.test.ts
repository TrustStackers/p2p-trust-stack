/**
 * Tests for the MLKEM768-X25519 hybrid KEM as an HPKE KemInterface.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/crypto/ml-kem-x25519.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CipherSuite, HkdfSha256 } from '@hpke/core';
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { MlKem768X25519 } from '../../src/crypto/ml-kem-x25519.js';
import { MLKEM768_X25519_ENC_BYTES } from '../../src/crypto/pqc.js';

test('MLKEM768-X25519 hybrid KEM works in HPKE-Base', async () => {
  const kem = new MlKem768X25519();
  const suite = new CipherSuite({ kem, kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });

  const recipient = await kem.generateKeyPair();
  const info = new TextEncoder().encode('YTSP-');
  const aad = new TextEncoder().encode('test aad');
  const plaintext = new TextEncoder().encode('pqc confidential payload');

  const sender = await suite.createSenderContext({ recipientPublicKey: recipient.publicKey, info });
  const ciphertext = new Uint8Array(await sender.seal(plaintext, aad));
  const enc = new Uint8Array(sender.enc);

  assert.equal(enc.length, MLKEM768_X25519_ENC_BYTES); // 1120

  const recipientCtx = await suite.createRecipientContext({ recipientKey: recipient, enc, info });
  const decrypted = new Uint8Array(await recipientCtx.open(ciphertext, aad));

  assert.deepEqual(decrypted, plaintext);
});

test('MLKEM768-X25519 decap with wrong aad fails', async () => {
  const kem = new MlKem768X25519();
  const suite = new CipherSuite({ kem, kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });

  const recipient = await kem.generateKeyPair();
  const info = new TextEncoder().encode('YTSP-');
  const sender = await suite.createSenderContext({ recipientPublicKey: recipient.publicKey, info });
  const ciphertext = new Uint8Array(await sender.seal(new TextEncoder().encode('x'), new TextEncoder().encode('aad1')));
  const enc = new Uint8Array(sender.enc);

  const recipientCtx = await suite.createRecipientContext({ recipientKey: recipient, enc, info });
  await assert.rejects(() => recipientCtx.open(ciphertext, new TextEncoder().encode('aad2')));
});
