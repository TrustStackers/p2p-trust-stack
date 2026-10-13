/**
 * TSP v3 (Rev 3) — golden-vector tests against the Trust Over IP specification
 * appendix test vectors (rev3.json, openwallet-foundation-labs/tsp).
 *
 * These lock the self-addressing digest (SAID) computation (spec §7.2.1) and
 * the message codec to the published wire bytes.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tsp/v3-golden.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeSaidDigest, tspSeal, tspOpen } from '../../src/tsp/v3/message.js';
import { generateEd25519KeyPair } from '../../src/crypto/primitives.js';

const ALICE = 'did:peer:4zQmUL61Nc1F7ioiKxHNqwnJXX4srhFsKKPo6TrCmhM3dfpq';
const BOB = 'did:peer:4zQmZmCAsG7j1ewTjXjtddwujik33CE2cMbYSPagpMiYnt1A';

// The `control-rfi-direct` vector: alice → bob, nonce = 16 bytes of 0x11.
const RFI_NONCE = new Uint8Array(16).fill(0x11);
const RFI_DIGEST_HEX = '6e872a160689e5bbafb7000c68fa809d1a301d2b3457fa2320e02bfbbd8c513a';

// The `control-rfa-direct` vector: bob → alice, echoing the RFI digest above.
const RFA_REPLY_DIGEST_B64 = 'VUPQxC2Cuq6cXHkAu3JG3hFdHxHi6YtUoRMfaK7lniE';

// The `direct-signed-only` vector (non-confidential) and alice's Ed25519 key.
const SIGNED_ONLY_MESSAGE =
  '-EA3YTSP-AAC4BATZGlkOnBlZXI6NHpRbVVMNjFOYzFGN2lvaUt4SE5xd25KWFg0c3Jo' +
  'RnNLS1BvNlRyQ21oTTNkZnBx4BATZGlkOnBlZXI6NHpRbVptQ0FzRzdqMWV3VGpYanRk' +
  'ZHd1amlrMzNDRTJjTWJZU1BhZ3BNaVludDFB-ZAMXSCS4BAA4BAA-AAI5BAHAHB1Ymxp' +
  'YyBhbm5vdW5jZW1lbnQh-CAX-KAWBACLj6MsdBES31rSLHtwvsl399JiRr8guUU--hau' +
  'BWZ9zftvcY7LWzfK5JyEOcqb2l1F5c32MNtpDsQjmQgn1m8F';
const ALICE_ED25519_PUBLIC_KEY = new Uint8Array(
  Buffer.from('b5DCBaChqWVVGJOsGWcKuKti0SKfm53pTfOwuj-hm9g', 'base64url'),
);

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

test('golden: control-rfi-direct digest (SAID, spec 7.2.1)', () => {
  const digest = computeSaidDigest('RFI', ALICE, BOB, { nonce: RFI_NONCE });
  assert.equal(hex(digest), RFI_DIGEST_HEX);
});

test('golden: control-rfa-direct Reply_Digest (SAID, spec 7.2.1)', () => {
  const requestDigest = Buffer.from(RFI_DIGEST_HEX, 'hex');
  const replyDigest = computeSaidDigest('RFA', BOB, ALICE, { requestDigest: new Uint8Array(requestDigest) });
  assert.equal(Buffer.from(replyDigest).toString('base64url'), RFA_REPLY_DIGEST_B64);
});

test('golden: tspSeal derives the RFI digest (not caller-supplied)', () => {
  const { secretKey, publicKey } = generateEd25519KeyPair();
  const sealed = tspSeal({
    vidSender: ALICE,
    vidReceiver: BOB,
    payload: { type: 'TSP_RFI', nonce: RFI_NONCE },
    signingSecretKey: secretKey,
  });
  const envelope = tspOpen({ message: sealed, senderPublicKey: publicKey });
  assert.equal(envelope.payload.type, 'TSP_RFI');
  const payload = envelope.payload as { digest?: Uint8Array };
  assert.equal(hex(payload.digest!), RFI_DIGEST_HEX);
});

test('golden: direct-signed-only message decodes and verifies', () => {
  const envelope = tspOpen({
    message: new TextEncoder().encode(SIGNED_ONLY_MESSAGE),
    senderPublicKey: ALICE_ED25519_PUBLIC_KEY,
  });
  assert.equal(envelope.vidSender, ALICE);
  assert.equal(envelope.vidReceiver, BOB);
  assert.equal(envelope.payload.type, 'TSP_GEN');
  const body = (envelope.payload as { body: Uint8Array }).body;
  assert.equal(new TextDecoder().decode(body), 'public announcement!');
});
