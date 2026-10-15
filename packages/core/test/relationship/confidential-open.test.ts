// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for the shared confidential-open rule (TSP_GEN_CONFIDENTIAL).
 *
 * This module is the ONE implementation both receivers use — the agent's
 * `RelationshipManager` and the utility server's `tsp-bridge`. The rule it
 * encodes is not obvious and is easy to get subtly wrong, which is why it is
 * pinned here:
 *
 *   A CESR HPKE-Base cipher carries NO KEM identifier. `enc || ciphertext` is one
 *   opaque primitive, so the split depends on which KEM sealed it — DHKEM(X25519)
 *   (enc = 32) or MLKEM768-X25519 (enc = 1120). A receiver therefore cannot trust
 *   its stored record as fact; it tries the expected split and falls back, and the
 *   AEAD tag makes that sound (at most one attempt can authenticate).
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test \
 *     test/relationship/confidential-open.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { tspSeal, encodeAad, TSP_HPKE_INFO } from '../../src/tsp/v3/message.js';
import { openConfidentialBody } from '../../src/relationship/confidential-open.js';
import {
  hpkeBaseSeal,
  importHpkePublicKey,
  generateEd25519KeyPair,
  generateX25519KeyPair,
} from '../../src/crypto/primitives.js';
import { hpkeHybridSeal } from '../../src/crypto/ml-kem-x25519.js';
import { generateMlKem768X25519KeyPair } from '../../src/crypto/pqc.js';

const SENDER = 'did:scid:vh:1:zSender';
const RECEIVER = 'did:scid:vh:1:zReceiver';

/** A receiver identity plus the sealer side of both KEMs. */
function makeEndpoint() {
  const signer = generateEd25519KeyPair();                  // the sender's signing key
  const agreementKeyPair = generateX25519KeyPair();         // the receiver's classical key
  const hybridKemKeyPair = generateMlKem768X25519KeyPair(); // the receiver's PQ key
  return { signer, agreementKeyPair, hybridKemKeyPair };
}

/** Seal a confidential body exactly as `RelationshipManager.sendConfidentialMessage` does. */
async function sealConfidential(
  endpoint: ReturnType<typeof makeEndpoint>,
  body: Uint8Array,
  kem: 'hybrid' | 'classical',
): Promise<Uint8Array> {
  const aad = encodeAad(SENDER, RECEIVER);
  const { enc, ciphertext } = kem === 'hybrid'
    ? await hpkeHybridSeal(endpoint.hybridKemKeyPair.publicKey, body, TSP_HPKE_INFO, aad)
    : await hpkeBaseSeal(
        await importHpkePublicKey(endpoint.agreementKeyPair.publicKey),
        body,
        TSP_HPKE_INFO,
        aad,
      );
  assert.equal(enc.length, kem === 'hybrid' ? 1120 : 32, `${kem} enc size`);

  return tspSeal({
    vidSender: SENDER,
    vidReceiver: RECEIVER,
    payload: { type: 'TSP_GEN_CONFIDENTIAL', enc, ciphertext },
    signingSecretKey: endpoint.signer.secretKey,
  });
}

function openParams(
  endpoint: ReturnType<typeof makeEndpoint>,
  message: Uint8Array,
  expectHybrid: boolean,
) {
  return {
    message,
    senderPublicKey: endpoint.signer.publicKey,
    vidSender: SENDER,
    vidReceiver: RECEIVER,
    agreementKeyPair: endpoint.agreementKeyPair,
    hybridKemKeyPair: endpoint.hybridKemKeyPair,
    expectHybrid,
  };
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

test('openConfidentialBody: opens a HYBRID-sealed body (enc = 1120)', async () => {
  const endpoint = makeEndpoint();
  const body = new TextEncoder().encode('hybrid secret');
  const message = await sealConfidential(endpoint, body, 'hybrid');

  const opened = await openConfidentialBody(openParams(endpoint, message, true));
  assert.ok(opened, 'the hybrid body must open');
  assert.equal(opened!.used, 'hybrid');
  assert.equal(opened!.mismatch, false);
  assert.deepEqual(opened!.plaintext, body);
});

test('openConfidentialBody: opens a CLASSICAL-sealed body (enc = 32)', async () => {
  const endpoint = makeEndpoint();
  const body = new TextEncoder().encode('classical secret');
  const message = await sealConfidential(endpoint, body, 'classical');

  const opened = await openConfidentialBody(openParams(endpoint, message, false));
  assert.ok(opened, 'the classical body must open');
  assert.equal(opened!.used, 'classical');
  assert.equal(opened!.mismatch, false);
  assert.deepEqual(opened!.plaintext, body);
});

// ---------------------------------------------------------------------------
// The reason the rule exists: the stored record can be stale
// ---------------------------------------------------------------------------

test('openConfidentialBody: opens and REPORTS a stale record (hint wrong both ways)', async () => {
  const endpoint = makeEndpoint();

  // Sealed hybrid, but the record says classical (the peer's #key-kem was added
  // after the record was written) — the fallback must still recover it.
  const hybridMessage = await sealConfidential(endpoint, new TextEncoder().encode('h1'), 'hybrid');
  const a = await openConfidentialBody(openParams(endpoint, hybridMessage, false));
  assert.ok(a, 'a hybrid body must open even when the hint says classical');
  assert.equal(a!.used, 'hybrid');
  assert.equal(a!.mismatch, true, 'the mismatch must be reported so callers can log the drift');

  // And the mirror image: sealed classical, record says hybrid.
  const classicalMessage = await sealConfidential(endpoint, new TextEncoder().encode('c1'), 'classical');
  const b = await openConfidentialBody(openParams(endpoint, classicalMessage, true));
  assert.ok(b, 'a classical body must open even when the hint says hybrid');
  assert.equal(b!.used, 'classical');
  assert.equal(b!.mismatch, true);
});

// ---------------------------------------------------------------------------
// Failures must be conclusive, not retryable
// ---------------------------------------------------------------------------

test('openConfidentialBody: returns undefined when this identity holds NO matching key', async () => {
  const sender = makeEndpoint();
  const body = new TextEncoder().encode('for someone else');
  const hybridMessage = await sealConfidential(sender, body, 'hybrid');
  const classicalMessage = await sealConfidential(sender, body, 'classical');

  // A receiver with neither key pair (a server provisioned before PQ keys, say).
  assert.equal(
    await openConfidentialBody({
      message: hybridMessage,
      senderPublicKey: sender.signer.publicKey,
      vidSender: SENDER,
      vidReceiver: RECEIVER,
      expectHybrid: true,
    }),
    undefined,
    'no keys must yield undefined, not a throw',
  );

  // A receiver whose keys are simply the wrong ones must also yield undefined:
  // the AEAD failing is conclusive evidence, not something to retry blindly.
  const wrong = makeEndpoint();
  assert.equal(
    await openConfidentialBody(openParams(wrong, classicalMessage, false)),
    undefined,
  );
});

test('openConfidentialBody: a tampered ciphertext never opens', async () => {
  const endpoint = makeEndpoint();
  const body = new TextEncoder().encode('tamper me');
  const message = await sealConfidential(endpoint, body, 'classical');

  // Flip a byte late in the frame — inside the ciphertext, past the split.
  const tampered = new Uint8Array(message);
  tampered[tampered.length - 20] ^= 0x01;

  assert.equal(
    await openConfidentialBody(openParams(endpoint, tampered, false)),
    undefined,
    'a tampered ciphertext must not authenticate under either split',
  );
});

test('openConfidentialBody: a plaintext TSP_GEN frame is not a confidential body', async () => {
  const endpoint = makeEndpoint();
  const sealed = tspSeal({
    vidSender: SENDER,
    vidReceiver: RECEIVER,
    payload: { type: 'TSP_GEN', body: new TextEncoder().encode('plain') },
    signingSecretKey: endpoint.signer.secretKey,
  });
  assert.equal(
    await openConfidentialBody(openParams(endpoint, sealed, false)),
    undefined,
    'the helper must not treat a plaintext payload as a confidential one',
  );
});

