// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for the witness attestation flow — Step 11, Task 11.6.
 *
 * Covers:
 *   - collectWitnessAttestations: happy path — builds a valid 'rotation-witness' VRC
 *   - verifyWitnessAttestation: happy path
 *   - verifyWitnessAttestation: rejects wrong claim type
 *   - verifyWitnessAttestation: rejects mismatched rotationDigest
 *   - verifyWitnessAttestation: rejects insufficient signers
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/did/witness-attestation.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { generateEd25519KeyPair, sha256 } from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { createVtc } from '../../src/vtc/vtc.js';
import { collectWitnessAttestations, verifyWitnessAttestation } from '../../src/did/witness-attestation.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeVid(): { vid: string; signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array } } {
  const kp = generateEd25519KeyPair();
  return { vid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, kp.publicKey), signingKeyPair: kp };
}

async function makeWitnessVtc(threshold = 2) {
  const w1 = makeVid();
  const w2 = makeVid();
  const identity = await createVtc({
    name: 'Test Witness VTC',
    founders: [w1, w2],
    threshold,
    allowedClaimTypes: ['witness-member', 'rotation-witness'],
  });
  return { governanceDoc: identity.governanceDoc, w1, w2 };
}

// ---------------------------------------------------------------------------
// collectWitnessAttestations / verifyWitnessAttestation — happy path
// ---------------------------------------------------------------------------

test('collectWitnessAttestations / verifyWitnessAttestation: happy path — 2-of-2 co-signed attestation verifies', async () => {
  const { governanceDoc, w1, w2 } = await makeWitnessVtc(2);
  const rotatingVid = makeVid().vid;
  const rotationEntryDigest = sha256(new TextEncoder().encode('fake-rotation-entry'));

  const vrc = collectWitnessAttestations({
    governanceDoc,
    rotatingVid,
    rotationEntryDigest,
    observedAt: 1700000000,
    witnesses: [w1, w2],
  });

  assert.equal(vrc.claim.type, 'rotation-witness');
  assert.equal(vrc.subjectVid, rotatingVid);

  const result = verifyWitnessAttestation(vrc, governanceDoc, rotationEntryDigest);
  assert.equal(result.valid, true, `expected valid attestation, got: ${result.reason}`);
  assert.equal(result.validSignatureCount, 2);
});

// ---------------------------------------------------------------------------
// verifyWitnessAttestation — wrong claim type
// ---------------------------------------------------------------------------

test('verifyWitnessAttestation: rejects a VRC with the wrong claim type', async () => {
  const { governanceDoc, w1, w2 } = await makeWitnessVtc(2);
  const rotatingVid = makeVid().vid;
  const rotationEntryDigest = sha256(new TextEncoder().encode('fake-rotation-entry'));

  // Build a 'witness-member' VRC instead of 'rotation-witness'.
  const { issueVrc } = await import('../../src/vtc/vtc.js');
  const wrongVrc = issueVrc({
    governanceDoc,
    subjectVid: rotatingVid,
    claim: { type: 'witness-member' },
    signers: [w1, w2],
  });

  const result = verifyWitnessAttestation(wrongVrc, governanceDoc, rotationEntryDigest);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'wrong-claim');
});

// ---------------------------------------------------------------------------
// verifyWitnessAttestation — mismatched rotationDigest
// ---------------------------------------------------------------------------

test('verifyWitnessAttestation: rejects a VRC whose rotationDigest does not match the expected digest', async () => {
  const { governanceDoc, w1, w2 } = await makeWitnessVtc(2);
  const rotatingVid = makeVid().vid;
  const rotationEntryDigest = sha256(new TextEncoder().encode('fake-rotation-entry'));
  const otherDigest = sha256(new TextEncoder().encode('a-different-entry'));

  const vrc = collectWitnessAttestations({
    governanceDoc,
    rotatingVid,
    rotationEntryDigest,
    observedAt: 1700000000,
    witnesses: [w1, w2],
  });

  const result = verifyWitnessAttestation(vrc, governanceDoc, otherDigest);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'wrong-claim');
});

// ---------------------------------------------------------------------------
// verifyWitnessAttestation — insufficient signers
// ---------------------------------------------------------------------------

test('verifyWitnessAttestation: rejects when fewer than threshold valid signers co-signed', async () => {
  const { governanceDoc, w1 } = await makeWitnessVtc(2);
  const rotatingVid = makeVid().vid;
  const rotationEntryDigest = sha256(new TextEncoder().encode('fake-rotation-entry'));

  // Simulate a governance doc with a lower threshold at issuance time, then
  // verify against the real (threshold=2) doc where only 1 signer is present.
  const laxDoc = { ...governanceDoc, threshold: 1 };
  const vrc = collectWitnessAttestations({
    governanceDoc: laxDoc,
    rotatingVid,
    rotationEntryDigest,
    observedAt: 1700000000,
    witnesses: [w1],
  });

  const result = verifyWitnessAttestation(vrc, governanceDoc, rotationEntryDigest);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'insufficient-signatures');
  assert.equal(result.validSignatureCount, 1);
});
