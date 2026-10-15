// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for resolution-aware VRC verification (verifyVrcResolved).
 *
 * Covers:
 *   - happy path: VRC verifies when admin DIDs resolve to the signer's key
 *   - degraded path: falls back to self-certifying when no adminDid present
 *   - rotation rejection: a signature whose DID now holds a different key fails
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/vtc/verify-vrc-resolved.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { generateEd25519KeyPair, ed25519ToX25519 } from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { buildDidPeer4Document } from '../../src/did/create.js';
import { encodePeer4 } from '../../src/did/numalgo4.js';
import { DidResolver } from '../../src/did/did-resolver.js';
import { createVtc, issueVrc, verifyVrcResolved } from '../../src/vtc/vtc.js';
import type { VtcGovernanceDoc } from '../../src/vtc/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFounder(): { vid: string; signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array } } {
  const kp = generateEd25519KeyPair();
  return { vid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, kp.publicKey), signingKeyPair: kp };
}

/** Build a did:peer:4 DID whose #key-1 is the given Ed25519 public key. */
async function makeDidForKey(publicKey: Uint8Array, agreementPublicKey?: Uint8Array): Promise<string> {
  const doc = buildDidPeer4Document(
    publicKey,
    agreementPublicKey ?? new Uint8Array(32),
  );
  const { did } = await encodePeer4(doc);
  return did;
}

async function makeGovernanceDocWithDids(): Promise<{
  doc: VtcGovernanceDoc;
  admin1: ReturnType<typeof makeFounder>;
  admin2: ReturnType<typeof makeFounder>;
}> {
  const admin1 = makeFounder();
  const admin2 = makeFounder();
  const identity = await createVtc({
    name: 'Witness VTC',
    founders: [admin1, admin2],
    threshold: 2,
    allowedClaimTypes: ['witness-member'],
  });

  const admin1Did = await makeDidForKey(admin1.signingKeyPair.publicKey);
  const admin2Did = await makeDidForKey(admin2.signingKeyPair.publicKey);

  // Attach non-digested adminDids (option a) parallel to adminVids.
  const doc: VtcGovernanceDoc = { ...identity.governanceDoc, adminDids: [admin1Did, admin2Did] };
  return { doc, admin1, admin2 };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('verifyVrcResolved: happy path — admin DIDs resolve to the signing keys', async () => {
  const { doc, admin1, admin2 } = await makeGovernanceDocWithDids();
  const subject = makeFounder();

  const vrc = issueVrc({
    governanceDoc: doc,
    subjectVid: subject.vid,
    claim: { type: 'witness-member' },
    signers: [admin1, admin2],
  });

  const resolver = new DidResolver();
  const result = await verifyVrcResolved(vrc, doc, resolver);
  assert.equal(result.valid, true, `expected valid VRC, got: ${result.reason}`);
  assert.equal(result.validSignatureCount, 2);
});

test('verifyVrcResolved: degrades to self-certifying when no adminDid/DID present', async () => {
  // No adminDids attached — resolution path is skipped per signature.
  const admin1 = makeFounder();
  const admin2 = makeFounder();
  const identity = await createVtc({
    name: 'Witness VTC',
    founders: [admin1, admin2],
    threshold: 2,
    allowedClaimTypes: ['witness-member'],
  });
  const subject = makeFounder();
  const vrc = issueVrc({
    governanceDoc: identity.governanceDoc,
    subjectVid: subject.vid,
    claim: { type: 'witness-member' },
    signers: [admin1, admin2],
  });

  const resolver = new DidResolver();
  const result = await verifyVrcResolved(vrc, identity.governanceDoc, resolver);
  assert.equal(result.valid, true, `expected valid VRC (self-certifying fallback), got: ${result.reason}`);
  assert.equal(result.validSignatureCount, 2);
});

test('verifyVrcResolved: rejects when an admin DID now resolves to a rotated (different) key', async () => {
  const { doc, admin1, admin2 } = await makeGovernanceDocWithDids();
  const subject = makeFounder();

  const vrc = issueVrc({
    governanceDoc: doc,
    subjectVid: subject.vid,
    claim: { type: 'witness-member' },
    signers: [admin1, admin2],
  });

  // Simulate admin1's DID rotating to a NEW key: its DID document's #key-1 is
  // now a different public key, so the self-certifying VID no longer matches
  // the live assertionMethod key.
  const rotatedKey = generateEd25519KeyPair();
  const rotatedDid = await makeDidForKey(rotatedKey.publicKey);
  const rotatedDoc: VtcGovernanceDoc = { ...doc, adminDids: [rotatedDid, doc.adminDids![1]] };

  const resolver = new DidResolver();
  const result = await verifyVrcResolved(vrc, rotatedDoc, resolver);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'signer-key-rotated-or-unresolvable');
});
