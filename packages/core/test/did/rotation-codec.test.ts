// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for rotation log codec — Step 11, Task 11.6.
 *
 * Covers:
 *   - computeRotationEntryDigest determinism
 *   - computeNextKeyCommitment (simple sha256 wrapper)
 *   - encodeRotationLogEntry / decodeRotationLogEntry round-trip (with and
 *     without witnessAttestations, with and without prevHash)
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/did/rotation-codec.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { generateEd25519KeyPair, signEd25519, sha256 } from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { buildDidPeer4Document } from '../../src/did/create.js';
import {
  computeRotationEntryDigest,
  computeNextKeyCommitments,
  encodeRotationLogEntry,
  decodeRotationLogEntry,
} from '../../src/did/rotation-codec.js';
import { createVtc, issueVrc } from '../../src/vtc/vtc.js';
import type { RotationLogEntry } from '../../src/did/rotation-types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeVid(): { vid: string; signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array } } {
  const kp = generateEd25519KeyPair();
  return { vid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, kp.publicKey), signingKeyPair: kp };
}


function makeGenesisEntry(): { entry: RotationLogEntry; signingKeyPair: ReturnType<typeof generateEd25519KeyPair> } {
  const signingKeyPair = generateEd25519KeyPair();
  const nextKeyPair = generateEd25519KeyPair();
  const doc = buildDidPeer4Document(signingKeyPair.publicKey, generateEd25519KeyPair().publicKey);
  const docWithId = { ...doc, id: `did:webvh-rotating:${Buffer.from(signingKeyPair.publicKey).toString('hex')}` };

  const unsigned = {
    version: 0,
    didDocument: docWithId,
    prevHash: null as Uint8Array | null,
    nextKeyCommitments: computeNextKeyCommitments([nextKeyPair.publicKey]),
    createdAt: 1700000000,
  };
  const digest = computeRotationEntryDigest(unsigned);
  const signature = signEd25519(digest, signingKeyPair.secretKey);

  const entry: RotationLogEntry = { ...unsigned, digest, signature, witnessAttestations: [] };
  return { entry, signingKeyPair };
}

// ---------------------------------------------------------------------------
// computeRotationEntryDigest
// ---------------------------------------------------------------------------

test('computeRotationEntryDigest: deterministic for identical fields', () => {
  const { entry } = makeGenesisEntry();
  const d1 = computeRotationEntryDigest(entry);
  const d2 = computeRotationEntryDigest({ ...entry });
  assert.deepEqual(d1, d2);
  assert.equal(d1.length, 32);
});

test('computeRotationEntryDigest: differs when version differs', () => {
  const { entry } = makeGenesisEntry();
  const d1 = computeRotationEntryDigest(entry);
  const d2 = computeRotationEntryDigest({ ...entry, version: 1 });
  assert.notDeepEqual(d1, d2);
});

// ---------------------------------------------------------------------------
// computeNextKeyCommitments
// ---------------------------------------------------------------------------

test('computeNextKeyCommitments: equals sha256(publicKey)', () => {
  const kp = generateEd25519KeyPair();
  const commitments = computeNextKeyCommitments([kp.publicKey]);
  assert.deepEqual(commitments, [sha256(kp.publicKey)]);
});

// ---------------------------------------------------------------------------
// encodeRotationLogEntry / decodeRotationLogEntry round-trip
// ---------------------------------------------------------------------------

test('encodeRotationLogEntry / decodeRotationLogEntry: round-trips a genesis entry (no witness attestations)', () => {
  const { entry } = makeGenesisEntry();

  const encoded = encodeRotationLogEntry(entry);
  const decoded = decodeRotationLogEntry(encoded);

  assert.equal(decoded.version, entry.version);
  assert.deepEqual(decoded.didDocument, entry.didDocument);
  assert.equal(decoded.prevHash, null);
  assert.deepEqual(decoded.nextKeyCommitments, entry.nextKeyCommitments);
  assert.equal(decoded.createdAt, entry.createdAt);
  assert.deepEqual(decoded.digest, entry.digest);
  assert.deepEqual(decoded.signature, entry.signature);
  assert.deepEqual(decoded.witnessAttestations, []);
});

test('encodeRotationLogEntry / decodeRotationLogEntry: round-trips an entry with a non-null prevHash', () => {
  const { entry: genesis } = makeGenesisEntry();
  const nextKeyPair = generateEd25519KeyPair();
  const doc2 = buildDidPeer4Document(generateEd25519KeyPair().publicKey, generateEd25519KeyPair().publicKey);
  const docWithId = { ...doc2, id: genesis.didDocument.id };

  const unsigned = {
    version: 1,
    didDocument: docWithId,
    prevHash: genesis.digest as Uint8Array | null,
    nextKeyCommitments: computeNextKeyCommitments([nextKeyPair.publicKey]),
    createdAt: 1700000100,
  };
  const digest = computeRotationEntryDigest(unsigned);
  const signature = signEd25519(digest, generateEd25519KeyPair().secretKey);
  const entry: RotationLogEntry = { ...unsigned, digest, signature, witnessAttestations: [] };

  const decoded = decodeRotationLogEntry(encodeRotationLogEntry(entry));
  assert.equal(decoded.version, 1);
  assert.deepEqual(decoded.prevHash, genesis.digest);
  assert.deepEqual(decoded.nextKeyCommitments, entry.nextKeyCommitments);
});

test('encodeRotationLogEntry / decodeRotationLogEntry: round-trips an entry with witnessAttestations', async () => {
  const admin1 = makeVid();
  const admin2 = makeVid();
  const identity = await createVtc({
    name: 'Test Witness VTC',
    founders: [admin1, admin2],
    threshold: 2,
    allowedClaimTypes: ['rotation-witness'],
  });

  const { entry: genesis } = makeGenesisEntry();
  const vrc = issueVrc({
    governanceDoc: identity.governanceDoc,
    subjectVid: makeVid().vid,
    claim: {
      type: 'rotation-witness',
      rotationDigest: Buffer.from(genesis.digest).toString('base64'),
      observedAt: 1700000050,
    },
    signers: [admin1, admin2],
  });

  const entryWithAttestation: RotationLogEntry = { ...genesis, witnessAttestations: [vrc] };

  const decoded = decodeRotationLogEntry(encodeRotationLogEntry(entryWithAttestation));
  assert.equal(decoded.witnessAttestations.length, 1);
  assert.equal(decoded.witnessAttestations[0].claim.type, 'rotation-witness');
  assert.deepEqual(decoded.witnessAttestations[0].digest, vrc.digest);
  assert.equal(decoded.witnessAttestations[0].signatures.length, 2);
});
