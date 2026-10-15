// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for VTC/VRC CESR codec + digest computation — Step 10, Task 10.7.
 *
 * Covers:
 *   - encodeVidList / decodeVidList round-trip
 *   - encodeSignatureList / decodeSignatureList round-trip
 *   - encodeGovernanceDoc / decodeGovernanceDoc round-trip
 *   - encodeVrc / decodeVrc round-trip
 *   - computeGovernanceDocDigest / computeVrcDigest determinism
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/vtc/codec.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { generateEd25519KeyPair, signEd25519 } from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import {
  encodeVidList,
  decodeVidList,
  encodeSignatureList,
  decodeSignatureList,
  encodeGovernanceDoc,
  decodeGovernanceDoc,
  encodeVrc,
  decodeVrc,
  computeGovernanceDocDigest,
  computeVrcDigest,
} from '../../src/vtc/codec.js';
import type { Vrc, VrcSignature, VtcGovernanceDoc } from '../../src/vtc/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeVid(): { vid: string; secretKey: Uint8Array; publicKey: Uint8Array } {
  const kp = generateEd25519KeyPair();
  return { vid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, kp.publicKey), ...kp };
}

// ---------------------------------------------------------------------------
// VID list round-trip
// ---------------------------------------------------------------------------

test('encodeVidList / decodeVidList: round-trips a list of VIDs', () => {
  const a = makeVid();
  const b = makeVid();
  const c = makeVid();

  const encoded = encodeVidList([a.vid, b.vid, c.vid]);
  const decoded = decodeVidList(encoded);

  assert.deepEqual(decoded, [a.vid, b.vid, c.vid]);
});

test('encodeVidList / decodeVidList: round-trips an empty list', () => {
  const encoded = encodeVidList([]);
  const decoded = decodeVidList(encoded);
  assert.deepEqual(decoded, []);
});

// ---------------------------------------------------------------------------
// Signature list round-trip
// ---------------------------------------------------------------------------

test('encodeSignatureList / decodeSignatureList: round-trips signatures', () => {
  const a = makeVid();
  const b = makeVid();
  const digest = new Uint8Array(32).fill(7);

  const sigs: VrcSignature[] = [
    { signerVid: a.vid, signature: signEd25519(digest, a.secretKey) },
    { signerVid: b.vid, signature: signEd25519(digest, b.secretKey) },
  ];

  const encoded = encodeSignatureList(sigs);
  const decoded = decodeSignatureList(encoded);

  assert.equal(decoded.length, 2);
  assert.equal(decoded[0].signerVid, a.vid);
  assert.deepEqual(decoded[0].signature, sigs[0].signature);
  assert.equal(decoded[1].signerVid, b.vid);
  assert.deepEqual(decoded[1].signature, sigs[1].signature);
});

// ---------------------------------------------------------------------------
// Digest determinism
// ---------------------------------------------------------------------------

test('computeGovernanceDocDigest: deterministic for identical fields', () => {
  const admin = makeVid();
  const vtc = makeVid();

  const base = {
    vtcVid: vtc.vid,
    vtcDid: 'did:peer:4:zSomething',
    name: 'Witness VTC',
    adminVids: [admin.vid],
    threshold: 1,
    allowedClaimTypes: ['witness-member'],
    createdAt: 1700000000,
  };

  const d1 = computeGovernanceDocDigest(base);
  const d2 = computeGovernanceDocDigest({ ...base });

  assert.deepEqual(d1, d2);
  assert.equal(d1.length, 32);
});

test('computeVrcDigest: deterministic for identical fields', () => {
  const subject = makeVid();
  const issuer = makeVid();

  const base = {
    subjectVid: subject.vid,
    issuerVid: issuer.vid,
    claim: { type: 'witness-member' },
    issuedAt: 1700000000,
    expiresAt: undefined,
  };

  const d1 = computeVrcDigest(base);
  const d2 = computeVrcDigest({ ...base });

  assert.deepEqual(d1, d2);
  assert.equal(d1.length, 32);
});

test('computeVrcDigest: differs when claim differs', () => {
  const subject = makeVid();
  const issuer = makeVid();

  const d1 = computeVrcDigest({
    subjectVid: subject.vid,
    issuerVid: issuer.vid,
    claim: { type: 'witness-member' },
    issuedAt: 1700000000,
    expiresAt: undefined,
  });
  const d2 = computeVrcDigest({
    subjectVid: subject.vid,
    issuerVid: issuer.vid,
    claim: { type: 'other-claim' },
    issuedAt: 1700000000,
    expiresAt: undefined,
  });

  assert.notDeepEqual(d1, d2);
});

// ---------------------------------------------------------------------------
// Full frame round-trip — VtcGovernanceDoc
// ---------------------------------------------------------------------------

test('encodeGovernanceDoc / decodeGovernanceDoc: round-trips a full governance doc', () => {
  const admin1 = makeVid();
  const admin2 = makeVid();
  const vtc = makeVid();

  const unsigned: Omit<VtcGovernanceDoc, 'digest' | 'signatures'> = {
    vtcVid: vtc.vid,
    vtcDid: 'did:peer:4:zAbc123',
    name: 'Genesis Witness VTC',
    adminVids: [admin1.vid, admin2.vid],
    threshold: 2,
    allowedClaimTypes: ['witness-member'],
    createdAt: 1700000000,
  };
  const digest = computeGovernanceDocDigest(unsigned);
  const signatures: VrcSignature[] = [
    { signerVid: admin1.vid, signature: signEd25519(digest, admin1.secretKey) },
    { signerVid: admin2.vid, signature: signEd25519(digest, admin2.secretKey) },
  ];

  const doc: VtcGovernanceDoc = { ...unsigned, digest, signatures };

  const encoded = encodeGovernanceDoc(doc);
  const decoded = decodeGovernanceDoc(encoded);

  assert.equal(decoded.vtcVid, doc.vtcVid);
  assert.equal(decoded.vtcDid, doc.vtcDid);
  assert.equal(decoded.name, doc.name);
  assert.deepEqual(decoded.adminVids, doc.adminVids);
  assert.equal(decoded.threshold, doc.threshold);
  assert.deepEqual(decoded.allowedClaimTypes, doc.allowedClaimTypes);
  assert.equal(decoded.createdAt, doc.createdAt);
  assert.deepEqual(decoded.digest, doc.digest);
  assert.equal(decoded.signatures.length, 2);
  assert.equal(decoded.signatures[0].signerVid, admin1.vid);
  assert.deepEqual(decoded.signatures[0].signature, signatures[0].signature);
});

// ---------------------------------------------------------------------------
// Full frame round-trip — Vrc
// ---------------------------------------------------------------------------

test('encodeVrc / decodeVrc: round-trips a full Vrc', () => {
  const subject = makeVid();
  const issuer = makeVid();
  const admin = makeVid();

  const unsigned: Omit<Vrc, 'digest' | 'signatures'> = {
    subjectVid: subject.vid,
    issuerVid: issuer.vid,
    claim: { type: 'witness-member' },
    issuedAt: 1700000000,
    expiresAt: 1800000000,
  };
  const digest = computeVrcDigest(unsigned);
  const signatures: VrcSignature[] = [
    { signerVid: admin.vid, signature: signEd25519(digest, admin.secretKey) },
  ];

  const vrc: Vrc = { ...unsigned, digest, signatures };

  const encoded = encodeVrc(vrc);
  const decoded = decodeVrc(encoded);

  assert.equal(decoded.subjectVid, vrc.subjectVid);
  assert.equal(decoded.issuerVid, vrc.issuerVid);
  assert.deepEqual(decoded.claim, vrc.claim);
  assert.equal(decoded.issuedAt, vrc.issuedAt);
  assert.equal(decoded.expiresAt, vrc.expiresAt);
  assert.deepEqual(decoded.digest, vrc.digest);
  assert.equal(decoded.signatures.length, 1);
  assert.equal(decoded.signatures[0].signerVid, admin.vid);
});

test('encodeVrc / decodeVrc: round-trips a Vrc with no expiresAt', () => {
  const subject = makeVid();
  const issuer = makeVid();
  const admin = makeVid();

  const unsigned: Omit<Vrc, 'digest' | 'signatures'> = {
    subjectVid: subject.vid,
    issuerVid: issuer.vid,
    claim: { type: 'witness-member' },
    issuedAt: 1700000000,
  };
  const digest = computeVrcDigest(unsigned);
  const vrc: Vrc = {
    ...unsigned,
    digest,
    signatures: [{ signerVid: admin.vid, signature: signEd25519(digest, admin.secretKey) }],
  };

  const decoded = decodeVrc(encodeVrc(vrc));
  assert.equal(decoded.expiresAt, undefined);
});
