// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Unit tests for the shared RFI/RFA self-addressing digest verification
 * (TSP Rev 3 §7.2.1).
 *
 * This module is the SINGLE implementation both handshake responders use — the
 * agent's `RelationshipManager` and the utility server's `tsp-bridge`. They had
 * diverged (the server verified nothing at all, so a mis-addressed or tampered
 * invite was accepted and answered), so these tests pin the rules both sides now
 * share.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/relationship/handshake-verify.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeSaidDigest } from '../../src/tsp/v3/message.js';
import { verifyRfiDigest, verifyRfaDigests, verifySenderDocumentBinding } from '../../src/relationship/handshake-verify.js';
import { generateEd25519KeyPair } from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { createDidPeer4 } from '../../src/did/create.js';
import { resolveDidPeer4 } from '../../src/did/resolve.js';

const ALICE = 'did:scid:vh:1:zAlice';
const BOB = 'did:scid:vh:1:zBob';
const CAROL = 'did:scid:vh:1:zCarol';
const NONCE = new Uint8Array(16).fill(0x33);

function rfiDigest(sender: string, receiver: string): Uint8Array {
  return computeSaidDigest('RFI', sender, receiver, { nonce: NONCE });
}

function reasonOf(result: { ok: boolean }): string {
  return (result as unknown as { reason: string }).reason;
}

// ---------------------------------------------------------------------------
// RFI
// ---------------------------------------------------------------------------

test('verifyRfiDigest: accepts an invite computed for us', () => {
  const digest = rfiDigest(ALICE, BOB);
  assert.deepEqual(verifyRfiDigest({ vidSender: ALICE, localDid: BOB, nonce: NONCE, digest }), { ok: true });
});

test('verifyRfiDigest: accepts an invite whose envelope receiver is us', () => {
  const digest = rfiDigest(ALICE, BOB);
  const result = verifyRfiDigest({
    vidSender: ALICE, localDid: BOB, nonce: NONCE, digest, receiverVid: BOB,
  });
  assert.deepEqual(result, { ok: true });
});

test('verifyRfiDigest: an invite addressed to a THIRD party is reported precisely', () => {
  // The stale/mismatched-OOBI case: the invite is internally consistent but was
  // computed for CAROL, so it can never match BOB.
  const digest = rfiDigest(ALICE, CAROL);
  const result = verifyRfiDigest({
    vidSender: ALICE, localDid: BOB, nonce: NONCE, digest, receiverVid: CAROL,
  });
  assert.equal(result.ok, false);
  assert.equal(reasonOf(result), 'rfi_addressed_elsewhere');
  assert.match((result as unknown as { detail: string }).detail, /addressed=did:scid:vh:1:zCarol/);
});

test('verifyRfiDigest: rejects a mismatched digest', () => {
  const result = verifyRfiDigest({
    vidSender: ALICE, localDid: BOB, nonce: NONCE, digest: new Uint8Array(32).fill(0x11), receiverVid: BOB,
  });
  assert.equal(result.ok, false);
  assert.equal(reasonOf(result), 'rfi_digest_mismatch');
});

test('verifyRfiDigest: rejects a missing digest', () => {
  const result = verifyRfiDigest({ vidSender: ALICE, localDid: BOB, nonce: NONCE, digest: undefined });
  assert.equal(result.ok, false);
  assert.equal(reasonOf(result), 'rfi_digest_mismatch');
  assert.match((result as unknown as { detail: string }).detail, /actual=none/);
});

// ---------------------------------------------------------------------------
// RFA
// ---------------------------------------------------------------------------

test('verifyRfaDigests: accepts a correctly built accept', () => {
  const requestDigest = rfiDigest(ALICE, BOB);
  const replyDigest = computeSaidDigest('RFA', ALICE, BOB, { requestDigest });
  const result = verifyRfaDigests({
    vidSender: ALICE, localDid: BOB,
    digest: requestDigest, replyDigest,
    expectedRfiDigest: requestDigest, receiverVid: BOB,
  });
  assert.deepEqual(result, { ok: true });
});

test('verifyRfaDigests: accepts without expectedRfiDigest (responder side)', () => {
  const requestDigest = rfiDigest(ALICE, BOB);
  const replyDigest = computeSaidDigest('RFA', ALICE, BOB, { requestDigest });
  const result = verifyRfaDigests({
    vidSender: ALICE, localDid: BOB, digest: requestDigest, replyDigest,
  });
  assert.deepEqual(result, { ok: true });
});

test('verifyRfaDigests: rejects an accept for an RFI we did not send', () => {
  const theirDigest = rfiDigest(ALICE, CAROL);
  const replyDigest = computeSaidDigest('RFA', ALICE, BOB, { requestDigest: theirDigest });
  const result = verifyRfaDigests({
    vidSender: ALICE, localDid: BOB,
    digest: theirDigest, replyDigest,
    expectedRfiDigest: rfiDigest(ALICE, BOB),
  });
  assert.equal(result.ok, false);
  assert.equal(reasonOf(result), 'rfa_digest_mismatch');
});

test('verifyRfaDigests: rejects a wrong Reply_Digest', () => {
  const requestDigest = rfiDigest(ALICE, BOB);
  const result = verifyRfaDigests({
    vidSender: ALICE, localDid: BOB,
    digest: requestDigest, replyDigest: new Uint8Array(32).fill(0x99),
  });
  assert.equal(result.ok, false);
  assert.equal(reasonOf(result), 'rfa_reply_digest_mismatch');
});

test('verifyRfaDigests: rejects a missing Reply_Digest', () => {
  const requestDigest = rfiDigest(ALICE, BOB);
  const result = verifyRfaDigests({
    vidSender: ALICE, localDid: BOB, digest: requestDigest, replyDigest: undefined,
  });
  assert.equal(result.ok, false);
  assert.equal(reasonOf(result), 'rfa_reply_digest_mismatch');
});

test('verifyRfaDigests: rejects an accept addressed elsewhere', () => {
  const requestDigest = rfiDigest(ALICE, BOB);
  const replyDigest = computeSaidDigest('RFA', ALICE, BOB, { requestDigest });
  const result = verifyRfaDigests({
    vidSender: ALICE, localDid: BOB,
    digest: requestDigest, replyDigest, receiverVid: CAROL,
  });
  assert.equal(result.ok, false);
  assert.equal(reasonOf(result), 'rfa_addressed_elsewhere');
});

// ---------------------------------------------------------------------------
// verifySenderDocumentBinding (H1) — the inline document must name the same
// identity as the envelope's sender. See the module docblock for why the SAID
// cannot do this job on its own.
// ---------------------------------------------------------------------------

/**
 * Build a REAL did:peer:4 identity (the same call the e2e harness and the agent
 * use) so the documents under test are production-shaped, not hand-rolled
 * multibase strings.
 */
async function realIdentity() {
  const result = await createDidPeer4({ peerId: 'test-peer', multiaddrs: ['/ip4/127.0.0.1/tcp/1'] });
  const document = await resolveDidPeer4(result.did);
  const cesrVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, result.signingKeyPair.publicKey);
  return { did: result.did, document, cesrVid };
}

test('verifySenderDocumentBinding: accepts a real document whose id is the envelope sender', async () => {
  const a = await realIdentity();
  assert.deepEqual(
    verifySenderDocumentBinding({ vidSender: a.did, document: a.document }),
    { ok: true },
  );
});

test('verifySenderDocumentBinding: accepts the CESR-key VID form (spec-conformant producer)', async () => {
  const a = await realIdentity();
  // The document's id is a DID; the envelope names the CESR encoding of the
  // document's own signing key. Same identity — and this is the exact relation
  // `LocalIdentity.cesrVid` / the OOBI's `vid` field rely on.
  assert.deepEqual(
    verifySenderDocumentBinding({ vidSender: a.cesrVid, document: a.document }),
    { ok: true },
  );
});

test('verifySenderDocumentBinding: REJECTS a document belonging to a different identity', async () => {
  // The substitution H1 is about: the envelope names Alice (the value the SAID
  // covers, and which several paths use as the peer's identity) while the
  // document — the source of the trusted signing key — belongs to Mallory.
  const alice = await realIdentity();
  const mallory = await realIdentity();

  const result = verifySenderDocumentBinding({
    vidSender: alice.did,
    document: mallory.document,
  });
  assert.equal(result.ok, false);
  assert.equal(reasonOf(result), 'sender_document_mismatch');
  // The detail must name both sides so a log alone can diagnose it.
  const detail = (result as unknown as { detail: string }).detail;
  assert.match(detail, /zQm/);
  assert.ok(detail.includes('envelope sender='), 'the detail must label the claimed sender');
  assert.ok(detail.includes('doc.id='), 'the detail must label the document id');
});

test('verifySenderDocumentBinding: REJECTS a document with no id', async () => {
  const a = await realIdentity();
  const { id: _omit, ...withoutId } = a.document as { id?: string };
  const result = verifySenderDocumentBinding({
    vidSender: a.did,
    document: withoutId as never,
  });
  assert.equal(result.ok, false);
  assert.equal(reasonOf(result), 'sender_document_missing_id');
});

test('verifySenderDocumentBinding: REJECTS a document with no usable key', async () => {
  const a = await realIdentity();
  // A document that names someone OTHER than the claimed sender, and publishes
  // no key that could account for the claim.
  const result = verifySenderDocumentBinding({
    vidSender: 'did:scid:vh:1:zSomeone',
    document: { id: a.did } as never,
  });
  assert.equal(result.ok, false);
  assert.equal(reasonOf(result), 'sender_document_mismatch');
  assert.match((result as unknown as { detail: string }).detail, /docKey=none/);
});

test('verifySenderDocumentBinding: REJECTS a missing document', () => {
  const result = verifySenderDocumentBinding({ vidSender: ALICE, document: undefined });
  assert.equal(result.ok, false);
  assert.equal(reasonOf(result), 'sender_document_missing_id');
});
