// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for the TSP v3 (Rev 3) message codec.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tsp/v3-message.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateEd25519KeyPair } from '../../src/crypto/primitives.js';
import { tspSeal, tspOpen, peekEnvelope, computeSaidDigest, assertSignableWithinLimit, advanceRoutingField, TSP_MAX_SIGNABLE_CHARS } from '../../src/tsp/v3/message.js';
import { TSP_CURRENT_VERSION_STRING } from '../../src/tsp/version.js';

const ALICE = 'did:peer:4zQmUL61Nc1F7ioiKxHNqwnJXX4srh';
const BOB = 'did:peer:4zQmZmA0sG7j1ewTjXjtdwujik33CE2cMbYSPagpMiYnt1A';

function newSigner() {
  const keyPair = generateEd25519KeyPair();
  return { vid: ALICE, keyPair };
}

function zeros(n: number): Uint8Array {
  return new Uint8Array(n);
}

test('TSP_GEN round trip: signature verifies, body preserved', () => {
  const s = newSigner();
  const body = new TextEncoder().encode('hello v3 TSP');
  const sealed = tspSeal({ vidSender: s.vid, vidReceiver: BOB, payload: { type: 'TSP_GEN', body }, signingSecretKey: s.keyPair.secretKey });
  const envelope = tspOpen({ message: sealed, senderPublicKey: s.keyPair.publicKey });
  assert.equal(envelope.version, TSP_CURRENT_VERSION_STRING);
  assert.equal(envelope.vidSender, s.vid);
  assert.equal(envelope.vidReceiver, BOB);
  assert.equal(envelope.payload.type, 'TSP_GEN');
  assert.deepEqual((envelope.payload as { body: Uint8Array }).body, body);
});

test('TSP_GEN with NULL receiver round trips', () => {
  const s = newSigner();
  const sealed = tspSeal({ vidSender: s.vid, vidReceiver: null, payload: { type: 'TSP_GEN', body: new Uint8Array([1, 2, 3]) }, signingSecretKey: s.keyPair.secretKey });
  const envelope = tspOpen({ message: sealed, senderPublicKey: s.keyPair.publicKey });
  assert.equal(envelope.vidReceiver, null);
  assert.deepEqual((envelope.payload as { body: Uint8Array }).body, new Uint8Array([1, 2, 3]));
});

test('TSP_GEN sealed message uses -E## envelope + YTSP-AAC + XSCS', () => {
  const s = newSigner();
  const sealed = tspSeal({ vidSender: s.vid, vidReceiver: BOB, payload: { type: 'TSP_GEN', body: new TextEncoder().encode('x') }, signingSecretKey: s.keyPair.secretKey });
  const str = new TextDecoder().decode(sealed);
  assert.ok(str.startsWith('-E'), 'envelope starts with -E##');
  assert.ok(str.includes('YTSP-AAC'), 'contains version YTSP-AAC');
  assert.ok(str.includes('XSCS'), 'contains XSCS field tag');
});

test('TSP_RFI round trip preserves nonce and derives the self-addressing digest', () => {
  const s = newSigner();
  const nonce = new Uint8Array(16).fill(0x11);
  const sealed = tspSeal({ vidSender: s.vid, vidReceiver: BOB, payload: { type: 'TSP_RFI', nonce }, signingSecretKey: s.keyPair.secretKey });
  const envelope = tspOpen({ message: sealed, senderPublicKey: s.keyPair.publicKey });
  assert.equal(envelope.payload.type, 'TSP_RFI');
  const p = envelope.payload as { nonce: Uint8Array; digest: Uint8Array };
  assert.deepEqual(p.nonce, nonce);
  assert.deepEqual(p.digest, computeSaidDigest('RFI', s.vid, BOB, { nonce }));
});

test('TSP_RFA round trip preserves digest and derives the Reply_Digest', () => {
  const s = newSigner();
  const digest = new Uint8Array(32).fill(0x33);
  const sealed = tspSeal({ vidSender: s.vid, vidReceiver: BOB, payload: { type: 'TSP_RFA', digest }, signingSecretKey: s.keyPair.secretKey });
  const envelope = tspOpen({ message: sealed, senderPublicKey: s.keyPair.publicKey });
  assert.equal(envelope.payload.type, 'TSP_RFA');
  const p = envelope.payload as { digest: Uint8Array; replyDigest: Uint8Array };
  assert.deepEqual(p.digest, digest);
  assert.deepEqual(p.replyDigest, computeSaidDigest('RFA', s.vid, BOB, { requestDigest: digest }));
});

test('TSP_RFD round trip preserves digest', () => {
  const s = newSigner();
  const digest = new Uint8Array(32).fill(0x55);
  const sealed = tspSeal({ vidSender: s.vid, vidReceiver: BOB, payload: { type: 'TSP_RFD', digest }, signingSecretKey: s.keyPair.secretKey });
  const envelope = tspOpen({ message: sealed, senderPublicKey: s.keyPair.publicKey });
  assert.equal(envelope.payload.type, 'TSP_RFD');
  assert.deepEqual((envelope.payload as { digest: Uint8Array }).digest, digest);
});

test('tampered payload causes signature verification failure', () => {
  const s = newSigner();
  const sealed = tspSeal({ vidSender: s.vid, vidReceiver: BOB, payload: { type: 'TSP_GEN', body: new TextEncoder().encode('original') }, signingSecretKey: s.keyPair.secretKey });
  const bytes = new Uint8Array(sealed);
  bytes[6] ^= 0xff; // inside the signable portion
  assert.throws(() => tspOpen({ message: bytes, senderPublicKey: s.keyPair.publicKey }), /signature/i);
});

test('wrong sender public key fails to open', () => {
  const s = newSigner();
  const other = newSigner();
  const sealed = tspSeal({ vidSender: s.vid, vidReceiver: BOB, payload: { type: 'TSP_GEN', body: new TextEncoder().encode('x') }, signingSecretKey: s.keyPair.secretKey });
  assert.throws(() => tspOpen({ message: sealed, senderPublicKey: other.keyPair.publicKey }), /signature/i);
});

test('non -E## message throws SyntaxError', () => {
  assert.throws(() => tspOpen({ message: new TextEncoder().encode('not a message'), senderPublicKey: zeros(32) }), SyntaxError);
});

// ---------------------------------------------------------------------------
// Big counter form (--E#####) — regression: the encoder's own output for any
// message over 4095 quadlets (16 380 chars) used to be rejected by both
// tspOpen and peekEnvelope, so every large payload was dropped SILENTLY by the
// receiver and the sender timed out after 30 s.
// ---------------------------------------------------------------------------

test('TSP_GEN over the 4095-quadlet boundary round-trips in the Big envelope form', () => {
  const s = newSigner();
  const body = zeros(13_000).fill(0x41);

  const sealed = tspSeal({
    vidSender: s.vid, vidReceiver: BOB,
    payload: { type: 'TSP_GEN', body },
    signingSecretKey: s.keyPair.secretKey,
  });

  // Documents the wire form this test exists for: the encoder switches to the
  // Big counter automatically, and the decoder must accept it.
  const head = new TextDecoder().decode(sealed).slice(0, 3);
  assert.equal(head, '--E', 'a body this size must use the Big envelope form');

  // peek() (no signature verification) must work — the relationship layer uses
  // it to resolve the sender before calling tspOpen().
  const peeked = peekEnvelope(sealed);
  assert.equal(peeked.payloadType, 'TSP_GEN');
  assert.equal(peeked.vidSender, s.vid);

  const envelope = tspOpen({ message: sealed, senderPublicKey: s.keyPair.publicKey });
  assert.equal(envelope.payload.type, 'TSP_GEN');
  assert.equal((envelope.payload as { body: Uint8Array }).body.length, 13_000);
  assert.deepEqual((envelope.payload as { body: Uint8Array }).body, body);
});

test('TSP_GEN round-trips at 40 KB and 1 MB (Big envelope + Big payload group)', () => {
  const s = newSigner();
  for (const size of [40_000, 1_000_000]) {
    const body = new Uint8Array(size);
    for (let i = 0; i < size; i++) body[i] = i & 0xff;

    const sealed = tspSeal({
      vidSender: s.vid, vidReceiver: BOB,
      payload: { type: 'TSP_GEN', body },
      signingSecretKey: s.keyPair.secretKey,
    });
    assert.equal(new TextDecoder().decode(sealed).slice(0, 3), '--E');

    const envelope = tspOpen({ message: sealed, senderPublicKey: s.keyPair.publicKey });
    const opened = (envelope.payload as { body: Uint8Array }).body;
    assert.equal(opened.length, size, `body length must survive a ${size}-byte round trip`);
    assert.deepEqual(opened, body, `body bytes must survive a ${size}-byte round trip`);
  }
});

test('TSP_RFI with a large inline DID document round-trips (relationship handshake)', () => {
  const s = newSigner();
  const nonce = new Uint8Array(16).fill(0x7e);
  // A DID document large enough to push the RFI past the 4095-quadlet boundary.
  const bigDoc = {
    id: s.vid,
    verificationMethod: [{ id: `${s.vid}#key-1`, publicKeyMultibase: 'z6Mk' + 'q'.repeat(44) }],
    alsoKnownAs: ['vta:vta:alice'],
    padding: 'x'.repeat(24_000),
  };

  const sealed = tspSeal({
    vidSender: s.vid, vidReceiver: BOB,
    payload: { type: 'TSP_RFI', nonce, didDocument: bigDoc as never },
    signingSecretKey: s.keyPair.secretKey,
  });
  assert.equal(new TextDecoder().decode(sealed).slice(0, 3), '--E');

  // The handshake reads the document from peek() before tspOpen().
  const peeked = peekEnvelope(sealed);
  assert.equal(peeked.payloadType, 'TSP_RFI');
  assert.deepEqual(peeked.didDocument, bigDoc as never);

  const envelope = tspOpen({ message: sealed, senderPublicKey: s.keyPair.publicKey });
  const payload = envelope.payload as { type: string; nonce: Uint8Array; digest?: Uint8Array; didDocument?: unknown };
  assert.deepEqual(payload.nonce, nonce, 'nonce must survive');
  assert.deepEqual(payload.didDocument, bigDoc as never);
  // The self-addressing digest covers only version+VIDs+payload fields, so the
  // oversized inline document must not change it.
  assert.deepEqual(payload.digest, computeSaidDigest('RFI', s.vid, BOB, { nonce }));
});

test('seal-time size guard rejects only pathological sizes', () => {
  assert.doesNotThrow(() => assertSignableWithinLimit(TSP_MAX_SIGNABLE_CHARS));
  assert.throws(() => assertSignableWithinLimit(TSP_MAX_SIGNABLE_CHARS + 1), RangeError);
});

// ---------------------------------------------------------------------------
// Routing fields (H3) — Reply_Path / Referral_Field
//
// The decoder used to advance a hard-coded 4 bytes past each routing field.
// That is correct only while the field is EMPTY (`-JAA`); a real `-J##` group
// would have shifted every following byte — including the inlined DID document
// — and fed garbage to parseDidDocument, silently. These tests pin the advance
// and both rejection paths. The advance is exercised through the exported
// helper rather than a signed message because the encoder deliberately cannot
// emit routing, so a hand-built message is the only other option (and would
// have to reimplement the framing this suite already covers).
// ---------------------------------------------------------------------------

test('routing: an empty Reply_Path/Referral_Field is stepped by its real length', () => {
  // `-JAA` is a -J counter with count 0: a 4-char header and no content.
  const fields = '-JAA' + '-JAA' + '4BAA' + '<document follows>';

  const afterReplyPath = advanceRoutingField(fields, 0, 'Reply_Path');
  assert.equal(afterReplyPath, 4, 'an empty routing field is 4 chars');
  assert.equal(fields.slice(afterReplyPath), '-JAA4BAA<document follows>');

  const afterReferral = advanceRoutingField(fields, afterReplyPath, 'Referral_Field');
  assert.equal(afterReferral, 8, 'two empty routing fields occupy 8 chars');
  assert.equal(
    fields.slice(afterReferral),
    '4BAA<document follows>',
    'the payload after the routing fields must be untouched — this is what the DID document parse depends on',
  );
});

test('routing: a NON-EMPTY routing field is rejected loudly, never mis-sliced', () => {
  // `-JAB` is a -J counter with count 1, i.e. one quadlet of routing data
  // follows. Stepping a fixed 4 bytes would land inside that content and shift
  // everything after it.
  const withContent = '-JAB' + 'AAAA' + '4BAA';

  assert.throws(
    () => advanceRoutingField(withContent, 0, 'Reply_Path'),
    (err: unknown) => {
      assert.ok(err instanceof SyntaxError, 'must be a SyntaxError');
      assert.match((err as Error).message, /Reply_Path/, 'must name the offending field');
      assert.match((err as Error).message, /1 quadlet/, 'must say how much routing data it found');
      assert.match((err as Error).message, /does not support/, 'must say routing is unsupported');
      assert.match((err as Error).message, /Refusing to mis-slice/, 'must state the refusal, not a misparse');
      return true;
    },
  );

  // The same field is rejected under the referral name too (same advance site).
  assert.throws(
    () => advanceRoutingField(withContent, 0, 'Referral_Field'),
    /Referral_Field/,
  );
});

test('routing: a non-routing counter where a routing field belongs is rejected', () => {
  // Right shape (a 4-char counter, count 0), wrong family: `-ZAA` is the
  // payload group counter, not a routing field.
  assert.throws(
    () => advanceRoutingField('-ZAA' + '4BAA', 0, 'Reply_Path'),
    (err: unknown) => {
      assert.match((err as Error).message, /-J## routing counter/);
      return true;
    },
  );

  // A payload truncated before the routing fields must fail loudly rather than
  // silently yielding "no document" — the failure mode this replaced.
  assert.throws(() => advanceRoutingField('', 0, 'Reply_Path'), /not a counter/);
});

test('routing: a sealed RFI still round-trips its DID document past the routing fields', () => {
  const s = newSigner();
  const nonce = new Uint8Array(16).fill(0x5a);
  const didDocument = {
    id: s.vid,
    verificationMethod: [{ id: `${s.vid}#key-1`, publicKeyMultibase: 'z6Mk' + 'r'.repeat(44) }],
  };

  const sealed = tspSeal({
    vidSender: s.vid, vidReceiver: BOB,
    payload: { type: 'TSP_RFI', nonce, didDocument: didDocument as never },
    signingSecretKey: s.keyPair.secretKey,
  });

  // The encoder writes the EMPTY routing form only. If it ever emitted a
  // non-empty `-J##` group, the decoder would now throw on its own output —
  // which is the behaviour these tests want to make impossible to ship.
  const sealedText = new TextDecoder().decode(sealed);
  assert.ok(sealedText.includes('-JAA-JAA'), 'the encoded RFI must carry the two empty routing fields');

  // And the document after them still parses, on both decode paths.
  assert.deepEqual(peekEnvelope(sealed).didDocument, didDocument as never);
  const envelope = tspOpen({ message: sealed, senderPublicKey: s.keyPair.publicKey });
  assert.deepEqual(
    (envelope.payload as { didDocument?: unknown }).didDocument,
    didDocument as never,
    'the DID document must survive the routing fields on the tspOpen path too',
  );

  // The digest covers the routing fields in their empty form; the golden vectors
  // in v3-golden.test.ts pin that coverage, so a change here fails loudly there.
  assert.deepEqual(
    (envelope.payload as { digest?: Uint8Array }).digest,
    computeSaidDigest('RFI', s.vid, BOB, { nonce }),
  );
});
