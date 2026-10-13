/**
 * Tests for did:peer:4 numalgo4 codec.
 *
 * Covers:
 *   - encode/decode round trip
 *   - correct multicodec prefix bytes (0x80 0x04 = json 0x0200)
 *   - correct multihash structure (code 18 = sha2-256, 32-byte digest)
 *   - hash verification
 *   - tamper detection
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/did/numalgo4.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base58btc } from 'multiformats/bases/base58';
import { encodePeer4, decodePeer4, verifyPeer4Hash } from '../../src/did/numalgo4.js';
import { resolveDidPeer4 } from '../../src/did/resolve.js';
import type { DidDocument } from '../../src/did/types.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeDoc(): DidDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [
      {
        id: '#key-1',
        type: 'Multikey',
        controller: '',
        publicKeyMultibase: 'z6MkfakeKeyExampleXXXXXXXXXXXXXXXXXXXXXXXXXX',
      },
    ],
    authentication: ['#key-1'],
    keyAgreement: ['#key-2'],
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('numalgo4: encode produces a valid did:peer:4 string', async () => {
  const doc = makeDoc();
  const { did, shortFormDid, longFormSuffix, hashComponent } = await encodePeer4(doc);

  assert.ok(did.startsWith('did:peer:4'), 'DID must start with did:peer:4');
  assert.ok(did.includes(':'), 'long-form DID must contain a colon separator');
  assert.ok(longFormSuffix.startsWith('z'), 'long-form suffix must be base58btc (starts with z)');
  assert.ok(hashComponent.startsWith('z'), 'hash component must be base58btc (starts with z)');
  assert.ok(shortFormDid.startsWith('did:peer:4'), 'short-form DID must start with did:peer:4');
  assert.ok(!shortFormDid.includes(':' + longFormSuffix), 'short-form DID must not include the long-form suffix');
});

test('numalgo4: long-form suffix has correct json multicodec prefix (0x80 0x04)', async () => {
  const doc = makeDoc();
  const { longFormSuffix } = await encodePeer4(doc);

  const decoded = base58btc.decode(longFormSuffix);
  assert.equal(decoded[0], 0x80, 'first byte of multicodec prefix must be 0x80');
  assert.equal(decoded[1], 0x04, 'second byte of multicodec prefix must be 0x04');
});

test('numalgo4: hash component is a base58btc-encoded sha2-256 multihash', async () => {
  const doc = makeDoc();
  const { hashComponent } = await encodePeer4(doc);

  const mhBytes = base58btc.decode(hashComponent);
  // multihash format: [code_varint, length_varint, digest...]
  // sha2-256 code = 18 (0x12), length = 32 (0x20)
  assert.equal(mhBytes[0], 18, 'multihash code must be 18 (sha2-256)');
  assert.equal(mhBytes[1], 32, 'multihash digest length must be 32');
  assert.equal(mhBytes.length, 34, 'total multihash bytes must be 34 (2 header + 32 digest)');
});

test('numalgo4: decode round-trips the document', async () => {
  const doc = makeDoc();
  const { did } = await encodePeer4(doc);
  const { document: decoded } = decodePeer4(did);

  assert.deepEqual(decoded, doc, 'decoded document must deep-equal the original');
});

test('numalgo4: decode strips the id field if present in the encoded doc', async () => {
  // The id field should not be in the encoded document, but if it somehow
  // ends up there, decode should still work.
  const doc = makeDoc();
  const { did } = await encodePeer4(doc);
  const { document: decoded } = decodePeer4(did);

  assert.ok(!('id' in decoded) || decoded.id === undefined, 'decoded document must not have an id field');
});

test('numalgo4: verifyPeer4Hash returns true for a valid DID', async () => {
  const doc = makeDoc();
  const { did } = await encodePeer4(doc);
  const ok = await verifyPeer4Hash(did);
  assert.equal(ok, true, 'verifyPeer4Hash must return true for a freshly encoded DID');
});

test('numalgo4: verifyPeer4Hash returns false for a tampered hash component', async () => {
  const doc = makeDoc();
  const { did, hashComponent, longFormSuffix } = await encodePeer4(doc);

  // Flip the last character of the hash component
  const tamperedHash = hashComponent.slice(0, -1) + (hashComponent.endsWith('A') ? 'B' : 'A');
  const tamperedDid = `did:peer:4${tamperedHash}:${longFormSuffix}`;

  const ok = await verifyPeer4Hash(tamperedDid);
  assert.equal(ok, false, 'verifyPeer4Hash must return false for a tampered hash component');
});

test('numalgo4: verifyPeer4Hash returns false for a tampered long-form suffix', async () => {
  const doc = makeDoc();
  const { did, hashComponent, longFormSuffix } = await encodePeer4(doc);

  // Flip the last character of the long-form suffix
  const tamperedSuffix = longFormSuffix.slice(0, -1) + (longFormSuffix.endsWith('A') ? 'B' : 'A');
  const tamperedDid = `did:peer:4${hashComponent}:${tamperedSuffix}`;

  const ok = await verifyPeer4Hash(tamperedDid);
  assert.equal(ok, false, 'verifyPeer4Hash must return false for a tampered long-form suffix');
});

test('numalgo4: decodePeer4 throws for a non-did:peer:4 string', () => {
  assert.throws(
    () => decodePeer4('did:web:example.com'),
    /not a did:peer:4/,
    'must throw for a non-did:peer:4 DID',
  );
});

test('numalgo4: decodePeer4 throws for a short-form-only DID (no long-form suffix)', () => {
  assert.throws(
    () => decodePeer4('did:peer:4zQmSomehash'),
    /missing long-form suffix/,
    'must throw for a short-form-only DID',
  );
});

test('numalgo4: two different documents produce different DIDs', async () => {
  const doc1 = makeDoc();
  const doc2 = { ...makeDoc(), authentication: ['#key-1', '#key-extra'] };

  const { did: did1 } = await encodePeer4(doc1);
  const { did: did2 } = await encodePeer4(doc2);

  assert.notEqual(did1, did2, 'different documents must produce different DIDs');
});

// ---------------------------------------------------------------------------
// F-007 — the embedded document's ROOT must be a JSON object
// ---------------------------------------------------------------------------
//
// `JSON.parse` accepts any valid JSON, and the decoder used to cast the result
// straight to `DidDocument`. The damage surfaced one call away: `resolveDidPeer4`
// returns `{ ...document, id: did }`, so a string payload spread into
// `{ 0: '3', id: did }`, `null` spread into `{ id: did }` (a document with no keys),
// and an array spread into index properties — each read as a valid resolution.

/** Build a did:peer:4 whose long-form suffix embeds exactly `payload` as JSON. */
function craftDidWithPayload(payload: string): string {
  const docBytes = new TextEncoder().encode(payload);
  const prefixed = new Uint8Array([0x80, 0x04, ...docBytes]); // 0x0200 json multicodec
  return `did:peer:4zPlaceholderHash:${base58btc.encode(prefixed)}`;
}

test('F-007: a non-object embedded root is REFUSED, and the error names the shape', () => {
  const cases: Array<[string, RegExp]> = [
    ['"3"', /must be a JSON object \(got string\)/],
    ['null', /must be a JSON object \(got null\)/],
    ['[]', /must be a JSON object \(got array\)/],
    ['true', /must be a JSON object \(got boolean\)/],
    ['42', /must be a JSON object \(got number\)/],
  ];

  for (const [payload, expected] of cases) {
    assert.throws(
      () => decodePeer4(craftDidWithPayload(payload)),
      expected,
      `payload ${payload} must be refused by name`,
    );
  }
});

test('F-007: the resolver no longer returns a spread-of-garbage "document"', () => {
  // This is the failure the audit described: before the check, this call SUCCEEDED and
  // produced `{ 0: '3', id: did }` — an object with no DID-document fields at all.
  assert.throws(
    () => resolveDidPeer4(craftDidWithPayload('"3"')),
    /must be a JSON object \(got string\)/,
  );
  assert.throws(
    () => resolveDidPeer4(craftDidWithPayload('null')),
    /must be a JSON object \(got null\)/,
  );
});

test('F-007: an OBJECT root still decodes — including an id-less one (positive control)', () => {
  // The encoder deliberately omits `id` (the resolver adds it), so `{}` is legitimate
  // and the new check must not reject it. Without this control, the tests above would
  // pass just as well if the decoder rejected everything.
  const bare = decodePeer4(craftDidWithPayload('{}'));
  assert.deepEqual(bare.document, {}, 'an empty document object is legal');

  const keyed = decodePeer4(craftDidWithPayload('{"service":[]}'));
  assert.deepEqual(keyed.document, { service: [] }, 'a normal object decodes unchanged');
});

