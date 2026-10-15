// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for DidResolver — W3C DID Core / DID Resolution facade.
 *
 * Covers:
 *   - did:peer:4 offline resolution (document recovered from DID string)
 *   - dereferenceVerificationMethod: key bytes + proof purposes
 *   - assertionMethod emission on did:peer:4 documents
 *   - did:scid:vh resolution from a rotation-log source (chain replay)
 *   - method-not-supported error for unknown DID methods
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/did/did-resolver.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createDidPeer4 } from '../../src/did/create.js';
import { ScidVhMethod } from '../../src/did/scid-vh-method.js';
import { DidResolver } from '../../src/did/did-resolver.js';
import type { RotationLogSource } from '../../src/did/rotation-log-source.js';
import type { RotationLogEntry } from '../../src/did/rotation-types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** An in-memory rotation-log source for did:scid:vh resolution tests. */
function inMemoryLogSource(log: RotationLogEntry[]): RotationLogSource {
  return {
    async getLog(): Promise<RotationLogEntry[]> {
      return log;
    },
  };
}

/** Create a did:scid:vh identity (offline) and return its log + did. */
async function makeScidVhIdentity() {
  const method = new ScidVhMethod({});
  const result = await method.create();
  return { did: result.did, log: result.log, document: result.document };
}

// ---------------------------------------------------------------------------
// did:peer:4
// ---------------------------------------------------------------------------

test('DidResolver.resolve: recovers did:peer:4 document offline', async () => {
  const peer4 = await createDidPeer4();
  const resolver = new DidResolver();

  const result = await resolver.resolve(peer4.did);
  assert.ok(result.didDocument, 'didDocument must be present');
  assert.equal(result.didDocument!.id, peer4.did, 'resolved id must equal the DID');
  assert.equal(result.didResolutionMetadata.error, undefined);
});

test('DidResolver.resolve: returns invalidDid for a malformed did:peer:4', async () => {
  const resolver = new DidResolver();
  const result = await resolver.resolve('did:peer:4garbage');
  assert.equal(result.didDocument, null);
  assert.equal(result.didResolutionMetadata.error, 'invalidDid');
});

test('DidResolver.resolve: returns methodNotSupported for unknown methods', async () => {
  const resolver = new DidResolver();
  const result = await resolver.resolve('did:web:example.com');
  assert.equal(result.didDocument, null);
  assert.equal(result.didResolutionMetadata.error, 'methodNotSupported');
});

test('did:peer:4 document exposes assertionMethod = #key-1 (plus the PQ #key-mldsa)', async () => {
  const peer4 = await createDidPeer4();
  // #key-1 is the Ed25519 verification method. #key-mldsa is the ML-DSA-65 key
  // added by the TSP v3 post-quantum provisioning work, and it is an assertion
  // method too — a did:peer:4 document created now carries both, so this test
  // pins the PQ method's presence instead of the pre-PQ single-method shape.
  assert.deepEqual(peer4.document.assertionMethod, ['#key-1', '#key-mldsa']);
  assert.deepEqual(peer4.document.authentication, ['#key-1']);
});

test('DidResolver.dereferenceVerificationMethod: returns key bytes + purposes', async () => {
  const peer4 = await createDidPeer4();
  const resolver = new DidResolver();

  const vm = await resolver.dereferenceVerificationMethod(`${peer4.did}#key-1`);
  assert.ok(vm, 'verification method must dereference');
  assert.equal(vm!.fragment, 'key-1');
  assert.equal(vm!.rawKey.length, 32, 'Ed25519 public key is 32 bytes');
  assert.ok(vm!.proofPurposes.includes('authentication'), 'authentication purpose');
  assert.ok(vm!.proofPurposes.includes('assertionMethod'), 'assertionMethod purpose');
});

test('DidResolver.dereferenceVerificationMethod: returns null for unknown fragment', async () => {
  const peer4 = await createDidPeer4();
  const resolver = new DidResolver();
  const vm = await resolver.dereferenceVerificationMethod(`${peer4.did}#does-not-exist`);
  assert.equal(vm, null);
});

// ---------------------------------------------------------------------------
// did:scid:vh
// ---------------------------------------------------------------------------

test('DidResolver.resolve: reconstructs did:scid:vh document from the rotation log', async () => {
  const { did, log } = await makeScidVhIdentity();
  const resolver = new DidResolver({ logSource: inMemoryLogSource(log) });

  const result = await resolver.resolve(did);
  assert.ok(result.didDocument, 'didDocument must be present');
  assert.equal(result.didResolutionMetadata.error, undefined);
  // F-006: the spec types versionId as a STRING and does not put contentType on the
  // resolve path. Both were violated: it returned the raw integer 0 and stamped
  // 'application/did+ld+json' on every resolution.
  assert.equal(result.didDocumentMetadata.versionId, '0', 'genesis entry is version "0" (a string)');
  assert.equal(result.didResolutionMetadata.rotated, undefined, 'no rotation yet');
  assert.equal(
    result.didResolutionMetadata.contentType, undefined,
    'F-006: contentType belongs to dereferencing, not resolution',
  );
});

test('F-006: resolution metadata uses the spec shapes (string versionId, ISO-8601 updated, no contentType)', async () => {
  const { did, log } = await makeScidVhIdentity();
  const resolver = new DidResolver({ logSource: inMemoryLogSource(log) });

  const result = await resolver.resolve(did);

  assert.equal(typeof result.didDocumentMetadata.versionId, 'string');
  assert.equal(typeof result.didDocumentMetadata.updated, 'string');
  // ISO-8601 round-trips: parsing it back yields the log's own timestamp.
  const expectedUnix = log[log.length - 1].createdAt;
  assert.equal(
    Date.parse(result.didDocumentMetadata.updated!),
    expectedUnix * 1000,
    'the ISO-8601 timestamp must represent the log entry time exactly',
  );
  assert.match(result.didDocumentMetadata.updated!, /^\d{4}-\d{2}-\d{2}T/);

  // Every resolution return shape — including the error paths — omits contentType.
  const notFound = await new DidResolver().resolve('did:scid:vh:1:6Mkr6cy8emkvrxxEdW2rBfGv61cPpZxHmrBmEFXJS6LyPJ2');
  assert.equal(notFound.didResolutionMetadata.contentType, undefined);
  assert.equal(notFound.didResolutionMetadata.error, 'notFound');

  const unsupported = await new DidResolver().resolve('did:web:example.com');
  assert.equal(unsupported.didResolutionMetadata.contentType, undefined);
  assert.equal(unsupported.didResolutionMetadata.error, 'methodNotSupported');
});

test('DidResolver.resolve: returns notFound when no rotation log is available', async () => {
  const resolver = new DidResolver(); // no log source configured
  const result = await resolver.resolve('did:scid:vh:1:6Mkr6cy8emkvrxxEdW2rBfGv61cPpZxHmrBmEFXJS6LyPJ2');
  assert.equal(result.didDocument, null);
  assert.equal(result.didResolutionMetadata.error, 'notFound');
});
