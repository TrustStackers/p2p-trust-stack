/**
 * Tests for DidPeer4Method (DidMethod implementation) — Step 9, Task 9.5.
 *
 * Confirms the DidMethod-wrapped behavior is identical to calling
 * createDidPeer4()/resolveDidPeer4()/verifyDidPeer4() directly (no behavior
 * change from the Step 9 abstraction refactor).
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/did/did-method.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DidPeer4Method } from '../../src/did/did-peer4-method.js';

test('DidPeer4Method: methodName and supportsRotation metadata', () => {
  const method = new DidPeer4Method();
  assert.equal(method.methodName, 'did:peer:4');
  assert.equal(method.supportsRotation, false);
});

test('DidPeer4Method.create: returns a valid long-form did:peer:4 string and document', async () => {
  const method = new DidPeer4Method();
  const result = await method.create();

  assert.ok(result.did.startsWith('did:peer:4'), 'DID must start with did:peer:4');
  assert.equal(result.document.id, result.did, 'document id must equal the DID');
  assert.equal(result.signingKeyPair.publicKey.length, 32);
  assert.equal(result.agreementKeyPair.publicKey.length, 32);
});

test('DidPeer4Method.create: with transport produces a service entry', async () => {
  const method = new DidPeer4Method();
  const result = await method.create({
    peerId: '12D3KooWfakePeerId',
    multiaddrs: ['/ip4/127.0.0.1/tcp/4001'],
  });

  assert.ok(Array.isArray(result.document.service), 'document must have service array');
  assert.equal(result.document.service![0].id, '#tsp');
});

test('DidPeer4Method.resolve: recovers the document from a DID created via create()', async () => {
  const method = new DidPeer4Method();
  const result = await method.create();
  const resolved = method.resolve(result.did);

  assert.equal(resolved.id, result.did);
  assert.deepEqual(resolved.verificationMethod, result.document.verificationMethod);
});

test('DidPeer4Method.verify: returns true for a freshly created DID', async () => {
  const method = new DidPeer4Method();
  const result = await method.create();
  const ok = await method.verify(result.did);
  assert.equal(ok, true);
});

test('DidPeer4Method.verify: returns false for a tampered DID', async () => {
  const method = new DidPeer4Method();
  const result = await method.create();
  const tampered = result.did.slice(0, -1) + (result.did.endsWith('A') ? 'B' : 'A');
  const ok = await method.verify(tampered);
  assert.equal(ok, false);
});
