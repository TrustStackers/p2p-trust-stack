/**
 * Tests for createDidPeer4() / resolveDidPeer4() / verifyDidPeer4().
 *
 * Covers:
 *   - createDidPeer4() produces a valid long-form DID string
 *   - resolveDidPeer4() recovers the original document
 *   - verifyDidPeer4() confirms self-certification
 *   - document round-trip: resolved document matches constructed document
 *   - with and without transport service entry
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/did/create-resolve.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDidPeer4 } from '../../src/did/create.js';
import { resolveDidPeer4 } from '../../src/did/resolve.js';
import { verifyDidPeer4 } from '../../src/did/verify.js';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('createDidPeer4: returns a valid long-form did:peer:4 string', async () => {
  const result = await createDidPeer4();

  assert.ok(result.did.startsWith('did:peer:4'), 'DID must start with did:peer:4');
  assert.ok(result.did.includes(':'), 'long-form DID must contain a colon separator after the hash');
  assert.ok(result.shortFormDid.startsWith('did:peer:4'), 'short-form DID must start with did:peer:4');
  assert.ok(!result.shortFormDid.includes(':', 9), 'short-form DID must not contain a second colon');
});

test('createDidPeer4: returns Ed25519 and X25519 key pairs', async () => {
  const result = await createDidPeer4();

  assert.equal(result.signingKeyPair.secretKey.length, 32, 'Ed25519 secret key must be 32 bytes');
  assert.equal(result.signingKeyPair.publicKey.length, 32, 'Ed25519 public key must be 32 bytes');
  assert.equal(result.agreementKeyPair.secretKey.length, 32, 'X25519 secret key must be 32 bytes');
  assert.equal(result.agreementKeyPair.publicKey.length, 32, 'X25519 public key must be 32 bytes');
});

test('createDidPeer4: document has correct structure', async () => {
  const result = await createDidPeer4();
  const doc = result.document;

  assert.ok(Array.isArray(doc['@context']), 'document must have @context array');
  assert.ok(doc['@context'].includes('https://www.w3.org/ns/did/v1'), 'document must include W3C DID context');
  // The two CLASSICAL slots keep their positions and encodings; the post-quantum
  // roots of trust (#key-mldsa / #key-kem) are appended — see G7e.
  assert.equal(doc.verificationMethod[0].id, '#key-1', 'slot 0 is the Ed25519 signing key');
  assert.equal(doc.verificationMethod[1].id, '#key-2', 'slot 1 is the X25519 agreement key');
  assert.equal(doc.verificationMethod[0].type, 'Multikey', 'verification method type must be Multikey');
  assert.ok(doc.verificationMethod[0].publicKeyMultibase.startsWith('z6Mk'), 'Ed25519 key must start with z6Mk');
  assert.ok(doc.verificationMethod[1].publicKeyMultibase.startsWith('z6LS'), 'X25519 key must start with z6LS');
  assert.deepEqual(doc.authentication, ['#key-1'], 'authentication must reference #key-1');
  assert.equal(doc.keyAgreement?.[0], '#key-2', 'classical X25519 leads keyAgreement');
  assert.ok(doc.verificationMethod.find(vm => vm.id === '#key-mldsa'), 'ML-DSA-65 root of trust is published');
  assert.ok(doc.verificationMethod.find(vm => vm.id === '#key-kem'), 'hybrid KEM key is published');
  assert.ok(!doc.id, 'document must not have an id field (set after resolution)');
});

test('createDidPeer4: document includes TSP service entry when transport is provided', async () => {
  const result = await createDidPeer4({
    peerId: '12D3KooWfakePeerId',
    multiaddrs: ['/ip4/127.0.0.1/tcp/4001'],
  });

  assert.ok(Array.isArray(result.document.service), 'document must have service array');
  assert.equal(result.document.service!.length, 1, 'document must have exactly one service entry');
  assert.equal(result.document.service![0].id, '#tsp', 'service id must be #tsp');
  assert.equal(result.document.service![0].type, 'TSPTransport', 'service type must be TSPTransport');
});

test('createDidPeer4: document has no service entry when transport is omitted', async () => {
  const result = await createDidPeer4();
  assert.ok(!result.document.service || result.document.service.length === 0, 'document must not have service entry when transport is omitted');
});

test('resolveDidPeer4: recovers the original document', async () => {
  const result = await createDidPeer4();
  const resolved = resolveDidPeer4(result.did);

  // The resolved document should match the original, plus have the id field set
  assert.equal(resolved.id, result.did, 'resolved document id must equal the full long-form DID');
  assert.deepEqual(resolved.verificationMethod, result.document.verificationMethod, 'verification methods must match');
  assert.deepEqual(resolved.authentication, result.document.authentication, 'authentication must match');
  assert.deepEqual(resolved.keyAgreement, result.document.keyAgreement, 'keyAgreement must match');
});

test('resolveDidPeer4: resolved document has id set to the full DID', async () => {
  const result = await createDidPeer4();
  const resolved = resolveDidPeer4(result.did);

  assert.equal(resolved.id, result.did, 'resolved document id must be the full long-form DID string');
});

test('verifyDidPeer4: returns true for a freshly created DID', async () => {
  const result = await createDidPeer4();
  const ok = await verifyDidPeer4(result.did);
  assert.equal(ok, true, 'verifyDidPeer4 must return true for a freshly created DID');
});

test('verifyDidPeer4: returns false for a tampered DID', async () => {
  const result = await createDidPeer4();
  // Flip the last character of the DID
  const tampered = result.did.slice(0, -1) + (result.did.endsWith('A') ? 'B' : 'A');
  const ok = await verifyDidPeer4(tampered);
  assert.equal(ok, false, 'verifyDidPeer4 must return false for a tampered DID');
});

test('createDidPeer4: two calls produce different DIDs', async () => {
  const result1 = await createDidPeer4();
  const result2 = await createDidPeer4();
  assert.notEqual(result1.did, result2.did, 'two createDidPeer4 calls must produce different DIDs');
});

// ---------------------------------------------------------------------------
// Slot-A (utility server): separate permanent TSP VID key vs did:scid:vh
// identity key, both seedable; TSP key stays at verificationMethod[0] (#key-1)
// so handshake verification is unchanged; the did:scid:vh chain follows
// #key-scid so a log roll never changes the TSP VID.
// ---------------------------------------------------------------------------

test('ScidVhMethod.create: Slot-A seeds unrelated identity + TSP VID keys deterministically', async () => {
  const { ScidVhMethod } = await import('../../src/did/scid-vh-method.js');
  const { generateEd25519KeyPairFromSeed } = await import('../../src/crypto/primitives.js');
  const { computeNextKeyCommitment } = await import('../../src/did/rotation-codec.js');

  const didSeed = new Uint8Array(32).fill(1);
  const tspSeed = new Uint8Array(32).fill(2);
  const identityKp = generateEd25519KeyPairFromSeed(didSeed);
  const tspKp = generateEd25519KeyPairFromSeed(tspSeed);
  assert.notDeepEqual(identityKp.publicKey, tspKp.publicKey, 'identity and TSP keys must be unrelated');

  const env: Map<string, any[]> = new Map();
  const store = {
    appendEntry: (did: string, e: any) => { env.set(did, [...(env.get(did) ?? []), e]); },
    getLog: (did: string) => env.get(did) ?? [],
    getLatestEntry: (did: string) => (env.get(did) ?? []).at(-1),
  } as any;

  const method = new ScidVhMethod({ store } as any);
  const created = await method.create({ peerId: 'peer', multiaddrs: [] }, {
    identitySeed: didSeed,
    transportSigningKeyPair: tspKp,
  });
  const doc = created.document;

  // Slot-A slot mapping. The classical slots keep their positions; the PQ roots
  // of trust are APPENDED, so #key-1/#key-2/#key-scid still mean what they did.
  assert.equal(doc.verificationMethod[0].id, '#key-1', 'slot 0 is the TSP VID key');
  assert.equal(doc.verificationMethod[1].id, '#key-2', 'slot 1 is the agreement key');
  assert.equal(doc.verificationMethod[2].id, '#key-scid', 'slot 2 is the Slot-A identity key');
  assert.ok(doc.verificationMethod.find(vm => vm.id === '#key-mldsa'), 'ML-DSA-65 root of trust is published');
  assert.ok(doc.verificationMethod.find(vm => vm.id === '#key-kem'), 'hybrid KEM key is published');
  const { extractEd25519PublicKey } = await import('../../src/relationship/key-extract.js');
  assert.deepEqual(extractEd25519PublicKey(doc), tspKp.publicKey, 'verificationMethod[0] must be the TSP VID key (handshake unchanged)');
  const idSlot = doc.verificationMethod.find(vm => vm.id === '#key-scid');
  assert.ok(idSlot, 'Slot-A doc must carry the identity key at #key-scid');

  // Both keys deterministic from seeds (two identical creates → same output)
  const created2 = await method.create({ peerId: 'peer', multiaddrs: [] }, {
    identitySeed: didSeed,
    transportSigningKeyPair: generateEd25519KeyPairFromSeed(tspSeed),
  });
  assert.equal(created.did, created2.did, 'seeded create must be deterministic');
});

test('ScidVhMethod.create: self-commit then genuine rotation keeps TSP VID stable', async () => {
  const { ScidVhMethod } = await import('../../src/did/scid-vh-method.js');
  const { generateEd25519KeyPairFromSeed, generateEd25519KeyPair } = await import('../../src/crypto/primitives.js');

  const didSeed = new Uint8Array(32).fill(7);
  const tspKp = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(8));
  const identityKp = generateEd25519KeyPairFromSeed(didSeed);

  let log: any[] = [];
  const store = {
    appendEntry: (_did: string, e: any) => { log = [...log, e]; },
    getLog: () => log,
    getLatestEntry: () => log.at(-1),
  } as any;

  const method = new ScidVhMethod({ store } as any);
  const created = await method.create({ peerId: 'peer' }, { identitySeed: didSeed, transportSigningKeyPair: tspKp });

  // 1. Self-commit (same identity key) — name-only advance, TSP VID unchanged.
  const spec = new (await import('../../src/did/speculative-rotation.js')).SpeculativeRotationService();
  const sres = await spec.computeSpeculativeRotation({
    name: 'alice', namespace: 'p2pts', did: created.did,
    currentLog: log,
    outgoingSigningKeyPair: identityKp,
    newSigningKeyPair: identityKp,
    nextSigningPublicKey: created.nextSigningKeyPairs[0].publicKey,
  });
  store.appendEntry(created.did, sres.rotationEntry);

  // 2. Genuine rotation to the pre-committed next key.
  const nextKp = created.nextSigningKeyPairs[0];
  const spec2 = new (await import('../../src/did/speculative-rotation.js')).SpeculativeRotationService();
  const sres2 = await spec2.computeSpeculativeRotation({
    name: 'bob', namespace: 'p2pts', did: created.did,
    currentLog: log,
    outgoingSigningKeyPair: identityKp,
    newSigningKeyPair: nextKp,
    nextSigningPublicKey: generateEd25519KeyPair().publicKey,
  });
  store.appendEntry(created.did, sres2.rotationEntry);

  // Full chain (genesis → self-commit → rotation) must resolve & validate.
  const resolved = method.resolve(created.did) as any;
  assert.ok(resolved.alsoKnownAs?.includes('vta:p2pts:alice'), 'name must survive to the resolved doc');

  // TSP VID key at verificationMethod[0] is UNCHANGED across every entry.
  const { extractEd25519PublicKey } = await import('../../src/relationship/key-extract.js');
  for (const entry of log) {
    assert.deepEqual(extractEd25519PublicKey(entry.didDocument), tspKp.publicKey,
      'TSP VID key at verificationMethod[0] must never change across self-commit or rotation');
  }
});
