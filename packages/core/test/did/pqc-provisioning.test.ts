/**
 * Tests for post-quantum ROOT-OF-TRUST provisioning (G7e).
 *
 * Guideline being implemented:
 *
 *  1. Reserve ML-DSA for high-value, async "roots of trust" — VIDs, key rotation,
 *     out-of-band introductions.
 *  2. Lightweight signatures (Ed25519) for ephemeral transactional messages.
 *
 * So this layer PROVISIONS and PUBLISHES the PQ keys (identity creation →
 * keystore/`keys` rows → DID document) and leaves ordinary TSP messages on
 * Ed25519. The assertions below pin the parts that are easy to get wrong:
 *
 *  - the PQ entries are APPENDED, so `verificationMethod[0]`/`[1]` keep their
 *    Ed25519/X25519 meaning (both extractors read BY INDEX);
 *  - the ML-DSA entry uses the REGISTERED `ml-dsa-65-pub` multicodec (0x1211);
 *  - the hybrid KEM entry does NOT claim a multicodec (none is registered) and
 *    names its algorithm in `type`;
 *  - seeded (utility-server) identities stay reproducible from config;
 *  - `buildCleanPeer4FromDocument` does not silently DROP the PQ keys.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/did/pqc-provisioning.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateEd25519KeyPair, ed25519ToX25519 } from '../../src/crypto/primitives.js';
import {
  ML_DSA_65_PUB_MULTICODEC,
  mlDsa65Sign,
  mlDsa65Verify,
  mlKem768X25519Encap,
  mlKem768X25519Decap,
  generateMlDsa65KeyPairFromSeed,
  generateMlKem768X25519KeyPairFromSeed,
} from '../../src/crypto/pqc.js';
import { buildDidPeer4Document } from '../../src/did/create.js';
import { ScidVhMethod } from '../../src/did/scid-vh-method.js';
import {
  extractEd25519PublicKey,
  extractX25519PublicKey,
  extractMlDsa65PublicKey,
  extractHybridKemPublicKey,
  buildCleanPeer4FromDocument,
} from '../../src/relationship/key-extract.js';

const SEED = new Uint8Array(32).fill(0x5a);

function makeDoc(withPqc: boolean, slotA = false) {
  const ed = generateEd25519KeyPair();
  const x = ed25519ToX25519(ed.secretKey);
  const pqc = withPqc
    ? {
        mlDsa65PublicKey: generateMlDsa65KeyPairFromSeed(SEED).publicKey,
        hybridKemPublicKey: generateMlKem768X25519KeyPairFromSeed(SEED).publicKey,
      }
    : undefined;
  return { ed, x, doc: buildDidPeer4Document(ed.publicKey, x.publicKey, undefined, slotA ? generateEd25519KeyPair().publicKey : undefined, pqc) };
}

test('PUBLISHED: ML-DSA-65 as a real Multikey, hybrid KEM under its own type', () => {
  const { doc } = makeDoc(true);

  const mldsa = doc.verificationMethod.find((m) => m.id === '#key-mldsa');
  assert.ok(mldsa, '#key-mldsa is present');
  assert.equal(mldsa!.type, 'Multikey', 'uses the registered multicodec, so type is Multikey');
  assert.equal(ML_DSA_65_PUB_MULTICODEC, 0x1211, 'multicodec value is the registered ml-dsa-65-pub');
  assert.ok(mldsa!.publicKeyMultibase.startsWith('z'), 'base58btc multibase');

  const kem = doc.verificationMethod.find((m) => m.id === '#key-kem');
  assert.ok(kem, '#key-kem is present');
  assert.equal(kem!.type, 'MLKEM768X25519PublicKey', 'algorithm named in type (no ML-KEM multicodec exists)');
  assert.ok(kem!.publicKeyMultibase.startsWith('u'), 'plain base64url multibase, no invented prefix');

  // Both round-trip through the extractors.
  const mlDsa = extractMlDsa65PublicKey(doc);
  assert.equal(mlDsa?.length, 1952, 'ML-DSA-65 public key length');
  const hybrid = extractHybridKemPublicKey(doc);
  assert.equal(hybrid?.length, 1216, 'MLKEM768-X25519 public key length');
});

test('INDEX CONTRACT: appending PQ entries does not move [0]/[1] (extractors read by index)', () => {
  for (const slotA of [false, true]) {
    const { ed, x, doc } = makeDoc(true, slotA);
    assert.deepEqual(extractEd25519PublicKey(doc), ed.publicKey, `[0] is still the Ed25519 signing key (slotA=${slotA})`);
    assert.deepEqual(extractX25519PublicKey(doc), x.publicKey, `[1] is still the X25519 agreement key (slotA=${slotA})`);
    assert.equal(doc.verificationMethod[0].id, '#key-1');
    assert.equal(doc.verificationMethod[1].id, '#key-2');
    if (slotA) assert.equal(doc.verificationMethod[2].id, '#key-scid', '#key-scid keeps its place');
  }
});

test('RELATIONSHIPS: ML-DSA asserts, hybrid KEM agrees, classical entries stay first', () => {
  const { doc } = makeDoc(true);
  assert.ok(doc.assertionMethod?.includes('#key-mldsa'), 'ML-DSA-65 is an assertion method');
  assert.equal(doc.keyAgreement?.[0], '#key-2', 'classical X25519 remains first in keyAgreement');
  assert.ok(doc.keyAgreement?.includes('#key-kem'), 'hybrid KEM is a keyAgreement method');
});

test('BACKWARD COMPAT: a document without PQ keys still resolves, extractors return undefined', () => {
  const { doc } = makeDoc(false);
  assert.equal(doc.verificationMethod.length, 2);
  assert.equal(extractMlDsa65PublicKey(doc), undefined, 'absence is reported, not thrown');
  assert.equal(extractHybridKemPublicKey(doc), undefined);
  assert.deepEqual(doc.assertionMethod, ['#key-1']);
  assert.deepEqual(doc.keyAgreement, ['#key-2']);
});

test('SEEDED IDENTITIES stay reproducible: same seed → same DID and same PQ keys', async () => {
  const method = () => new ScidVhMethod({ store: undefined } as any);
  const a = await method().create(undefined, { identitySeed: SEED });
  const b = await method().create(undefined, { identitySeed: SEED });

  assert.equal(a.did, b.did, 'genesis → SCID reproducible from config');
  assert.ok(a.mlDsa65KeyPair && a.hybridKemKeyPair, 'PQ keys are provisioned');
  assert.deepEqual(a.mlDsa65KeyPair!.publicKey, b.mlDsa65KeyPair!.publicKey, 'ML-DSA key deterministic');
  assert.deepEqual(a.hybridKemKeyPair!.publicKey, b.hybridKemKeyPair!.publicKey, 'hybrid KEM key deterministic');

  // A different seed gives different keys.
  const other = await method().create(undefined, { identitySeed: new Uint8Array(32).fill(0x11) });
  assert.notDeepEqual(other.mlDsa65KeyPair!.publicKey, a.mlDsa65KeyPair!.publicKey);

  // A NON-seeded identity gets fresh keys (random).
  const r1 = await method().create();
  const r2 = await method().create();
  assert.notDeepEqual(r1.mlDsa65KeyPair!.publicKey, r2.mlDsa65KeyPair!.publicKey);
});

test('the provisioned keys are USABLE as roots of trust', async () => {
  const method = new ScidVhMethod({ store: undefined } as any);
  const created = await method.create(undefined, { identitySeed: SEED });

  // ML-DSA-65 signs/verifies — what a rotation entry or an introduction will use.
  const statement = new TextEncoder().encode('rotation entry v1 / VID introduction');
  const sig = mlDsa65Sign(statement, created.mlDsa65KeyPair!.secretKey);
  assert.equal(mlDsa65Verify(sig, statement, created.mlDsa65KeyPair!.publicKey), true);
  assert.equal(
    mlDsa65Verify(sig, new TextEncoder().encode('tampered'), created.mlDsa65KeyPair!.publicKey),
    false,
  );

  // The PUBLISHED key is the one that verifies (not just the in-memory pair).
  const published = extractMlDsa65PublicKey(created.document)!;
  assert.deepEqual(published, created.mlDsa65KeyPair!.publicKey);
  assert.equal(mlDsa65Verify(sig, statement, published), true);

  // Hybrid KEM encaps/decaps with the published key.
  const { enc, sharedSecret } = mlKem768X25519Encap(extractHybridKemPublicKey(created.document)!);
  const recovered = mlKem768X25519Decap(enc, created.hybridKemKeyPair!.secretKey);
  assert.deepEqual(recovered, sharedSecret, 'hybrid KEM agreement works with the published key');
});

test('PEER RECORDS: buildCleanPeer4FromDocument preserves the PQ keys', () => {
  const base = makeDoc(true).doc;
  const peerDoc = {
    ...base,
    service: [{
      id: '#tsp',
      type: 'TSPTransport' as const,
      serviceEndpoint: { peerId: '12D3KooWexample', multiaddrs: ['/ip4/127.0.0.1/tcp/4001'] },
    }],
  };

  const rebuilt = buildCleanPeer4FromDocument(peerDoc);
  assert.ok(rebuilt.verificationMethod.find((m) => m.id === '#key-mldsa'), 'ML-DSA key survives the rebuild');
  assert.ok(rebuilt.verificationMethod.find((m) => m.id === '#key-kem'), 'hybrid KEM key survives the rebuild');
  assert.ok(rebuilt.service?.[0], 'transport entry survives');
  assert.deepEqual(extractMlDsa65PublicKey(rebuilt), extractMlDsa65PublicKey(peerDoc), 'same ML-DSA key');
});
