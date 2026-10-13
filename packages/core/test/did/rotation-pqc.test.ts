/**
 * Tests for the ML-DSA-65 ROTATION-ENTRY signature (G7f).
 *
 * Guideline being implemented: reserve ML-DSA for high-value, async "roots of
 * trust" — explicitly including KEY ROTATION — while ephemeral messages stay on
 * Ed25519.
 *
 * The rotation log is the identity's long-lived root of trust, and its
 * `signed_entry` column has a FIXED Ed25519-sized layout. An ML-DSA-65 signature
 * is 3309 bytes (vs 64), so it travels in an APPENDED, length-prefixed tail
 * behind a flags byte. These tests pin:
 *
 *  - the genesis entry is ML-DSA-signed and verifies against `#key-mldsa`;
 *  - the tail survives the store round-trip;
 *  - an entry with NO tail writes/reads the pre-change fixed layout exactly
 *    (so blobs written before this change still unpack);
 *  - a rotation re-publishes the PQ keys and PQ-signs the new entry.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/did/rotation-pqc.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runMigrations } from '../../src/db/migrate.js';
import { IdentityResolver } from '../../src/services/identity-resolver.js';
import { ScidVhMethod } from '../../src/did/scid-vh-method.js';
import { RotationLogStore } from '../../src/did/rotation-log-store.js';
import { extractMlDsa65PublicKey, extractHybridKemPublicKey } from '../../src/relationship/key-extract.js';
import { mlDsa65Verify } from '../../src/crypto/pqc.js';
import type { RotationLogEntry } from '../../src/did/rotation-types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SEED = new Uint8Array(32).fill(0x33);

/** A store-backed method (for resolve/log reads) plus a store-less creator. */
function makeMethod(): { store: RotationLogStore; resolver: IdentityResolver; method: ScidVhMethod } {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  const resolver = new IdentityResolver(db);
  const store = new RotationLogStore(db, resolver);
  // NOTE: store-less, exactly as production wires it (`createVta` passes
  // `store: undefined` and persists the log itself). A store-configured method
  // auto-appends the genesis entry DURING create(), which requires the identity's
  // DID document row to exist first — impossible at that point.
  const method = new ScidVhMethod({ store: undefined } as any);
  return { store, resolver, method };
}

function ensureIdentity(resolver: IdentityResolver, did: string, doc: object): void {
  if (resolver.lookupByDid(did)) return;
  resolver.resolveRemoteIdentity({
    did,
    method: 'scid-vh',
    didDocumentJson: JSON.stringify(doc),
    isPrimary: true,
    recordedByNode: 'test',
  });
}

test('GENESIS: the version-0 entry is ML-DSA-65 signed and verifies against #key-mldsa', async () => {
  const { method } = makeMethod();
  const created = await method.create(undefined, { identitySeed: SEED });
  const entry = created.log[0];

  assert.ok(entry.mlDsa65Signature, 'genesis entry carries an ML-DSA-65 signature');
  assert.equal(entry.mlDsa65Signature!.length, 3309, 'ML-DSA-65 signature length');

  const published = extractMlDsa65PublicKey(entry.didDocument);
  assert.ok(published, 'the entry publishes #key-mldsa');
  assert.equal(
    mlDsa65Verify(entry.mlDsa65Signature!, entry.digest, published!),
    true,
    'the PQ signature verifies over the entry digest with the PUBLISHED key',
  );

  assert.equal(entry.signature.length, 64, 'the classical Ed25519 key-continuity signature is kept');
});

test('STORE ROUND-TRIP: the appended ML-DSA-65 tail survives persist/read', async () => {
  const { store, resolver, method } = makeMethod();
  const created = await method.create(undefined, { identitySeed: SEED });
  ensureIdentity(resolver, created.did, created.document);
  store.appendEntry(created.did, created.log[0]);

  const read = store.getLog(created.did);
  assert.equal(read.length, 1);
  assert.deepEqual(read[0].mlDsa65Signature, created.log[0].mlDsa65Signature, 'signature round-trips');
  assert.deepEqual(read[0].signature, created.log[0].signature, 'Ed25519 signature round-trips');
  assert.deepEqual(read[0].digest, created.log[0].digest, 'digest round-trips');
});


test('BACKWARD COMPAT: an entry with no PQ signature writes/reads the pre-change layout', async () => {
  const { store, resolver, method } = makeMethod();
  const created = await method.create(undefined, { identitySeed: SEED });
  ensureIdentity(resolver, created.did, created.document);

  // Exactly what pre-PQ code produced: the fixed layout, no appended tail.
  const legacy: RotationLogEntry = { ...created.log[0], mlDsa65Signature: undefined };
  store.appendEntry(created.did, legacy);

  const read = store.getLog(created.did);
  assert.equal(read[0].mlDsa65Signature, undefined, 'no tail → no signature');
  // The critical part: the reader must not consume any of the 64-byte Ed25519
  // body as if it were a tail, or the digest/signature would be corrupted.
  assert.deepEqual(read[0].signature, legacy.signature, 'Ed25519 body read intact');
  assert.deepEqual(read[0].digest, legacy.digest, 'digest read intact');
});

test('ROTATION: re-publishes the PQ keys and PQ-signs the new entry', async () => {
  const { method } = makeMethod();
  const created = await method.create(undefined, { identitySeed: SEED });

  const { generateEd25519KeyPair } = await import('../../src/crypto/primitives.js');
  const rotated = await method.rotate({
    currentLog: created.log,
    outgoingSigningKeyPair: created.signingKeyPair,
    // Must be the key pre-committed by the genesis entry (pre-rotation check).
    newSigningKeyPair: created.nextSigningKeyPairs[0],
    nextSigningPublicKey: generateEd25519KeyPair().publicKey,
    witnessAttestations: [],
    mlDsa65KeyPair: created.mlDsa65KeyPair,
  });

  assert.ok(rotated.mlDsa65Signature, 'the rotation entry is PQ-signed');
  const published = extractMlDsa65PublicKey(rotated.didDocument);
  assert.deepEqual(
    published,
    created.mlDsa65KeyPair!.publicKey,
    'the ML-DSA root of trust is CARRIED INTO the rotated document (not dropped)',
  );
  assert.ok(
    extractHybridKemPublicKey(rotated.didDocument),
    'the hybrid KEM key is carried into the rotated document too',
  );
  assert.equal(
    mlDsa65Verify(rotated.mlDsa65Signature!, rotated.digest, published!),
    true,
    'the rotation signature verifies against the re-published key',
  );
});

test('ROTATION without a PQ key stays classical (nothing fabricated, key still carried)', async () => {
  const { method } = makeMethod();
  const created = await method.create(undefined, { identitySeed: SEED });
  const { generateEd25519KeyPair } = await import('../../src/crypto/primitives.js');

  const rotated = await method.rotate({
    currentLog: created.log,
    outgoingSigningKeyPair: created.signingKeyPair,
    newSigningKeyPair: created.nextSigningKeyPairs[0],
    nextSigningPublicKey: generateEd25519KeyPair().publicKey,
    witnessAttestations: [],
    // no mlDsa65KeyPair — an identity without PQ provisioning
  });

  assert.equal(rotated.mlDsa65Signature, undefined, 'no PQ signature is fabricated');
  assert.equal(rotated.signature.length, 64, 'the classical signature is still present');
  // Even without a caller-supplied key, an already-published PQ key is carried forward.
  assert.deepEqual(
    extractMlDsa65PublicKey(rotated.didDocument),
    created.mlDsa65KeyPair!.publicKey,
    'the published PQ key is preserved rather than stripped',
  );
});
