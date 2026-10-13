/**
 * Tests that a did:scid:vh identity is fully reproducible from its identity
 * seed — the property the cross-device seed-phrase claim/import flow depends on.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/did/scid-vh-seed-determinism.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { ScidVhMethod } from '../../src/did/scid-vh-method.js';
import { exportSeedPhrase, importSeedPhrase } from '../../src/crypto/seed-phrase.js';
import { generateEd25519KeyPairFromSeed } from '../../src/crypto/primitives.js';

test('did:scid:vh DID is deterministic from identitySeed (seed-phrase round-trip)', async () => {
  const identitySeed = new Uint8Array(randomBytes(32));

  const m1 = new ScidVhMethod({ store: undefined });
  const r1 = await m1.create(undefined, { identitySeed });

  // Export the seed phrase from the genesis signing key.
  const mnemonic = exportSeedPhrase(r1.signingKeyPair).mnemonic;

  // Import the seed phrase → reconstruct the keypair, then the seed.
  const kp = await importSeedPhrase(mnemonic, async (seed) => generateEd25519KeyPairFromSeed(seed));
  const reconstructedSeed = kp.secretKey.slice(0, 32);

  assert.deepEqual(Array.from(reconstructedSeed), Array.from(identitySeed), 'seed should round-trip');

  const m2 = new ScidVhMethod({ store: undefined });
  const r2 = await m2.create(undefined, { identitySeed: reconstructedSeed });

  assert.equal(r1.did, r2.did, 'DID must be deterministic from the seed');
  assert.deepEqual(
    Array.from(r1.signingKeyPair.publicKey),
    Array.from(r2.signingKeyPair.publicKey),
    'signing public key must round-trip',
  );
});
