/**
 * Seed-at-rest tests (audit F-022).
 *
 * The property that matters most is the one that keeps the live rig working:
 * a seed already stored as plain hex must still load, unchanged, with no
 * passphrase configured. Encryption is a strict upgrade applied on write.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/crypto/seed-at-rest.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveSeedPassphrase,
  protectSeedHex,
  unprotectSeedHex,
  readPersistedSeed,
  writeSeedValue,
  isProtectedSeed,
  SEED_PASSPHRASE_ENV,
} from '../../src/crypto/seed-at-rest.js';

const PASS = 'correct horse battery staple';
const SEED = 'a'.repeat(64);

test('writeSeedValue: no passphrase keeps the legacy hex shape (no deployment breaks)', async () => {
  const written = await writeSeedValue(SEED, undefined);
  assert.equal(written, SEED, 'still a plain hex string');
  assert.equal(isProtectedSeed(written), false);

  const read = await readPersistedSeed(written, undefined, 'libp2p.seedHex');
  assert.deepEqual(read, { hex: SEED, legacyPlaintext: true }, 'and it reads back unchanged');
});

test('protect → unprotect round-trips the seed, and only with the right passphrase', async () => {
  const blob = await protectSeedHex(SEED, PASS);
  assert.equal(blob.v, 1);
  assert.equal(blob.algorithm, 'aes-256-gcm');
  assert.equal(isProtectedSeed(blob), true);
  assert.notEqual(blob.ct, SEED, 'the ciphertext is not the seed');

  assert.equal(await unprotectSeedHex(blob, PASS), SEED, 'round trip');

  await assert.rejects(
    () => unprotectSeedHex(blob, 'wrong passphrase'),
    'a wrong passphrase must fail, not return garbage',
  );
});

test('readPersistedSeed: reads a protected seed with the passphrase set', async () => {
  const blob = await protectSeedHex(SEED, PASS);
  const read = await readPersistedSeed(blob, PASS, 'identity.didSeedHex');
  assert.deepEqual(read, { hex: SEED, legacyPlaintext: false });
});

test('readPersistedSeed: a protected seed without a passphrase is a LOUD failure, never a silent regenerate', async () => {
  const blob = await protectSeedHex(SEED, PASS);
  await assert.rejects(
    () => readPersistedSeed(blob, undefined, 'identity.tspVidSeedHex'),
    /is encrypted, but TSP_SEED_PASSPHRASE is not set/,
    'an operator must be told to set the passphrase — silently making a new identity would be worse',
  );
});

test('readPersistedSeed: absent and empty values mean "generate a new one"', async () => {
  assert.equal(await readPersistedSeed(undefined, undefined, 'x'), undefined);
  assert.equal(await readPersistedSeed(null, undefined, 'x'), undefined);
  assert.equal(await readPersistedSeed('', undefined, 'x'), undefined);
});

test('readPersistedSeed: an unrecognised shape is rejected rather than guessed', async () => {
  await assert.rejects(
    () => readPersistedSeed({ seed: SEED }, PASS, 'libp2p.seedHex'),
    /unrecognised shape/,
  );
});

test('readPersistedSeed: a tampered blob fails loudly', async () => {
  const blob = await protectSeedHex(SEED, PASS);
  // Flip a byte of the ciphertext: GCM authentication must catch it.
  const bytes = Buffer.from(blob.ct, 'base64');
  bytes[0] = bytes[0] ^ 0xff;
  const tampered = { ...blob, ct: bytes.toString('base64') };
  await assert.rejects(
    () => readPersistedSeed(tampered, PASS, 'libp2p.seedHex'),
    /could not be decrypted/,
  );
});

test('resolveSeedPassphrase: reads the env, treats blank as unset', () => {
  const saved = process.env[SEED_PASSPHRASE_ENV];
  try {
    delete process.env[SEED_PASSPHRASE_ENV];
    assert.equal(resolveSeedPassphrase(), undefined);

    process.env[SEED_PASSPHRASE_ENV] = '   ';
    assert.equal(resolveSeedPassphrase(), undefined, 'whitespace counts as unset');

    process.env[SEED_PASSPHRASE_ENV] = '  my passphrase  ';
    assert.equal(resolveSeedPassphrase(), 'my passphrase', 'trimmed');
  } finally {
    if (saved === undefined) delete process.env[SEED_PASSPHRASE_ENV];
    else process.env[SEED_PASSPHRASE_ENV] = saved;
  }
});

test('writeSeedValue: with a passphrase the persisted value is encrypted, and reads back', async () => {
  const written = await writeSeedValue(SEED, PASS);
  assert.equal(isProtectedSeed(written), true, 'a passphrase switches the on-disk shape');
  const read = await readPersistedSeed(written, PASS, 'libp2p.seedHex');
  assert.deepEqual(read, { hex: SEED, legacyPlaintext: false });
});
