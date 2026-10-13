/**
 * F-021 / ruling Y1 — a private key never crosses the provisioning boundary.
 *
 * The finding: `ContextManager.provision()` derived the app context's keys, stored them
 * in the context's OWN keystore, and then also returned the raw secret bytes in
 * `AppCredentialBundle` — so the isolated copy was defeated by the one handed to the
 * caller. Ruling Y1: "the VTA should never hand out private keys; it should use the
 * private keys in the cryptographic operations needed by other processes."
 *
 * The shape test below is the important one: it pins the returned keys, so a future
 * edit that adds a secret field back fails here loudly. The keystore test proves the
 * key is nonetheless available where it is used.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/agent/context-provisioning.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ContextManager } from '../../src/runtime/context-manager.js';
import { generateEd25519KeyPair, ed25519ToX25519 } from '@p2p-trust-stack/core/crypto/primitives.js';
import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { cesrEncode } from '@p2p-trust-stack/core/crypto/cesr.js';
import { CESR_CODES } from '@p2p-trust-stack/core/crypto/codes.js';

/** A throwaway P2PTS home so the test never touches the real one. */
function tempHome(): string {
  return mkdtempSync(join(tmpdir(), 'f021-context-'));
}

test('F-021: the bundle carries PUBLIC identifiers only — no secret-key field survives', async () => {
  const home = tempHome();
  try {
    const mgr = new ContextManager('app-under-test', home);
    const bundle = await mgr.provision(
      generateEd25519KeyPair(),
      generateEd25519KeyPair(),
      { passphrase: 'test-passphrase', deviceLocal: true },
    );

    // 1. The exact key set. This is the assertion that would catch a re-introduced
    //    `contextSigningKey`/`contextAgreementKey` — the F-021 defect itself.
    assert.deepEqual(
      Object.keys(bundle).sort(),
      [
        'allowedKeyIds', 'contextAgreementVid', 'contextDid', 'contextId',
        'contextSigningVid', 'expiresAt', 'keysStayInContext', 'keystorePath',
      ].sort(),
      'the bundle must expose public identifiers and the keystore path — and nothing else',
    );

    // 2. No field is binary key material.
    for (const [key, value] of Object.entries(bundle)) {
      assert.notEqual(value instanceof Uint8Array, true, `${key} must not carry raw key bytes`);
    }

    // 3. The VIDs are real CESR public keys, not placeholders.
    assert.match(bundle.contextSigningVid, /^D/, 'an Ed25519 CESR public key');
    assert.equal(bundle.contextAgreementVid.length > 0, true);
    assert.equal(bundle.keysStayInContext, true);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('F-021: the private key IS available where it is used — the context keystore', async () => {
  const home = tempHome();
  try {
    const mgr = new ContextManager('app-keystore', home);
    const rootSigning = generateEd25519KeyPair();
    const rootAgreement = ed25519ToX25519(rootSigning.secretKey);

    const bundle = await mgr.provision(rootSigning, rootAgreement, {
      passphrase: 'test-passphrase',
      deviceLocal: true,
    });

    // The returned path is where the key lives, and it round-trips with the passphrase.
    const ks = new SqliteKeyStore(bundle.keystorePath);
    try {
      const signing = await ks.retrieveKeyPairAsync('app-keystore', 'ed25519', 'test-passphrase');
      assert.ok(signing?.secretKey, 'the signing key must be retrievable by its owner');
      // …and the public half is exactly what the bundle advertised.
      assert.equal(
        bundle.contextSigningVid,
        cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, signing!.publicKey),
        'the advertised VID must be the stored key\'s public half',
      );
    } finally {
      ks.close();
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
