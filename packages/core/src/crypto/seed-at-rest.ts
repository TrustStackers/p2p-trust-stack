/**
 * Seed-at-rest protection (audit F-022).
 *
 * The finding: the root seed — which derives the libp2p Peer ID, the
 * `did:scid:vh` identity key and the permanent TSP VID — was persisted to
 * `config.json` as plain hex, alongside a plaintext BIP-39 mnemonic export path.
 * Anyone who reads that file owns the node's identity.
 *
 * What this module changes: with `TSP_SEED_PASSPHRASE` set, every persisted
 * secret is written as an AES-256-GCM blob (the same primitive the keystore uses
 * for key material) instead of hex. Without it, writes stay hex — so **no
 * existing deployment breaks** — and the caller is expected to warn.
 *
 * Reads accept BOTH shapes:
 *   - a hex string            → legacy plaintext, returned with `legacyPlaintext: true`
 *   - a protected blob object → decrypted, and a clear error if no passphrase is set
 *
 * This is deliberately not a BIP-39 passphrase: adding one would change key
 * derivation and therefore every existing DID. Protecting the file at rest is
 * the change that cannot alter an identity.
 *
 * ## The mnemonic export path stays plaintext — deliberate, decided 2026-09-24 (F-022-i)
 *
 * `resolveSeedPassphrase` protects the seed **as persisted by this node**. The
 * separate mnemonic *export* path still returns the phrase in the clear, and that
 * is the chosen behaviour rather than an oversight:
 *
 *   - a mnemonic exists to be written down and carried off the machine — encrypting
 *     it under the key held on the same machine protects nothing it does not already
 *     protect, and makes disaster recovery strictly harder, which is the one job a
 *     mnemonic has;
 *   - the operator asking for it is already authenticated and already holds the
 *     node's key material, so the export grants no capability they did not have.
 *
 * Revisiting this is a policy change, not a bug fix: if more than one operator can
 * reach the export surface, require the passphrase to be re-presented at export time
 * (and log the export), rather than encrypting the phrase.
 */

import { encryptSecretKey, decryptSecretKey } from '../keystore/sqlite-keystore.js';

export const SEED_PASSPHRASE_ENV = 'TSP_SEED_PASSPHRASE';

/** The on-disk shape of an encrypted seed. Versioned so the format can change. */
export interface ProtectedSeed {
  v: 1;
  algorithm: 'aes-256-gcm';
  /** base64 ciphertext */
  ct: string;
  /** base64 PBKDF2 salt */
  salt: string;
  /** base64 GCM nonce */
  nonce: string;
  /** base64 GCM auth tag */
  tag: string;
}

/**
 * The passphrase to use for seed-at-rest encryption.
 *
 * Resolution order is **explicit argument → `TSP_SEED_PASSPHRASE` → `undefined`**, matching the
 * other policy switches (`resolveOobiSignaturePolicy`, `resolveMembershipPresentationPolicy`,
 * `resolveOperationProofPolicy`, `resolveDtgProfilePolicy`): the environment is the convenient
 * default, never the only option. An explicit empty string means "no passphrase" and does **not**
 * fall through to the environment.
 */
export function resolveSeedPassphrase(explicit?: string): string | undefined {
  const raw = (explicit ?? process.env[SEED_PASSPHRASE_ENV] ?? '').trim();
  return raw.length > 0 ? raw : undefined;
}

export function isProtectedSeed(value: unknown): value is ProtectedSeed {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return v.v === 1 && v.algorithm === 'aes-256-gcm'
    && typeof v.ct === 'string' && typeof v.salt === 'string'
    && typeof v.nonce === 'string' && typeof v.tag === 'string';
}

/** Hex → the value to persist: hex without a passphrase, a blob with one. */
export async function protectSeedHex(
  hex: string,
  passphrase: string,
): Promise<ProtectedSeed> {
  const blob = await encryptSecretKey(Buffer.from(hex, 'hex'), passphrase);
  return {
    v: 1,
    algorithm: 'aes-256-gcm',
    ct: Buffer.from(blob.ciphertext).toString('base64'),
    salt: Buffer.from(blob.salt).toString('base64'),
    nonce: Buffer.from(blob.nonce).toString('base64'),
    tag: Buffer.from(blob.authTag).toString('base64'),
  };
}

/** The inverse of {@link protectSeedHex}. Throws if the passphrase is wrong. */
export async function unprotectSeedHex(
  seed: ProtectedSeed,
  passphrase: string,
): Promise<string> {
  const secret = await decryptSecretKey(
    {
      ciphertext: new Uint8Array(Buffer.from(seed.ct, 'base64')),
      salt: new Uint8Array(Buffer.from(seed.salt, 'base64')),
      nonce: new Uint8Array(Buffer.from(seed.nonce, 'base64')),
      authTag: new Uint8Array(Buffer.from(seed.tag, 'base64')),
    },
    passphrase,
  );
  return Buffer.from(secret).toString('hex');
}

export interface PersistedSeed {
  /** The seed as hex, ready for `generateEd25519KeyPairFromSeed` / libp2p. */
  hex: string;
  /** True when the value was stored in the clear — worth warning about. */
  legacyPlaintext: boolean;
}

/**
 * Read a persisted seed in either shape.
 *
 * @param value       the raw config.json value (`undefined` when absent)
 * @param passphrase  from {@link resolveSeedPassphrase}
 * @param label       field name, used in error messages
 * @returns the seed, or `undefined` when the field is absent
 * @throws when the value is an encrypted blob and no passphrase is available, or
 *         when decryption fails (wrong passphrase / tampered file) — both are
 *         conditions an operator must see, not silently regenerate a new identity
 */
export async function readPersistedSeed(
  value: unknown,
  passphrase: string | undefined,
  label: string,
): Promise<PersistedSeed | undefined> {
  if (value === undefined || value === null) return undefined;

  if (typeof value === 'string') {
    if (value.length === 0) return undefined;
    return { hex: value, legacyPlaintext: true };
  }

  if (isProtectedSeed(value)) {
    if (!passphrase) {
      throw new Error(
        `${label} in config.json is encrypted, but ${SEED_PASSPHRASE_ENV} is not set — ` +
        'set it to the passphrase used when the file was written',
      );
    }
    try {
      return { hex: await unprotectSeedHex(value, passphrase), legacyPlaintext: false };
    } catch {
      throw new Error(
        `${label} in config.json could not be decrypted with ${SEED_PASSPHRASE_ENV} — ` +
        'wrong passphrase, or the file was modified',
      );
    }
  }

  throw new Error(`${label} in config.json has an unrecognised shape`);
}

/** The value to persist for a seed: hex without a passphrase, a blob with one. */
export async function writeSeedValue(
  hex: string,
  passphrase: string | undefined,
): Promise<string | ProtectedSeed> {
  return passphrase ? protectSeedHex(hex, passphrase) : hex;
}
