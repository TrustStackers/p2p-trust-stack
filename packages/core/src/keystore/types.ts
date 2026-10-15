// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Key store interface — Step 2.
 *
 * Abstracts secure storage of Ed25519 and X25519 key pairs, keyed by VID
 * and key type. Implementations must encrypt secret keys at rest.
 */

/**
 * 'ed25519-next' (Step 11) stores a ScidVhMethod identity's pending
 * pre-committed "next" signing key pair (see docs/implementation-plan-step11.md
 * §3/§8) — the secret half of the key whose public key hash is committed to
 * by the current rotation log entry's `nextKeyCommitment`. Persisted so it
 * survives Agent.unlock() without requiring the caller to hold onto it
 * externally between sessions.
 */
export type KeyType = 'ed25519' | 'x25519' | 'ed25519-next' | (string & {});


export interface RawKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Secure key store interface.
 *
 * Secret keys are encrypted with a passphrase-derived key (Argon2id KDF +
 * AES-256-GCM). The passphrase is never stored — it is required for every
 * store and retrieve operation.
 */
export interface KeyStore {
  /**
   * Encrypt and store a key pair for the given VID and key type.
   * Overwrites any existing entry for the same (vid, keyType) pair.
   */
  storeKeyPairAsync(vid: string, keyType: KeyType, keyPair: RawKeyPair, passphrase: string): Promise<void>;

  /**
   * Retrieve and decrypt a key pair for the given VID and key type.
   * @throws if no entry exists, or if the passphrase is wrong (AES-GCM auth tag mismatch)
   */
  retrieveKeyPairAsync(vid: string, keyType: KeyType, passphrase: string): Promise<RawKeyPair>;

  /** Close the underlying database connection. */
  close(): void;
}
