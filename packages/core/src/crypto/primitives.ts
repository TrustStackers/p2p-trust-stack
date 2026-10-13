/**
 * TSP crypto primitives — Step 1.
 *
 * Wraps @noble/curves, @noble/hashes, and @hpke/core into a clean,
 * TSP-oriented API. Nothing in this file knows about TSP message formats;
 * it is purely a crypto utility layer.
 */

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { timingSafeEqual } from 'node:crypto';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { blake2b as nobleBlake2b } from '@noble/hashes/blake2.js';
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js';
import { CipherSuite, HkdfSha256 } from '@hpke/core';
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519';
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';

// ---------------------------------------------------------------------------
// Key pair types
// ---------------------------------------------------------------------------

/** Ed25519 signature key sizes (bytes). */
export const ED25519_SECRET_KEY_BYTES = 32;
export const ED25519_PUBLIC_KEY_BYTES = 32;

export interface Ed25519KeyPair {
  secretKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array; // 32 bytes
}

export interface X25519KeyPair {
  secretKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array; // 32 bytes
}

// ---------------------------------------------------------------------------
// Ed25519 — signing / verification
// ---------------------------------------------------------------------------

/** Generate a fresh Ed25519 key pair. */
export function generateEd25519KeyPair(): Ed25519KeyPair {
  return ed25519.keygen();
}

/**
 * Derive an Ed25519 key pair deterministically from a 32-byte seed.
 * The seed IS the secret key (RFC 8032 / libp2p-compatible), from which the
 * public key is derived. Used to seed stable identity keys (e.g. the utility
 * server's did:scid:vh identity key and its permanent TSP VID key) from
 * config.json seeds, so a key survives restarts deterministically.
 */
export function generateEd25519KeyPairFromSeed(seed: Uint8Array): Ed25519KeyPair {
  if (seed.length !== 32) {
    throw new Error('generateEd25519KeyPairFromSeed: seed must be 32 bytes');
  }
  const publicKey = ed25519.getPublicKey(seed);
  return { secretKey: seed, publicKey };
}

/**
 * Sign a message with an Ed25519 secret key.
 * @returns 64-byte signature
 */
export function signEd25519(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, secretKey);
}

/**
 * Verify an Ed25519 signature.
 * @returns true if the signature is valid for the given message and public key
 */
export function verifyEd25519(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return ed25519.verify(signature, message, publicKey);
}

// ---------------------------------------------------------------------------
// X25519 — key agreement
// ---------------------------------------------------------------------------

/** Generate a fresh X25519 key pair (independent of any Ed25519 key). */
export function generateX25519KeyPair(): X25519KeyPair {
  return x25519.keygen();
}

/**
 * Derive an X25519 key pair from an Ed25519 secret key.
 *
 * TSP VIDs carry both a signing key (Ed25519) and an agreement key (X25519).
 * When both are derived from the same seed, this helper converts the Ed25519
 * secret key to its X25519 equivalent using the standard Montgomery conversion.
 */
export function ed25519ToX25519(ed25519SecretKey: Uint8Array): X25519KeyPair {
  const secretKey = ed25519.utils.toMontgomerySecret(ed25519SecretKey);
  const publicKey = x25519.getPublicKey(secretKey);
  return { secretKey, publicKey };
}

// ---------------------------------------------------------------------------
// Digest functions
// ---------------------------------------------------------------------------

/**
 * SHA2-256 digest.
 * @returns 32-byte digest
 */
/**
 * Constant-time equality for two secret-derived strings (audit F-020).
 *
 * A plain `a === b` on a MAC or signature comparison exits at the first
 * differing byte, so the elapsed time reveals how many leading bytes were
 * correct — enough to forge a value one byte at a time.
 *
 * Both inputs are hashed before comparing, for two reasons: the comparison then
 * runs over fixed-length buffers (no length oracle), and `timingSafeEqual` cannot
 * throw on inputs of unequal length.
 */
export function timingSafeEqualString(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const encoder = new TextEncoder();
  const digestA = sha256(encoder.encode(a));
  const digestB = sha256(encoder.encode(b));
  return timingSafeEqual(digestA, digestB);
}

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/**
 * Blake2b-256 digest.
 *
 * TSP requires both SHA2-256 and Blake2b as supported digest functions
 * (used in TSP_DIGEST for relationship-forming messages). This function
 * always produces a 32-byte (256-bit) output.
 *
 * @returns 32-byte digest
 */
export function blake2b256(data: Uint8Array): Uint8Array {
  return nobleBlake2b(data, { dkLen: 32 });
}

// ---------------------------------------------------------------------------
// HKDF
// ---------------------------------------------------------------------------

/**
 * HKDF key derivation (RFC 5869).
 *
 * @param hashFn  Hash function to use — pass `nobleSha256` for SHA-256
 * @param ikm     Input key material
 * @param salt    Optional salt (recommended)
 * @param info    Context / application-specific info
 * @param length  Output length in bytes
 */
export function hkdf(
  hashFn: Parameters<typeof nobleHkdf>[0],
  ikm: Uint8Array,
  salt: Uint8Array | undefined,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return nobleHkdf(hashFn, ikm, salt, info, length);
}

// ---------------------------------------------------------------------------
// HPKE-Auth (Step 1 primitive — no TSP message-format integration)
// ---------------------------------------------------------------------------

/**
 * Import a raw X25519 public key (32 bytes) as an HPKE-compatible CryptoKey.
 *
 * Used to convert the remote peer's X25519 key (stored as raw bytes in the
 * relationship table) into the CryptoKey format required by hpkeAuthSeal/Open.
 *
 * @param rawPublicKey  32-byte X25519 public key
 * @returns CryptoKey suitable for use as the `recipientPublicKey` or `senderPublicKey`
 *          argument to hpkeAuthSeal / hpkeAuthOpen
 */
export async function importHpkePublicKey(rawPublicKey: Uint8Array): Promise<CryptoKey> {
  const kem = new DhkemX25519HkdfSha256();
  // Use slice() to ensure the Uint8Array owns its own ArrayBuffer (byteLength === 32).
  // Some Uint8Arrays (e.g. from @noble/curves) share a larger backing buffer, which
  // causes @hpke/dhkem-x25519 to reject the key with "Invalid length of the key".
  const buf = rawPublicKey.byteLength === rawPublicKey.buffer.byteLength
    ? rawPublicKey.buffer as ArrayBuffer
    : rawPublicKey.slice(0).buffer as ArrayBuffer;
  return kem.importKey('raw', buf, true);
}

/**
 * Import a raw X25519 key pair (32-byte secretKey + 32-byte publicKey) as an
 * HPKE-compatible HpkeKeyPair (CryptoKey pair).
 *
 * Used to convert the local agreementKeyPair (stored as raw bytes in LocalIdentity)
 * into the CryptoKey format required by hpkeAuthSeal/Open.
 *
 * @param raw  Object with `secretKey` (32 bytes) and `publicKey` (32 bytes)
 * @returns HpkeKeyPair suitable for use as the `senderKey` or `recipientKey`
 *          argument to hpkeAuthSeal / hpkeAuthOpen
 */
export async function importHpkeKeyPair(raw: {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}): Promise<HpkeKeyPair> {
  const kem = new DhkemX25519HkdfSha256();
  // Use slice() to ensure each Uint8Array owns its own 32-byte ArrayBuffer.
  // @noble/curves returns Uint8Arrays that share a larger backing buffer (byteLength=64),
  // which causes @hpke/dhkem-x25519 to reject the key with "Invalid length of the key".
  const secretBuf = raw.secretKey.byteLength === raw.secretKey.buffer.byteLength
    ? raw.secretKey.buffer as ArrayBuffer
    : raw.secretKey.slice(0).buffer as ArrayBuffer;
  const publicBuf = raw.publicKey.byteLength === raw.publicKey.buffer.byteLength
    ? raw.publicKey.buffer as ArrayBuffer
    : raw.publicKey.slice(0).buffer as ArrayBuffer;
  const privateKey = await kem.importKey('raw', secretBuf, false);
  const publicKey = await kem.importKey('raw', publicBuf, true);
  return { privateKey, publicKey };
}


/**
 * Lazily-created HPKE cipher suite:
 *   DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20/Poly1305
 *
 * This matches the suite specified in Step 7 of the TSP next-steps doc.
 * Exposed here as a tested primitive; message-level integration is Step 7.
 */
function makeSuite(): CipherSuite {
  return new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
}

export interface HpkeKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/** Generate an HPKE X25519 key pair (suitable for use with hpkeAuthSeal/Open). */
export async function generateHpkeKeyPair(): Promise<HpkeKeyPair> {
  const kem = new DhkemX25519HkdfSha256();
  return kem.generateKeyPair();
}

/**
 * HPKE-Auth seal: encrypt plaintext for a recipient, authenticated by the sender's key pair.
 *
 * @param recipientPublicKey  Recipient's HPKE public key
 * @param senderKeyPair       Sender's HPKE key pair (provides authentication)
 * @param plaintext           Data to encrypt
 * @param aad                 Additional authenticated data (optional)
 * @returns { enc, ciphertext } — enc is the encapsulated key (send alongside ciphertext)
 */
export async function hpkeAuthSeal(
  recipientPublicKey: CryptoKey,
  senderKeyPair: HpkeKeyPair,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<{ enc: Uint8Array; ciphertext: Uint8Array }> {
  const suite = makeSuite();
  const sender = await suite.createSenderContext({
    recipientPublicKey,
    senderKey: senderKeyPair,
  });
  const ciphertext = new Uint8Array(await sender.seal(plaintext, aad));
  const enc = new Uint8Array(sender.enc);
  return { enc, ciphertext };
}

/**
 * HPKE-Auth open: decrypt ciphertext, verifying it was sealed by the expected sender.
 *
 * @param recipientKeyPair    Recipient's HPKE key pair
 * @param senderPublicKey     Sender's HPKE public key (for authentication)
 * @param enc                 Encapsulated key from hpkeAuthSeal
 * @param ciphertext          Ciphertext from hpkeAuthSeal
 * @param aad                 Additional authenticated data (must match what was passed to seal)
 * @returns Decrypted plaintext
 */
export async function hpkeAuthOpen(
  recipientKeyPair: HpkeKeyPair,
  senderPublicKey: CryptoKey,
  enc: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const suite = makeSuite();
  const recipient = await suite.createRecipientContext({
    recipientKey: recipientKeyPair,
    enc,
    senderPublicKey,
  });
  return new Uint8Array(await recipient.open(ciphertext, aad));
}

/**
 * HPKE-Base seal (RFC 9180 base mode — no sender authentication at the HPKE
 * layer; sender authenticity comes from the outer TSP signature). TSP Rev 3
 * uses HPKE-Base with `info = "YTSP-"` and `aad = CONCAT(TSP_Version,
 * VID_sndr, VID_rcvr)`.
 *
 * @param recipientPublicKey  Recipient's HPKE public key
 * @param plaintext           Data to encrypt
 * @param info                Application info (TSP uses `YTSP-`)
 * @param aad                 Additional authenticated data (TSP envelope)
 * @returns { enc, ciphertext } — enc is the encapsulated key (send alongside ciphertext)
 */
export async function hpkeBaseSeal(
  recipientPublicKey: CryptoKey,
  plaintext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
): Promise<{ enc: Uint8Array; ciphertext: Uint8Array }> {
  const suite = makeSuite();
  const sender = await suite.createSenderContext({ recipientPublicKey, info });
  const ciphertext = new Uint8Array(await sender.seal(plaintext, aad));
  const enc = new Uint8Array(sender.enc);
  return { enc, ciphertext };
}

/**
 * HPKE-Base open: decrypt ciphertext sealed in base mode.
 *
 * @param recipientKeyPair  Recipient's HPKE key pair
 * @param enc               Encapsulated key from hpkeBaseSeal
 * @param ciphertext        Ciphertext from hpkeBaseSeal
 * @param info              Application info (must match seal)
 * @param aad               Additional authenticated data (must match seal)
 * @returns Decrypted plaintext
 */
export async function hpkeBaseOpen(
  recipientKeyPair: HpkeKeyPair,
  enc: Uint8Array,
  ciphertext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const suite = makeSuite();
  const recipient = await suite.createRecipientContext({ recipientKey: recipientKeyPair, enc, info });
  return new Uint8Array(await recipient.open(ciphertext, aad));
}
