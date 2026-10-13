/**
 * Post-quantum crypto primitives (TSP Rev 3 — D2: PQC always-on).
 *
 * - ML-DSA-65 (FIPS 204) signatures — CESR code `1AAQ`.
 * - MLKEM768-X25519 hybrid KEM (draft-ietf-hpke-pq-05, KEM id 0x647a):
 *       enc = concat(mlkem_enc, x25519_enc)
 *       ss  = concat(mlkem_ss,  x25519_ss)
 *
 * These are the raw primitives; HPKE integration and the message-codec
 * signature dispatch live in the codec layers.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';

/** SHA-256 (local name keeps the file's `concat` helper style readable). */
const sha256 = (bytes: Uint8Array): Uint8Array => nobleSha256(bytes);

// ---------------------------------------------------------------------------
// Sizes (verified against @noble/post-quantum)
// ---------------------------------------------------------------------------

export const ML_DSA_65_SK_BYTES = 4032;
export const ML_DSA_65_PK_BYTES = 1952;
export const ML_DSA_65_SIG_BYTES = 3309;
export const ML_DSA_65_SIGNATURE_CODE = '1AAQ' as const;

/**
 * Multicodec code for an ML-DSA-65 public key (`ml-dsa-65-pub`), varint-encoded
 * as the two bytes `0x91 0x24`.
 *
 * Registered in the multicodec table and used in production (e.g.
 * `affinidi-secrets-resolver` `ML_DSA_65_PUB = 0x1211`), so a DID-document
 * Multikey entry can carry it as a real, self-describing prefix.
 */
export const ML_DSA_65_PUB_MULTICODEC = 0x1211;

/**
 * NOTE: there is deliberately no equivalent constant for ML-KEM. No multicodec
 * is registered for ML-KEM public keys (the W3C CCG issue selecting PQ Multikey
 * prefixes, `w3c-ccg/di-quantum-safe#5`, is still open and the table's PQ rows
 * cover ML-DSA/SLH-DSA only), so the hybrid KEM key must not be given an invented
 * prefix — see `buildDidPeer4Document`, which carries it under an explicitly
 * algorithm-named `VerificationMethod.type` instead.
 */

export const ML_KEM_768_SK_BYTES = 2400;
export const ML_KEM_768_PK_BYTES = 1184;
export const ML_KEM_768_CT_BYTES = 1088;
export const ML_KEM_768_SS_BYTES = 32;

export const X25519_PK_BYTES = 32;
export const X25519_SK_BYTES = 32;

/** MLKEM768-X25519 hybrid KEM (HPKE-PQ id 0x647a). */
export const MLKEM768_X25519_KEM_ID = 0x647a;
export const MLKEM768_X25519_SK_BYTES = ML_KEM_768_SK_BYTES + X25519_SK_BYTES; // 2432
export const MLKEM768_X25519_PK_BYTES = ML_KEM_768_PK_BYTES + X25519_PK_BYTES; // 1216
export const MLKEM768_X25519_ENC_BYTES = ML_KEM_768_CT_BYTES + X25519_PK_BYTES; // 1120
export const MLKEM768_X25519_SS_BYTES = ML_KEM_768_SS_BYTES + X25519_SK_BYTES; // 64

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// ---------------------------------------------------------------------------
// ML-DSA-65 signatures
// ---------------------------------------------------------------------------

export interface MlDsa65KeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateMlDsa65KeyPair(): MlDsa65KeyPair {
  return ml_dsa65.keygen();
}

/**
 * Deterministic ML-DSA-65 key pair from a 32-byte seed.
 *
 * Needed for SEEDED identities (the utility server): its genesis → SCID must be
 * reproducible from config, and the PQ public key is published in the DID
 * document, so a random key would break that reproducibility.
 */
export function generateMlDsa65KeyPairFromSeed(seed: Uint8Array): MlDsa65KeyPair {
  if (seed.length !== 32) {
    throw new RangeError(`generateMlDsa65KeyPairFromSeed: seed must be 32 bytes, got ${seed.length}`);
  }
  // Domain-separated from the Ed25519 keys derived from the same seed.
  return ml_dsa65.keygen(sha256(concat(seed, new Uint8Array([0x02]))));
}

export function mlDsa65Sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_dsa65.sign(message, secretKey);
}

export function mlDsa65Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  return ml_dsa65.verify(signature, message, publicKey);
}

export function mlDsa65GetPublicKey(secretKey: Uint8Array): Uint8Array {
  return ml_dsa65.getPublicKey(secretKey);
}

/**
 * Encode a 3309-byte ML-DSA-65 signature as the CESR `1AAQ` primitive.
 * 3309 is a multiple of 3, so no lead pad is required; the text form is
 * `1AAQ` + 4412 base64url chars = 4416 chars (1103 triplets).
 */
export function encodeMlDsa65Signature(signature: Uint8Array): string {
  if (signature.length !== ML_DSA_65_SIG_BYTES) {
    throw new RangeError(`encodeMlDsa65Signature: expected ${ML_DSA_65_SIG_BYTES} bytes, got ${signature.length}`);
  }
  return ML_DSA_65_SIGNATURE_CODE + Buffer.from(signature).toString('base64url');
}

/**
 * Decode a CESR `1AAQ` ML-DSA-65 signature primitive back to its 3309 raw bytes.
 * @throws SyntaxError if the string is not a well-formed `1AAQ` primitive
 */
export function decodeMlDsa65Signature(encoded: string): Uint8Array {
  if (!encoded.startsWith(ML_DSA_65_SIGNATURE_CODE)) {
    throw new SyntaxError(`decodeMlDsa65Signature: expected "${ML_DSA_65_SIGNATURE_CODE}" prefix, got ${JSON.stringify(encoded.slice(0, 8))}`);
  }
  const bytes = Buffer.from(encoded.slice(ML_DSA_65_SIGNATURE_CODE.length), 'base64url');
  if (bytes.length !== ML_DSA_65_SIG_BYTES) {
    throw new SyntaxError(`decodeMlDsa65Signature: expected ${ML_DSA_65_SIG_BYTES} bytes, got ${bytes.length}`);
  }
  return new Uint8Array(bytes);
}

// ---------------------------------------------------------------------------
// MLKEM768-X25519 hybrid KEM
// ---------------------------------------------------------------------------

export interface MlKem768X25519KeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateMlKem768X25519KeyPair(): MlKem768X25519KeyPair {
  const m = ml_kem768.keygen();
  const x = x25519.keygen();
  return {
    secretKey: concat(m.secretKey, x.secretKey),
    publicKey: concat(m.publicKey, x.publicKey),
  };
}

/**
 * Deterministic MLKEM768-X25519 key pair from a 32-byte seed (see
 * `generateMlDsa65KeyPairFromSeed` for why determinism matters).
 *
 * ML-KEM-768's own keygen takes a 64-byte seed; the X25519 half takes 32 — both
 * are derived from the supplied seed with distinct domain-separation tags.
 */
export function generateMlKem768X25519KeyPairFromSeed(seed: Uint8Array): MlKem768X25519KeyPair {
  if (seed.length !== 32) {
    throw new RangeError(`generateMlKem768X25519KeyPairFromSeed: seed must be 32 bytes, got ${seed.length}`);
  }
  const kemSeed = concat(
    sha256(concat(seed, new Uint8Array([0x03]))),
    sha256(concat(seed, new Uint8Array([0x04]))),
  );
  const m = ml_kem768.keygen(kemSeed);
  const x = x25519.keygen(sha256(concat(seed, new Uint8Array([0x05]))));
  return {
    secretKey: concat(m.secretKey, x.secretKey),
    publicKey: concat(m.publicKey, x.publicKey),
  };
}

export function mlKem768X25519Encap(
  publicKey: Uint8Array,
): { enc: Uint8Array; sharedSecret: Uint8Array } {
  if (publicKey.length !== MLKEM768_X25519_PK_BYTES) {
    throw new RangeError(`mlKem768X25519Encap: public key must be ${MLKEM768_X25519_PK_BYTES} bytes`);
  }
  const mlkemPk = publicKey.slice(0, ML_KEM_768_PK_BYTES);
  const xPk = publicKey.slice(ML_KEM_768_PK_BYTES);
  const m = ml_kem768.encapsulate(mlkemPk);
  const eph = x25519.keygen();
  const xss = x25519.getSharedSecret(eph.secretKey, xPk);
  return {
    enc: concat(m.cipherText, eph.publicKey),
    sharedSecret: concat(m.sharedSecret, xss),
  };
}

export function mlKem768X25519Decap(enc: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (enc.length !== MLKEM768_X25519_ENC_BYTES) {
    throw new RangeError(`mlKem768X25519Decap: enc must be ${MLKEM768_X25519_ENC_BYTES} bytes`);
  }
  if (secretKey.length !== MLKEM768_X25519_SK_BYTES) {
    throw new RangeError(`mlKem768X25519Decap: secret key must be ${MLKEM768_X25519_SK_BYTES} bytes`);
  }
  const mlkemSk = secretKey.slice(0, ML_KEM_768_SK_BYTES);
  const xSk = secretKey.slice(ML_KEM_768_SK_BYTES);
  const mlkemCt = enc.slice(0, ML_KEM_768_CT_BYTES);
  const epub = enc.slice(ML_KEM_768_CT_BYTES);
  const mss = ml_kem768.decapsulate(mlkemCt, mlkemSk);
  const xss = x25519.getSharedSecret(xSk, epub);
  return concat(mss, xss);
}
