/**
 * DTG Digest Encoding — Multibase/Multihash for digest-valued members.
 *
 * Per the DTG Credentials Core Specification v1.0, section "Digest Encoding":
 * digest-valued members (`digestMultibase` here; `parent` and `accepts` on the
 * VDC) are encoded as **Multibase over a Multihash**:
 *
 *   digestMultibase = multibase('z', multihash(sha2-256, digest))
 *                   = 'z' + base58btc(0x12 0x20 ‖ digest)
 *
 * `0x12` is the multihash code for sha2-256 and `0x20` the digest length, which
 * is why every such string begins `zQm…`.
 *
 * Why this exists (F-002, researched 2026-09-25): the VWC adapter emitted
 * `digest: "sha256:<hex>"`, which is not the spec's encoding. The v1.0 statement
 * profile moves that value into `credentialSubject.object.digestMultibase`, so
 * the encoding had to be implemented alongside the profile change.
 *
 * The base58btc codec is the one already used for `proofValue` in
 * `dtg-credential.ts` — imported rather than duplicated.
 */
import { sha256 } from '../../crypto/primitives.js';
import { toBase58btc, fromBase58btc } from '../dtg-credential.js';

/** Multihash code for SHA-256 (table 1 of the multihash spec). */
const SHA2_256_CODE = 0x12;
/** Digest length for SHA-256, in bytes. */
const SHA2_256_LENGTH = 0x20;
/** 0x12 0x20 — the two-byte header every `zQm…` string carries. */
const SHA2_256_PREFIX = [SHA2_256_CODE, SHA2_256_LENGTH] as const;

/**
 * Multibase/multihash for a SHA-256 digest: `'z' + base58btc(0x1220 ‖ digest)`.
 *
 * @param digest 32 raw SHA-256 bytes (NOT hex, NOT a `sha256:`-prefixed string).
 */
export function toSha256MultibaseMultihash(digest: Uint8Array): string {
  if (digest.length !== SHA2_256_LENGTH) {
    throw new Error(
      `toSha256MultibaseMultihash: expected a ${SHA2_256_LENGTH}-byte digest, got ${digest.length}`,
    );
  }
  const multihash = new Uint8Array(SHA2_256_PREFIX.length + digest.length);
  multihash.set(SHA2_256_PREFIX, 0);
  multihash.set(digest, SHA2_256_PREFIX.length);
  return toBase58btc(multihash);
}

/** Convenience: hash bytes and encode in one step. */
export function sha256MultibaseMultihash(data: Uint8Array): string {
  return toSha256MultibaseMultihash(sha256(data));
}

/**
 * Inverse of {@link toSha256MultibaseMultihash}. Returns the raw 32-byte digest.
 * Throws on a wrong multibase prefix, a wrong algorithm code, or a wrong length —
 * a value that is only *shaped* like a multihash is not accepted.
 */
export function fromSha256MultibaseMultihash(encoded: string): Uint8Array {
  const decoded = fromBase58btc(encoded);
  if (decoded.length !== SHA2_256_PREFIX.length + SHA2_256_LENGTH) {
    throw new Error(
      `fromSha256MultibaseMultihash: expected ${SHA2_256_PREFIX.length + SHA2_256_LENGTH} bytes, got ${decoded.length}`,
    );
  }
  if (decoded[0] !== SHA2_256_CODE || decoded[1] !== SHA2_256_LENGTH) {
    throw new Error(
      `fromSha256MultibaseMultihash: not a sha2-256 multihash (header 0x${decoded[0].toString(16)} 0x${decoded[1].toString(16)})`,
    );
  }
  return decoded.slice(SHA2_256_PREFIX.length);
}

/**
 * Normalise a caller-supplied digest to the spec's Multibase/Multihash form.
 *
 * The VEC's input (`endorsedCredentialDigest`) has never been validated — callers
 * pass whatever their own hashing produced. A digest-valued member MUST be
 * multibase/multihash, so this converts the two shapes that are unambiguous and
 * otherwise passes the value through with a warning rather than throwing inside
 * an issuance path.
 *
 * Accepts: an existing multibase multihash (`z…`), `sha256:<64 hex>`, or a bare
 * 64-character hex SHA-256 digest.
 */
export function toDigestMultibase(raw: string): string {
  if (/^z[1-9A-HJ-NP-Za-km-z]+$/.test(raw)) return raw; // already multibase

  const hex = raw.startsWith('sha256:') ? raw.slice('sha256:'.length) : raw;
  if (/^[0-9a-fA-F]{64}$/.test(hex)) {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return toSha256MultibaseMultihash(bytes);
  }

  console.warn(
    `[dtg-profile] endorsedCredentialDigest is neither a multibase multihash nor a ` +
      `sha256 hex digest; passing it through unencoded (${raw.slice(0, 24)}…)`,
  );
  return raw;
}

