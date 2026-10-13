/**
 * TSP v3 (Rev 3) field codecs — CESR 2.0 foundation.
 *
 * These are the leaf-level CESR encodings the Rev 3 wire format is built from.
 * They deliberately reuse the existing `cesrEncode`/`cesrDecode` layer
 * (`src/crypto/cesr.ts`), whose underlying `cesr` npm library (v0.1.2) already
 * implements the CESR 2.0 code table (`-_AAACAA`, genus AAA v2.00).
 *
 * ## Confirmed wire forms (Rev 3 spec §9)
 *   - VID_String : variable-length bytes, no type code — `4B##`/`5B##`/`6B##`
 *                  (or Big `7AAB####`…). NULL VID = `4BAA`.
 *   - SHA2-256   : `I` + 43 chars
 *   - Blake2b-256: `F` + 43 chars
 */

import { cesrEncode, cesrDecode, CESR_CODES } from '../crypto/cesr.js';

// ---------------------------------------------------------------------------
// VID_String — the Rev 3 "self-certifying key" identifier
// ---------------------------------------------------------------------------

/** The NULL VID — a VID_String of zero length (`4BAA`). */
export const NULL_VID = '4BAA' as const;

/**
 * Encode raw key bytes as a Rev 3 VID_String (variable-length bytes, no type code).
 * For a 32-byte Ed25519 key this yields a `5B##…` form; for empty bytes `4BAA`.
 */
export function encodeVid(bytes: Uint8Array): string {
  return cesrEncode(CESR_CODES.VARIABLE_BYTES, bytes);
}

/**
 * Decode a Rev 3 VID_String back to raw bytes.
 * @throws SyntaxError if the string is not a valid variable-length CESR bytes item
 */
export function decodeVid(vid: string): Uint8Array {
  const item = cesrDecode(vid);
  // cesrDecode returns CESR_CODES.VARIABLE_BYTES for any of the variable-length
  // byte codes (4B/5B/6B/7AAB/8AAB/9AAB). Reject fixed-size codes here so a VID
  // can never silently carry a non-key primitive.
  if (item.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError(`decodeVid: expected variable-length VID_String, got code "${item.code}"`);
  }
  return item.bytes;
}

/** True if the VID is the NULL VID (zero-length). */
export function isNullVid(vid: string): boolean {
  return decodeVid(vid).length === 0;
}

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

/** Encode a 32-byte SHA2-256 digest (`I` code). */
export function encodeDigestSha256(bytes: Uint8Array): string {
  return cesrEncode(CESR_CODES.SHA2_256_DIGEST, bytes);
}

/** Encode a 32-byte Blake2b-256 digest (`F` code). */
export function encodeDigestBlake2b(bytes: Uint8Array): string {
  return cesrEncode(CESR_CODES.BLAKE2B_256_DIGEST, bytes);
}

// ---------------------------------------------------------------------------
// TSP payload field types (X-prefixed 3-char CESR tags) — Rev 3 spec §9
// ---------------------------------------------------------------------------

/** Generic control payload field. */
export const TSP_FIELD_CTL = 'XCTL' as const;
/** Upper-layer application payload (sniffable CESR stream). */
export const TSP_FIELD_SCS = 'XSCS' as const;
/** Nested / routed message hop. */
export const TSP_FIELD_HOP = 'XHOP' as const;
/** Relationship-forming invite (was `TSP_RFI` in v2). */
export const TSP_FIELD_RFI = 'XRFI' as const;
/** Relationship-forming accept (was `TSP_RFA` in v2). */
export const TSP_FIELD_RFA = 'XRFA' as const;
/** Relationship-forming decline (new in Rev 3). */
export const TSP_FIELD_RFD = 'XRFD' as const;

// ---------------------------------------------------------------------------
// CESR 2.0 / post-quantum identifiers
// ---------------------------------------------------------------------------

/** CESR code table genus/version in use by Rev 3 (genus AAA, version 2.00). */
export const CESR_CODE_TABLE_V2 = '-_AAACAA' as const;

/** ML-DSA-65 signature CESR code (FIPS 204 / CRYSTALS-Dilithium). */
export const ML_DSA_65_SIGNATURE_CODE = '1AAQ' as const;

/** HPKE KEM id for the MLKEM768-X25519 hybrid KEM (draft-ietf-hpke-pq). */
export const MLKEM768_X25519_KEM_ID = 0x647a;
