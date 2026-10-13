/**
 * Minimal CESR-style code table.
 *
 * This is NOT spec-complete CESR (KERI). It is a deliberately minimal subset
 * sufficient for TSP Steps 1–3: sign/verify round trips, digest encoding, and
 * variable-length binary field encoding for TSP message bodies.
 *
 * Encoding convention (backed by the `cesr` npm library):
 *   Fixed-length primitives:
 *     code + base64url(bytes)
 *     The expected byte length for each code is fixed and validated on encode.
 *
 *   Variable-length primitives (VARIABLE_BYTES):
 *     Uses the cesr library's native Bytes_L0/L1/L2 codes (4B/5B/6B) for
 *     payloads up to ~12285 bytes, and Bytes_Big_L0/L1/L2 (7AAB/8AAB/9AAB)
 *     for larger payloads. The lead byte count is chosen automatically by
 *     pickVariableBytesCode() in cesr.ts.
 *
 *   Group framing:
 *     Uses the cesr library's GenericGroup counter: '-T' + 2-char base64url
 *     count (0–4095), or '--T' + 5-char count for groups > 4095 items.
 *     Example: '-TAE' = GenericGroup with 4 items.
 *
 * Code assignments follow CESR conventions where possible:
 *   https://trustoverip.github.io/tswg-cesr-specification/
 *
 * NOTE: Two internal codes differ from the cesr library's wire codes:
 *   - SHA2_256_DIGEST: internal 'E', wire 'I' (cesr lib's 'E' is Blake3-256)
 *   - X25519_PUBLIC_KEY: internal 'X', wire 'C'
 *   - NONCE (24 bytes): internal '0A', encoded as variable-length (4B/5B/6B)
 *     because the cesr lib's '0A' is Salt_128 (16 bytes, not 24)
 * See src/crypto/cesr.ts for the translation layer.
 */

export const CESR_CODES = {
  /** Ed25519 verification key — 32 bytes */
  ED25519_PUBLIC_KEY: 'D',

  /** Ed25519 signature — 64 bytes */
  ED25519_SIGNATURE: '0B',

  /** X25519 public key (key agreement) — 32 bytes */
  X25519_PUBLIC_KEY: 'X',

  /** Nonce / random salt — 24 bytes */
  NONCE: '0A',

  /** SHA2-256 digest — 32 bytes */
  SHA2_256_DIGEST: 'E',

  /** Blake2b-256 digest — 32 bytes */
  BLAKE2B_256_DIGEST: 'F',

  /**
   * Variable-length binary field — arbitrary byte length.
   *
   * This is the canonical internal code name for variable-length items.
   * On the wire, the cesr library uses Bytes_L0/L1/L2 codes (4B/5B/6B)
   * depending on the lead byte count needed for 3-byte alignment:
   *   - '4B' (Bytes_L0): byteLength % 3 === 0 (no lead bytes)
   *   - '5B' (Bytes_L1): byteLength % 3 === 2 (1 lead byte)
   *   - '6B' (Bytes_L2): byteLength % 3 === 1 (2 lead bytes)
   * For payloads > ~12285 bytes, the Big variants are used (7AAB/8AAB/9AAB).
   *
   * The internal code '4B' is used as the canonical name for all variable-length
   * items regardless of which wire code was used to encode them.
   */
  VARIABLE_BYTES: '4B',
} as const;

export type CesrCodeKey = keyof typeof CESR_CODES;
export type CesrCode = (typeof CESR_CODES)[CesrCodeKey];

/** Expected raw byte length for each fixed-length code. -1 = variable length. */
export const CESR_BYTE_LENGTHS: Record<CesrCode, number> = {
  [CESR_CODES.ED25519_PUBLIC_KEY]: 32,
  [CESR_CODES.ED25519_SIGNATURE]: 64,
  [CESR_CODES.X25519_PUBLIC_KEY]: 32,
  [CESR_CODES.NONCE]: 24,
  [CESR_CODES.SHA2_256_DIGEST]: 32,
  [CESR_CODES.BLAKE2B_256_DIGEST]: 32,
  [CESR_CODES.VARIABLE_BYTES]: -1,  // variable — length encoded in the stream
};
