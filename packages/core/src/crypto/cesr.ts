/**
 * CESR codec — backed by the `cesr` npm library (v0.1.2).
 *
 * This module provides the same public API as the previous hand-rolled codec
 * (cesrEncode, cesrDecode, cesrEncodeGroup, cesrDecodeGroup) but delegates
 * all encoding/decoding to the cesr library's Matter and Counter classes.
 *
 * ## Wire format
 *
 * Fixed-length primitives:
 *   <code><base64url(bytes)>
 *   e.g. 'D' + 43 base64url chars for Ed25519 public key (32 bytes)
 *
 * Variable-length primitives:
 *   <code><base64url(bytes)>
 *   where code is '4B' (Bytes_L0), '5B' (Bytes_L1), or '6B' (Bytes_L2)
 *   chosen by: leadSize = (3 - (byteLength % 3)) % 3
 *   For payloads > ~12285 bytes, the Big variants are used: '7AAB'/'8AAB'/'9AAB'.
 *
 * Group frame (cesr lib Counter format):
 *   -T<b64count><item1><item2>...<itemN>
 *   where -T is the GenericGroup counter code and <b64count> is a 2-char
 *   base64url-encoded count (0–4095). For counts > 4095, the big counter
 *   format is used: --T<b64count> (8 chars total).
 *   Example: '-TAE' = GenericGroup with 4 items.
 *
 * ## Code mapping (internal name → wire code)
 *
 * Most internal codes match the cesr library wire codes exactly:
 *   - ED25519_PUBLIC_KEY: 'D'  (matches)
 *   - ED25519_SIGNATURE:  '0B' (matches)
 *   - BLAKE2B_256_DIGEST: 'F'  (matches)
 *   - VARIABLE_BYTES:     '4B' (canonical internal name; wire may be 4B/5B/6B/7AAB/8AAB/9AAB)
 *
 * Two codes differ from the cesr library's wire codes:
 *   - X25519_PUBLIC_KEY: internal 'X', wire 'C' (cesr lib's 'X' is unused)
 *   - SHA2_256_DIGEST:   internal 'E', wire 'I' (cesr lib's 'E' is Blake3-256)
 *   - NONCE (24 bytes):  internal '0A', encoded as variable-length (4B/5B/6B)
 *     because the cesr lib's '0A' is Salt_128 (16 bytes, not 24)
 *
 * See src/crypto/codes.ts for the full code table.
 */

import { Matter, Counter } from 'cesr';
import {
  CESR_CODES,
  CESR_BYTE_LENGTHS,
  type CesrCode,
} from './codes.js';

// ---------------------------------------------------------------------------
// Counter (group framing) constants
// ---------------------------------------------------------------------------

/**
 * The cesr library's GenericGroup counter code (small, count 0–4095).
 * Wire format: '-T' + 2 base64url chars for count = 4 chars total.
 * Example: '-TAE' = GenericGroup with count 4.
 */
const GENERIC_GROUP_CODE = '-T' as const;

/**
 * The cesr library's GenericGroup counter code (big, count 4096+).
 * Wire format: '--T' + 5 base64url chars for count = 8 chars total.
 */
const GENERIC_GROUP_BIG_CODE = '--T' as const;

// ---------------------------------------------------------------------------
// Internal → wire code translation
// ---------------------------------------------------------------------------

// Only two codes differ between our internal names and the cesr library wire codes.
const INTERNAL_TO_WIRE: Partial<Record<CesrCode, string>> = {
  [CESR_CODES.X25519_PUBLIC_KEY]: Matter.Code.X25519,   // 'X' → 'C'
  [CESR_CODES.SHA2_256_DIGEST]:   Matter.Code.SHA2_256, // 'E' → 'I'
};

// Reverse map: wire code → our internal code (only for the two that differ).
const WIRE_TO_INTERNAL: Record<string, CesrCode> = {
  [Matter.Code.X25519]:   CESR_CODES.X25519_PUBLIC_KEY,
  [Matter.Code.SHA2_256]: CESR_CODES.SHA2_256_DIGEST,
};

// ---------------------------------------------------------------------------
// Variable-length bytes helper
// ---------------------------------------------------------------------------

/**
 * Pick the correct cesr library variable-length bytes code for a given byte length.
 *
 * The cesr library uses three codes for variable-length bytes, chosen based on
 * the number of lead bytes needed to pad the payload to a multiple of 3:
 *   leadSize = (3 - (byteLength % 3)) % 3
 *   leadSize 0 → Bytes_L0 ('4B')  — byteLength divisible by 3
 *   leadSize 1 → Bytes_L1 ('5B')  — byteLength ≡ 2 mod 3
 *   leadSize 2 → Bytes_L2 ('6B')  — byteLength ≡ 1 mod 3
 *
 * For payloads > ~12285 bytes, the Big variants are used (7AAB/8AAB/9AAB).
 */
function pickVariableBytesCode(byteLength: number): string {
  const leadSize = (3 - (byteLength % 3)) % 3;
  // The L0/L1/L2 codes use a 2-char base64 length field (max 4095 groups = 12285 bytes).
  // For larger payloads, use the Big variants with a 4-char length field.
  const needsBig = (byteLength + leadSize) > 4095 * 3;
  if (leadSize === 0) return needsBig ? Matter.Code.Bytes_Big_L0 : Matter.Code.Bytes_L0;
  if (leadSize === 1) return needsBig ? Matter.Code.Bytes_Big_L1 : Matter.Code.Bytes_L1;
  return needsBig ? Matter.Code.Bytes_Big_L2 : Matter.Code.Bytes_L2;
}

// Set of all variable-length bytes wire codes (small and big variants).
const VARIABLE_BYTES_CODES = new Set([
  Matter.Code.Bytes_L0,     // '4B'
  Matter.Code.Bytes_L1,     // '5B'
  Matter.Code.Bytes_L2,     // '6B'
  Matter.Code.Bytes_Big_L0, // '7AAB'
  Matter.Code.Bytes_Big_L1, // '8AAB'
  Matter.Code.Bytes_Big_L2, // '9AAB'
]);

// ---------------------------------------------------------------------------
// Single primitive encode / decode
// ---------------------------------------------------------------------------

/**
 * Encode a raw byte array as a CESR primitive string.
 *
 * For fixed-length codes: validates exact byte length, returns code + base64url(bytes).
 * For VARIABLE_BYTES: selects the correct L0/L1/L2 code based on byte length.
 * For NONCE (24 bytes): encoded as variable-length (cesr lib's '0A' is 16-byte Salt_128).
 *
 * @param code  One of the CESR_CODES values
 * @param bytes Raw bytes
 * @throws RangeError if bytes.length does not match the expected length for fixed-length codes
 */
export function cesrEncode(code: CesrCode, bytes: Uint8Array): string {
  const expected = CESR_BYTE_LENGTHS[code];

  if (expected === -1 || code === CESR_CODES.NONCE) {
    // Variable-length (VARIABLE_BYTES) or NONCE (24 bytes, no fixed-length code in cesr lib):
    // use cesr library's native L0/L1/L2 encoding.
    if (expected !== -1 && bytes.length !== expected) {
      throw new RangeError(
        `cesrEncode: code "${code}" expects ${expected} bytes, got ${bytes.length}`,
      );
    }
    const libCode = pickVariableBytesCode(bytes.length);
    return Matter.from(libCode, bytes).text();
  }

  // Fixed-length: validate byte length, then encode via cesr library.
  if (bytes.length !== expected) {
    throw new RangeError(
      `cesrEncode: code "${code}" expects ${expected} bytes, got ${bytes.length}`,
    );
  }
  // Translate internal code to cesr library wire code if needed.
  const wireCode = INTERNAL_TO_WIRE[code] ?? code;
  return Matter.from(wireCode, bytes).text();
}

/**
 * Decode a CESR primitive string back to its code and raw bytes.
 *
 * Uses Matter.peek() to parse the frame and determine the code, then maps
 * wire codes back to our internal code names where they differ.
 *
 * @throws SyntaxError if the string does not start with a known code
 * @throws Error if the cesr library cannot parse the frame
 */
/**
 * Convert an ASCII CESR string to a Uint8Array for the cesr library.
 * The cesr library's Matter.peek() and Counter.peek() expect Uint8Array,
 * but we receive JavaScript strings. For short strings (< ~300 chars) the
 * type-only cast accidentally works because character codes align with byte
 * values. For long strings (1400+ chars), the cesr library's internal byte
 * offset math drifts from character positions, causing misparsing.
 */
function strToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function cesrDecode(text: string): { code: CesrCode; bytes: Uint8Array } {
  // Use Matter.peek to parse the frame — this handles all code types uniformly
  // without manual prefix-sniffing.
  const peekResult = Matter.peek(strToBytes(text));
  if (!peekResult.frame) {
    throw new SyntaxError(`cesrDecode: could not parse CESR frame from "${text.slice(0, 8)}..."`);
  }

  const wireCode = peekResult.frame.code;
  const bytes = new Uint8Array(peekResult.frame.raw);

  // Variable-length bytes codes → canonical VARIABLE_BYTES internal code.
  if (VARIABLE_BYTES_CODES.has(wireCode)) {
    return { code: CESR_CODES.VARIABLE_BYTES, bytes };
  }

  // Map wire code back to internal code (for the two that differ).
  const internalCode = WIRE_TO_INTERNAL[wireCode] as CesrCode | undefined;
  if (internalCode !== undefined) {
    return { code: internalCode, bytes };
  }

  // For all other codes, the wire code IS the internal code — validate it's known.
  if (!(wireCode in CESR_BYTE_LENGTHS)) {
    throw new SyntaxError(`cesrDecode: unknown code prefix in "${text.slice(0, 8)}..."`);
  }

  return { code: wireCode as CesrCode, bytes };
}

// ---------------------------------------------------------------------------
// Group framing
// ---------------------------------------------------------------------------

/**
 * Encode an ordered list of (code, bytes) pairs as a CESR group frame.
 *
 * Output format: -T<b64count><item1><item2>...<itemN>
 * Example: '-TAE' + items = GenericGroup with 4 items.
 */
export function cesrEncodeGroup(
  parts: Array<{ code: CesrCode; bytes: Uint8Array }>,
): string {
  const header = Counter.v1.GenericGroup(parts.length).text();
  const items = parts.map(({ code, bytes }) => cesrEncode(code, bytes));
  return header + items.join('');
}

/**
 * Decode a CESR group frame back to an ordered list of (code, bytes) pairs.
 *
 * Expects the cesr library's GenericGroup counter format: -T<b64count><items>
 *
 * @throws SyntaxError if the frame header is malformed or any item fails to decode
 */
export function cesrDecodeGroup(
  text: string,
): Array<{ code: CesrCode; bytes: Uint8Array }> {
  // All counter codes start with '-'; Matter codes never do.
  if (!text.startsWith('-')) {
    throw new SyntaxError(
      `cesrDecodeGroup: expected GenericGroup counter prefix "-T", got "${text.slice(0, 4)}"`,
    );
  }

  // Use Counter.peek to parse the counter header.
  let peekResult: ReturnType<typeof Counter.peek>;
  try {
    peekResult = Counter.peek(strToBytes(text));
  } catch (e) {
    throw new SyntaxError(
      `cesrDecodeGroup: invalid counter header: ${(e as Error).message}`,
    );
  }

  if (!peekResult.frame) {
    throw new SyntaxError(
      `cesrDecodeGroup: counter header too short in "${text.slice(0, 8)}"`,
    );
  }

  // Validate that this is a GenericGroup counter (code '-T' or '--T').
  const counterCode = peekResult.frame.code;
  if (counterCode !== GENERIC_GROUP_CODE && counterCode !== GENERIC_GROUP_BIG_CODE) {
    throw new SyntaxError(
      `cesrDecodeGroup: expected GenericGroup counter ("-T" or "--T"), got "${counterCode}"`,
    );
  }

  const count = peekResult.frame.count;
  let remaining = text.slice(peekResult.n);
  const results: Array<{ code: CesrCode; bytes: Uint8Array }> = [];

  for (let i = 0; i < count; i++) {
    if (remaining.length === 0) {
      throw new SyntaxError(
        `cesrDecodeGroup: expected ${count} items but ran out of input at item ${i}`,
      );
    }

    // Use Matter.peek to determine the size of the next item.
    const matterPeek = Matter.peek(strToBytes(remaining));
    if (!matterPeek.frame) {
      throw new SyntaxError(
        `cesrDecodeGroup: unknown code at item ${i}: "${remaining.slice(0, 8)}"`,
      );
    }

    const itemText = remaining.slice(0, matterPeek.n);
    results.push(cesrDecode(itemText));
    remaining = remaining.slice(matterPeek.n);
  }

  if (remaining.length > 0) {
    throw new SyntaxError(
      `cesrDecodeGroup: ${remaining.length} trailing characters after ${count} items`,
    );
  }

  return results;
}

// Re-export codes for convenience
export { CESR_CODES } from './codes.js';
export type { CesrCode } from './codes.js';
