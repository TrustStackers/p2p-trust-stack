/**
 * CESR 2.0 framing helpers for TSP v3 (Rev 3).
 *
 * Thin, purpose-built wrappers over the `cesr` npm library's v2 code tables
 * (`Counter.v2`, `Matter.Code`). The Rev 3 wire format is CESR 2.0
 * (genus AAA v2.00, `-_AAACAA`), which the library already implements.
 *
 * ## What lives here vs. elsewhere
 *   - This module: nonce (`0A` Salt_128), and the `-E##` (signable-data
 *     envelope) / `-Z##` (payload) counters.
 *   - `src/tsp/version.ts`: the `YTSP-###` version string (literal).
 *   - `src/tsp/fields.ts`: VID_String, digests, X-field-tag constants.
 *
 * ## Note on tag codes
 * The TSP version (`Y` Tag7 → `YTSP-AAC`) and payload-field tags (`X` Tag3 →
 * `XRFI`/`XRFA`/…) are carried as *literal* base64url-safe strings, not
 * base64-encoded bytes. The cesr lib's `Matter.from` over-encodes tag raw
 * bytes (it treats them as arbitrary data), but `Matter.peek` parses the
 * literal forms correctly. We therefore keep tags as string constants and use
 * the library only for the nonce and the counters.
 */

import { Matter, Counter } from 'cesr';

// ---------------------------------------------------------------------------
// Nonce — Salt_128 (16 bytes = 128-bit), code `0A`
// ---------------------------------------------------------------------------

/** The Rev 3 nonce byte length (128-bit). */
export const NONCE_BYTES = 16;

/**
 * Encode a 128-bit (16-byte) nonce as a CESR `0A` primitive
 * (`0A` + 22 base64url chars = 24 chars total).
 * @throws RangeError if bytes.length !== 16
 */
export function encodeNonce(bytes: Uint8Array): string {
  if (bytes.length !== NONCE_BYTES) {
    throw new RangeError(`encodeNonce: nonce must be ${NONCE_BYTES} bytes, got ${bytes.length}`);
  }
  return Matter.from(Matter.Code.Salt_128, bytes).text();
}

/**
 * Decode a CESR `0A` nonce primitive back to its 16 raw bytes.
 * @throws SyntaxError if the string is not a valid Salt_128 primitive
 */
export function decodeNonce(nonce: string): Uint8Array {
  const peek = Matter.peek(new TextEncoder().encode(nonce));
  if (!peek.frame || peek.frame.code !== Matter.Code.Salt_128) {
    throw new SyntaxError(`decodeNonce: expected Salt_128 ("0A") primitive, got ${JSON.stringify(nonce.slice(0, 8))}`);
  }
  const raw = peek.frame.raw;
  return new Uint8Array(raw);
}

// ---------------------------------------------------------------------------
// Counters — signable-data envelope (`-E##`) and payload (`-Z##`)
// ---------------------------------------------------------------------------

/**
 * Encode the TSP envelope tag (`TSP_Tag`): a CESR 2.0 signable-data counter.
 * The count is the number of *quadlets* (4 base64url chars) of the signable
 * portion that follows (version + VIDs + payload — everything before the
 * signature). Emits `-E##` for counts < 4096 and `--E#####` above.
 */
export function encodeEnvelopeTag(quadletCount: number): string {
  return Counter.v2.ESSRWrapperGroup(quadletCount).text();
}

/**
 * Encode the TSP payload tag (`TSP_Payload_Tag`): a CESR 2.0 payload counter.
 * The count is the number of quadlets of the payload fields that follow.
 * Emits `-Z##` for counts < 4096 and `--Z#####` above.
 */
export function encodePayloadTag(quadletCount: number): string {
  return Counter.v2.ESSRPayloadGroup(quadletCount).text();
}

/** A decoded CESR counter (code + count). */
export interface CounterInfo {
  /** The resolved counter code, e.g. `-E`, `--E`, `-Z`, `--Z`. */
  code: string;
  /** The count (quadlets) encoded in the counter. */
  count: number;
}

/**
 * Decode a CESR counter header.
 * @throws SyntaxError if the string is not a valid counter
 */
export function decodeCounter(text: string): CounterInfo {
  const peek = Counter.peek(new TextEncoder().encode(text));
  if (!peek.frame) {
    throw new SyntaxError(`decodeCounter: could not parse counter from ${JSON.stringify(text.slice(0, 8))}`);
  }
  return { code: peek.frame.code, count: peek.frame.count };
}

// ---------------------------------------------------------------------------
// HPKE-Base ciphertext — variable-length `4F/5F/6F` (+ big variants)
// ---------------------------------------------------------------------------

const HPKE_BASE_CIPHER_CODES = new Set([
  Matter.Code.HPKEBase_Cipher_L0, // '4F'
  Matter.Code.HPKEBase_Cipher_L1, // '5F'
  Matter.Code.HPKEBase_Cipher_L2, // '6F'
  Matter.Code.HPKEBase_Cipher_Big_L0, // '7AAF'
  Matter.Code.HPKEBase_Cipher_Big_L1, // '8AAF'
  Matter.Code.HPKEBase_Cipher_Big_L2, // '9AAF'
]);

function pickHpkeBaseCipherCode(byteLength: number): string {
  const leadSize = (3 - (byteLength % 3)) % 3;
  const needsBig = (byteLength + leadSize) > 4095 * 3;
  if (leadSize === 0) return needsBig ? Matter.Code.HPKEBase_Cipher_Big_L0 : Matter.Code.HPKEBase_Cipher_L0;
  if (leadSize === 1) return needsBig ? Matter.Code.HPKEBase_Cipher_Big_L1 : Matter.Code.HPKEBase_Cipher_L1;
  return needsBig ? Matter.Code.HPKEBase_Cipher_Big_L2 : Matter.Code.HPKEBase_Cipher_L2;
}

/**
 * Encode an HPKE-Base ciphertext (`enc || ct`) as a `4F/5F/6F` primitive
 * (lead pad chosen by byte length).
 */
export function encodeHpkeBaseCipher(bytes: Uint8Array): string {
  return Matter.from(pickHpkeBaseCipherCode(bytes.length), bytes).text();
}

/**
 * Decode an HPKE-Base ciphertext primitive back to its raw bytes.
 * @throws SyntaxError if the string is not an HPKE-Base cipher primitive
 */
export function decodeHpkeBaseCipher(cipher: string): Uint8Array {
  const peek = Matter.peek(new TextEncoder().encode(cipher));
  if (!peek.frame || !HPKE_BASE_CIPHER_CODES.has(peek.frame.code)) {
    throw new SyntaxError(
      `decodeHpkeBaseCipher: expected HPKE-Base cipher (4F/5F/6F), got ${JSON.stringify(cipher.slice(0, 8))}`,
    );
  }
  return new Uint8Array(peek.frame.raw);
}
