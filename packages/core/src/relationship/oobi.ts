/**
 * OOBI (Out-of-Band Introduction) encoding/decoding — Step 4, Task 4.1.
 *
 * An OOBI is the artifact shared out-of-band (QR code, link, copy-paste) that
 * lets one endpoint learn another's VID and transport address before any TSP
 * message is sent.
 *
 * ## Wire format
 *
 * A CESR group frame with 3 items:
 *
 *   -TAC<vid><peerIdBytes><multiaddrsJsonBytes>
 *
 * Where:
 *   - `-TAC` = GenericGroup counter with 3 items
 *   - `vid`              = cesrEncode(ED25519_PUBLIC_KEY, senderEd25519PublicKey) [44 chars]
 *   - `peerIdBytes`      = cesrEncode(VARIABLE_BYTES, UTF-8(peerId))             [variable]
 *   - `multiaddrsJsonBytes` = cesrEncode(VARIABLE_BYTES, UTF-8(JSON.stringify(multiaddrs))) [variable]
 *
 * The OOBI is a CESR-encoded string (ASCII-safe, base64url), suitable for
 * embedding in a URL, QR code, or copy-paste.
 *
 * Reference: docs/implementation-plan-step4.md, Task 4.1
 */

import {
  cesrEncode,
  cesrDecode,
  cesrDecodeGroup,
  cesrEncodeGroup,
  CESR_CODES,
} from '../crypto/cesr.js';
import {
  mlDsa65Sign,
  mlDsa65Verify,
  encodeMlDsa65Signature,
  decodeMlDsa65Signature,
} from '../crypto/pqc.js';
import type { OobiPayload } from './types.js';

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/**
 * Encode an OOBI as a CESR group frame string.
 *
 * 4 items (unsigned, the established form), plus an OPTIONAL 5th
 * VARIABLE_BYTES item carrying an ML-DSA-65 signature over the first four
 * (see `signOobi`). The 4-item form stays valid so already-issued OOBIs and
 * unsigned introductions keep working.
 *
 * @param oobi  The OOBI payload to encode
 * @returns     CESR group frame string starting with "-TAC"
 */
export function encodeOobi(oobi: OobiPayload): string {
  const items = encodeOobiBodyItems(oobi);
  if (oobi.mlDsa65Signature) {
    // The signature lives in a VARIABLE_BYTES item as its `1AAQ` CESR text: that
    // keeps the frame a plain CESR group and avoids inventing a group-item code
    // for ML-DSA (whose signature primitive is a 1AAQ text primitive, not part of
    // the -T/-C/-K counter families CESR groups use).
    items.push({
      code: CESR_CODES.VARIABLE_BYTES,
      bytes: new TextEncoder().encode(encodeMlDsa65Signature(oobi.mlDsa65Signature)),
    });
  }
  return cesrEncodeGroup(items);
}

/**
 * The canonical bytes an ML-DSA-65 introduction signature covers: the OOBI's
 * 4-item group frame WITHOUT the signature item.
 *
 * `signOobi` and `verifyOobiSignature` both derive the signable input from this
 * one function, so they can never disagree about what was signed.
 */
export function oobiIntroductionBytes(oobi: OobiPayload): Uint8Array {
  return new TextEncoder().encode(cesrEncodeGroup(encodeOobiBodyItems(oobi)));
}

/**
 * Sign an OOBI as an out-of-band introduction using the identity's ML-DSA-65
 * root-of-trust key.
 *
 * @returns a copy of `oobi` carrying `mlDsa65Signature`
 */
export function signOobi(
  oobi: OobiPayload,
  mlDsa65SecretKey: Uint8Array,
): OobiPayload {
  const signature = mlDsa65Sign(oobiIntroductionBytes(oobi), mlDsa65SecretKey);
  return { ...oobi, mlDsa65Signature: signature };
}

/**
 * Verify an OOBI's ML-DSA-65 introduction signature.
 *
 * @returns `true` when the signature is valid; `false` when the OOBI carries no
 *          signature or the signature does not match (callers that REQUIRE a
 *          signed introduction should test that separately, so "unsigned" and
 *          "forged" stay distinguishable).
 */
export function verifyOobiSignature(oobi: OobiPayload, mlDsa65PublicKey: Uint8Array): boolean {
  if (!oobi.mlDsa65Signature) return false;
  return mlDsa65Verify(oobi.mlDsa65Signature, oobiIntroductionBytes(oobi), mlDsa65PublicKey);
}

/** The 4-item body (vid, peerId, multiaddrs, did) shared by encode/sign/verify. */
function encodeOobiBodyItems(oobi: OobiPayload) {
  // Decode the VID string back to raw bytes for encoding.
  // The VID is already a CESR-encoded ED25519_PUBLIC_KEY string (44 chars starting with 'D').
  // We need the raw 32-byte public key to re-encode it in the group frame.
  const vidItem = cesrDecode(oobi.cesrVid);
  if (vidItem.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
    throw new TypeError(
      `encodeOobi: vid must be a CESR-encoded ED25519_PUBLIC_KEY, got code "${vidItem.code}"`,
    );
  }

  const peerIdBytes = new TextEncoder().encode(oobi.peerId);
  const multiaddrsJsonBytes = new TextEncoder().encode(JSON.stringify(oobi.multiaddrs));
  // The sender's real DID is REQUIRED (strict 4-item OOBI — no 3-item legacy).
  const didBytes = new TextEncoder().encode(oobi.did);

  return [
    { code: CESR_CODES.ED25519_PUBLIC_KEY, bytes: vidItem.bytes },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: peerIdBytes },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: multiaddrsJsonBytes },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: didBytes },
  ];
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/**
 * Decode a CESR-encoded OOBI string back to an OobiPayload.
 *
 * @param encoded  CESR group frame string (as produced by encodeOobi)
 * @returns        Decoded OobiPayload
 * @throws SyntaxError if the string is malformed or has wrong structure
 */
export function decodeOobi(encoded: string): OobiPayload {
  const items = cesrDecodeGroup(encoded);

  // 4 items = the established (unsigned) introduction; 5 = the same plus an
  // ML-DSA-65 signature item. Anything else is not an OOBI.
  if (items.length !== 4 && items.length !== 5) {
    throw new SyntaxError(
      `decodeOobi: expected 4 items (or 5 with an ML-DSA-65 signature) in OOBI group frame, got ${items.length}`,
    );
  }

  const [vidItem, peerIdItem, multiaddrsItem, didItem, sigItem] = items;

  if (vidItem.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
    throw new SyntaxError(
      `decodeOobi: expected ED25519_PUBLIC_KEY for vid, got "${vidItem.code}"`,
    );
  }
  if (peerIdItem.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError(
      `decodeOobi: expected VARIABLE_BYTES for peerId, got "${peerIdItem.code}"`,
    );
  }
  if (multiaddrsItem.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError(
      `decodeOobi: expected VARIABLE_BYTES for multiaddrs, got "${multiaddrsItem.code}"`,
    );
  }

  // Re-encode the raw public key bytes back to a CESR VID string.
  const vid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, vidItem.bytes);

  const peerId = new TextDecoder().decode(peerIdItem.bytes);

  let multiaddrs: string[];
  try {
    multiaddrs = JSON.parse(new TextDecoder().decode(multiaddrsItem.bytes)) as string[];
  } catch (e) {
    throw new SyntaxError(
      `decodeOobi: failed to parse multiaddrs JSON: ${(e as Error).message}`,
    );
  }

  if (!Array.isArray(multiaddrs)) {
    throw new SyntaxError('decodeOobi: multiaddrs must be a JSON array');
  }

  // The 4th item carries the sender's real DID (required — no 3-item legacy).
  if (didItem.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError('decodeOobi: expected VARIABLE_BYTES for did');
  }
  const did = new TextDecoder().decode(didItem.bytes);
  if (!did) {
    throw new SyntaxError('decodeOobi: empty did item');
  }

  // Optional 5th item: the ML-DSA-65 introduction signature (`1AAQ` text).
  let mlDsa65Signature: Uint8Array | undefined;
  if (sigItem) {
    if (sigItem.code !== CESR_CODES.VARIABLE_BYTES) {
      throw new SyntaxError(
        `decodeOobi: expected VARIABLE_BYTES for the ML-DSA-65 signature item, got "${sigItem.code}"`,
      );
    }
    mlDsa65Signature = decodeMlDsa65Signature(new TextDecoder().decode(sigItem.bytes));
  }

  return { cesrVid: vid, peerId, multiaddrs, did, mlDsa65Signature };
}
