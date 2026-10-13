/**
 * did:peer numalgo4 codec — Step 2.
 *
 * Implements the did:peer:4 encoding and decoding scheme:
 *   https://identity.foundation/peer-did-method-spec/#creating-a-did-peer-4
 *
 * Encoding:
 *   1. JSON-encode the DID document (without an `id` field).
 *   2. Prefix with the `json` multicodec varint (0x0200 → bytes 0x80 0x04).
 *   3. Multibase-encode (base58btc) → long-form suffix (starts with 'z').
 *   4. SHA-256 hash the long-form suffix string bytes, wrap as a multihash,
 *      multibase-encode (base58btc) → hash component.
 *   5. Assemble: did:peer:4{hashComponent}:{longFormSuffix}
 *
 * Decoding (resolution):
 *   1. Extract the long-form suffix after the second colon.
 *   2. Multibase-decode (base58btc).
 *   3. Strip and validate the json multicodec varint prefix.
 *   4. JSON-parse the remaining bytes → DidDocument.
 *
 * Verification:
 *   Recompute the hash component from the long-form suffix and compare to
 *   the hash embedded in the DID string.
 */

import { base58btc } from 'multiformats/bases/base58';
import { sha256 } from 'multiformats/hashes/sha2';
import type { DidDocument } from './types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** JSON multicodec code (0x0200), varint-encoded as two bytes: 0x80 0x04 */
const JSON_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x04]);

const DID_PEER_4_PREFIX = 'did:peer:4';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Decode a varint from the start of a Uint8Array. Returns [value, bytesConsumed]. */
function decodeVarint(bytes: Uint8Array): [number, number] {
  let value = 0;
  let shift = 0;
  let i = 0;
  while (i < bytes.length) {
    const byte = bytes[i++];
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
    if (shift >= 35) throw new RangeError('numalgo4: varint overflow');
  }
  return [value, i];
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/**
 * Encode a DID document into a did:peer:4 long-form DID string.
 *
 * The document must NOT contain an `id` field (the DID is derived from the
 * document, so including it would create a circular dependency).
 *
 * @returns { did, shortFormDid, longFormSuffix, hashComponent }
 */
export async function encodePeer4(document: DidDocument): Promise<{
  did: string;
  shortFormDid: string;
  longFormSuffix: string;
  hashComponent: string;
}> {
  // 1. JSON-encode the document (without id)
  const docWithoutId = { ...document };
  delete docWithoutId.id;
  const docBytes = new TextEncoder().encode(JSON.stringify(docWithoutId));

  // 2. Prefix with json multicodec varint (0x0200)
  const prefixed = new Uint8Array(JSON_MULTICODEC_PREFIX.length + docBytes.length);
  prefixed.set(JSON_MULTICODEC_PREFIX, 0);
  prefixed.set(docBytes, JSON_MULTICODEC_PREFIX.length);

  // 3. Multibase-encode (base58btc) → long-form suffix
  const longFormSuffix = base58btc.encode(prefixed);

  // 4. SHA-256 hash the long-form suffix string bytes, wrap as multihash,
  //    multibase-encode (base58btc) → hash component
  const longFormBytes = new TextEncoder().encode(longFormSuffix);
  const mh = await sha256.digest(longFormBytes);
  const hashComponent = base58btc.encode(mh.bytes);

  // 5. Assemble
  const did = `${DID_PEER_4_PREFIX}${hashComponent}:${longFormSuffix}`;
  const shortFormDid = `${DID_PEER_4_PREFIX}${hashComponent}`;

  return { did, shortFormDid, longFormSuffix, hashComponent };
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/**
 * Decode a did:peer:4 long-form DID string back to its embedded DID document.
 *
 * @throws if the DID string is not a valid long-form did:peer:4
 */
export function decodePeer4(did: string): { document: DidDocument; longFormSuffix: string; hashComponent: string } {
  if (!did.startsWith(DID_PEER_4_PREFIX)) {
    throw new SyntaxError(`decodePeer4: not a did:peer:4 DID: "${did.slice(0, 30)}"`);
  }

  const afterPrefix = did.slice(DID_PEER_4_PREFIX.length);
  const colonIdx = afterPrefix.indexOf(':');
  if (colonIdx === -1) {
    throw new SyntaxError('decodePeer4: missing long-form suffix (no second colon)');
  }

  const hashComponent = afterPrefix.slice(0, colonIdx);
  const longFormSuffix = afterPrefix.slice(colonIdx + 1);

  if (!longFormSuffix.startsWith('z')) {
    throw new SyntaxError('decodePeer4: long-form suffix must be base58btc (starts with "z")');
  }

  // Multibase-decode
  const prefixed = base58btc.decode(longFormSuffix);

  // Strip and validate the json multicodec varint prefix
  const [codec, consumed] = decodeVarint(prefixed);
  if (codec !== 0x0200) {
    throw new SyntaxError(`decodePeer4: expected json multicodec (0x0200), got 0x${codec.toString(16)}`);
  }

  // JSON-parse the remaining bytes
  const docBytes = prefixed.slice(consumed);
  const docJson = new TextDecoder().decode(docBytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(docJson);
  } catch (e) {
    throw new SyntaxError(`decodePeer4: failed to parse embedded DID document: ${(e as Error).message}`);
  }

  // F-007: `JSON.parse` succeeds for ANY valid JSON, not just an object, and the old
  // `as DidDocument` cast silenced the difference. The damage was downstream rather
  // than here: `resolveDidPeer4` returns `{ ...document, id: did }`, so
  //   - a string payload ("3") spread into `{ 0: '3', id: did }`;
  //   - a null payload spread into `{ id: did }` — a document with no keys at all;
  //   - an array spread into index properties;
  // each of those flowing onward as a successfully "resolved" DID document.
  //
  // An object is required. `{}` is legitimate (the encoder deliberately omits `id`),
  // so nothing beyond the container type is enforced here.
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new SyntaxError(
      'decodePeer4: the embedded DID document must be a JSON object ' +
      `(got ${describeJsonRoot(parsed)})`,
    );
  }

  return { document: parsed as DidDocument, longFormSuffix, hashComponent };
}

/** Name the JSON root shape, so the error says what was there instead of "invalid". */
function describeJsonRoot(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value; // 'string' | 'number' | 'boolean' | 'object'
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Verify a did:peer:4 DID string by recomputing the hash component from the
 * embedded long-form suffix and confirming it matches the hash in the DID.
 *
 * @returns true if the DID is self-consistent; false otherwise
 */
export async function verifyPeer4Hash(did: string): Promise<boolean> {
  try {
    const { longFormSuffix, hashComponent } = decodePeer4(did);

    // Recompute the hash component
    const longFormBytes = new TextEncoder().encode(longFormSuffix);
    const mh = await sha256.digest(longFormBytes);
    const recomputedHash = base58btc.encode(mh.bytes);

    return recomputedHash === hashComponent;
  } catch {
    return false;
  }
}
