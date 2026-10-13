/**
 * Shared helpers for extracting Ed25519 / X25519 public keys from a DID
 * document. Used by both RelationshipStore (via FK join) and
 * RelationshipManager (during RFI/RFA processing).
 */

import type { DidDocument } from '../did/types.js';
import type { ServiceEndpoint } from '../did/types.js';
import { buildDidPeer4Document } from '../did/create.js';

/**
 * Extract the Ed25519 public key (32 bytes) from a DID document's
 * verificationMethod[0].publicKeyMultibase field.
 */
export function extractEd25519PublicKey(doc: DidDocument): Uint8Array {
  const vm = doc.verificationMethod?.[0];
  if (!vm?.publicKeyMultibase) {
    throw new Error('extractEd25519PublicKey: no verificationMethod[0].publicKeyMultibase in didDocument');
  }
  return decodeMultikeyPublicKey(vm.publicKeyMultibase, 0xed01, 32);
}

/**
 * Extract the X25519 public key (32 bytes) from a DID document's
 * verificationMethod[1]'s publicKeyMultibase field.
 */
export function extractX25519PublicKey(doc: DidDocument): Uint8Array {
  const vm = doc.verificationMethod?.[1];
  if (!vm?.publicKeyMultibase) {
    throw new Error('extractX25519PublicKey: no verificationMethod[1].publicKeyMultibase in didDocument');
  }
  return decodeMultikeyPublicKey(vm.publicKeyMultibase, 0xec01, 32);
}

/**
 * Extract the ML-DSA-65 public key (1952 bytes) from a DID document's
 * `#key-mldsa` verification method (Multikey, multicodec `0x1211`).
 *
 * Found by `id`, never by index — PQ entries are appended so that
 * verificationMethod[0]/[1] keep their Ed25519/X25519 meaning.
 *
 * @returns the key, or `undefined` when the document publishes no ML-DSA key
 *          (every peer created before PQ provisioning, and any third-party DID).
 */
export function extractMlDsa65PublicKey(doc: DidDocument): Uint8Array | undefined {
  const vm = doc.verificationMethod?.find((m) => m.id === '#key-mldsa');
  if (!vm?.publicKeyMultibase) return undefined;
  return decodeMultikeyPublicKey(vm.publicKeyMultibase, 0x9124, 1952);
}

/**
 * Extract the MLKEM768-X25519 hybrid KEM public key (1216 bytes) from a DID
 * document's `#key-kem` verification method.
 *
 * That entry is NOT a Multikey (no multicodec is registered for ML-KEM), so the
 * value is a multibase `u`-prefixed base64url string; the algorithm is named by
 * the method's `type`.
 *
 * @returns the key, or `undefined` when the document publishes no hybrid KEM key.
 */
export function extractHybridKemPublicKey(doc: DidDocument): Uint8Array | undefined {
  const vm = doc.verificationMethod?.find((m) => m.id === '#key-kem');
  if (!vm?.publicKeyMultibase) return undefined;
  if (vm.type !== 'MLKEM768X25519PublicKey') {
    throw new TypeError(
      `extractHybridKemPublicKey: #key-kem has type "${vm.type}", expected ` +
      `"MLKEM768X25519PublicKey" — refusing to guess the encoding`,
    );
  }
  const encoded = vm.publicKeyMultibase;
  if (!encoded.startsWith('u')) {
    throw new TypeError(
      `extractHybridKemPublicKey: expected a multibase 'u' (base64url) value, got '${encoded[0]}'`,
    );
  }
  const bytes = new Uint8Array(Buffer.from(encoded.slice(1), 'base64url'));
  if (bytes.length !== 1216) {
    throw new TypeError(
      `extractHybridKemPublicKey: expected 1216 bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

/**
 * Build a clean, minimal did:peer:4 document from any DID document.
 *
 * Extracts the Ed25519 + X25519 keys and optional transport service endpoint,
 * then calls buildDidPeer4Document() to produce a proper did:peer:4-shaped
 * document. This is used by the relationship handshake to store a consistent
 * peer4 record regardless of what DID method the remote peer uses.
 *
 * The resulting document has `id` and `controller` unset (empty) — consistent
 * with did:peer:4's self-certifying design where the DID is derived from the
 * document hash.
 */
export function buildCleanPeer4FromDocument(doc: DidDocument): DidDocument {
  const ed25519Key = extractEd25519PublicKey(doc);
  const x25519Key = extractX25519PublicKey(doc);
  const serviceEndpoint = doc.service?.[0]?.serviceEndpoint;
  const transport: ServiceEndpoint | undefined =
    serviceEndpoint && typeof serviceEndpoint === 'object' && 'peerId' in serviceEndpoint
      ? serviceEndpoint as ServiceEndpoint
      : undefined;
  // Carry the peer's PQ keys through the rebuild — without this the ML-DSA-65 and
  // hybrid KEM keys would be silently DROPPED from the stored peer4 record, making
  // every root-of-trust signature unverifiable after the first handshake.
  return buildDidPeer4Document(ed25519Key, x25519Key, transport, undefined, {
    mlDsa65PublicKey: extractMlDsa65PublicKey(doc),
    hybridKemPublicKey: extractHybridKemPublicKey(doc),
  });
}

/**
 * Extract a display name from a DID document's `alsoKnownAs` array, if
 * present. Names are registered as `vta:<namespace>:<name>` URIs (see
 * did/name-uri.ts); this returns just the `<name>` segment for display,
 * or undefined if no vta: name URI is present.
 *
 * Used when a remote peer's DID document arrives during the RFI/RFA
 * handshake — the peer's registered name travels inline in the exchanged
 * document even though the stored peer4 record itself (built via
 * buildCleanPeer4FromDocument) intentionally strips alsoKnownAs to stay a
 * minimal, self-certifying did:peer:4 shape.
 */
export function extractDisplayNameFromDocument(doc: DidDocument): string | undefined {
  const akaEntries = doc.alsoKnownAs ?? [];
  for (const uri of akaEntries) {
    const match = uri.match(/^vta:[a-zA-Z0-9][a-zA-Z0-9.-]*:([a-zA-Z0-9][a-zA-Z0-9_-]{0,63})$/);
    if (match) return match[1];
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function decodeMultikeyPublicKey(
  publicKeyMultibase: string,
  expectedPrefix: number,
  keyLength: number,
): Uint8Array {
  if (!publicKeyMultibase.startsWith('z')) {
    throw new Error(
      `decodeMultikeyPublicKey: expected 'z' (base58btc) prefix, got '${publicKeyMultibase[0]}'`,
    );
  }

  const base58Encoded = publicKeyMultibase.slice(1);
  const decoded = base58btcDecode(base58Encoded);

  const prefix = (decoded[0] << 8) | decoded[1];
  if (prefix !== expectedPrefix) {
    throw new Error(
      `decodeMultikeyPublicKey: expected multicodec prefix 0x${expectedPrefix.toString(16)}, got 0x${prefix.toString(16)}`,
    );
  }

  const rawKey = decoded.slice(2);
  if (rawKey.length !== keyLength) {
    throw new Error(
      `decodeMultikeyPublicKey: expected ${keyLength} bytes, got ${rawKey.length}`,
    );
  }

  return rawKey;
}

function base58btcDecode(encoded: string): Uint8Array {
  let value = BigInt(0);
  const base = BigInt(58);

  for (const char of encoded) {
    const digit = BASE58_ALPHABET.indexOf(char);
    if (digit === -1) {
      throw new Error(`base58btcDecode: invalid character '${char}'`);
    }
    value = value * base + BigInt(digit);
  }

  const bytes: number[] = [];
  while (value > BigInt(0)) {
    bytes.unshift(Number(value & BigInt(0xff)));
    value >>= BigInt(8);
  }

  let leadingZeros = 0;
  for (const char of encoded) {
    if (char === '1') leadingZeros++;
    else break;
  }

  return new Uint8Array([...new Array(leadingZeros).fill(0), ...bytes]);
}