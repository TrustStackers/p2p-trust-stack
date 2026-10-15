// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Rotation log codec — digest computation + CESR encode/decode — Step 11, §2.2.
 *
 * Mirrors src/vtc/codec.ts's approach: JSON-encode structured/variable fields
 * (didDocument, witnessAttestations) as VARIABLE_BYTES CESR blobs; fixed
 * fields (version, hashes, signature) get existing CESR codes reused from
 * src/crypto/codes.ts.
 *
 * Reference: docs/implementation-plan-step11.md §2.2.
 */

import {
  cesrEncodeGroup,
  cesrDecodeGroup,
  CESR_CODES,
} from '../crypto/cesr.js';
import { sha256 } from '../crypto/primitives.js';
import { encodeVrc, decodeVrc, asCesrVrc } from '../vtc/codec.js';
import type { DidDocument } from './types.js';
import type { Vrc } from '../vtc/types.js';
import type { RotationLogEntry } from './rotation-types.js';

// ---------------------------------------------------------------------------
// Digest computation
// ---------------------------------------------------------------------------

/**
 * Compute the self-addressing digest for a rotation log entry's canonical
 * fields (everything except `digest` and `signature`).
 *
 * The canonical encoding is a stable JSON string over the fields in a fixed
 * key order, so the digest is deterministic regardless of object key
 * insertion order. `witnessAttestations` are excluded from the digest input
 * (they are collected/attached after the entry's core fields are fixed and
 * signed — attaching more attestations later must not change the entry's
 * identity/digest).
 */
export function computeRotationEntryDigest(
  entry: Pick<RotationLogEntry, 'version' | 'parameters' | 'didDocument' | 'prevHash' | 'nextKeyCommitments' | 'createdAt'>,
): Uint8Array {
  const canonical = JSON.stringify({
    version: entry.version,
    parameters: entry.parameters ?? null,
    didDocument: entry.didDocument,
    prevHash: entry.prevHash ? Buffer.from(entry.prevHash).toString('base64') : null,
    nextKeyCommitments: entry.nextKeyCommitments.map(k => Buffer.from(k).toString('base64')),
    createdAt: entry.createdAt,
  });
  return sha256(new TextEncoder().encode(canonical));
}

// ---------------------------------------------------------------------------
// Next-key commitment helper
// ---------------------------------------------------------------------------

/** Compute hash commitments to a set of to-be-used-next signing public keys. */
export function computeNextKeyCommitments(nextPublicKeys: Uint8Array[]): Uint8Array[] {
  return nextPublicKeys.map(k => sha256(k));
}

/** Compute a single hash commitment (backward-compat helper). */
export function computeNextKeyCommitment(nextPublicKey: Uint8Array): Uint8Array {
  return sha256(nextPublicKey);
}

// ---------------------------------------------------------------------------
// Full CESR group frame encode/decode — RotationLogEntry
// ---------------------------------------------------------------------------

/**
 * Encode a RotationLogEntry as a full CESR group frame.
 *
 * Frame layout (6 items):
 *   [digest, signature, prevHashBlob (JSON: prevHash base64 or null),
 *    nextKeyCommitment, metaBlob (JSON: version/didDocument/createdAt),
 *    witnessAttestationsBlob (JSON array of base64-encoded encodeVrc() frames)]
 */
export function encodeRotationLogEntry(entry: RotationLogEntry): Uint8Array {
  const prevHashBlob = JSON.stringify({
    prevHash: entry.prevHash ? Buffer.from(entry.prevHash).toString('base64') : null,
  });
  const nextKeyCommitmentsBlob = JSON.stringify({
    nextKeyCommitments: entry.nextKeyCommitments.map(k => Buffer.from(k).toString('base64')),
  });
  const meta = JSON.stringify({
    version: entry.version,
    parameters: entry.parameters ?? null,
    didDocument: entry.didDocument,
    createdAt: entry.createdAt,
  });
  const witnessAttestationsBlob = JSON.stringify(
    entry.witnessAttestations.map(vrc =>
      // Witness-attestation VRCs are encoded with the VTC/VRC binary codec, whose
      // VID fields are CESR-encoded Ed25519 keys — not DIDs. `asCesrVrc` names
      // the offending field if an attestation was built with a DID/UUID, instead
      // of failing with a bare "expected ED25519_PUBLIC_KEY" from inside cesrDecode.
      Buffer.from(encodeVrc(asCesrVrc(vrc))).toString('base64'),
    ),
  );

  const frame = cesrEncodeGroup([
    { code: CESR_CODES.SHA2_256_DIGEST, bytes: entry.digest },
    { code: CESR_CODES.ED25519_SIGNATURE, bytes: entry.signature },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode(prevHashBlob) },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode(nextKeyCommitmentsBlob) },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode(meta) },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode(witnessAttestationsBlob) },
  ]);
  return new TextEncoder().encode(frame);
}

/** Inverse of encodeRotationLogEntry. */
export function decodeRotationLogEntry(bytes: Uint8Array): RotationLogEntry {
  const text = new TextDecoder().decode(bytes);
  const items = cesrDecodeGroup(text);
  if (items.length !== 6) {
    throw new SyntaxError(`decodeRotationLogEntry: expected 6 items, got ${items.length}`);
  }
  const [digestItem, signatureItem, prevHashItem, nextKeyCommitmentsItem, metaItem, witnessAttestationsItem] = items;

  if (digestItem.code !== CESR_CODES.SHA2_256_DIGEST) {
    throw new SyntaxError(`decodeRotationLogEntry: expected SHA2_256_DIGEST for digest, got code "${digestItem.code}"`);
  }
  if (signatureItem.code !== CESR_CODES.ED25519_SIGNATURE) {
    throw new SyntaxError(`decodeRotationLogEntry: expected ED25519_SIGNATURE for signature, got code "${signatureItem.code}"`);
  }
  if (prevHashItem.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError(`decodeRotationLogEntry: expected VARIABLE_BYTES for prevHash, got code "${prevHashItem.code}"`);
  }
  if (nextKeyCommitmentsItem.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError(`decodeRotationLogEntry: expected VARIABLE_BYTES for nextKeyCommitments, got code "${nextKeyCommitmentsItem.code}"`);
  }
  if (metaItem.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError(`decodeRotationLogEntry: expected VARIABLE_BYTES for meta, got code "${metaItem.code}"`);
  }
  if (witnessAttestationsItem.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError(`decodeRotationLogEntry: expected VARIABLE_BYTES for witnessAttestations, got code "${witnessAttestationsItem.code}"`);
  }

  const prevHashParsed = JSON.parse(new TextDecoder().decode(prevHashItem.bytes)) as { prevHash: string | null };
  const nextKeyCommitmentsParsed = JSON.parse(
    new TextDecoder().decode(nextKeyCommitmentsItem.bytes),
  ) as { nextKeyCommitments: string[] };
  const meta = JSON.parse(new TextDecoder().decode(metaItem.bytes)) as {
    version: number;
    parameters?: import('./types.js').DidParameters | null;
    didDocument: DidDocument;
    createdAt: number;
  };
  const witnessAttestationsEncoded = JSON.parse(
    new TextDecoder().decode(witnessAttestationsItem.bytes),
  ) as string[];
  const witnessAttestations: Vrc[] = witnessAttestationsEncoded.map(b64 =>
    decodeVrc(new Uint8Array(Buffer.from(b64, 'base64'))),
  );

  return {
    version: meta.version,
    parameters: meta.parameters ?? undefined,
    didDocument: meta.didDocument,
    prevHash: prevHashParsed.prevHash ? new Uint8Array(Buffer.from(prevHashParsed.prevHash, 'base64')) : null,
    nextKeyCommitments: nextKeyCommitmentsParsed.nextKeyCommitments.map(b64 => new Uint8Array(Buffer.from(b64, 'base64'))),
    createdAt: meta.createdAt,
    digest: digestItem.bytes,
    signature: signatureItem.bytes,
    witnessAttestations,
  };
}
