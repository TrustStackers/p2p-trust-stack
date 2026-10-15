// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * VTC/VRC CESR encoding + digest computation — Step 10, §3.
 *
 * Following the existing pattern in src/tsp/v3/message.ts / src/crypto/cesr.ts,
 * both VtcGovernanceDoc and Vrc are encoded as CESR group frames. Structured
 * fields without a natural fixed-length CESR code (name/threshold/claim types,
 * claim payloads) are JSON-encoded and wrapped as a single VARIABLE_BYTES
 * item, mirroring how `didDocument` is carried in TspRfiPayload/TspRfaPayload.
 *
 * The canonical "signed bytes" for governance-doc founding signatures and for
 * Vrc admin signatures are the digest bytes themselves (32-byte SHA2-256) —
 * each admin signs the digest, not the full re-encoded document. This mirrors
 * how TSP_RFI/RFA already use a self-addressing digest.
 *
 * Reference: docs/implementation-plan-step10.md §3.
 */

import {
  cesrEncode,
  cesrDecode,
  cesrEncodeGroup,
  cesrDecodeGroup,
  CESR_CODES,
} from '../crypto/cesr.js';
import { sha256 } from '../crypto/primitives.js';
import type { CesrVid } from '../tsp/v3/types.js';
import type {
  Vrc,
  VtcGovernanceDoc,
  CesrVrc,
  CesrVrcSignature,
  CesrVtcGovernanceDoc,
} from './types.js';

// ---------------------------------------------------------------------------
// CESR VID validation + branding
// ---------------------------------------------------------------------------

/** Whether `value` is a CESR-encoded Ed25519 public key (the codec's VID form). */
export function isCesrVid(value: unknown): value is CesrVid {
  if (typeof value !== 'string' || value.length === 0) return false;
  try {
    return cesrDecode(value).code === CESR_CODES.ED25519_PUBLIC_KEY;
  } catch {
    return false;
  }
}

/**
 * Assert that `value` is a CESR-encoded Ed25519 public key and brand it.
 *
 * `field` (and `owner`) name the offending position in the thrown message —
 * this is the whole point of the conversion: a DID or a UUID reaching the codec
 * used to surface as a bare `expected ED25519_PUBLIC_KEY` from deep inside
 * `cesrDecode`, with no indication of *which* field was wrong.
 *
 * @throws TypeError when `value` is not a CESR Ed25519 public key string
 */
export function asCesrVid(value: unknown, field?: string, owner?: string): CesrVid {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(
      `${owner ?? 'asCesrVid'}: ${field ?? 'vid'} must be a CESR-encoded Ed25519 public key string ` +
      `(got ${value === null ? 'null' : typeof value})`,
    );
  }
  let code: string;
  try {
    code = cesrDecode(value).code;
  } catch (err) {
    throw new TypeError(
      `${owner ?? 'asCesrVid'}: ${field ?? 'vid'} is not CESR-encodable ` +
      `(${(err as Error)?.message ?? String(err)}) — it looks like ` +
      `${describeVidLike(value)}; the VTC/VRC binary codec stores VIDs as CESR Ed25519 keys`,
    );
  }
  if (code !== CESR_CODES.ED25519_PUBLIC_KEY) {
    throw new TypeError(
      `${owner ?? 'asCesrVid'}: ${field ?? 'vid'} has CESR code "${code}", expected ` +
      `ED25519_PUBLIC_KEY — it looks like ${describeVidLike(value)}`,
    );
  }
  return value as CesrVid;
}

/** Human-readable diagnosis for a value that is not a CESR key string. */
function describeVidLike(value: string): string {
  if (value.startsWith('did:')) return `a DID ("${value.slice(0, 24)}…")`;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
    return `a UUID (identity key), not a VID`;
  }
  if (value.startsWith('D')) return `a malformed CESR key primitive`;
  return `neither a DID nor a CESR key primitive ("${value.slice(0, 24)}…")`;
}

/**
 * Validate a general `Vrc` for encoding: every VID field must be CESR-encoded.
 * @throws TypeError naming the offending field
 */
export function asCesrVrc(vrc: Vrc): CesrVrc {
  asCesrVid(vrc.subjectVid, 'subjectVid', 'asCesrVrc');
  asCesrVid(vrc.issuerVid, 'issuerVid', 'asCesrVrc');
  for (const [i, sig] of vrc.signatures.entries()) {
    asCesrVid(sig.signerVid, `signatures[${i}].signerVid`, 'asCesrVrc');
  }
  return vrc as CesrVrc;
}

/**
 * Validate a general `VtcGovernanceDoc` for encoding.
 * @throws TypeError naming the offending field
 */
export function asEncodedGovernanceDoc(doc: VtcGovernanceDoc): CesrVtcGovernanceDoc {
  asCesrVid(doc.vtcVid, 'vtcVid', 'asEncodedGovernanceDoc');
  for (const [i, vid] of doc.adminVids.entries()) {
    asCesrVid(vid, `adminVids[${i}]`, 'asEncodedGovernanceDoc');
  }
  for (const [i, sig] of doc.signatures.entries()) {
    asCesrVid(sig.signerVid, `signatures[${i}].signerVid`, 'asEncodedGovernanceDoc');
  }
  return doc as CesrVtcGovernanceDoc;
}

// ---------------------------------------------------------------------------
// VID list
// ---------------------------------------------------------------------------

/** CESR group of ED25519_PUBLIC_KEY items. */
export function encodeVidList(vids: CesrVid[]): string {
  return cesrEncodeGroup(
    vids.map((vid, i) => {
      // Name the field BEFORE decoding: a brand-bypassing caller that passes a
      // DID/UUID should get the same legible message as one that came through
      // `asEncodedGovernanceDoc`, not a bare `cesrDecode` parse error.
      asCesrVid(vid, `vids[${i}]`, 'encodeVidList');
      const decoded = cesrDecode(vid);
      if (decoded.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
        throw new TypeError(
          `encodeVidList: vids[${i}] expected ED25519_PUBLIC_KEY, got code "${decoded.code}"`,
        );
      }
      return { code: CESR_CODES.ED25519_PUBLIC_KEY, bytes: decoded.bytes };
    }),
  );
}

/** Inverse of encodeVidList. */
export function decodeVidList(text: string): CesrVid[] {
  const items = cesrDecodeGroup(text);
  return items.map(item => {
    if (item.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
      throw new SyntaxError(`decodeVidList: expected ED25519_PUBLIC_KEY, got code "${item.code}"`);
    }
    return cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, item.bytes) as CesrVid;
  });
}

// ---------------------------------------------------------------------------
// Signature list
// ---------------------------------------------------------------------------

/** CESR group of alternating (ED25519_PUBLIC_KEY signerVid, ED25519_SIGNATURE signature) pairs. */
export function encodeSignatureList(sigs: CesrVrcSignature[]): string {
  const parts: Array<{ code: typeof CESR_CODES.ED25519_PUBLIC_KEY | typeof CESR_CODES.ED25519_SIGNATURE; bytes: Uint8Array }> = [];
  for (const [i, sig] of sigs.entries()) {
    asCesrVid(sig.signerVid, `signatures[${i}].signerVid`, 'encodeSignatureList');
    const decodedVid = cesrDecode(sig.signerVid);
    if (decodedVid.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
      throw new TypeError(
        `encodeSignatureList: signatures[${i}].signerVid expected ED25519_PUBLIC_KEY, got code "${decodedVid.code}"`,
      );
    }
    parts.push({ code: CESR_CODES.ED25519_PUBLIC_KEY, bytes: decodedVid.bytes });
    parts.push({ code: CESR_CODES.ED25519_SIGNATURE, bytes: sig.signature });
  }
  return cesrEncodeGroup(parts);
}

/** Inverse of encodeSignatureList. */
export function decodeSignatureList(text: string): CesrVrcSignature[] {
  const items = cesrDecodeGroup(text);
  if (items.length % 2 !== 0) {
    throw new SyntaxError(`decodeSignatureList: expected an even number of items, got ${items.length}`);
  }
  const sigs: CesrVrcSignature[] = [];
  for (let i = 0; i < items.length; i += 2) {
    const vidItem = items[i];
    const sigItem = items[i + 1];
    if (vidItem.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
      throw new SyntaxError(`decodeSignatureList: expected ED25519_PUBLIC_KEY at index ${i}, got code "${vidItem.code}"`);
    }
    if (sigItem.code !== CESR_CODES.ED25519_SIGNATURE) {
      throw new SyntaxError(`decodeSignatureList: expected ED25519_SIGNATURE at index ${i + 1}, got code "${sigItem.code}"`);
    }
    sigs.push({
      signerVid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, vidItem.bytes) as CesrVid,
      signature: sigItem.bytes,
    });
  }
  return sigs;
}

// ---------------------------------------------------------------------------
// Digest computation
// ---------------------------------------------------------------------------

/**
 * Compute the self-addressing digest for a governance doc's canonical fields
 * (everything except `digest` and `signatures`).
 *
 * The canonical encoding is a stable JSON string over the fields in a fixed
 * key order, so the digest is deterministic regardless of object key
 * insertion order.
 */
export function computeGovernanceDocDigest(
  doc: Omit<VtcGovernanceDoc, 'digest' | 'signatures'>,
): Uint8Array {
  const canonical = JSON.stringify({
    vtcVid: doc.vtcVid,
    vtcDid: doc.vtcDid,
    name: doc.name,
    adminVids: doc.adminVids,
    threshold: doc.threshold,
    allowedClaimTypes: doc.allowedClaimTypes,
    createdAt: doc.createdAt,
  });
  return sha256(new TextEncoder().encode(canonical));
}

/**
 * Compute the self-addressing digest for a Vrc's canonical fields (everything
 * except `digest` and `signatures`).
 */
export function computeVrcDigest(vrc: Omit<Vrc, 'digest' | 'signatures'>): Uint8Array {
  const canonical = JSON.stringify({
    subjectVid: vrc.subjectVid,
    issuerVid: vrc.issuerVid,
    claim: vrc.claim,
    issuedAt: vrc.issuedAt,
    expiresAt: vrc.expiresAt ?? null,
  });
  return sha256(new TextEncoder().encode(canonical));
}

// ---------------------------------------------------------------------------
// Full CESR group frame encode/decode — VtcGovernanceDoc
// ---------------------------------------------------------------------------

/**
 * Encode a VtcGovernanceDoc as a full CESR group frame.
 *
 * Frame layout (5 items):
 *   [digest, adminVidsGroup, metaBlob (JSON: name/threshold/allowedClaimTypes/createdAt/vtcDid), signaturesGroup, vtcVid]
 */
export function encodeGovernanceDoc(doc: CesrVtcGovernanceDoc): Uint8Array {
  const adminVidsGroup = encodeVidList(doc.adminVids);
  const signaturesGroup = encodeSignatureList(doc.signatures);
  const meta = JSON.stringify({
    name: doc.name,
    threshold: doc.threshold,
    allowedClaimTypes: doc.allowedClaimTypes,
    createdAt: doc.createdAt,
    vtcDid: doc.vtcDid,
  });

  asCesrVid(doc.vtcVid, 'vtcVid', 'encodeGovernanceDoc');
  const vidDecoded = cesrDecode(doc.vtcVid);
  if (vidDecoded.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
    throw new TypeError(`encodeGovernanceDoc: expected ED25519_PUBLIC_KEY for vtcVid, got code "${vidDecoded.code}"`);
  }

  const frame = cesrEncodeGroup([
    { code: CESR_CODES.SHA2_256_DIGEST, bytes: doc.digest },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode(adminVidsGroup) },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode(meta) },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode(signaturesGroup) },
    { code: CESR_CODES.ED25519_PUBLIC_KEY, bytes: vidDecoded.bytes },
  ]);
  return new TextEncoder().encode(frame);
}

/** Inverse of encodeGovernanceDoc. */
export function decodeGovernanceDoc(bytes: Uint8Array): CesrVtcGovernanceDoc {
  const text = new TextDecoder().decode(bytes);
  const items = cesrDecodeGroup(text);
  if (items.length !== 5) {
    throw new SyntaxError(`decodeGovernanceDoc: expected 5 items, got ${items.length}`);
  }
  const [digestItem, adminVidsItem, metaItem, signaturesItem, vtcVidItem] = items;

  if (digestItem.code !== CESR_CODES.SHA2_256_DIGEST) {
    throw new SyntaxError(`decodeGovernanceDoc: expected SHA2_256_DIGEST for digest, got code "${digestItem.code}"`);
  }
  if (adminVidsItem.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError(`decodeGovernanceDoc: expected VARIABLE_BYTES for adminVids, got code "${adminVidsItem.code}"`);
  }
  if (metaItem.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError(`decodeGovernanceDoc: expected VARIABLE_BYTES for meta, got code "${metaItem.code}"`);
  }
  if (signaturesItem.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError(`decodeGovernanceDoc: expected VARIABLE_BYTES for signatures, got code "${signaturesItem.code}"`);
  }
  if (vtcVidItem.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
    throw new SyntaxError(`decodeGovernanceDoc: expected ED25519_PUBLIC_KEY for vtcVid, got code "${vtcVidItem.code}"`);
  }

  const adminVids = decodeVidList(new TextDecoder().decode(adminVidsItem.bytes));
  const meta = JSON.parse(new TextDecoder().decode(metaItem.bytes)) as {
    name: string;
    threshold: number;
    allowedClaimTypes: string[];
    createdAt: number;
    vtcDid: string;
  };
  const signatures = decodeSignatureList(new TextDecoder().decode(signaturesItem.bytes));
  const vtcVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, vtcVidItem.bytes) as CesrVid;

  return {
    vtcVid,
    vtcDid: meta.vtcDid,
    name: meta.name,
    adminVids,
    threshold: meta.threshold,
    allowedClaimTypes: meta.allowedClaimTypes,
    createdAt: meta.createdAt,
    digest: digestItem.bytes,
    signatures,
  };
}

// ---------------------------------------------------------------------------
// Full CESR group frame encode/decode — Vrc
// ---------------------------------------------------------------------------

/**
 * Encode a Vrc as a full CESR group frame.
 *
 * Frame layout (5 items):
 *   [digest, subjectVid, issuerVid, metaBlob (JSON: claim/issuedAt/expiresAt), signaturesGroup]
 */
export function encodeVrc(vrc: CesrVrc): Uint8Array {
  // Pre-validate so a caller that bypassed the type brand (`as CesrVrc`) still
  // gets a field-named TypeError rather than a bare `cesrDecode` parse error.
  asCesrVid(vrc.subjectVid, 'subjectVid', 'encodeVrc');
  asCesrVid(vrc.issuerVid, 'issuerVid', 'encodeVrc');
  const subjectDecoded = cesrDecode(vrc.subjectVid);
  if (subjectDecoded.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
    throw new TypeError(`encodeVrc: expected ED25519_PUBLIC_KEY for subjectVid, got code "${subjectDecoded.code}"`);
  }
  const issuerDecoded = cesrDecode(vrc.issuerVid);
  if (issuerDecoded.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
    throw new TypeError(`encodeVrc: expected ED25519_PUBLIC_KEY for issuerVid, got code "${issuerDecoded.code}"`);
  }

  const meta = JSON.stringify({
    claim: vrc.claim,
    issuedAt: vrc.issuedAt,
    expiresAt: vrc.expiresAt ?? null,
  });
  const signaturesGroup = encodeSignatureList(vrc.signatures);

  const frame = cesrEncodeGroup([
    { code: CESR_CODES.SHA2_256_DIGEST, bytes: vrc.digest },
    { code: CESR_CODES.ED25519_PUBLIC_KEY, bytes: subjectDecoded.bytes },
    { code: CESR_CODES.ED25519_PUBLIC_KEY, bytes: issuerDecoded.bytes },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode(meta) },
    { code: CESR_CODES.VARIABLE_BYTES, bytes: new TextEncoder().encode(signaturesGroup) },
  ]);
  return new TextEncoder().encode(frame);
}

/** Inverse of encodeVrc. */
export function decodeVrc(bytes: Uint8Array): CesrVrc {
  const text = new TextDecoder().decode(bytes);
  const items = cesrDecodeGroup(text);
  if (items.length !== 5) {
    throw new SyntaxError(`decodeVrc: expected 5 items, got ${items.length}`);
  }
  const [digestItem, subjectItem, issuerItem, metaItem, signaturesItem] = items;

  if (digestItem.code !== CESR_CODES.SHA2_256_DIGEST) {
    throw new SyntaxError(`decodeVrc: expected SHA2_256_DIGEST for digest, got code "${digestItem.code}"`);
  }
  if (subjectItem.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
    throw new SyntaxError(`decodeVrc: expected ED25519_PUBLIC_KEY for subjectVid, got code "${subjectItem.code}"`);
  }
  if (issuerItem.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
    throw new SyntaxError(`decodeVrc: expected ED25519_PUBLIC_KEY for issuerVid, got code "${issuerItem.code}"`);
  }
  if (metaItem.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError(`decodeVrc: expected VARIABLE_BYTES for meta, got code "${metaItem.code}"`);
  }
  if (signaturesItem.code !== CESR_CODES.VARIABLE_BYTES) {
    throw new SyntaxError(`decodeVrc: expected VARIABLE_BYTES for signatures, got code "${signaturesItem.code}"`);
  }

  const subjectVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, subjectItem.bytes) as CesrVid;
  const issuerVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, issuerItem.bytes) as CesrVid;
  const meta = JSON.parse(new TextDecoder().decode(metaItem.bytes)) as {
    claim: Record<string, unknown> & { type: string };
    issuedAt: number;
    expiresAt: number | null;
  };
  const signatures = decodeSignatureList(new TextDecoder().decode(signaturesItem.bytes));

  return {
    subjectVid,
    issuerVid,
    claim: meta.claim,
    issuedAt: meta.issuedAt,
    expiresAt: meta.expiresAt ?? undefined,
    digest: digestItem.bytes,
    signatures,
  };
}
