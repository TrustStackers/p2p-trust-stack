// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * rotation-entry-codec — pack/unpack the `rotation_log.signed_entry` blob and
 * (de)serialize a `RotationLogEntry` for the wire.
 *
 * ## Why this exists
 *
 * A `did:scid:vh` DID is a bare SCID hash, so resolving it means replaying the
 * append-only rotation log. Every writer in this repo stores that log as a
 * single packed BLOB in `rotation_log.signed_entry` (see
 * `src/did/rotation-log-store.ts` and
 * `utility-server/src/db/yugabyte-rotation-log-store.ts`). The public resolver
 * needs to READ that blob back into a `RotationLogEntry` so
 * `ScidVhMethod.resolveFromLog()` can validate the chain — and it needs to
 * WRITE the entry out as JSON for the `/…/did.jsonl` endpoint.
 *
 * This module is the single ML-DSA-aware reader/writer for both directions.
 * (The two existing stores each keep a private copy of the pack/unpack pair;
 * consolidating them onto this module is a follow-up, deliberately not done
 * here so this change cannot disturb the agent's own rotation path.)
 *
 * ## Blob layout (all lengths big-endian)
 *
 *   [4-byte docLen][docJson UTF-8]
 *   [4-byte paramsLen][paramsJson UTF-8]
 *   [32-byte digest][64-byte Ed25519 signature]
 *   [OPTIONAL: 1-byte flags][4-byte mlDsaLen][mlDsa65 signature]
 *
 * The ML-DSA-65 tail is APPENDED and length-prefixed (it is 3309 bytes, vs
 * Ed25519's 64), and the flags byte marks its presence. A blob written before
 * PQ provisioning simply ends after the 64-byte signature, so legacy blobs
 * read unchanged.
 *
 * ## Wire JSON shape
 *
 * `rotationEntryToJson()` emits the shape `HttpRotationLogSource.coerceEntry()`
 * (`src/did/rotation-log-source.ts`) already expects, so a remote node can
 * fetch a log from this resolver and replay it with no adapter:
 *
 *   { version, parameters, didDocument, prevHash, nextKeyCommitments,
 *     createdAt, digest, signature, mlDsa65Signature?, witnessAttestations }
 *
 * Byte fields are base64 strings.
 */

import type { DidDocument, DidParameters } from './types.js';
import type { RotationLogEntry } from './rotation-types.js';

/** The fields carried by the packed `signed_entry` blob. */
export interface PackedRotationEntry {
  didDocument: DidDocument;
  parameters?: DidParameters;
  digest: Uint8Array;
  signature: Uint8Array;
  mlDsa65Signature?: Uint8Array;
}

const FLAG_MLDSA_PRESENT = 0x01;

/** Coerce a DB/blob value (Buffer, Uint8Array, number[], base64 string) to bytes. */
export function toUint8Array(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value as number[]);
  if (typeof value === 'string') return new Uint8Array(Buffer.from(value, 'base64'));
  if (
    value &&
    typeof value === 'object' &&
    (value as { type?: string }).type === 'Buffer' &&
    Array.isArray((value as { data?: unknown }).data)
  ) {
    return new Uint8Array((value as { data: number[] }).data);
  }
  throw new Error('rotation-entry-codec: cannot coerce value to Uint8Array');
}

/** Pack a rotation entry into the `signed_entry` BLOB layout. */
export function packRotationEntry(entry: PackedRotationEntry): Uint8Array {
  const docJson = new TextEncoder().encode(JSON.stringify(entry.didDocument));
  const paramsJson = new TextEncoder().encode(JSON.stringify(entry.parameters ?? null));
  const pqcTail = entry.mlDsa65Signature ? 1 + 4 + entry.mlDsa65Signature.length : 0;
  const packed = new Uint8Array(
    4 + docJson.length + 4 + paramsJson.length + entry.digest.length + entry.signature.length + pqcTail,
  );
  const view = new DataView(packed.buffer);
  view.setUint32(0, docJson.length, false);
  packed.set(docJson, 4);
  view.setUint32(4 + docJson.length, paramsJson.length, false);
  packed.set(paramsJson, 4 + docJson.length + 4);
  const offset = 4 + docJson.length + 4 + paramsJson.length;
  packed.set(entry.digest, offset);
  packed.set(entry.signature, offset + entry.digest.length);
  if (entry.mlDsa65Signature) {
    const tail = offset + entry.digest.length + entry.signature.length;
    packed[tail] = FLAG_MLDSA_PRESENT;
    view.setUint32(tail + 1, entry.mlDsa65Signature.length, false);
    packed.set(entry.mlDsa65Signature, tail + 5);
  }
  return packed;
}

/** Unpack a `signed_entry` BLOB back into its fields (ML-DSA tail preserved). */
export function unpackRotationEntry(bytes: Uint8Array): PackedRotationEntry {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const docLen = view.getUint32(0, false);
  const docJson = new TextDecoder().decode(bytes.subarray(4, 4 + docLen));
  const paramsLenOffset = 4 + docLen;
  const paramsLen = view.getUint32(paramsLenOffset, false);
  const paramsJson = new TextDecoder().decode(
    bytes.subarray(paramsLenOffset + 4, paramsLenOffset + 4 + paramsLen),
  );
  const offset = paramsLenOffset + 4 + paramsLen;
  const digest = bytes.slice(offset, offset + 32);
  const signature = bytes.slice(offset + 32, offset + 32 + 64);

  let mlDsa65Signature: Uint8Array | undefined;
  const tail = offset + 32 + 64;
  if (tail + 5 <= bytes.length && (bytes[tail] & FLAG_MLDSA_PRESENT) === FLAG_MLDSA_PRESENT) {
    const len = view.getUint32(tail + 1, false);
    if (tail + 5 + len <= bytes.length) {
      mlDsa65Signature = bytes.slice(tail + 5, tail + 5 + len);
    }
  }

  let parameters: DidParameters | undefined;
  try {
    parameters = (JSON.parse(paramsJson) as DidParameters | null) ?? undefined;
  } catch {
    /* legacy format — no parameters block */
  }

  return { didDocument: JSON.parse(docJson) as DidDocument, parameters, digest, signature, mlDsa65Signature };
}

/**
 * Parse the `new_public_key` column, which carries the JSON array of base64
 * next-key commitments (legacy rows carry a single raw key instead).
 */
export function parseNextKeyCommitments(raw: Uint8Array): Uint8Array[] {
  try {
    const arr = JSON.parse(new TextDecoder().decode(raw)) as unknown;
    if (Array.isArray(arr)) {
      return arr.map((b64) => new Uint8Array(Buffer.from(String(b64), 'base64')));
    }
  } catch {
    /* legacy single-key format: the raw bytes ARE the one commitment */
  }
  return [new Uint8Array(raw)];
}

// ---------------------------------------------------------------------------
// Wire JSON
// ---------------------------------------------------------------------------

export interface RotationEntryJson {
  version: number;
  parameters?: DidParameters;
  didDocument: DidDocument;
  prevHash: string | null;
  nextKeyCommitments: string[];
  createdAt: number;
  digest: string;
  signature: string;
  mlDsa65Signature?: string;
  witnessAttestations: unknown[];
}

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');

/** Serialize a rotation entry to the wire shape consumed by HttpRotationLogSource. */
export function rotationEntryToJson(entry: RotationLogEntry): RotationEntryJson {
  return {
    version: entry.version,
    ...(entry.parameters ? { parameters: entry.parameters } : {}),
    didDocument: entry.didDocument,
    prevHash: entry.prevHash ? b64(entry.prevHash) : null,
    nextKeyCommitments: entry.nextKeyCommitments.map(b64),
    createdAt: entry.createdAt,
    digest: b64(entry.digest),
    signature: b64(entry.signature),
    ...(entry.mlDsa65Signature ? { mlDsa65Signature: b64(entry.mlDsa65Signature) } : {}),
    witnessAttestations: entry.witnessAttestations ?? [],
  };
}

/** Serialize a whole log as line-delimited JSON (`application/jsonl`). */
export function rotationLogToJsonl(entries: RotationLogEntry[]): string {
  if (entries.length === 0) return '';
  return entries.map((e) => JSON.stringify(rotationEntryToJson(e))).join('\n') + '\n';
}

const unb64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64'));

/**
 * Parse the wire JSON back into a `RotationLogEntry`.
 *
 * Used by the utility server to persist an agent-pushed rotation log: the push
 * payload is JSON (so `Uint8Array` fields had to be base64 on the wire), and
 * this is the inverse of `rotationEntryToJson`. Tolerant by design — a field the
 * sender omitted yields an empty/`null` value rather than throwing, so a
 * slightly older agent cannot fail a whole push.
 */
export function rotationEntryFromJson(json: RotationEntryJson): RotationLogEntry {
  return {
    version: Number(json.version),
    parameters: json.parameters,
    didDocument: json.didDocument,
    prevHash: json.prevHash ? unb64(json.prevHash) : null,
    nextKeyCommitments: (json.nextKeyCommitments ?? []).map(unb64),
    createdAt: Number(json.createdAt ?? 0),
    digest: unb64(json.digest),
    signature: unb64(json.signature),
    ...(json.mlDsa65Signature ? { mlDsa65Signature: unb64(json.mlDsa65Signature) } : {}),
    witnessAttestations: (json.witnessAttestations ?? []) as RotationLogEntry['witnessAttestations'],
  };
}
