// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * RotationLogStore — key rotation history persistence using the shared
 * P2PTS migration table `rotation_log` (0004).
 *
 * Maps agent-specific rotation data into the standard P2PTS rotation_log schema:
 *   - did_document_id FK → the DID document being rotated
 *   - version → rotation version number (1-based, auto-incremented)
 *   - new_public_key → the new Ed25519 public key (BLOB)
 *   - signed_entry → the full signed rotation entry (BLOB)
 *   - previous_hash → hash link to prior entry
 *
 * Agent-specific payloads (did_document_json, digest, signature) are stored
 * in the existing `new_public_key`/`signed_entry` columns where the standard
 * schema already accommodates rotation commit data.
 */

import type { DatabaseSync } from 'node:sqlite';
import type { IdentityResolver } from '../services/identity-resolver.js';
import type { DidDocument } from './types.js';
import type { RotationLogEntry } from './rotation-types.js';
import { generateUuid } from '../db/uuid-helpers.js';

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

interface RotationLogRow {
  uuid: string;
  did_document_uuid: string;
  version: number;
  previous_hash: Buffer | Uint8Array | null;
  new_public_key: Buffer | Uint8Array;
  signed_entry: Buffer | Uint8Array;
  created_at: number | null;
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

function packSignedEntry(
  didDocument: DidDocument,
  parameters: import('./types.js').DidParameters | undefined,
  digest: Uint8Array,
  signature: Uint8Array,
  mlDsa65Signature?: Uint8Array,
): Uint8Array {
  // Pack the DID document JSON + parameters + digest + signature into a single binary blob
  // for the signed_entry column. The format is:
  //   [4-byte doc_len BE][doc_json UTF-8][4-byte params_len BE][params_json UTF-8][32-byte digest][64-byte signature]
  //     [OPTIONAL: 1-byte flags][4-byte mlDsa_len BE][mlDsa65 signature]
  //
  // The ML-DSA-65 tail is APPENDED and length-prefixed rather than given a fixed
  // slot (it is 3309 bytes, vs Ed25519's 64), and the flags byte marks its
  // presence. Blobs written before this change simply end after the 64-byte
  // signature, so `unpackSignedEntry` reads them unchanged.
  const docJson = new TextEncoder().encode(JSON.stringify(didDocument));
  const paramsJson = new TextEncoder().encode(JSON.stringify(parameters ?? null));
  const pqcTail = mlDsa65Signature ? 1 + 4 + mlDsa65Signature.length : 0;
  const packed = new Uint8Array(
    4 + docJson.length + 4 + paramsJson.length + digest.length + signature.length + pqcTail,
  );
  const view = new DataView(packed.buffer);
  view.setUint32(0, docJson.length, false); // Big-endian length
  packed.set(docJson, 4);
  view.setUint32(4 + docJson.length, paramsJson.length, false);
  packed.set(paramsJson, 4 + docJson.length + 4);
  const offset = 4 + docJson.length + 4 + paramsJson.length;
  packed.set(digest, offset);
  packed.set(signature, offset + digest.length);
  if (mlDsa65Signature) {
    const tail = offset + digest.length + signature.length;
    packed[tail] = 0x01; // flags: bit 0 = ML-DSA-65 signature present
    view.setUint32(tail + 1, mlDsa65Signature.length, false);
    packed.set(mlDsa65Signature, tail + 5);
  }
  return packed;
}

function unpackSignedEntry(packed: Uint8Array): {
  parameters?: import('./types.js').DidParameters;
  didDocument: DidDocument;
  digest: Uint8Array;
  signature: Uint8Array;
  mlDsa65Signature?: Uint8Array;
} {
  const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
  const docLen = view.getUint32(0, false);
  const docJson = new TextDecoder().decode(packed.slice(4, 4 + docLen));
  const paramsLenOffset = 4 + docLen;
  const paramsLen = view.getUint32(paramsLenOffset, false);
  const paramsJson = new TextDecoder().decode(packed.slice(paramsLenOffset + 4, paramsLenOffset + 4 + paramsLen));
  const offset = paramsLenOffset + 4 + paramsLen;
  const digest = packed.slice(offset, offset + 32);
  const signature = packed.slice(offset + 32, offset + 32 + 64);

  // Optional ML-DSA-65 tail (see packSignedEntry). Present only when the entry
  // was created by an identity that has a PQ root-of-trust key.
  let mlDsa65Signature: Uint8Array | undefined;
  const tail = offset + 32 + 64;
  if (packed.length >= tail + 5) {
    const flags = packed[tail];
    if (flags & 0x01) {
      const sigLen = view.getUint32(tail + 1, false);
      mlDsa65Signature = packed.slice(tail + 5, tail + 5 + sigLen);
    }
  }

  let parameters: import('./types.js').DidParameters | undefined;
  try {
    parameters = JSON.parse(paramsJson) ?? undefined;
  } catch { /* legacy format: no parameters block */ }
  return {
    parameters,
    didDocument: JSON.parse(docJson) as DidDocument,
    digest,
    signature,
    mlDsa65Signature,
  };
}

function parseNextKeyCommitments(raw: Uint8Array): Uint8Array[] {
  try {
    const json = new TextDecoder().decode(raw);
    const arr = JSON.parse(json) as string[];
    return arr.map(b64 => new Uint8Array(Buffer.from(b64, 'base64')));
  } catch {
    // Legacy single-key format: raw bytes as one commitment
    return [new Uint8Array(raw)];
  }
}

function rowToEntry(row: RotationLogRow): RotationLogEntry {
  const unpacked = unpackSignedEntry(new Uint8Array(row.signed_entry));

  return {
    version: row.version,
    parameters: unpacked.parameters,
    didDocument: unpacked.didDocument,
    prevHash: row.previous_hash ? new Uint8Array(row.previous_hash) : null,
    nextKeyCommitments: parseNextKeyCommitments(new Uint8Array(row.new_public_key)),
    createdAt: row.created_at ?? 0,
    digest: unpacked.digest,
    signature: unpacked.signature,
    mlDsa65Signature: unpacked.mlDsa65Signature,
    witnessAttestations: [],
  };
}

// ---------------------------------------------------------------------------
// RotationLogStore
// ---------------------------------------------------------------------------

export class RotationLogStore {
  private readonly db: DatabaseSync;
  private readonly resolver: IdentityResolver;

  constructor(db: DatabaseSync, resolver: IdentityResolver) {
    this.db = db;
    this.resolver = resolver;
  }

  /**
   * Append a new rotation entry. Version auto-increments from the previous
   * highest version for this DID document.
   */
  appendEntry(did: string, entry: RotationLogEntry): void {
    const resolved = this.resolver.lookupByDid(did);
    if (!resolved || !resolved.didDocumentUuid) {
      throw new Error(`RotationLogStore.appendEntry: DID document not found for "${did}"`);
    }

    // Use the entry's own version number (0 for genesis, N for rotation).
    const version = entry.version;

    const packed = packSignedEntry(entry.didDocument, entry.parameters, entry.digest, entry.signature, entry.mlDsa65Signature);
    const uuid = generateUuid();

    this.db.prepare(`
      INSERT INTO rotation_log
        (did_document_uuid, version, previous_hash,
         new_public_key, signed_entry, uuid, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      resolved.didDocumentUuid,
      version,
      entry.prevHash,
      Buffer.from(JSON.stringify(entry.nextKeyCommitments.map(k => Buffer.from(k).toString('base64')))),
      packed,
      uuid,
      entry.createdAt,
    );
  }

  /** Return the full rotation log for a DID, ordered by version ascending. */
  getLog(did: string): RotationLogEntry[] {
    const resolved = this.resolver.lookupByDid(did);
    if (!resolved || !resolved.didDocumentUuid) return [];

    const rows = this.db.prepare(`
      SELECT * FROM rotation_log
      WHERE did_document_uuid = ?
      ORDER BY version ASC
    `).all(resolved.didDocumentUuid) as unknown as RotationLogRow[];

    return rows.map(rowToEntry);
  }

  /** Return the latest (highest-version) entry, or undefined. */
  getLatestEntry(did: string): RotationLogEntry | undefined {
    const resolved = this.resolver.lookupByDid(did);
    if (!resolved || !resolved.didDocumentUuid) return undefined;

    const row = this.db.prepare(`
      SELECT * FROM rotation_log
      WHERE did_document_uuid = ?
      ORDER BY version DESC LIMIT 1
    `).get(resolved.didDocumentUuid) as RotationLogRow | undefined;

    return row ? rowToEntry(row) : undefined;
  }
}