// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * SpeculativeRotationService — computes a rotation entry with a name in
 * alsoKnownAs WITHOUT persisting it to the rotation log store.
 *
 * This is the core of the "speculative DID log roll" mechanism. The rotation
 * entry is fully computed (signed, digest computed, DID document built) but
 * NOT written to the rotation log. The entry is held in memory and passed to
 * the transaction coordinator's participants.
 *
 * If the transaction commits:
 *   → The agent-side participant finalizes the entry (writes to rotation log).
 *
 * If the transaction aborts:
 *   → The entry is simply discarded. No rollback needed — it was never
 *     persisted.
 *
 * This is shared-core DID logic — used by both agent and utility server code.
 */

import type { Ed25519KeyPair } from '../crypto/primitives.js';
import { signEd25519, ed25519ToX25519 } from '../crypto/primitives.js';
import { extractEd25519PublicKey, extractX25519PublicKey } from '../relationship/key-extract.js';
import { buildDidPeer4Document } from './create.js';
import { computeRotationEntryDigest, computeNextKeyCommitment } from './rotation-codec.js';
import type { DidDocument, DidParameters, ServiceEndpoint } from './types.js';
import type { RotationLogEntry } from './rotation-types.js';
import type { Vrc } from '../vtc/types.js';
import { buildNameUri } from './name-uri.js';

// ---------------------------------------------------------------------------
// bytesEqual helper (same as scid-vh-method.ts)
// ---------------------------------------------------------------------------

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SpeculativeRotationParams {
  /** The name being claimed. */
  name: string;
  /** The namespace for the name. */
  namespace: string;
  /** The agent's DID. */
  did: string;
  /** The current rotation log (must contain at least the genesis entry). */
  currentLog: RotationLogEntry[];
  /** The outgoing signing key pair (must match the current key in the log). */
  outgoingSigningKeyPair: Ed25519KeyPair;
  /** The new signing key pair (must match a nextKeyCommitment in the log). */
  newSigningKeyPair: Ed25519KeyPair;
  /** The next signing public key (for pre-rotation commitment). */
  nextSigningPublicKey: Uint8Array;
  /** Optional witness attestations for the rotation. */
  witnessAttestations?: Vrc[];
  /** Optional transport service endpoint to include in the DID document. */
  transport?: ServiceEndpoint;
}

export interface SpeculativeRotationResult {
  /** The fully computed rotation entry (signed, with digest). NOT persisted. */
  rotationEntry: RotationLogEntry;
  /** The new DID document with the name in alsoKnownAs. */
  didDocument: DidDocument;
  /** The name URI (e.g., vta:p2pts:alice). */
  nameUri: string;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class SpeculativeRotationService {
  /**
   * Compute a speculative rotation entry that adds a name to the DID
   * document's alsoKnownAs array.
   *
   * This performs ALL the same validation and computation as
   * ScidVhMethod.rotate() EXCEPT it does NOT call store.appendEntry().
   * The returned entry is fully valid and signed, but not yet persisted.
   *
   * @throws If validation fails (key mismatch, name already claimed, etc.)
   */
  async computeSpeculativeRotation(
    params: SpeculativeRotationParams,
  ): Promise<SpeculativeRotationResult> {
    const {
      name,
      namespace,
      currentLog,
      outgoingSigningKeyPair,
      newSigningKeyPair,
      nextSigningPublicKey,
      witnessAttestations,
      transport,
    } = params;

    if (currentLog.length === 0) {
      throw new Error(
        'SpeculativeRotation: currentLog must contain at least the genesis entry',
      );
    }

    const prevEntry = currentLog[currentLog.length - 1];
    const nameUri = buildNameUri(namespace, name);

    // ── Validation 1: outgoing key must match current key ──────────────
    const prevDocumentSigningKey = await extractSigningPublicKey(prevEntry.didDocument);
    if (!bytesEqual(outgoingSigningKeyPair.publicKey, prevDocumentSigningKey)) {
      throw new Error(
        'SpeculativeRotation: outgoingSigningKeyPair does not match the ' +
        "previous entry's current signing key",
      );
    }

    // ── Validation 2: new key must match a nextKeyCommitment ───────────
    // OR equal the current key (self-commit). A self-commit lets a metadata-only
    // change (e.g. adding a name to alsoKnownAs) advance the did:scid:vh log
    // WITHOUT rotating the signing identity, keeping the transport VID stable
    // per ToIP. Genuine rotation still requires a matching pre-commitment.
    const expectedCommitment = computeNextKeyCommitment(newSigningKeyPair.publicKey);
    const isSelfCommit = bytesEqual(newSigningKeyPair.publicKey, prevDocumentSigningKey);
    const matchesAny = isSelfCommit || prevEntry.nextKeyCommitments.some(c =>
      bytesEqual(expectedCommitment, c),
    );
    if (!matchesAny) {
      throw new Error(
        'SpeculativeRotation: newSigningKeyPair does not match any of the ' +
        "previous entry's nextKeyCommitments",
      );
    }

    // ── Validation 3: name must not already be claimed ─────────────────
    const currentNames = prevEntry.didDocument.alsoKnownAs ?? [];
    if (currentNames.includes(nameUri)) {
      throw new Error(
        `SpeculativeRotation: name "${nameUri}" is already claimed`,
      );
    }

    // ── Build new DID document ─────────────────────────────────────────
    const newAlsoKnownAs = [...currentNames, nameUri];
    const prevParameters = prevEntry.parameters ?? {};

    // Slot-A: when the previous document carries a distinct #key-scid (identity)
    // slot, the did:scid:vh chain and the TSP VID are DECOUPLED. A log roll must
    // preserve the permanent TSP key at verificationMethod[0]/#key-1 and its
    // agreement key (#key-2), advancing ONLY the identity key in #key-scid.
    // For agents (no #key-scid), the new identity key becomes both (legacy).
    const prevHasSlotA = prevEntry.didDocument.verificationMethod.some(vm => vm.id === '#key-scid');
    let docSigningKey: Uint8Array;
    let docAgreementKey: Uint8Array;
    let identitySlotKey: Uint8Array | undefined;
    if (prevHasSlotA) {
      docSigningKey = extractEd25519PublicKey(prevEntry.didDocument);   // TSP VID key [0] — preserved
      docAgreementKey = extractX25519PublicKey(prevEntry.didDocument);  // agreement [1] — preserved
      identitySlotKey = newSigningKeyPair.publicKey;                    // identity key → #key-scid
    } else {
      docSigningKey = newSigningKeyPair.publicKey;                      // legacy: identity key is the VID
      docAgreementKey = ed25519ToX25519(newSigningKeyPair.secretKey).publicKey;
    }

    const newDocument = buildDidPeer4Document(
      docSigningKey,
      docAgreementKey,
      transport,
      identitySlotKey,
    );

    const nextKeyCommitment = computeNextKeyCommitment(nextSigningPublicKey);
    // The new entry's commitment set includes BOTH its live key (so a subsequent
    // metadata-only self-commit can advance the log without rotating) AND a fresh
    // next key (so a genuine rotation remains possible). Mirrors ScidVhMethod.rotate
    // semantics and keeps the chain valid under either advance mode.
    const nextKeyCommitments = [computeNextKeyCommitment(newSigningKeyPair.publicKey), nextKeyCommitment];
    const newParameters: DidParameters = {
      ...prevParameters,
      nextKeyHashes: nextKeyCommitments.map(h => Buffer.from(h).toString('base64')),
    };

    const documentWithId: DidDocument = {
      ...newDocument,
      id: prevEntry.didDocument.id,
      alsoKnownAs: newAlsoKnownAs,
      parameters: newParameters,
    };

    // ── Build unsigned entry ───────────────────────────────────────────
    const unsignedEntry = {
      version: prevEntry.version + 1,
      parameters: newParameters,
      didDocument: documentWithId,
      prevHash: (prevEntry.digest as Uint8Array) ?? null,
      nextKeyCommitments,
      createdAt: Math.floor(Date.now() / 1000),
    };

    const digest = computeRotationEntryDigest(unsignedEntry);

    // ── Sign with outgoing key (key-continuity proof) ──────────────────
    const signature = signEd25519(digest, outgoingSigningKeyPair.secretKey);

    const rotationEntry: RotationLogEntry = {
      ...unsignedEntry,
      digest,
      signature,
      witnessAttestations: witnessAttestations ?? [],
    };

    return {
      rotationEntry,
      didDocument: documentWithId,
      nameUri,
    };
  }
}

// ---------------------------------------------------------------------------
// Helper: extract signing public key from DID document
// (mirrors scid-vh-method.ts)
// ---------------------------------------------------------------------------

async function extractSigningPublicKey(doc: DidDocument): Promise<Uint8Array> {
  // Slot-A: prefer the dedicated did:scid:vh identity key (#key-scid) when present.
  // Fall back to #key-1 for agents (whose only signing key is the TSP key).
  const vm = doc.verificationMethod.find((m) => m.id === '#key-scid')
    ?? doc.verificationMethod.find((m) => m.id === '#key-1');
  if (!vm) {
    throw new Error(
      'extractSigningPublicKey: no #key-scid or #key-1 verification method found in DID document',
    );
  }
  // Multikey format: base58btc with 'z' multibase prefix.
  // The decoded bytes include a 2-byte multicodec prefix (0xed01 for
  // Ed25519 public key).  We strip it to get the raw 32-byte key so it
  // can be compared with Ed25519KeyPair.publicKey.
  const key = vm.publicKeyMultibase;
  if (key.startsWith('z')) {
    const { base58btc } = await import('multiformats/bases/base58');
    const decoded = base58btc.decode(key);
    if (decoded.length > 2 && decoded[0] === 0xed && decoded[1] === 0x01) {
      return decoded.slice(2);
    }
    return decoded;
  }
  throw new Error(`Cannot decode verification method key: ${key.slice(0, 20)}...`);
}
