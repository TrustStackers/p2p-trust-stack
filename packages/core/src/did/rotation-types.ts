/**
 * RotationLogEntry type — Step 11, Task 11.1.
 *
 * did:webvh-inspired hash-chained rotation log format. Each entry hash-chains
 * to the previous entry and pre-commits to the *next* signing key
 * (pre-rotation), so a compromise of the *current* key alone cannot be used
 * to forge a future rotation without also having pre-committed the
 * attacker's key in advance.
 *
 * Reference: docs/implementation-plan-step11.md §2.
 */

import type { DidDocument } from './types.js';
import type { Vrc } from '../vtc/types.js';

/**
 * A single entry in a rotating VID's append-only log.
 *
 * Design notes:
 * - The signature is by the PREVIOUS key (the one pre-committed by the prior
 *   entry's `nextKeyCommitment`), not the new one — this is the crux of
 *   pre-rotation. Version 0 has no prior commitment, so it's self-signed by
 *   its own initial key (bootstrap case, analogous to did:peer:4's
 *   self-certification).
 * - `witnessAttestations` embeds `Vrc` objects directly (Step 10 type) — no
 *   new credential shape invented; a rotation attestation IS a VRC with
 *   `claim.type === 'rotation-witness'` and `claim.rotationDigest === entry.digest`.
 */
export interface RotationLogEntry {
  /** 0-indexed version number; version 0 is the genesis entry. */
  version: number;
  /** DID method parameters that govern this entry's state (updateKeys, nextKeyHashes, etc.). */
  parameters?: import('./types.js').DidParameters;
  /** The DID document valid as of this version. */
  didDocument: DidDocument;
  /** SHA2-256 digest of the previous entry's canonical bytes; null for version 0. */
  prevHash: Uint8Array | null;
  /**
   * Hash commitments to candidate NEXT signing public keys (pre-rotation).
   * Multiple candidates are supported — on the next rotate(), the new
   * document's signing key must hash to one of these values, proving
   * the rotation was pre-planned and allowing fallback candidate keys.
   */
  nextKeyCommitments: Uint8Array[];
  /** Unix timestamp (seconds) this entry was created. */
  createdAt: number;
  /** Self-addressing digest of this entry's canonical fields (excl. signature). */
  digest: Uint8Array;
  /**
   * Signature over `digest` by the CURRENT signing key (the one this entry
   * rotates FROM — i.e. the key pre-committed by the prior entry's
   * nextKeyCommitments, or the entry's own initial key for version 0).
   */
  signature: Uint8Array;
  /**
   * Optional ML-DSA-65 signature over `digest`, by the identity's POST-QUANTUM
   * ROOT-OF-TRUST key (the `#key-mldsa` key in `didDocument`).
   *
   * Key rotation is one of the high-value, long-lived, ASYNCHRONOUS statements
   * ML-DSA-65 is reserved for, so an entry that has a PQ key available carries
   * this alongside the classical Ed25519 `signature`. Absent for entries created
   * by identities that predate PQ provisioning — `validateChain` accepts those
   * (classical-only) but REJECTS an entry whose ML-DSA signature is present and
   * invalid.
   */
  mlDsa65Signature?: Uint8Array;
  /** Optional witness attestation VRCs collected for this rotation (empty for version 0). */
  witnessAttestations: Vrc[];
}
