/**
 * DidMethod — DID-method-agnostic identity abstraction — Step 9, Task 9.1.
 *
 * `Agent`, `LocalIdentity`, and `RelationshipManager` depend on this interface
 * rather than calling did:peer:4-specific functions directly. This allows a
 * second DID method (e.g. a future did:webvh-style rotating method, Step 11)
 * to be introduced later without touching any of that call-site code.
 *
 * Reference: docs/cross-layer-integration-plan.md, Decision 2.1, Step 9.
 */

import type { DidDocument, ServiceEndpoint } from './types.js';

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/** Result returned by DidMethod.create(). */
export interface DidMethodCreateResult {
  /** Full DID string (long-form for did:peer:4; method-specific shape otherwise). */
  did: string;
  /** The resolved DID document (with `id` populated). */
  document: DidDocument;
  /** Ed25519 signing key pair. */
  signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array };
  /** X25519 key agreement key pair. */
  agreementKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array };
  /**
   * ML-DSA-65 signing key pair — the POST-QUANTUM ROOT OF TRUST.
   *
   * Deliberately NOT used to sign ordinary TSP messages: those are ephemeral
   * (Ed25519, cheap), while ML-DSA-65 is reserved for high-value, long-lived,
   * asynchronous statements — VID creation/rotation and out-of-band
   * introductions. Published as `#key-mldsa` in the DID document.
   */
  mlDsa65KeyPair?: { secretKey: Uint8Array; publicKey: Uint8Array };
  /**
   * MLKEM768-X25519 hybrid KEM key pair — post-quantum key agreement, published
   * as `#key-kem` in the DID document (and paired with the classical X25519
   * `#key-2` each peer already publishes).
   */
  hybridKemKeyPair?: { secretKey: Uint8Array; publicKey: Uint8Array };
}

// ---------------------------------------------------------------------------
// DidMethod interface
// ---------------------------------------------------------------------------

/**
 * A DID-method-agnostic identity interface.
 *
 * Every concrete DID method (did:peer:4 today; a rotating did:webvh-style
 * method later) implements this same shape so that `Agent` and
 * `RelationshipManager` never need to know which method is in use.
 */
export interface DidMethod {
  /** Human-readable method name, e.g. 'did:peer:4'. */
  readonly methodName: string;

  /** Whether this method supports key rotation (false for did:peer:4). */
  readonly supportsRotation: boolean;

  /**
   * Whether this DID method supports `alsoKnownAs` in the DID document
   * for native agent name binding.
   */
  readonly supportsAlsoKnownAs: boolean;

  /**
   * Return the method's name binding type.
   * 'alsoKnownAs' — names stored in DID document (did:scidvh)
   * 'vrc' — names via VRC claim (did:peer:4)
   * 'none' — no name binding support
   */
  getNameBindingType(): 'alsoKnownAs' | 'vrc' | 'none';

  /**
   * Read current alsoKnownAs names from a DID document.
   * Returns empty array for methods without alsoKnownAs support.
   */
  getAlsoKnownAs?(did: string): string[];

  /**
   * Create a new identity: generates key pairs, constructs a DID document,
   * and encodes it as a DID string.
   *
   * @param transport  Optional transport info (peerId + multiaddrs) to embed
   *                   in the DID document's service entry.
   */
  create(transport?: ServiceEndpoint): Promise<DidMethodCreateResult>;

  /**
   * Resolve a DID string to its DID document.
   *
   * For did:peer:4 this is a fully offline, local operation (the document is
   * embedded in the DID string itself). Future rotating methods may need
   * additional local state (e.g. a rotation log) but should still avoid any
   * network call for this phase.
   *
   * @throws if the DID string cannot be resolved by this method
   */
  resolve(did: string): DidDocument;

  /**
   * Verify that a DID string is self-consistent / not tampered with.
   *
   * For did:peer:4 this recomputes the embedded hash. Async because the
   * underlying hash primitive (multiformats sha256.digest) is async.
   *
   * @returns true if the DID is valid/self-consistent; false otherwise
   */
  verify(did: string): Promise<boolean>;
}
