/**
 * DID-related types for did:peer:4 VID creation (Step 2).
 */

/**
 * DID document parameters block — per did:webvh spec, carries identifiers
 * for key management, witnesses, and (optionally) human-readable names.
 */
export interface DidParameters {
  /** Human-readable aliases for this DID (W3C DID Core §5.4). */
  alsoKnownAs?: string[];
  /** Authorized update keys (multi-signature support). */
  updateKeys?: string[];
  /** Hashes of pre-committed candidate next keys. */
  nextKeyHashes?: string[];
  /** The controller DID for delegated identities. */
  controller?: string;
  /** Witness DIDs for external attestation on rotation entries. */
  witness?: { id: string; weight: number }[];
  /** Method-specific threshold (e.g., minimum witness attestations). */
  threshold?: number;
}

/** A W3C DID verification method (Multikey format). */
export interface VerificationMethod {
  id: string;
  /**
   * `Multikey` for entries whose `publicKeyMultibase` carries a REGISTERED
   * multicodec prefix (Ed25519 0xed01, X25519 0xec01, ML-DSA-65 0x1211).
   *
   * `MLKEM768X25519PublicKey` is used for the hybrid KEM key, because no
   * multicodec is registered for ML-KEM public keys (see
   * `ML_DSA_65_PUB_MULTICODEC` in crypto/pqc.ts) — so the algorithm is named in
   * the type instead of claiming a prefix that does not exist. The value is a
   * multibase `u`-prefixed base64url string.
   */
  type: 'Multikey' | 'MLKEM768X25519PublicKey';
  controller: string;
  publicKeyMultibase: string;
}

/** A DID service entry. */
export interface ServiceEndpoint {
  peerId: string;
  multiaddrs?: string[];
}

export interface DidService {
  id: string;
  type: string;
  serviceEndpoint: ServiceEndpoint | string;
}

/**
 * Minimal DID document structure used for did:peer:4.
 *
 * The `id` field is intentionally absent from the document that gets
 * embedded in the DID string (per the did:peer:4 spec — the document
 * must not contain its own DID, since the DID is derived from the document).
 * After resolution the `id` is populated with the resolved DID string.
 */
export interface DidDocument {
  '@context': string[];
  id?: string;
  /** W3C DID Core §5.4 — also known as (agent names). */
  alsoKnownAs?: string[];
  /** Method-specific parameters (updateKeys, nextKeyHashes, controller, etc.). */
  parameters?: DidParameters;
  verificationMethod: VerificationMethod[];
  /**
   * W3C DID Core verification relationship §5.3.2: keys authorized to make
   * assertions (sign verifiable credentials/claims). Added so proof
   * verification can confirm proofPurpose ≤ assertionMethod.
   */
  assertionMethod?: string[];
  authentication: string[];
  keyAgreement: string[];
  service?: DidService[];
}

/** Result returned by createDidPeer4(). */
export interface DidPeer4Result {
  /** Long-form DID string: did:peer:4{hash}:{encodedDoc} */
  did: string;
  /** Short-form DID string: did:peer:4{hash} */
  shortFormDid: string;
  /** The DID document (without the id field — as embedded in the DID string) */
  document: DidDocument;
  /** Ed25519 signing key pair */
  signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array };
  /** X25519 key agreement key pair */
  agreementKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array };
  /** ML-DSA-65 root-of-trust signing key pair (published as `#key-mldsa`). */
  mlDsa65KeyPair?: { secretKey: Uint8Array; publicKey: Uint8Array };
  /** MLKEM768-X25519 hybrid KEM key pair (published as `#key-kem`). */
  hybridKemKeyPair?: { secretKey: Uint8Array; publicKey: Uint8Array };
}
