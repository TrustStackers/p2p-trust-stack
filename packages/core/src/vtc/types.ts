/**
 * VTC/VRC data model — Step 10, Tasks 10.1, 10.2.
 *
 * Just enough of Layer 3 to represent "membership in a witness pool": a VTC
 * identity (Decision 2.6 — VTC-as-VTA), an admin list, and VRC issuance with
 * M-of-N co-sign verification (Decision 2.7 — message-level co-signing, not
 * threshold cryptography).
 *
 * Reference: docs/cross-layer-integration-plan.md §2.3, §2.6, §2.7;
 *            docs/implementation-plan-step10.md §2.
 */

import type { DidDocument } from '../did/types.js';
import type { Vid, CesrVid } from '../tsp/v3/types.js';

// ---------------------------------------------------------------------------
// Encoded forms (CESR-key VIDs)
// ---------------------------------------------------------------------------

/**
 * The *encoded* forms of the VTC/VRC data model — the shape the binary codec
 * (`src/vtc/codec.ts`) reads and writes, where every VID is a CESR-encoded
 * Ed25519 public key rather than a DID.
 *
 * `Vrc`/`VtcGovernanceDoc` are the general model and are ALSO produced by the
 * database layer (`src/vtc/store.ts`) with **DIDs and UUIDs** in those fields —
 * so a `Vrc` is not necessarily encodable. Only `CesrVrc` is, and the only way
 * to obtain one is `asCesrVrc()` / `decodeVrc()`, which validate the CESR form
 * at runtime. That is the guard: the compiler rejects handing a DID-bearing `Vrc`
 * to `encodeVrc`.
 */
export type CesrVrcSignature = Omit<VrcSignature, 'signerVid'> & {
  signerVid: CesrVid;
};

export type CesrVrc = Omit<Vrc, 'subjectVid' | 'issuerVid' | 'signatures'> & {
  subjectVid: CesrVid;
  issuerVid: CesrVid;
  signatures: CesrVrcSignature[];
};

export type CesrVtcGovernanceDoc = Omit<VtcGovernanceDoc, 'vtcVid' | 'adminVids' | 'signatures'> & {
  vtcVid: CesrVid;
  adminVids: CesrVid[];
  signatures: CesrVrcSignature[];
};

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

/**
 * A single admin's signature over a VRC's (or governance doc's) canonical
 * digest. Per Decision 2.7, a VTC's "signature" on any payload it issues is a
 * bundle of these — not a single threshold key.
 */
export interface VrcSignature {
  /**
   * The signing admin's VID.
   *
   * **D-5b (2026-09-24): this field is NOT unconditionally a CESR key.** The general
   * model is what `src/vtc/store.ts` persists, and it writes DIDs/UUIDs here; only
   * the encoded model (`CesrVrcSignature`, obtained through `asCesrVrc()` /
   * `decodeVrc()`) guarantees the CESR-key form the binary codec requires. The
   * earlier comment claimed a CESR key outright, which is exactly the trap H17 named:
   * a reader (and the compiler) could not tell a key-valued field from a DID-valued
   * one, and the codec then failed deep inside `cesrDecode` at runtime.
   */
  signerVid: Vid;
  /** 64-byte Ed25519 signature over the digest. */
  signature: Uint8Array;
  /**
   * Optional DID of the signer (non-digested metadata). When present, a
   * resolution-aware verifier resolves this DID to confirm `signerVid`'s key is
   * still in the current DID document's assertionMethod (key-rotation aware).
   */
  signerDid?: string;
}

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

/**
 * A claim type the VTC can issue. Extensible — Step 10 only exercises
 * 'witness-member'; generalized membership/claim types arrive in Step 12.
 */
export interface VrcClaim {
  type: string; // e.g. 'witness-member'
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Vrc — community-issued claim credential (NOT a DTG RelationshipCredential)
// ---------------------------------------------------------------------------

/**
 * A community-issued claim credential (VTC-admin-issued, M-of-N co-signed).
 *
 * **IMPORTANT:** This is a VTC-issued credential — it requires a community
 * (vtcVid) and M-of-N admin co-signatures. It is NOT a DTG `RelationshipCredential`
 * (which is peer-to-peer, no VTC involved, W3C VC shaped).
 *
 * For DTG `RelationshipCredential`, see `src/services/dtg-credential.ts`.
 *
 * Aliased as `CommunityClaimCredential` for disambiguation in DTG contexts.
 *
 * Represents "VTA X holds claim C from VTC Y."
 */
export interface Vrc {
  /**
   * The credential subject's (the member's) VID.
   *
   * D-5b: a CESR-encoded key **only** in the encoded form (`CesrVrc`); the store also
   * persists DIDs/UUIDs here. See `VrcSignature.signerVid` for why that distinction is
   * stated rather than assumed.
   */
  subjectVid: Vid;
  /** The VTC's own VID (the issuer) — same shape as any VTA's VID (Decision 2.6). */
  issuerVid: Vid;
  /** The claim being asserted, e.g. { type: 'witness-member' }. */
  claim: VrcClaim;
  /** Unix timestamp (seconds) when the VRC was issued. */
  issuedAt: number;
  /** Optional unix timestamp (seconds) after which the VRC is no longer valid. */
  expiresAt?: number;
  /** Self-addressing digest of the VRC's canonical fields. */
  digest: Uint8Array;
  /** M-of-N signature bundle — one entry per co-signing admin. */
  signatures: VrcSignature[];
}

// ---------------------------------------------------------------------------
// VtcGovernanceDoc
// ---------------------------------------------------------------------------

/**
 * The governance document for a VTC — defines who its admins are, the
 * signature threshold, and what claim types it is allowed to issue.
 *
 * A VTC is itself a VTA (Decision 2.6): `vtcVid`/`vtcDid` are produced by the
 * same DidMethod used for any individual VTA identity.
 */
export interface VtcGovernanceDoc {
  /**
   * The VTC's own VID. D-5b: a CESR-encoded key **only** in the encoded form
   * (`CesrVtcGovernanceDoc`); the store may persist a DID/UUID here.
   */
  vtcVid: Vid;
  /** The VTC's full DID string (method-specific; did:peer:4 today). */
  vtcDid: string;
  /** Human-readable name for the VTC (display only — not part of the signed digest fields beyond being included in it). */
  name: string;
  /** CESR-encoded Ed25519 public keys of the current admin set. */
  adminVids: Vid[];
  /**
   * Admin DIDs, parallel to `adminVids` (same index).
   *
   * OPTION A — non-digested metadata: NOT included in
   * `computeGovernanceDocDigest()` nor in the CESR frame, so adding this field
   * does not change the governance doc's self-addressing digest and does not
   * invalidate existing stored/transmitted docs. It exists solely so a
   * resolution-aware verifier can resolve each admin's current DID document and
   * confirm the signing VID is still present in that document's assertionMethod
   * (i.e. honor key rotation). Absent an entry (legacy docs), verification
   * falls back to the self-certifying `signerVid` check.
   */
  adminDids?: string[];
  /** Signature threshold — a VRC needs ≥ M valid admin signatures to verify. */
  threshold: number;
  /** Claim types this VTC is allowed to issue (Step 10: typically just ['witness-member']). */
  allowedClaimTypes: string[];
  /** Unix timestamp (seconds) when the governance doc was created. */
  createdAt: number;
  /** Self-addressing digest of the doc's canonical fields (excluding digest/signatures themselves). */
  digest: Uint8Array;
  /** Founding-admin signatures over the digest (same M-of-N shape as a Vrc). */
  signatures: VrcSignature[];
}

// ---------------------------------------------------------------------------
// VtcIdentity (return shape from createVtc())
// ---------------------------------------------------------------------------

/** Everything createVtc() produces — identity + governance doc + key material. */
export interface VtcIdentity {
  governanceDoc: VtcGovernanceDoc;
  /** The VTC's own DID document (from DidMethod.create()). */
  didDocument: DidDocument;
  /**
   * The VTC's own signing/agreement key pairs.
   *
   * NOTE: per Decision 2.7, these are NOT "the VTC's key" in a threshold-crypto
   * sense — they exist because DidMethod.create() always produces a keypair for
   * any identity, VTC or individual. Left open whether this keypair is ever used
   * for anything beyond DID-document self-certification (see implementation-plan-step10.md §10).
   */
  signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array };
  agreementKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array };
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

export interface VrcVerifyResult {
  valid: boolean;
  validSignatureCount: number;
  /** Populated when valid === false. */
  reason?: string;
}
