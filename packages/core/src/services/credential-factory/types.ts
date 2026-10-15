// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * CredentialFactory — Domain types, interfaces, and request/response models.
 *
 * Defines the universal credential domain model that every layer can agree on,
 * independent of storage format (vcType column) or serialization (W3C VC / CESR).
 *
 * @module credential-factory/types
 */

// ── Credential Domain Types ─────────────────────────────────────────────

/**
 * The credential types defined by DTG Core Credentials WD01.
 * These are the spec-conformant types. Not mapped 1:1 to vcType column values.
 */
export type DtgCredentialType =
  | 'RelationshipCredential'    // VRC — peer-to-peer edge
  | 'MembershipCredential'      // VMC — community edge (+ PHC variant)
  | 'InvitationCredential'      // VIC — onboarding authorization
  | 'PersonaCredential'         // VPC — persona DID → relationship link
  | 'EndorsementCredential'     // VEC — community reputation assertion
  | 'WitnessCredential'         // VWC — third-party edge attestation
  | 'DelegationCredential'      // VDC — delegation of authority (under discussion)
  | 'AuthorizationCredential';  // VAC — authorization grant (under discussion)

/**
 * Non-credential verifiable data structures defined by DTG spec.
 */
export type DtgVerifiableDataStructure =
  | 'RelationshipCard';         // RCard — JCard-based contact card

export type CredentialKind = DtgCredentialType | DtgVerifiableDataStructure;

/** The scenario in which a credential is meant to be used — drives UI grouping. */
export type CredentialScenario =
  | 'peer-verification'         // I want to prove this person is real (VRC)
  | 'community-join'            // I want to join a VTC (VMC via invite)
  | 'community-issue'           // I want to issue a membership/endorsement (VMC/E/VWC)
  | 'invite-new-member'         // I want to invite someone (VIC)
  | 'manage-personas'           // I want to create a separate persona (VPC)
  | 'share-contact'             // I want to share my contact card (RCard)
  | 'delegate-authority';       // I want to delegate powers (VDC — future)

/** How this credential is governed. */
export type GovernanceModel =
  | 'peer-to-peer'              // No VTC — two peers mutually attest (VRC, RCard)
  | 'community-governed'        // VTC admin set + threshold (VMC, VEC, VWC)
  | 'self-issued'               // Holder issues to self (VPC)
  | 'ceremony-bound';           // Credential only valid within ceremony (VIC)

/** The serialization format produced. */
export type CredentialFormat =
  | 'w3c-vc-json-ld'            // DTG-compliant W3C VC
  | 'cesr-group-frame'          // Internal CESR encoding
  | 'jcard';                    // RFC 7095 JCard (for RCard)

// ── Minting Request (Universal Input) ───────────────────────────────────

/**
 * The universal credential minting request.
 *
 * Not every field applies to every credential type. The factory validates
 * that the right fields are present for the requested kind + scenario.
 */
export interface CredentialMintRequest {
  /** Which DTG credential type to mint. */
  kind: CredentialKind;

  /** The scenario the caller is acting within — drives validation and UI. */
  scenario: CredentialScenario;

  // ── Identities ──────────────────────────────────────────────────────
  /** The DID of the issuer. For community credentials: the VTC's DID. */
  issuerDid: string;
  /** The DID of the subject (who the credential is about). */
  subjectDid: string;
  /** Optional: a specific identity UUID for the subject. */
  subjectIdentityUuid?: string;

  // ── Claim payload ───────────────────────────────────────────────────
  /** The claim being asserted. Shape depends on credential kind. */
  claim: Record<string, unknown>;

  // ── Governance (community-governed only) ─────────────────────────────
  /** The VTC's governance document DID. Required for community-governed. */
  governanceDid?: string;
  /** Admin signatures. Required for community-governed if not in ceremony. */
  adminSignatures?: Array<{ signerDid: string; signature: Uint8Array }>;

  // ── Signing ─────────────────────────────────────────────────────────
  /** The signing key for the issuer. Required for DTG VC production; optional
   *  for server-side record-only credential creation. */
  signerSecretKey?: Uint8Array;
  /** The verification method DID URL (e.g. 'did:peer:4...z#key-1'). */
  verificationMethod: string;
  /** Optional: override the signing key for a specific proof format. */
  proofOptions?: {
    format?: 'DataIntegrityProof';
    cryptosuite?: string;
    created?: Date;
  };

  // ── Lifecycle ───────────────────────────────────────────────────────
  validFrom?: Date;
  validUntil?: Date;

  // ── Ceremony context (ceremony-bound only) ───────────────────────────
  /** The threadId of the trust task ceremony. REQUIRED for VWC. */
  taskContext?: string;

  // ── Personhood ──────────────────────────────────────────────────────
  /**
   * Mark this VMC as a PersonhoodCredential. Only for MembershipCredential.
   *
   * F-01 / F-02: the `PersonhoodCredential` type is added **before** signing
   * (via `typeOverride`), so it is inside the signed bytes. The post-sign
   * `vc.type = […]` mutation that used to invalidate every PHC is prohibited —
   * `buildDtgCredential()` deep-freezes its result, so it would now throw.
   */
  assertPersonhood?: boolean;

  // ── Extensions ──────────────────────────────────────────────────────
  /** Arbitrary metadata for P2PTS-specific extensions. */
  extension?: Record<string, unknown>;
}

// ── Minting Result ─────────────────────────────────────────────────────

/**
 * Result of a successful credential minting operation.
 */
export interface CredentialMintResult {
  /** Deterministic UUID for cross-node dedup (also the primary key). */
  credentialUuid: string;
  /** The serialized credential in its native format. */
  serialized: string;
  /** The format of `serialized`. */
  format: CredentialFormat;
  /** The W3C VC JSON (populated for DTG credentials, null for CESR). */
  w3cVcJson: string | null;
  /** The CESR-encoded credential (populated for community, null for DTG). */
  cesrEncoded: string | null;
  /** The self-addressing digest (SHA-256 hex). */
  digest: string;
  /** The credential kind that was minted. */
  kind: CredentialKind;
  /** Whether a ceremony proposal was created (for community-governed). */
  ceremonyProposalId?: number;
}

// ── Verification ───────────────────────────────────────────────────────

/**
 * Result of credential verification.
 */
export interface CredentialVerifyResult {
  valid: boolean;
  reason?: string;
  /** The credential kind detected, if parseable. */
  detectedKind?: CredentialKind;
  /** For community credentials: number of valid admin signatures. */
  validSignatureCount?: number;
  /** For DTG credentials: whether the proof verified. */
  proofVerified?: boolean;
  /**
   * For ceremony-bound credentials: whether the task's OUTCOME EVIDENCE was
   * fetched and its digest matched.
   *
   * Deliberately never set today. It was previously populated from the mere
   * PRESENCE of `taskContext` (`obj.taskContext !== undefined`), which reported a
   * verification that never ran (audit F-003). Unset means "not checked" — the
   * truthful value until the evidence fetch + digest comparison is implemented.
   */
  taskContextVerified?: boolean;
}

// ── View Model (UI) ────────────────────────────────────────────────────

/**
 * A view model for the UI's Credentials tab — one row per credential,
 * annotated with scenario, governance, and usage hints.
 */
export interface CredentialViewModel {
  // ── Identity ────────────────────────────────────────────────────────
  credentialUuid: string;
  kind: CredentialKind;
  scenario: CredentialScenario;
  governance: GovernanceModel;
  format: CredentialFormat;

  // ── Display ─────────────────────────────────────────────────────────
  label: string;               // "Relationship Credential"
  shortCode: string;           // "VRC"
  issuerName: string;
  subjectName: string;
  claimSummary: string;        // One-line summary of the claim

  // ── Status ──────────────────────────────────────────────────────────
  status: 'issued' | 'pending_signatures' | 'revoked' | 'expired';
  isDtgConformant: boolean;    // Has valid W3C VC JSON
  hasTaskContext: boolean;     // Carries threadId
  validFrom: Date | null;
  validUntil: Date | null;

  // ── Governance ──────────────────────────────────────────────────────
  governanceDid?: string;      // VTC DID for community-governed
  thresholdRequired?: number;  // M-of-N threshold
  signatureCount?: number;     // Current valid signatures

  // ── Usage hints ─────────────────────────────────────────────────────
  usageScenario: string;       // "Use this to prove you're a real person to any verifier"
  canPresent: boolean;         // Can this be presented to a verifier?
  canRevoke: boolean;          // Can the holder revoke this?
}

// ── Factory Interface ───────────────────────────────────────────────────

/**
 * The CredentialFactory — unified interface for credential operations.
 *
 * Injected dependencies (not hard-coded):
 *   - db: DataSource — the application database
 *   - guard: GovernanceGuard — governance rule validation
 *   - coordinator: CeremonyCoordinator — ceremony lifecycle (optional, for governed creds)
 *   - txManager: TransactionManager — transaction coordinator (optional, for agent↔server transport)
 */
export interface CredentialFactory {
  // ── Minting ────────────────────────────────────────────────────────
  /**
   * Mint a credential of any supported kind.
   *
   * Routes internally to the correct signing path (W3C VC for DTG types,
   * CESR for community credentials, JCard for RCards). Validates governance
   * rules before minting community-governed credentials.
   */
  mint(request: CredentialMintRequest): Promise<CredentialMintResult>;

  // ── Verification ────────────────────────────────────────────────────
  /**
   * Verify any credential, auto-detecting format and kind.
   * Uses W3C VC proof verification for DTG credentials,
   * CESR signature verification for community credentials.
   */
  verify(raw: string | Uint8Array | Record<string, unknown>): Promise<CredentialVerifyResult>;

  // ── View model for UI ───────────────────────────────────────────────
  /**
   * Build a CredentialViewModel for every credential in the database,
   * annotated with scenario, governance, and usage hints.
   * The UI's Credentials tab calls this to populate grouped lists.
   */
  listViewModels(
    filters?: {
      identityId?: number;
      kind?: CredentialKind;
      scenario?: CredentialScenario;
      status?: 'issued' | 'pending_signatures' | 'revoked' | 'expired';
    },
  ): Promise<CredentialViewModel[]>;

  // ── Introspection ───────────────────────────────────────────────────
  /**
   * Which credential kinds are appropriate for a given scenario?
   * Used by the UI to show only relevant options in dropdowns.
   */
  kindsForScenario(scenario: CredentialScenario): CredentialKind[];

  /**
   * What governance model applies to a given credential kind?
   */
  governanceForKind(kind: CredentialKind): GovernanceModel;

  /**
   * Which scenarios can a given credential be used in?
   */
  scenariosForKind(kind: CredentialKind): CredentialScenario[];

  /**
   * Does a credential kind require a ceremony (governance proposal + approvals)?
   */
  requiresCeremony(kind: CredentialKind): boolean;

  /**
   * Does a credential kind produce a W3C VC (DTG-conformant) output?
   */
  producesDtgVc(kind: CredentialKind): boolean;
}
