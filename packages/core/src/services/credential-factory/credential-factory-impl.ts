// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * CredentialFactoryImpl — unified credential minting, verification, and display.
 *
 * Routes minting requests to the correct signing path (W3C VC for DTG types,
 * CESR for community credentials, JCard for RCards). Invokes GovernanceGuard
 * and CeremonyCoordinator where required by the credential kind's governance model.
 *
 * Uses the TransactionCoordinator (via TransactionManager) for agent↔server
 * transport when minting community-governed credentials that require ceremony.
 *
 * @module credential-factory/credential-factory-impl
 */

import { sha256 } from '../../crypto/primitives.js';
import { buildDtgCredential, serializeDtgCredential, verifyDtgProof } from '../dtg-credential.js';
import type { DtgCredentialVc } from '../dtg-credential.js';
import { toDtgVic } from '../dtg/dtg-vic.js';
import { toDtgVpc } from '../dtg/dtg-vpc.js';
import { toDtgVec } from '../dtg/dtg-vec.js';
import { DTG_PREDICATE_ENDORSES, DTG_PREDICATE_WITNESSED } from '../dtg/profile-policy.js';
import type { OobiPayload } from '../../relationship/types.js';
import { buildRCard } from '../dtg/rcard.js';
import type { ProfileCard } from '../profiles.js';

import type { DataSource } from '../../db/data-source.js';
import * as credentialsRepo from '../../db/repositories/credentials-repo.js';
import type { VcType, CredentialRow } from '../../db/repositories/credentials-repo.js';
import type { GovernanceGuard } from '../governance-guard.js';
import type { CeremonyCoordinator } from '../../tx/ceremony-coordinator.js';
import { DidResolver } from '../../did/did-resolver.js';


import type {
  CredentialKind,
  CredentialScenario,
  GovernanceModel,
  CredentialFormat,
  CredentialMintRequest,
  CredentialMintResult,
  CredentialVerifyResult,
  CredentialViewModel,
  CredentialFactory,
} from './types.js';

// ── VcType ↔ CredentialKind Mapping ──────────────────────────────────────

/**
 * Map the existing vc_type column values to the new CredentialKind domain type.
 * Some old vcType values don't have a 1:1 match — we use closest equivalents.
 */
export function vcTypeToKind(vcType: VcType): CredentialKind {
  switch (vcType) {
    case 'vrc': return 'RelationshipCredential';
    case 'vmc': return 'MembershipCredential';
    case 'vec': return 'EndorsementCredential';
    case 'vic': return 'InvitationCredential';
    case 'custom_endorsement': return 'WitnessCredential';
    case 'delegation': return 'DelegationCredential';
    default: return 'RelationshipCredential'; // fallback
  }
}

/**
 * Map a CredentialKind to the vc_type column value for storage.
 */
export function kindToVcType(kind: CredentialKind): VcType {
  switch (kind) {
    case 'RelationshipCredential': return 'vrc';
    case 'MembershipCredential': return 'vmc';
    case 'EndorsementCredential': return 'vec';
    case 'WitnessCredential': return 'custom_endorsement';
    case 'DelegationCredential': return 'delegation';
    case 'AuthorizationCredential': return 'delegation'; // closest fit
    case 'InvitationCredential': return 'vic';
    case 'PersonaCredential': return 'custom_endorsement'; // no dedicated column value
    case 'RelationshipCard': return 'custom_endorsement'; // non-credential structure
    default: return 'custom_endorsement';
  }
}

// ── Credential Registry (Routing Table) ──────────────────────────────────

/**
 * The routing table that defines every credential kind's properties.
 * Adding a new credential type = adding one row here + one builder function.
 */
interface RegistryEntry {
  scenario: CredentialScenario[];
  governance: GovernanceModel;
  format: CredentialFormat;
  producesDtgVc: boolean;
  requiresCeremony: boolean;
  label: string;
  shortCode: string;
  usageHint: string;
}

export const CREDENTIAL_REGISTRY: Record<CredentialKind, RegistryEntry> = {
  // ── Edge Credentials ────────────────────────────────────────────────
  RelationshipCredential: {
    scenario: ['peer-verification'],
    governance: 'peer-to-peer',
    format: 'w3c-vc-json-ld',
    producesDtgVc: true,
    requiresCeremony: false,
    label: 'Relationship Credential',
    shortCode: 'VRC',
    usageHint: 'Proves a bidirectional trust relationship with one specific peer. Use to verify personhood or establish a trusted channel.',
  },
  MembershipCredential: {
    scenario: ['community-join', 'community-issue'],
    governance: 'community-governed',
    format: 'w3c-vc-json-ld',
    producesDtgVc: true,
    requiresCeremony: true,
    label: 'Membership Credential',
    shortCode: 'VMC',
    usageHint: 'Proves membership in a Verified Trust Community. A PHC variant proves unique personhood. Required for community-gated access.',
  },

  // ── Invitation Credentials ──────────────────────────────────────────
  InvitationCredential: {
    scenario: ['invite-new-member'],
    governance: 'ceremony-bound',
    format: 'w3c-vc-json-ld',
    producesDtgVc: true,
    requiresCeremony: true,
    label: 'Invitation Credential',
    shortCode: 'VIC',
    usageHint: 'Authorizes a prospective member to join a community. Only valid within the onboarding ceremony.',
  },

  // ── Annotation Credentials ──────────────────────────────────────────
  PersonaCredential: {
    scenario: ['manage-personas'],
    governance: 'self-issued',
    format: 'w3c-vc-json-ld',
    producesDtgVc: true,
    requiresCeremony: false,
    label: 'Persona Credential',
    shortCode: 'VPC',
    usageHint: 'Links a persona-specific DID to your core identity. Use to present differently in different contexts without correlation.',
  },
  EndorsementCredential: {
    scenario: ['community-issue'],
    governance: 'community-governed',
    format: 'w3c-vc-json-ld',
    producesDtgVc: true,
    requiresCeremony: true,
    label: 'Endorsement Credential',
    shortCode: 'VEC',
    usageHint: 'Community-issued attestation of skills, reputation, or qualifications. The endorsement vocabulary is community-defined.',
  },
  WitnessCredential: {
    scenario: ['community-issue'],
    governance: 'community-governed',
    format: 'w3c-vc-json-ld',
    producesDtgVc: true,
    requiresCeremony: true,
    label: 'Witness Credential',
    shortCode: 'VWC',
    usageHint: 'Third-party attestation that a relationship or event occurred under specific conditions. Carries a trust task context binding.',
  },

  // ── Verifiable Data Structures ──────────────────────────────────────
  RelationshipCard: {
    scenario: ['share-contact'],
    governance: 'peer-to-peer',
    format: 'jcard',
    producesDtgVc: true,   // Wraps JCard in a W3C VC envelope
    requiresCeremony: false,
    label: 'Contact Card',
    shortCode: 'RCard',
    usageHint: 'Human-readable contact information (name, email, phone, etc.) wrapped in a verifiable card. Share with contacts.',
  },

  // ── (future) ─────────────────────────────────────────
  DelegationCredential: {
    scenario: ['delegate-authority'],
    governance: 'community-governed',
    format: 'w3c-vc-json-ld',
    producesDtgVc: true,
    requiresCeremony: true,
    label: 'Delegation Credential',
    shortCode: 'VDC',
    usageHint: 'Delegates authority from one entity to another within a community. Future spec — not yet finalized.',
  },
  AuthorizationCredential: {
    scenario: ['delegate-authority'],
    governance: 'community-governed',
    format: 'w3c-vc-json-ld',
    producesDtgVc: true,
    requiresCeremony: true,
    label: 'Authorization Credential',
    shortCode: 'VAC',
    usageHint: 'Grants specific permissions or access rights. Future spec — not yet finalized.',
  },
};

// ── CredentialFactory Implementation ─────────────────────────────────────

/**
 * The CredentialFactoryImpl — unified credential minting, verification, and display.
 *
 * Dependencies are injected via constructor (not hard-coded):
 *   - db: DataSource — the application database
 *   - guard: GovernanceGuard — governance rule validation
 *   - ceremonyCoordinator: CeremonyCoordinator — ceremony lifecycle (optional)
 *   - txManager: TransactionManager — transaction coordinator (optional)
 */
export class CredentialFactoryImpl implements CredentialFactory {
  private readonly db: DataSource;
  private readonly guard?: GovernanceGuard;
  private readonly ceremonyCoordinator?: CeremonyCoordinator;
  private readonly didResolver: DidResolver;

  constructor(
    db: DataSource,
    guard?: GovernanceGuard,
    ceremonyCoordinator?: CeremonyCoordinator,
    didResolver?: DidResolver,
  ) {
    this.db = db;
    this.guard = guard;
    this.ceremonyCoordinator = ceremonyCoordinator;
    this.didResolver = didResolver ?? new DidResolver();
  }

  // ── Mint ────────────────────────────────────────────────────────────

  async mint(request: CredentialMintRequest): Promise<CredentialMintResult> {
    const reg = CREDENTIAL_REGISTRY[request.kind];
    if (!reg) throw new Error(`Unknown credential kind: ${request.kind}`);

    // 1. Validate that kind matches scenario.
    if (!reg.scenario.includes(request.scenario)) {
      throw new Error(
        `${request.kind} cannot be used in scenario '${request.scenario}'. ` +
        `Valid scenarios: ${reg.scenario.join(', ')}`,
      );
    }

    // 2. Governance check (for community-governed credentials).
    if (reg.governance === 'community-governed') {
      if (!this.guard) {
        throw new Error(`${request.kind} requires GovernanceGuard but none was provided to factory.`);
      }
      if (!request.governanceDid) {
        throw new Error(`${request.kind} requires governanceDid (the VTC's DID).`);
      }
      const result = await this.guard.validateCredentialIssuance({
        kind: request.kind,
        issuerDid: request.issuerDid,
        subjectDid: request.subjectDid,
        governanceDid: request.governanceDid,
        adminSignatures: request.adminSignatures,
      });
      if (!result.allowed) {
        throw new Error(`Governance rejected ${request.kind}: ${result.reason}`);
      }
    }

    // 3. Route to the correct builder based on format.
    let serialized: string;
    let w3cJson: string | null = null;
    let cesrEncoded: string | null = null;

    switch (reg.format) {
      case 'w3c-vc-json-ld': {
        if (request.signerSecretKey) {
          const vc = this.buildW3cVc(request);
          serialized = serializeDtgCredential(vc);
          w3cJson = serialized;
        } else {
          // Server-side record-only: no signing key, no DTG VC
          serialized = JSON.stringify(request.claim);
          w3cJson = null;
        }
        break;
      }
      case 'cesr-group-frame': {
        throw new Error('CESR credential minting via factory not yet implemented.');
      }
      case 'jcard': {
        if (request.signerSecretKey) {
          const vc = this.buildRCardVc(request);
          serialized = serializeDtgCredential(vc);
          w3cJson = serialized;
        } else {
          serialized = JSON.stringify(request.claim);
          w3cJson = null;
        }
        break;
      }
      default:
        throw new Error(`Unsupported credential format: ${reg.format}`);
    }

    // 4. Compute self-addressing digest
    const digestBytes = sha256(new TextEncoder().encode(serialized));
    const digest = Array.from(digestBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // 5. Store in database via credentials-repo.
    const issuerUuid = (request.extension?.issuerIdentityUuid as string) ?? '';
    const subjectUuid = request.subjectIdentityUuid ?? (request.extension?.subjectIdentityUuid as string) ?? '';

    const credentialUuid = await credentialsRepo.create(this.db, {
      vcType: kindToVcType(request.kind),
      issuerIdentityUuid: issuerUuid,
      subjectIdentityUuid: subjectUuid,
      w3cVcJson: w3cJson ?? undefined,
      claim: JSON.stringify(request.claim),
      validFrom: Math.floor((request.validFrom ?? new Date()).getTime() / 1000),
      validUntil: request.validUntil ? Math.floor(request.validUntil.getTime() / 1000) : undefined,
      credentialDigest: digest,
    });

    // 6. If ceremony-bound or community-governed, a ceremony proposal may be needed.
    let ceremonyProposalId: number | undefined;
    if (reg.requiresCeremony && this.ceremonyCoordinator && request.governanceDid) {
      // Ceremony proposal initiation is deferred to the caller/wire-up layer.
      // The factory records that a ceremony is needed but doesn't auto-initiate.
    }

    return {
      credentialUuid,
      serialized,
      format: reg.format,
      w3cVcJson: w3cJson,
      cesrEncoded,
      digest,
      kind: request.kind,
      ceremonyProposalId,
    };
  }

  // ── W3C VC Builders (internal routing) ──────────────────────────────

  private buildW3cVc(request: CredentialMintRequest): DtgCredentialVc {
    const validFrom = Math.floor((request.validFrom ?? new Date()).getTime() / 1000);
    const validUntil = request.validUntil
      ? Math.floor(request.validUntil.getTime() / 1000)
      : undefined;

    switch (request.kind) {
      case 'RelationshipCredential': {
        return buildDtgCredential({
          subtype: 'RelationshipCredential',
          id: `urn:uuid:${crypto.randomUUID()}`,
          issuerDid: request.issuerDid,
          subjectDid: request.subjectDid,
          claim: request.claim,
          validFrom,
          validUntil,
          verificationMethod: request.verificationMethod,
          signerSecretKey: request.signerSecretKey as Uint8Array,
        });
      }

      case 'MembershipCredential': {
        // F-01 / F-02: the personhood type array is decided BEFORE signing. The
        // old post-signing `vc.type = …` mutation changed the document under a
        // signature that already covered the previous array, so a PHC never
        // verified. `buildDtgCredential()` also deep-freezes its result, so that
        // mutation could not be reintroduced silently.
        return buildDtgCredential({
          subtype: 'MembershipCredential',
          id: `urn:uuid:${crypto.randomUUID()}`,
          issuerDid: request.issuerDid,
          subjectDid: request.subjectDid,
          claim: {
            memberOf: request.issuerDid,
            membershipRole: (request.claim.membershipRole as string) ?? 'member',
            membershipSince: new Date(validFrom * 1000).toISOString(),
            ...request.claim,
          },
          validFrom,
          validUntil,
          verificationMethod: request.verificationMethod,
          signerSecretKey: request.signerSecretKey as Uint8Array,
          ...(request.assertPersonhood
            ? { typeOverride: ['VerifiableCredential', 'DTGCredential', 'MembershipCredential', 'PersonhoodCredential'] }
            : {}),
        });
      }

      case 'WitnessCredential': {
        const claimJson = JSON.stringify(request.claim);
        const claimDigest = sha256(new TextEncoder().encode(claimJson));
        const digestHex = 'sha256:' + Array.from(claimDigest)
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');

        return buildDtgCredential({
          subtype: 'WitnessCredential',
          id: `urn:uuid:${crypto.randomUUID()}`,
          issuerDid: request.issuerDid,
          subjectDid: request.subjectDid,
          claim: {
            digest: digestHex,
            witnessContext: {
              event: request.claim.type ?? 'attestation',
              observedAt: new Date(validFrom * 1000).toISOString(),
              taskContext: request.taskContext,
              ...request.claim,
            },
          },
          validFrom,
          validUntil,
          verificationMethod: request.verificationMethod,
          signerSecretKey: request.signerSecretKey as Uint8Array,
        });
      }

      case 'EndorsementCredential': {
        return toDtgVec({
          issuerDid: request.issuerDid,
          subjectDid: request.subjectDid,
          endorsedCredentialDigest: request.claim.endorsedCredentialDigest as string,
          endorsementType: (request.claim.endorsementType as string) ?? 'community-endorsement',
          verificationMethod: request.verificationMethod,
          signerSecretKey: request.signerSecretKey as Uint8Array,
          validFrom,
          validUntil,
        });
      }

      case 'InvitationCredential': {
        const oobi = (request.claim.oobi as unknown as OobiPayload) ?? { vid: request.issuerDid, peerId: '', multiaddrs: [] };
        return toDtgVic({
          oobi,
          issuerDid: request.issuerDid,
          subjectDid: request.subjectDid,
          taskContext: request.taskContext ?? '',
          verificationMethod: request.verificationMethod,
          signerSecretKey: request.signerSecretKey as Uint8Array,
          validFrom,
          validUntil,
        });
      }

      case 'PersonaCredential': {
        return toDtgVpc({
          issuerDid: request.issuerDid,
          subjectDid: request.subjectDid,
          personaProfileId: (request.claim.personaProfileId as number) ?? 0,
          personaLabel: (request.claim.personaLabel as string) ?? 'persona',
          verificationMethod: request.verificationMethod,
          signerSecretKey: request.signerSecretKey as Uint8Array,
          validFrom,
          validUntil,
        });
      }

      case 'DelegationCredential':
      case 'AuthorizationCredential': {
        return buildDtgCredential({
          subtype: request.kind,
          id: `urn:uuid:${crypto.randomUUID()}`,
          issuerDid: request.issuerDid,
          subjectDid: request.subjectDid,
          claim: request.claim,
          validFrom,
          validUntil,
          verificationMethod: request.verificationMethod,
          signerSecretKey: request.signerSecretKey as Uint8Array,
        });
      }

      default:
        throw new Error(`No W3C VC builder for credential kind: ${request.kind}`);
    }
  }

  private buildRCardVc(request: CredentialMintRequest): DtgCredentialVc {
    const profile: ProfileCard = {
      profileUuid: (request.claim.profileUuid as string) ?? '',
      identityUuid: (request.extension?.subjectIdentityUuid as string) ?? '',
      label: (request.claim.label as string) ?? 'contact',
      purpose: (request.claim.purpose as string) ?? null,
      visibility: (request.claim.visibility as ProfileCard['visibility']) ?? 'public',
      claims: (request.claim.claims as ProfileCard['claims']) ?? [],
    };

    return buildRCard({
      profile,
      issuerDid: request.issuerDid,
      subjectDid: request.subjectDid,
      signerKey: {
        publicKey: new Uint8Array(32),
        secretKey: request.signerSecretKey as Uint8Array,
      },
      verificationMethod: request.verificationMethod,
      requestedKeys: request.extension?.requestedKeys as string[] | undefined,
    });
  }

  // ── Verify ──────────────────────────────────────────────────────────

  async verify(raw: string | Uint8Array | Record<string, unknown>): Promise<CredentialVerifyResult> {
    try {
      // Auto-detect format: try W3C VC JSON first
      let obj: Record<string, unknown>;
      if (typeof raw === 'string') {
        obj = JSON.parse(raw);
      } else if (raw instanceof Uint8Array) {
        obj = JSON.parse(new TextDecoder().decode(raw));
      } else {
        obj = raw;
      }

      // Check for W3C VC proof — a DataIntegrityProof of the suite we implement.
      // F-01: the cryptosuite is part of the gate, so a proof carrying a
      // different (or absent) cryptosuite is not silently treated as ours.
      const proofObj = obj.proof as Record<string, unknown> | undefined;
      if (proofObj && proofObj.type === 'DataIntegrityProof'
          && proofObj.cryptosuite === 'eddsa-jcs-2022') {
        const vc = obj as unknown as DtgCredentialVc;
        const typeArray = vc.type ?? [];
        // F-002: in v1.0 the profile is named by `credentialSubject.predicate`,
        // not by a type string, so detection has to read both.
        const subject = (vc.credentialSubject ?? {}) as Record<string, unknown>;
        const detectedKind = this.detectKindFromType(
          typeArray as string[],
          typeof subject.predicate === 'string' ? subject.predicate : undefined,
        );

        // Resolve the proof's verificationMethod (a DID URL) to key material,
        // bind the key to the credential's issuer (F-01), confirm the key is
        // authorized for the proof purpose, then verify the eddsa-jcs-2022
        // signature over the correct hashData.
        let proofVerified = false;
        let reason: string | undefined;
        try {
          const verificationMethod = vc.proof?.verificationMethod;
          if (!verificationMethod) {
            reason = 'proof missing verificationMethod';
          } else {
            const vm = await this.didResolver.dereferenceVerificationMethod(verificationMethod);
            if (!vm) {
              reason = `verificationMethod could not be dereferenced: ${verificationMethod}`;
            } else {
              // F-01 — bind verificationMethod, issuer and proofPurpose to the
              // authorized controller relationship. Without the controller check,
              // `issuer: did:victim` could be signed by an attacker's own key
              // under `verificationMethod: did:attacker#key-0`: the resolver would
              // fetch the attacker's key and the signature would verify.
              const issuerId = typeof vc.issuer === 'string'
                ? vc.issuer
                : (vc.issuer as { id?: string } | undefined)?.id;
              const purpose = vc.proof.proofPurpose ?? 'assertionMethod';
              if (!issuerId) {
                reason = 'credential has no issuer to bind the verification method to';
              } else if (vm.controller !== issuerId) {
                reason = `verificationMethod controller '${vm.controller}' is not the credential issuer '${issuerId}'`;
              } else if (!vm.proofPurposes.includes(purpose)) {
                // Fail CLOSED: the key must be authorized for the purpose by the
                // issuer's own DID document (it used to fail open when the key was
                // listed under no relationship at all).
                reason = `key for ${verificationMethod} is not authorized for proof purpose '${purpose}'`;
              } else {
                proofVerified = verifyDtgProof(vc, vm.rawKey);
                if (!proofVerified) reason = 'signature verification failed';
              }
            }
          }
        } catch (err) {
          reason = `proof verification error: ${(err as Error)?.message ?? String(err)}`;
        }

        // F-003, second half — `taskContextVerified` is deliberately NOT set here.
        //
        // It used to be `obj.taskContext !== undefined ? true : undefined`: a
        // PRESENCE check reported as verification. Nothing fetched the outcome
        // evidence and nothing compared a digest, so the flag could not
        // distinguish "the property exists" from "the evidence is valid".
        //
        // Setting it honestly needs three things that do not exist yet: resolve
        // the task context the claim references, fetch its outcome evidence, and
        // compare the digest. Until then "not checked" is the true value, and the
        // field is left unset (no caller reads it today — verified across the
        // tree, which is why removing the false positive is behaviour-preserving).

        return {
          valid: proofVerified,
          ...(reason ? { reason } : {}),
          detectedKind,
          proofVerified,
        };
      }

      // Not a W3C VC — try CESR or unknown
      return {
        valid: false,
        reason: 'Credential format not recognized — expected DataIntegrityProof (eddsa-jcs-2022) proof',
      };
    } catch (err) {
      return {
        valid: false,
        reason: `Verification error: ${(err as Error)?.message ?? err}`,
      };
    }
  }

  /**
   * Detect the credential kind from its `type` array — and, for a v1.0 statement
   * credential, which carries no concrete subtype, from its predicate.
   *
   * F-002: this is the verifier-side half of the profile change.
   * `WitnessCredential` and `EndorsementCredential` are profile names that are
   * "no longer a W3C type string", so a VEC/VWC's meaning lives in
   * `credentialSubject.predicate`; a type-only dispatch would return undefined
   * for both and lose the distinction the type string used to carry.
   */
  private detectKindFromType(typeArray: string[], predicate?: string): CredentialKind | undefined {
    if (typeArray.includes('StatementCredential')) {
      if (predicate === DTG_PREDICATE_WITNESSED) return 'WitnessCredential';
      if (predicate === DTG_PREDICATE_ENDORSES) return 'EndorsementCredential';
      return undefined;
    }
    const typeMap: Record<string, CredentialKind> = {
      'RelationshipCredential': 'RelationshipCredential',
      'MembershipCredential': 'MembershipCredential',
      'InvitationCredential': 'InvitationCredential',
      'PersonaCredential': 'PersonaCredential',
      'EndorsementCredential': 'EndorsementCredential',
      'WitnessCredential': 'WitnessCredential',
      'DelegationCredential': 'DelegationCredential',
      'AuthorizationCredential': 'AuthorizationCredential',
      'RelationshipCard': 'RelationshipCard',
    };
    for (const type of typeArray) {
      if (typeMap[type]) return typeMap[type];
    }
    return undefined;
  }

  // ── View Models ─────────────────────────────────────────────────────

  async listViewModels(filters?: {
    identityUuid?: string;
    kind?: CredentialKind;
    scenario?: CredentialScenario;
    status?: 'issued' | 'pending_signatures' | 'revoked' | 'expired';
  }): Promise<CredentialViewModel[]> {
    const rows = await credentialsRepo.list(this.db, {
      vcType: filters?.kind ? kindToVcType(filters.kind) : undefined,
    });

    return rows
      .filter(r => {
        if (!filters?.status) return true;
        return r.status === filters.status;
      })
      .filter(r => {
        if (!filters?.identityUuid) return true;
        return r.issuerIdentityUuid === filters.identityUuid || r.subjectIdentityUuid === filters.identityUuid;
      })
      .map(r => this.rowToViewModel(r))
      .filter(vm => {
        if (!filters?.scenario) return true;
        return vm.scenario === filters.scenario;
      });
  }

  private rowToViewModel(r: CredentialRow): CredentialViewModel {
    const kind = vcTypeToKind(r.vcType);
    const reg = CREDENTIAL_REGISTRY[kind];
    let claimSummary = '(none)';
    if (r.claim) {
      try {
        const parsed = JSON.parse(r.claim);
        claimSummary = (parsed.type as string) ?? (parsed.membershipRole as string) ?? JSON.stringify(parsed).slice(0, 40);
      } catch { claimSummary = r.claim.slice(0, 40); }
    }

    let hasTaskContext = false;
    if (r.w3cVcJson) {
      try { hasTaskContext = JSON.parse(r.w3cVcJson).taskContext !== undefined; } catch { /* ignore */ }
    }

    return {
      credentialUuid: r.uuid,
      kind,
      scenario: reg.scenario[0],
      governance: reg.governance,
      format: reg.format,
      label: reg.label,
      shortCode: reg.shortCode,
      issuerName: `#${r.issuerIdentityUuid.slice(0, 8)}`,
      subjectName: `#${r.subjectIdentityUuid.slice(0, 8)}`,
      claimSummary,
      status: r.status,
      isDtgConformant: r.w3cVcJson !== null,
      hasTaskContext,
      validFrom: r.validFrom ? new Date(r.validFrom * 1000) : null,
      validUntil: r.validUntil ? new Date(r.validUntil * 1000) : null,
      governanceDid: undefined,
      thresholdRequired: r.thresholdRequired ?? undefined,
      signatureCount: 0,
      usageScenario: reg.usageHint,
      canPresent: r.status === 'issued' && kind !== 'InvitationCredential',
      canRevoke: r.status === 'issued',
    };
  }

  // ── Introspection ───────────────────────────────────────────────────

  kindsForScenario(scenario: CredentialScenario): CredentialKind[] {
    return (Object.entries(CREDENTIAL_REGISTRY) as [CredentialKind, RegistryEntry][])
      .filter(([_, reg]) => reg.scenario.includes(scenario))
      .map(([kind]) => kind);
  }

  governanceForKind(kind: CredentialKind): GovernanceModel {
    return CREDENTIAL_REGISTRY[kind].governance;
  }

  scenariosForKind(kind: CredentialKind): CredentialScenario[] {
    return CREDENTIAL_REGISTRY[kind].scenario;
  }

  requiresCeremony(kind: CredentialKind): boolean {
    return CREDENTIAL_REGISTRY[kind].requiresCeremony;
  }

  producesDtgVc(kind: CredentialKind): boolean {
    return CREDENTIAL_REGISTRY[kind].producesDtgVc;
  }
}
