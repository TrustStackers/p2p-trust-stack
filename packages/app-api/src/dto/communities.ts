// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `communities` DTOs — the read models the Communities and Rules pages consume.
 *
 * Every type here is a **view**, never a database row. The domain assembles them from repositories
 * (`identities-repo`, `governance-repo`, `did-documents-repo`, `memberships-repo`) and from the typed agent
 * handle, so nothing in this file can carry a column name the caller would have to know about.
 *
 * ## Why the wire shape is preserved exactly
 *
 * These routes are already consumed by `communities.html` and `rules.html`. The DTOs keep the existing field
 * names (`adminThresholdM`, `parentCommunityUuid`, `personhoodAsserted`, …) rather than "improving" them, so
 * the delegation is a pure move: the pages must not need a single edit. Where a name is awkward it is kept
 * with a comment saying it is the wire contract, not a recommendation.
 */

/**
 * One row of the community list (`GET /api/communities`).
 *
 * The shape is the runtime's own list projection, kept verbatim: `communities.html` reads `name`, `did`,
 * `role`, `uuid`, `myRole` and `adminThresholdN` directly. Field names are the wire contract — `myRole`
 * carries the *caller's* membership role, which is what gates the "Invite Member" action, so it is not the
 * same thing as `role`.
 */
export interface CommunityDto {
  /** Stable cross-node anchor (the identity uuid). */
  uuid: string;
  name: string;
  /** `'vtc'` or `'vtn'` — what kind of community this is. */
  role: string;
  did: string;
  adminThresholdM: number | null;
  adminThresholdN: number | null;
  /** THIS agent's membership role in the community, or null when not a member. */
  myRole: string | null;
}

/** A member as the detail view renders them. */
export interface CommunityMemberDto {
  name: string;
  did: string | null;
  role: string;
  status: string;
  /** True once the mutual-acknowledgment ceremony has completed for this member. */
  personhoodAsserted: boolean;
}

/** The governance half of the detail view. */
export interface CommunityGovernanceDto {
  adminThresholdM: number | null;
  adminThresholdN: number | null;
  /** Claim types the community permits, from its `claim-type-allow` policy bindings. */
  allowedClaimTypes: string[];
  parentCommunityUuid: string | null;
}

/** `GET /api/community-detail` — the community plus its roster and governance. */
export interface CommunityDetailDto {
  name: string;
  did: string | null;
  role: string;
  uuid: string;
  governance: CommunityGovernanceDto;
  members: CommunityMemberDto[];
}

/** `GET /api/vtcs/check-name` — the utility server's verdict on a proposed name. */
export interface CommunityNameCheckDto {
  available: boolean;
  message?: string;
}

/** A candidate parent VTN for the create-community picker. */
export interface ParentVtnDto {
  uuid: string;
  name: string | null;
  did: string | null;
  /**
   * The namespace this VTN serves. Present only when the value came from the utility server — a VTN learned
   * from the local list carries `null`, which is why the domain dedupes in favour of the entry that has one.
   */
  namespace: string | null;
}

/** A founding-admin candidate for the create-community checklist. */
export interface AdminCandidateDto {
  uuid: string;
  /** Null when the peer has no display name yet — the wire shape, preserved rather than invented. */
  name: string | null;
  did: string;
  /** True for this agent itself, which is always its own first founding admin. */
  isCreator: boolean;
}

/**
 * A governance-change proposal as the Rules page lists it.
 *
 * Re-exported rather than re-modelled: the utility server owns the proposal lifecycle (scope resolution,
 * hashing, durable fan-out), so this layer has no business reshaping its view. The alias exists so the domain
 * and the route share one name.
 */
export type { GovernanceChangeProposalView as GovernanceProposalDto }
  from '@p2p-trust-stack/core/services/governance-change.js';

/** A pending ceremony awaiting THIS agent's co-signature. */
export interface PendingCeremonyDto {
  /** The ceremony id the agent passes to `approveCeremony`. */
  ceremonyId: string;
  name?: string;
  kind?: string;
  /** Founding-admin uuids whose co-signature the ceremony requires. */
  adminUuids?: string[];
  threshold?: number;
  /** Distinct verified co-signatures recorded so far. */
  approvalCount?: number;
  proposalHash?: string;
  expiresAt?: number;
  status?: string;
}

/** One recorded step of a ceremony run, in the order it happened. */
export interface CeremonyLogStepDto {
  /** The step's trust-task type, e.g. `task:p2pts:credential:membership-vmc:0.1`. */
  type: string;
  /** Reader-facing wording, filled from the catalogue's `display` column. */
  label?: string | null;
  /** When the step was recorded. */
  recordedAt?: number;
}

/** One ceremony run as the Communities page lists it. */
export interface CeremonyLogThreadDto {
  threadId: string;
  /** Reader-facing name of the ceremony, from `ceremony_templates.display`. */
  label?: string | null;
  status?: string;
  startedAt?: number;
  stepCount?: number;
}

/** `GET /api/ceremony/:uuid` — a founding ceremony's current state. */
export interface CeremonyStatusDto {
  status?: string;
  errorReason?: string | null;
  /** Present only on failure; the route surfaces it as a 502 body. */
  error?: string;
  /** Distinct, verified co-signatures recorded so far (the server's `approvalCount`). */
  approvalCount?: number;
  /** The declared founding-admin uuid set (the server's `adminUuids`). */
  adminUuids?: string[];
}

/** The outcome of `POST /api/vtcs` — the founding ceremony's verdict. */
export interface CreateCommunityResultDto {
  success: boolean;
  error?: string;
  ceremonyId?: string;
  /** True when the ceremony is begun but still short of the co-signature quorum. */
  awaitingCoSignatures?: boolean;
  approvalsReceived?: number;
  approvalsRequired?: number;
}

/** The outcome of `POST /api/communities/:did/invite` — the minted VIC + shareable OOBI. */
export interface CommunityInviteDto {
  /** The signed InvitationCredential's uuid. */
  invitationUuid?: string;
  /** The shareable OOBI the invitee redeems. */
  oobi?: string;
  /** Present when the server refused the invitation. */
  error?: string;
}

/** The outcome of `POST /api/governance/propose` or `…/approve`. */
export interface GovernanceChangeResultDto {
  success: boolean;
  proposalId?: string;
  status?: string;
  error?: string;
}

/**
 * A community's governance summary — what a list view needs, and nothing it must not have.
 *
 * This exists because `GET /api/vtcs` used to return the raw `VtcGovernanceDoc[]`, which publishes
 * `adminVids` (CESR public keys), `digest` (raw bytes) and `signatures` (raw Ed25519 bytes). None of those
 * belongs on a wire, and the only consumer used none of them — it read `name`, `role` (a field that **does not
 * exist** on a governance doc, so every VTN rendered as "VTC") and fell back to printing admin **VIDs** as if
 * they were names.
 *
 * `kind` is resolved from the local `identities.role`, not from the signed document: the role is a local
 * classification, and putting it on `VtcGovernanceDoc` would imply it is part of what the admins signed.
 */
export interface GovernanceDocDto {
  /** The community's DID — an identity reference, not a key. */
  did: string;
  name: string;
  /** `'vtc'` or `'vtn'`. */
  kind: string;
  /** Signature threshold: a credential needs ≥ this many valid admin signatures. */
  threshold: number;
  /** Claim types this community is allowed to issue. */
  allowedClaimTypes: string[];
  /**
   * How many admins it has — a **count**, never the list.
   *
   * The list would be CESR public keys (`adminVids`) or identity DIDs (`adminDids`). A caller that needs
   * admin *names* asks `communities.detail()`, which is a different question with a different answer.
   */
  adminCount: number;
  createdAt: number;
}

