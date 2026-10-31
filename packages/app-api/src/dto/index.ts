// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * DTO barrel.
 *
 * Every type here is part of the public contract. Nothing in this directory may be a database row, and no
 * interface may carry an index signature — `test/trust_app_api/surface.test.ts` checks the source for both.
 */
export type {
  AgentMetaDto,
  AgentSummaryDto,
  IdentityRowDto,
  IdentityDto,
  SignResultDto,
  ActivateResultDto,
  DeactivateResultDto,
  CreatedIdentityDto,
  RecoveryStateDto,
  IdentityLookupDto,
} from './identity.js';

export type {
  HealthDto,
  ReadyDto,
  ConnectivityStatusDto,
  ConnectivityFailureKind,
  DiscoveredPeerDto,
  NetworkProfileDto,
  BootstrapStatusDto,
  BootstrapRefreshDto,
  UtilityServerStatusDto,
  VtnOptionDto,
  PushIdentityDto,
  OobiDto,
  ConnectionEventDto,
  BootstrapConfigView,
  BootstrapClientEnv,
} from './connectivity.js';

export type { RegisterResultDto, ResolvedNameDto, NameEntryDto } from './names.js';

export type {
  CredentialDto,
  CredentialSourceDto,
  CredentialSignatureDto,
  CredentialAckDto,
  CredentialScenarioDto,
  CredentialViewModelsDto,
  InvitationDto,
  StoredCredentialDto,
  VtcCredentialDto,
  IssueVrcInput,
  IssuedCredentialDto,
  VerifyVrcInput,
  VrcVerificationDto,
} from './credentials.js';

export type {
  ProfileVisibilityDto,
  ProfileClaimValueTypeDto,
  ProfileClaimDisclosureDto,
  ProfileDto,
  ProfileClaimDto,
  ProfileCardClaimDto,
  ProfileCardDto,
  ProfileSyncStatusDto,
  RemovedDto,
} from './profiles.js';

export type {
  CommunityDto,
  CommunityDetailDto,
  CommunityMemberDto,
  CommunityGovernanceDto,
  CommunityNameCheckDto,
  CommunityInviteDto,
  ParentVtnDto,
  AdminCandidateDto,
  CreateCommunityResultDto,
  GovernanceProposalDto,
  GovernanceChangeResultDto,
  GovernanceDocDto,
  CeremonyLogThreadDto,
  CeremonyLogStepDto,
  PendingCeremonyDto,
  CeremonyStatusDto,
} from './communities.js';

export type {
  ContextDto,
  ProvisionedContextDto,
  ContextCapability,
  ContextScopeStateDto,
} from './contexts.js';

export type {
  DelegationDto,
  DelegationRelationshipType,
  CreateDelegationInput,
} from './delegations.js';
