/**
 * `trust-app-api` — the public barrel.
 *
 * **This is the only module an application should import.** It exports the root factory, the event
 * catalogue and bus types, the `Host` seam, the DTOs, the typed errors, and the domain interfaces.
 *
 * It must **never** re-export `runtime/*`. `runtime/` is the relocated implementation, internal to the
 * layer: only `domains/` and `client/` may import it. `test/trust_app_api/surface.test.ts` asserts this file
 * contains no `runtime/` specifier — a layer the reference app can reach around is not a boundary.
 *
 * Type-only re-exports are used throughout (`export type { … }`) so that importing the barrel never pulls a
 * runtime module in for types alone.
 */

// ── Root ─────────────────────────────────────────────────────────────────────
export { API_VERSION, createAgentStack } from './client/trust-stack.js';
export type { TrustStack, CreateAgentStackOpts } from './client/trust-stack.js';

// ── Events ───────────────────────────────────────────────────────────────────
export { EventBus } from './client/events.js';
export type {
  SubscribeOpts,
  Subscription,
  StoredEvent,
  ReplayResult,
  EventBusOptions,
} from './client/events.js';
export { STACK_EVENTS, matchesFilter } from './events/catalog.js';
export type {
  StackEvent,
  StackEventPayloads,
  StackEventPayload,
  EventFilter,
} from './events/catalog.js';

// ── Host seam ────────────────────────────────────────────────────────────────
export { createNodeHost } from './host/node-host.js';
export type { NodeHostOptions } from './host/node-host.js';
export type { Host } from './host/types.js';
/**
 * The two runtime TYPES that `Host`'s own signatures require.
 *
 * **Types only — never a value.** `Host.createAgent()`/`unlockAgent()` return an `AgentHandle` and take an
 * `AgentConfig`, so without these a host author cannot name the type of what the public seam hands them. They
 * are re-exported as `export type`, which erases at runtime: there is no implementation reachable through them,
 * and the layer's modules remain unreachable around.
 *
 * `test/trust_app_api/surface.test.ts` asserts this is the COMPLETE list, so it cannot grow by accident, and that no
 * runtime VALUE is ever re-exported here.
 */
export type { AgentHandle } from './runtime/handle.js';
export type { AgentConfig } from './runtime/types.js';

// ── Errors ───────────────────────────────────────────────────────────────────
export {
  StackError,
  NoActiveAgentError,
  CapabilityError,
  NotImplementedError,
  UtilityServerUnavailableError,
} from './errors.js';

// ── Domain interfaces ────────────────────────────────────────────────────────
export type {
  IdentityApi,
  CreateIdentityOpts,
  ImportIdentityOpts,
  ActivateIdentityOpts,
} from './domains/identity.js';
export type { ConnectivityApi } from './domains/connectivity.js';
export type { CredentialsApi, CredentialsDeps, CredentialViewFilters } from './domains/credentials.js';
export type { CommunitiesApi, CommunitiesDeps } from './domains/communities.js';
export { CommunityNotFoundError } from './domains/communities.js';
export type { DelegationsApi, DelegationsDeps } from './domains/delegations.js';
export type { ContextsApi, ContextsDeps } from './domains/contexts.js';
export {
  asContext,
  METHOD_CLASSIFICATION,
  type ContextScopeOptions,
  type ScopedDomain,
  type ScopedTrustStack,
} from './client/scope.js';
export type {
  MessagingApi,
  SendResultDto,
  TranscriptDto,
  UnreadDto,
  ClearResultDto,
} from './domains/messaging.js';
export type {
  RelationshipsApi,
  RelationshipDto,
  ConnectResultDto,
  DuplicateNoticeDto,
  CeremonyStatusDto,
  ResetCeremonyDto,
  VerifyResultDto,
  VrcStatusDto,
  DtgVrcStatusDto,
} from './domains/relationships.js';
export type { NamesApi } from './domains/names.js';
export type {
  ProfilesApi,
  CreateProfileOpts,
  UpdateProfileOpts,
  AddClaimOpts,
  UpdateClaimOpts,
} from './domains/profiles.js';

// ── Stores (durable backing) ─────────────────────────────────────────────────
export { createAgentEventsStore } from './store/agent-events-store.js';
export { createAgentMessagesStore } from './store/message-store.js';
export type { EventStore } from './store/types.js';
export type { MessageStore, TranscriptEntry } from './store/message-store.js';

// ── DTOs ─────────────────────────────────────────────────────────────────────
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
  RegisterResultDto,
  ResolvedNameDto,
  NameEntryDto,
  ProfileDto,
  ProfileClaimDto,
  ProfileCardDto,
  ProfileCardClaimDto,
  ProfileSyncStatusDto,
  RemovedDto,
  HealthDto,
  ReadyDto,
  ConnectivityStatusDto,
  DiscoveredPeerDto,
  NetworkProfileDto,
  BootstrapStatusDto,
  BootstrapRefreshDto,
  UtilityServerStatusDto,
  PushIdentityDto,
  OobiDto,
  ConnectionEventDto,
  DelegationDto,
  DelegationRelationshipType,
  CreateDelegationInput,
  GovernanceDocDto,
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
} from './dto/index.js';
