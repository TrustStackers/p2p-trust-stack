// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * AgentHandle — public API interface for agent operations.
 *
 * The TUI, CLI, and any external application should program to this
 * interface rather than depending on concrete Agent classes directly.
 *
 * Implementation: BaseAgent, Peer4Agent, ScidVhAgent
 */

import type { RotationLogEntry } from '@p2p-trust-stack/core/did/rotation-types.js';
import type { RelationshipRecord } from '@p2p-trust-stack/core/relationship/types.js';
import type { Vrc, VrcClaim, VtcGovernanceDoc, VrcVerifyResult } from '@p2p-trust-stack/core/vtc/types.js';
import type { Ed25519KeyPair } from '@p2p-trust-stack/core/crypto/primitives.js';
import type { CesrVid } from '@p2p-trust-stack/core/tsp/v3/types.js';
import type { DiscoveredPeer } from '@p2p-trust-stack/core/transport/bootstrap-client.js';
import type { NetworkProfile } from '@p2p-trust-stack/core/platform/network-detect.js';
import type { ConnectivityStatus } from '@p2p-trust-stack/core/transport/relay-health.js';
import type {
  AgentConfig,
  AgentMeta,
  AgentSummary,
  IncomingMessage,
  ConnectionEvent,
} from './types.js';
import type { CreateVtcResult, VtcListItem, VtnHierarchyResult } from '@p2p-trust-stack/core/services/vtc.js';
import type { ProfileRow, ProfileCard } from '@p2p-trust-stack/core/services/profiles.js';

/**
 * Public API that every Agent implementation must expose.
 */
export interface AgentHandle {
  // ── Identity accessors ──────────────────────────────────────────────
  getVid(): string;
  getDid(): string;
  getName(): string;
  getMeta(): AgentMeta;
  getMultiaddrs(): string[];
  getPeerId(): string;
  /**
   * This agent's OWN SQLite database handle — its per-agent database at
   * P2PTS_HOME/vta/<agentKey>/p2pts-database.db. Available once the agent has
   * started. The web server uses this to serve identity/graph queries for the
   * ACTIVE agent; there is no shared database.
   */
  getDbHandle?(): import('node:sqlite').DatabaseSync;
  /** Sign an arbitrary message with this VTA's Ed25519 key. Returns base64 signature. */
  signMessage(message: string): string;

  // ── Lifecycle ───────────────────────────────────────────────────────
  start(onStatus?: (message: string) => void): Promise<void>;
  stop(): Promise<void>;

  // ── OOBI ────────────────────────────────────────────────────────────
  generateOobi(): string;

  // ── Relationship management ─────────────────────────────────────────
  connectToPeer(encodedOobi: string): Promise<void>;
  connectToDiscoveredPeer(discoveredPeer: DiscoveredPeer): Promise<void>;
  reconnectPeer(remoteDid: string, onStatus?: (message: string) => void): Promise<void>;
  listRelationships(): RelationshipRecord[];
  getRelationship(remoteDid: string): RelationshipRecord | undefined;
  disconnectPeer(remoteDid: string): Promise<void>;

  // ── Messaging ───────────────────────────────────────────────────────
  sendMessage(remoteDid: string, body: Uint8Array, onStatus?: (message: string) => void): Promise<void>;
  sendConfidentialMessage(remoteDid: string, body: Uint8Array, onStatus?: (message: string) => void): Promise<void>;

  // ── Event registration ─────────────────────────────────────────────
  onMessage(handler: (msg: IncomingMessage) => void): void;
  onRelationshipChange(handler: (record: RelationshipRecord) => void): void;
  onConnectionEvent(handler: (event: ConnectionEvent) => void): void;
  onNetworkChange(handler: (changedFields: string[]) => void): void;

  // ── Bootstrap integration ──────────────────────────────────────────
  refreshBootstrapPeers(onStatus?: (message: string) => void): Promise<DiscoveredPeer[]>;
  isBootstrapConnected(): boolean;
  getBootstrapRelayAddr(): string | undefined;
  getDiscoveredPeers(): DiscoveredPeer[];
  /**
   * The VTN key this agent identifies itself by (undefined until one is chosen).
   *
   * Sent to the bootstrap as the peer's `net` — there is no default, so an agent
   * that has not picked a VTN sends none rather than claiming another network's.
   */
  getNet?(): string | undefined;
  /**
   * Adopt a VTN and re-register with the bootstrap under that key.
   *
   * The login flow calls this once the user has picked from the discovered VTN
   * list, so the agent is identified by the network it is actually using.
   */
  setNet?(net: string, onStatus?: (message: string) => void): Promise<void>;
  reRegisterWithBootstrap(onStatus?: (message: string) => void): Promise<void>;
  /**
   * LIVE connectivity status: bootstrap reachability, the circuit-relay grant
   * (including "about to expire"), and whether the utility server is reachable.
   *
   * Derived on every call — never a cached flag — so UI/status surfaces cannot
   * report "connected" for a peer whose relay session is about to be cut off or
   * whose utility-server connection is down.
   *
   * Optional so existing Agent implementations remain valid; callers must fall
   * back gracefully.
   */
  getConnectivityStatus?(): ConnectivityStatus;

  // ── Network detection ──────────────────────────────────────────────
  getNetworkProfile(): NetworkProfile | undefined;
  isNetworkChanged(): boolean;
  getClientSourceAddr(): string | undefined;

  // ── Profiles & R-Cards ─────────────────────────────────────────────
  createProfile(input: { label: string; purpose?: string; visibility?: string }): Promise<ProfileRow>;
  listProfiles(): Promise<ProfileRow[]>;
  updateProfile(uuid: string, input: { label?: string; purpose?: string | null; visibility?: string; setDefault?: boolean }): Promise<ProfileRow>;
  removeProfile(uuid: string): Promise<void>;
  addProfileClaim(input: { profileUuid: string; claimKey: string; claimValue?: string | null; disclosure?: string }): Promise<any>;
  updateProfileClaim(claimUuid: string, input: { claimValue?: string | null; disclosure?: string }): Promise<any>;
  removeProfileClaim(claimUuid: string): Promise<void>;
  listProfileClaims(profileUuid: string): Promise<any[]>;
  getProfileCard(profileUuid: string, requestedKeys?: string[]): Promise<ProfileCard>;

  // ── VTC / VRC / VRC issuance ────────────────────────────────────────
  createVtn?(params: { name: string; adminIdentityIds: number[]; threshold?: number }): Promise<CreateVtcResult>;
  listVtcs?(): VtcListItem[];
  affiliateVtc?(vtcId: number, vtnId: number): Promise<void>;
  unaffiliateVtc?(vtcId: number): Promise<void>;
  getVtnHierarchy?(vtnId: number): VtnHierarchyResult;
  /**
   * Issue a VRC from a known VTC to a subject.
   *
   * `vtcDid` is a DID. `subjectVid`/`signers[].vid` are CESR-encoded Ed25519
   * public keys (`CesrVid`) — the form the VTC/VRC binary codec stores VIDs in.
   */
  issueVrc(params: {
    vtcDid: string;
    subjectVid: CesrVid;
    claim: VrcClaim;
    signers: Array<{ vid: CesrVid; signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array } }>;
    expiresAt?: number;
  }): Vrc;
  /**
   * Issue a VRC to a subject, signed with the **active identity's own** keypair.
   *
   * The difference from `issueVrc` is custody, not capability. `issueVrc` takes caller-supplied
   * `signers[].signingKeyPair` — correct for a co-signing ceremony (several admins, several keys), wrong for
   * the single-admin case the credentials page offers, because that form has no key material and routing
   * private keys through a web layer to satisfy the signature would defeat `scope.ts`'s denial of
   * `identity.sign`. Here the runtime signs, so no keypair crosses the boundary.
   *
   * Optional: a capability-scoped stack omits it, and the `credentials` domain reports that as
   * `not_implemented` rather than letting a missing capability look like an unknown community.
   */
  issueVrcForSelf?(params: {
    vtcDid: string;
    /** Omitted = self-issue. */
    subjectVid?: CesrVid;
    claim: VrcClaim;
    expiresAt?: number;
  }): Vrc;
  verifyVrc(vrc: Vrc): VrcVerifyResult;
  listVtcGovernanceDocs(): VtcGovernanceDoc[];
  listVrcsForSelf(): Vrc[];
  listCommunities(): VtcGovernanceDoc[];
  getCommunityByDid(did: string): VtcGovernanceDoc | undefined;
  /**
   * The community LIST projection — `{ uuid, name, role, did, adminThresholdM, adminThresholdN, myRole }`.
   *
   * Distinct from `listCommunities()`, which returns signed governance documents. This is the read model the
   * Communities page renders, and the runtime derives it from `governance` rather than from a role tag on the
   * identity — a rule worth not duplicating, so it is declared rather than re-derived. `myRole` is the
   * CALLER's membership role, which is what gates member-management actions in the UI.
   */
  listCommunitiesFromDb?(): Array<{
    uuid: string;
    name: string;
    role: string;
    did: string;
    adminThresholdM: number | null;
    adminThresholdN: number | null;
    myRole: string | null;
  }>;

  // ── Community ceremonies (create / co-sign / inspect) ───────────────
  //
  // Declared 2026-10-08. Every one of these was already a PUBLIC method on the runtime, but was absent from
  // this contract — so the adapter reached for all eight through `deps.agent as any`. Declaring them is what
  // took that counter to zero: the capability did not have to be built, only written down.
  /**
   * Begin a community-creation ceremony. The agent generates the ceremony id, so it can query and approve the
   * ceremony afterwards. Resolves `awaitingCoSignatures: true` when the founding-admin quorum is not yet met.
   */
  createCommunityCeremony?(params: {
    name: string;
    kind?: 'vtc' | 'vtn';
    threshold?: number;
    allowedClaimTypes?: string[];
    coadminUuids: string[];
    parentCommunityUuid?: string;
  }): Promise<{
    success: boolean;
    error?: string;
    ceremonyId?: string;
    /** True when the ceremony is begun but still short of the co-signature quorum. */
    awaitingCoSignatures?: boolean;
    /** Distinct co-signatures recorded so far. */
    approvalsReceived?: number;
    /** Founding admins whose co-signature is required (the declared admin count). */
    approvalsRequired?: number;
  }>;
  /** Co-sign a pending ceremony with this identity's Ed25519 key. */
  approveCeremony?(ceremonyId: string): Promise<{ success: boolean; status?: string; error?: string }>;
  /** Read a ceremony's current state from the server. */
  queryCeremony?(ceremonyId: string, opts?: {
    timeoutMs?: number;
    connectivityTimeoutMs?: number;
  }): Promise<{
    status?: string; errorReason?: string | null; error?: string;
    /** Distinct, verified co-signatures recorded so far (server `approvalCount`). */
    approvalCount?: number;
    /** The declared founding admin uuid set (server `adminUuids`). */
    adminUuids?: string[];
  }>;
  /** Ceremonies awaiting THIS agent's co-signature. */
  listPendingCeremonies?(): Promise<Array<Record<string, unknown>>>;
  /** What the server's ceremonies did, step by step, in plain language. */
  listCeremonyLog?(): Promise<Array<Record<string, unknown>>>;
  /** One ceremony run's recorded steps, in the order they happened. */
  getCeremonyLog?(threadId: string): Promise<Array<Record<string, unknown>>>;
  /** Abandon a ceremony so it can be started again. */
  resetCeremony?(ceremonyId: string): Promise<{ success: boolean; error?: string }>;

  // NOTE: `upsertRemoteVtc` is deliberately NOT declared here. The adapter used to call it with
  // `result.vtcData`, but `createCommunityCeremony` has never returned that field, so the call was
  // unreachable and the reach for the method was dead. Declaring it would be speculative surface.

  // ── Delegations ────────────────────────────────────────────────────
  createDelegation?(params: {
    principalIdentityId: number;
    dependentIdentityId: number;
    relationshipType: string;
    scope?: string;
  }): Promise<any>;
  listDelegations?(): any[];

  // ── Rotation (Verified History only) ───────────────────────────────
  rotate(params: {
    nextSigningPublicKey: Uint8Array;
    witnessAttestations?: Vrc[];
  }): Promise<RotationLogEntry>;
  getNextSigningKeyPair(): Ed25519KeyPair | undefined;
  listRotationLog(): RotationLogEntry[];

  // ── Name registration ──────────────────────────────────────────────
  /** Register a name for this agent. Creates a rotation entry with the name
   *  in alsoKnownAs, then sends a TSP name_register to the utility server.
   *  Returns { success: true } on acceptance, or { success: false, reason } on conflict. */
  registerName(params: {
    name: string;
    namespace: string;
    /** Optional agent-local profile uuid to attach as this name's primary R-Card. */
    profileUuid?: string;
  }): Promise<{ success: boolean; reason?: string }>;
  /** Resolve a name URI (vta:<ns>:<name>) to a connectable peer target. */
  resolveName(nameUri: string): Promise<import('@p2p-trust-stack/core/did/name-resolver.js').PeerTarget | undefined>;
  /**
   * Current profile/R-Card sync state: pending=true means the utility server
   * has NOT yet acknowledged the latest profile state (dropped while
   * disconnected or a failed push) and a retry is scheduled.
   */
  getProfileSyncStatus?(): { pending: boolean; lastError: string | null };
  /** Revoke a previously registered name. Creates a rotation entry removing
   *  the name from alsoKnownAs, then sends TSP name_revoke to the utility server. */
  revokeName(params: {
    name: string;
    namespace: string;
  }): Promise<{ success: boolean; reason?: string }>;
  /** List all names registered for this agent's DID. */
  listNames(): Promise<import('@p2p-trust-stack/core/did/name-service.js').NameEntry[]>;

  // ── Credential Factory ────────────────────────────────────────────
  /** Get the CredentialFactory instance for listing/viewing credentials. */
  getCredentialFactory(): import('@p2p-trust-stack/core/services/credential-factory/credential-factory-impl.js').CredentialFactoryImpl;

  // ── Context registry (P4 — scoped app contexts) ──────────────────────
  //
  // A context is a provisioned, revocable app scope: its own HKDF-derived keypair and its own database under
  // `P2PTS_HOME/contexts/<contextId>/`. An app never touches the root keypair.
  //
  // Declared 2026-10-09. All three were already PUBLIC on the runtime but absent from this contract — the same
  // "the capability exists, only the declaration is missing" situation as the community-ceremony methods.
  /**
   * Provision a new app context from this agent's root identity.
   *
   * **Audit F-021 / ruling Y1: a private key never crosses this boundary.** The returned bundle carries PUBLIC
   * identifiers only (`contextSigningVid` / `contextAgreementVid` — CESR-encoded public keys) plus the
   * `keystorePath` where the private halves live. It deliberately does NOT carry secret-key bytes: an app that
   * needs a signature opens the context keystore with its passphrase, so a context's key cannot be used after
   * the context is revoked.
   */
  provisionApp?(contextId: string, options?: {
    allowedKeyIds?: string[];
    expiresAt?: number;
    deviceLocal?: boolean;
  }): Promise<import('./context-manager.js').AppCredentialBundle>;
  /** Revoke a context: its keystore, its database and its directory are DELETED. */
  revokeApp?(contextId: string): Promise<void>;
  /** Every context provisioned under this home, from their stored metadata. */
  listProvisionedApps?(): Array<import('./context-manager.js').AppContext>;

  // ── Recovery (Phase H) ─────────────────────────────────────────────
  /** Fetch the full public identity state from the utility server for recovery. */
  fetchRecoveryState?(timeoutMs?: number): Promise<import('./modules/recovery.js').RecoveryState | null>;
  /** Look up any identity's public data from the utility server's history repository. */
  lookupIdentity?(did: string, timeoutMs?: number): Promise<import('@p2p-trust-stack/core/tx/services/identity-service.js').IdentityLookupResultPayload>;

  // ── Utility server TSP connection (Phase H) ─────────────────────────
  /** Whether the agent has an active TSP connection to a utility server. */
  isUtilityServerConnected?(): boolean;
  /** Get the utility server's VID if connected. */
  getUtilityServerDid?(): string | null;
  /** Configure/wire up utility server connection (after start). */
  configureUtilityServer?(params: { utilityServerOobi: string }): Promise<void>;
  /** Push identity to the utility server (Phase C replacement for REST). */
  pushIdentityToUtilityServer?(): Promise<boolean>;
  /**
   * Send one request/response query to the utility server over TSP.
   *
   * **Why this exists.** Five routes used to hand-build the same
   * `TspParticipantTransport` + `RemoteParticipant` pair for every agent→server protocol
   * (`name_check`, `namespace_info`, `vtc_invite`, `vtc_accept`, …), and building it means reaching into
   * `_txBootstrap`, `tspBridge` and `tspClient` — private runtime state that is not part of this contract.
   * Those five sites accounted for 20 of the adapter's `deps.agent as any` reaches, so this method is the
   * single seam that removes them.
   *
   * Rejects with `code: 'utility_server_unavailable'` when the server is not reachable, so a caller can tell
   * "not connected" (retryable, show the layer-aware reason) from "the server answered with a failure".
   */
  queryUtilityServer?<T = unknown>(
    protocol: string,
    payload?: Record<string, unknown>,
  ): Promise<T>;

  // ── Personhood Ceremony ─────────────────────────────────────────────────
  /** Acknowledge knowing a remote peer (initiate or respond to ceremony). */
  acknowledgeRemotePeer?(remoteDid: string): void;
  /** Durable ceremony-saga status for a peer (phase, failed step, retries). */
  getCeremonyStatus?(remoteDid: string): Promise<{
    phase: string;
    failedStep: string | null;
    lastError: string | null;
    attempt: number;
    complete: boolean;
    localAcked: boolean;
    remoteAcked: boolean;
    /** Server-owned personhood-ack window (60s) driving the UI countdown.
     *  Present even before the first press: it is synthesized from the
     *  relationship record when no ceremony session exists yet. */
    ack: import('@p2p-trust-stack/core/relationship/ceremony.js').CeremonyAckView;
    /** True when the utility archive is pending on the durable outbox pipeline
     *  (the peer-to-peer ceremony still completed). */
    archiveDeferred: boolean;
  } | null>;
  /** Reset an in-progress (stuck) personhood ceremony for a peer so a fresh
   *  OOBI exchange + connect can be attempted. Mirrors the ack-deadline
   *  teardown (session + relationship cleared, onCeremonyExpired fired). Only
   *  ceremonies still waiting at the personhood gate are reset. */
  resetPersonhoodCeremony?(remoteDid: string): Promise<{
    success: boolean;
    error?: string;
    reset?: boolean;
  }>;
  /** Register a handler for when ceremony prompts the user to acknowledge. */
  onCeremonyPrompt?(handler: (remoteDid: string) => void): void;
  /** Register a handler for when the ceremony completes (VRC issued). */
  onCeremonyComplete?(handler: (remoteDid: string) => void): void;
  /** Register a handler for when a leg permanently fails (UI surfaces the step). */
  onCeremonyFailed?(handler: (remoteDid: string, step: string, error: string) => void): void;
  /** Register a handler for when an uncompleted ceremony expires (connection reset). */
  onCeremonyExpired?(handler: (remoteDid: string) => void): void;
  /** Register a handler for when either side records a personhood ack, so the
   *  other display can react before its next poll. */
  onCeremonyAckChange?(handler: (remoteDid: string) => void): void;
  /** Register a handler for when an already-connected peer attempts a duplicate OOBI connect. */
  onDuplicateConnectNotice?(handler: (remoteDid: string, remoteName: string | null) => void): void;
  /** Read one pending duplicate-connect notice for a peer (consumes it). */
  getDuplicateConnectNotice?(remoteDid: string): { remoteName: string | null; at: number } | undefined;
  /**
   * Register a handler for a credential delivered to this agent (a VIC/VMC/VEC pushed from the utility server).
   *
   * Fires only when the credential is actually written locally — a re-delivery of one already held does not
   * announce. This is the only signal for an *arrival*; without it an observer must poll the local table.
   */
  onCredentialReceived?(handler: (credential: import('./tx/credential-receive-participant.js').PersistedCredentialEvent) => void): void;
  /**
   * Observe a community record arriving from the utility server, or its governance changing.
   *
   * `kind: 'membership'` is the community itself arriving (or its roster changing); `kind: 'governance'` is the
   * community's RULES changing, i.e. an approved governance change was applied. Both were previously
   * discoverable only by polling.
   */
  onCommunityChanged?(handler: (community: import('@p2p-trust-stack/core/tx/vtc-receive-participant.js').PersistedCommunityEvent) => void): void;
  /**
   * Observe a governance-change proposal arriving from the server's durable fan-out.
   *
   * This is the proposal ARRIVING, not its state changing — the pushed proposal is immutable and pending. A
   * later crystallization reaches the agent as a `community.changed` with `kind: 'governance'`.
   */
  onGovernanceProposal?(handler: (proposal: import('./tx/governance-proposal-receive-participant.js').PersistedProposalEvent) => void): void;
  /**
   * Observe ceremony PROGRESS — the server telling this agent that a founding co-signature landed.
   *
   * Distinct from `onGovernanceProposal`: this is the founding ceremony's own advancement, which had no signal
   * at all (the community does not exist until the ceremony crystallizes, so `community.changed` cannot carry
   * it). The nudge carries no log content — an observer re-reads `/api/ceremony-log`.
   */
  onCeremonyEvent?(handler: (event: import('./tx/ceremony-event-receive-participant.js').PersistedCeremonyEvent) => void): void;

  /** List VRC-connected peer identities from local database — for VTC co-admin checklist. */
  getVrcConnectedPeers?(): Array<{ name: string | null; did: string; uuid: string }>;
  /**
   * Live libp2p connections to a peer, for the relationship debug view.
   *
   * Declared 2026-10-09 (P3 rest). The adapter's `/api/relationships/:id/debug` reached into `deps.libp2pNode as
   * any` for this — the raw node is a dependency this layer deliberately does not own, so the capability is
   * declared here instead and the runtime keeps the node private.
   *
   * Reports `[]` rather than throwing when there is no node or no connection: "not connected" is a normal answer
   * for a debug view, not a failure.
   */
  getPeerConnections?(peerId: string): Array<{
    remoteAddr: string | null;
    direction: string | null;
    status: string | null;
  }>;

  // ── Governance changes (Phase B — Rules UI) ─────────────────────────────
  /** Propose a community rule/threshold change (server resolves scope + fans out). */
  proposeGovernanceChange?(params: {
    communityUuid: string;
    change: import('@p2p-trust-stack/core/services/governance-change.js').GovernanceChange;
    scope?: import('@p2p-trust-stack/core/services/governance-change.js').ApprovalScope;
    minApprovals?: number;
  }): Promise<{ success: boolean; proposalId?: string; status?: string; error?: string }>;
  /** Co-sign a pending governance-change proposal. */
  approveGovernanceChange?(proposalId: string): Promise<{ success: boolean; status?: string; error?: string }>;
  /** Pending governance-change proposals this VTA is an eligible approver for. */
  listPendingGovernanceChanges?(): Promise<import('@p2p-trust-stack/core/services/governance-change.js').GovernanceChangeProposalView[]>;
}

// ---------------------------------------------------------------------------
// AgentHandleFactory — static factory interface
// ---------------------------------------------------------------------------

export interface AgentHandleFactory {
  create(config: AgentConfig, registry?: import('./agent-registry.js').AgentRegistry): Promise<AgentHandle>;
  unlock(config: AgentConfig, registry?: import('./agent-registry.js').AgentRegistry): Promise<AgentHandle>;
  list(registry?: import('./agent-registry.js').AgentRegistry): AgentSummary[];
  delete(name: string, registry?: import('./agent-registry.js').AgentRegistry): void;
}