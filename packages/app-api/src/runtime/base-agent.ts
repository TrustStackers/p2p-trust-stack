// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * BaseAgent — abstract base class for all DID-method-specific Agent implementations.
 *
 * Implements {@link AgentHandle} to provide a stable public API that TUI/CLI/upper
 * layers depend on. Concrete subclasses (Peer4Agent, ScidVhAgent) extend
 * this class and implement abstract identity hooks.
 *
 * Contains all infrastructure logic shared between Peer4Agent and ScidVhAgent:
 * - Runtime lifecycle (libp2p node, transport, relationship manager)
 * - Relationship management (connect, reconnect, list)
 * - Messaging (send plain, send confidential)
 * - Event system (onMessage, onRelationshipChange, onConnectionEvent)
 * - VTC/VRC operations
 * - Static utilities (list, delete)
 *
 * ## Identity ownership
 *
 * BaseAgent OWNS agent identity metadata construction and database persistence.
 * Concrete subclasses ONLY handle cryptographic identity generation
 * ({@link generateCryptoIdentity}) and method-specific store/load hooks.
 * Agent metadata (name, VID, DID, createdAt, dataDir, method) is constructed
 * once in {@link initIdentity} and persisted to the `agents` table in
 * `agent-database.db` — the single source of truth.
 */

import { createLibp2p, type Libp2p } from 'libp2p';
import { randomBytes, randomUUID } from 'node:crypto';
import { tcp } from '@libp2p/tcp';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { identify } from '@libp2p/identify';
import { keys } from '@libp2p/crypto';

import type { DidMethod } from '@p2p-trust-stack/core/did/did-method.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';
import type { CesrVid } from '@p2p-trust-stack/core/tsp/v3/types.js';
import type { RotationLogEntry } from '@p2p-trust-stack/core/did/rotation-types.js';

import { Libp2pTransport } from '@p2p-trust-stack/core/transport/index.js';
import type { TspTransport } from '@p2p-trust-stack/core/transport/types.js';
import { AGENT_PORT_RANGE, AGENT_PORT_RANGE_LABEL } from '@p2p-trust-stack/core/transport/port-range.js';
import type { DiscoveredPeer } from '@p2p-trust-stack/core/transport/bootstrap-client.js';
import { RelationshipStore } from '@p2p-trust-stack/core/relationship/store.js';
import { RelationshipManager } from '@p2p-trust-stack/core/relationship/manager.js';
import { encodeOobi, decodeOobi, signOobi } from '@p2p-trust-stack/core/relationship/oobi.js';
import {
  acknowledgePeer,
  handlePersonhoodAck,
  localUserAcknowledges,
  advanceDueSessions,
  expireStaleCeremonies,
  finalizeCompletedCeremonies,
  isCeremonyStale,
  teardownCeremony,
  buildCeremonyAckView,
  type CeremonyAckView,
  type CeremonyContext,
  type PersonhoodAckMessage,
} from '@p2p-trust-stack/core/relationship/ceremony.js';
import type { LocalIdentity, RelationshipRecord } from '@p2p-trust-stack/core/relationship/types.js';
import { RelationshipAlreadyExistsError } from '@p2p-trust-stack/core/relationship/types.js';
import { VrcCeremonyStore } from '@p2p-trust-stack/core/tx/vrc-ceremony-store.js';
import type { VrcCeremonySession } from '@p2p-trust-stack/core/tx/vrc-ceremony-store.js';
import type { TransactionManager } from '@p2p-trust-stack/core/tx/manager.js';

import { AgentDatabase } from './agent-database.js';
import { AgentRegistry, defaultRegistry } from './agent-registry.js';
import type { AgentConfig, AgentMeta, AgentSummary, IncomingMessage, ConnectionEvent } from './types.js';

import { bootstrapAgentTxCoordinator } from './tx/bootstrap.js';
import type { AgentTxBootstrapResult } from './tx/bootstrap.js';
import type { PersistedCredentialEvent } from './tx/credential-receive-participant.js';
import type { PersistedCommunityEvent } from '@p2p-trust-stack/core/tx/vtc-receive-participant.js';
import type { PersistedProposalEvent } from './tx/governance-proposal-receive-participant.js';
import type { PersistedCeremonyEvent } from './tx/ceremony-event-receive-participant.js';
import { UtilityServerUnavailableError } from '../errors.js';
import { VrcCeremonyParticipant } from './tx/vrc-ceremony-participant.js';
import { VrcReceiveParticipant } from './tx/vrc-receive-participant.js';
import { PersonhoodAckReceiveParticipant } from './tx/personhood-ack-participant.js';
import {
  awaitCeremonyTerminal,
  CEREMONY_POLL_DEFAULTS,
} from './tx/ceremony-poll.js';
import {
  TspParticipantTransport,
  isTxProtocol,
  proofRefusalResponse,
  setLocalOperationSigner,
  RemoteParticipant,
  resolveNameViaCoordinator,
  revokeNameViaCoordinator,
  registerNameViaCoordinator,
} from '@p2p-trust-stack/core/tx/index.js';
import type {
  TxWireMessage,
  FinalizeRotationParams,
  RotationLogStore,
  SendReceipt,
} from '@p2p-trust-stack/core/tx/index.js';
import { SpeculativeRotationService } from '@p2p-trust-stack/core/did/speculative-rotation.js';

import type { Vrc, VrcClaim, VtcGovernanceDoc, VrcVerifyResult } from '@p2p-trust-stack/core/vtc/types.js';
import type { Ed25519KeyPair } from '@p2p-trust-stack/core/crypto/primitives.js';
import { signEd25519, ed25519ToX25519 } from '@p2p-trust-stack/core/crypto/primitives.js';

import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { cesrEncode, CESR_CODES } from '@p2p-trust-stack/core/crypto/cesr.js';
import { asCesrVid } from '@p2p-trust-stack/core/vtc/codec.js';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { CredentialFactoryImpl } from '@p2p-trust-stack/core/services/credential-factory/credential-factory-impl.js';

import type { AgentHandle } from './handle.js';
import { ConnectivityModule, VtcApiModule } from './modules/index.js';
import { TspClientModule } from './modules/tsp-client.js';
import { TspBridge } from './modules/tsp-bridge.js';
import { RecoveryModule } from './modules/recovery.js';
import type { NetworkProfile } from '@p2p-trust-stack/core/platform/network-detect.js';
import {
  deriveConnectivityStatus,
  describeConnectivityFailure,
  expiringRelayConnections,
  type ConnectivityStatus,
} from '@p2p-trust-stack/core/transport/relay-health.js';

import * as profilesService from '@p2p-trust-stack/core/services/profiles.js';
import type { ProfileRow } from '@p2p-trust-stack/core/db/repositories/profiles-repo.js';
import type { ProfileCard } from '@p2p-trust-stack/core/services/profiles.js';
import type { GovernanceChange, ApprovalScope, GovernanceChangeProposalView } from '@p2p-trust-stack/core/services/governance-change.js';
import { GovernanceChangeStore } from '@p2p-trust-stack/core/tx/governance-change-store.js';

import { NameService, type NameEntry } from '@p2p-trust-stack/core/did/name-service.js';
import { buildNameUri } from '@p2p-trust-stack/core/did/name-uri.js';
import { resolveNameFromLocalDb, type PeerTarget } from '@p2p-trust-stack/core/did/name-resolver.js';
import { DidResolver } from '@p2p-trust-stack/core/did/did-resolver.js';
import { LocalRotationLogSource } from '@p2p-trust-stack/core/did/rotation-log-source.js';
import { rotationEntryToJson, type RotationEntryJson } from '@p2p-trust-stack/core/did/rotation-entry-codec.js';
import { registerMaterializer } from '@p2p-trust-stack/core/exchange/index.js';
import { ExchangeEngine } from '@p2p-trust-stack/core/exchange/index.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';


// ---------------------------------------------------------------------------
// CryptoIdentityResult — returned by subclass generateCryptoIdentity()
// ---------------------------------------------------------------------------

/**
 * Result from the subclass's crypto identity generation.
 * BaseAgent uses this to construct AgentMeta, persist to the database,
 * and store keys in the keystore.
 */
export interface CryptoIdentityResult {
  signingKeyPair: Ed25519KeyPair;
  agreementKeyPair: Ed25519KeyPair;
  did: string;
  document: DidDocument;
  /** Method name for metadata ('peer4' | 'verified-history'). */
  method: string;
  /**
   * Post-quantum roots of trust, published in the DID document as
   * `#key-mldsa` / `#key-kem`.
   *
   * They MUST be carried here and persisted by `initIdentity()`, because
   * `loadIdentity()` reads them from the keystore by label — the document
   * published them, but nothing stored them, so every agent created through this
   * path reported "no ML-DSA-65 key", could not ML-DSA-sign its OOBI, could not
   * sign a rotation, and fell back to classical confidential traffic.
   */
  mlDsa65KeyPair?: Ed25519KeyPair;
  hybridKemKeyPair?: Ed25519KeyPair;
}

/**
 * Keystore `key_type` for the per-identity libp2p node seed.
 *
 * The transport Peer ID must stay stable across logins so the utility server
 * can keep routing TSP replies to us. We therefore persist a dedicated random
 * 32-byte seed — keyed by the DID (stable across rotations) rather than the VID
 * or the (rotatable) signing key — and derive the node key from it on every boot.
 */
const NODE_SEED_KEY_TYPE = 'libp2p-node-seed';

/**
 * Pull the `didDocument` out of an `exchange:identity-lookup` result.
 *
 * The pull path returns the recordset's materializer rows; depending on how the
 * response was wrapped this arrives as a row array or as `{ rows: [...] }`. Rather
 * than guess, accept both — and return `undefined` for `{ found: false }`
 * (the materializer's "no such identity" answer), which must NOT be mistaken for
 * a document.
 */
function didDocumentFromLookup(result: unknown): DidDocument | undefined {
  const rows: unknown[] = Array.isArray(result)
    ? result
    : (result && typeof result === 'object' && Array.isArray((result as { rows?: unknown[] }).rows))
      ? (result as { rows: unknown[] }).rows
      : [];
  for (const row of rows) {
    const doc = (row as { didDocument?: unknown } | null)?.didDocument;
    if (doc && typeof doc === 'object') return doc as DidDocument;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Connection method description helper
// ---------------------------------------------------------------------------

/**
 * Describe how a connection was established from a remote multiaddr string.
 * Mirrors the bootstrap server's describeConnectionMethod() so the agent-side
 * "Events & Messages" pane uses consistent terminology: direct TCP, direct
 * WebSocket, or circuit-relay (NAT traversal).
 */
function describeConnectionMethod(remoteAddr: string | undefined): string {
  if (!remoteAddr) return 'unknown transport';
  if (remoteAddr.includes('/p2p-circuit')) return 'circuit-relay (NAT traversal)';
  if (remoteAddr.includes('/ws')) return 'direct WebSocket';
  if (remoteAddr.includes('/tcp/')) return 'direct TCP';
  return 'unknown transport';
}

// ---------------------------------------------------------------------------
// BaseAgent implements AgentHandle
// ---------------------------------------------------------------------------

export abstract class BaseAgent implements AgentHandle {
  // ── Identity (set after create/unlock) ──────────────────────────────────
  protected readonly name: string;
  protected readonly passphrase: string;
  protected readonly port: number;
  protected readonly registry: AgentRegistry;
  protected readonly bootstrapUrl: string | undefined;
  /** Network/group (namespace) this agent joins, e.g. 'p2pts'. */
  protected readonly net: string;

  protected identity!: LocalIdentity;
  protected meta!: AgentMeta;
  protected readonly didMethod: DidMethod;

  // ── Runtime (set after start()) ──────────────────────────────────────────
  //
  // Transport is typed as interface (TspTransport) to enable dependency injection
  // and future swapping of implementations. All persistent data flows through
  // the shared AgentDatabase.
  protected libp2pNode?: Libp2p;
  protected transport?: TspTransport;
  protected store?: RelationshipStore;
  protected manager?: RelationshipManager;

  /** Shared database — opened in start(), closed in stop(). */
  protected db?: AgentDatabase;

  // ── Modules (Phase 3-5) ───────────────────────────────────────────────────
  protected connectivityModule = new ConnectivityModule();
  protected vtcApiModule = new VtcApiModule();

  // ── Phase H: TSP bridge & recovery ────────────────────────────────────────
  protected tspClient = new TspClientModule();
  protected tspBridge = new TspBridge();
  protected recoveryModule = new RecoveryModule();
  private utilityServerOobi: string | null = null;

  // ── Utility-server + relay connectivity supervisor (B1, hardened) ─────
  //
  // This replaces the previous fire-and-forget ladder that permanently gave up
  // after 10 attempts ("giving up until next peer:connect"). That terminal
  // state was one of the reasons a relay-session expiry broke the agent: once
  // the ladder exhausted itself, NOTHING re-armed it, so the utility server
  // stayed unreachable until the app was restarted or an unrelated peer
  // happened to connect inbound.
  //
  // The supervisor is now the single owner of recovery and never gives up:
  //   - repairs bootstrap reachability (the coordination plane) first
  //   - re-establishes the utility-server connection when the bridge is down
  //   - PROACTIVELY re-dials relayed connections whose grant is about to expire
  private connectivitySupervisorTimer?: ReturnType<typeof setInterval>;
  /** Backoff step counter for reconnects. Reset on success; never terminal. */
  private serverReconnectAttempt = 0;
  private serverReconnectTimer?: ReturnType<typeof setTimeout>;
  /** True while a relay-grant refresh (pre-emptive re-dial) is running. */
  private relayRefreshInFlight = false;
  /** Re-entrancy guard so ticks cannot overlap. */
  private connectivityTickInFlight = false;
  /** True once stop() has begun — blocks reconnect (re-)arming (zombie-loop fix). */
  private stopped = false;
  /** Last recovery failure, surfaced through getConnectivityStatus(). */
  private lastConnectivityError?: string;

  /** Connectivity supervisor cadence. */
  private static readonly CONNECTIVITY_TICK_MS = 15_000;

  // ── R-Card / profile sync state (R-Card propagation fix) ──────────────
  // The profile push is NO LONGER a silent fire-and-forget. Any failure
  // (disconnected, coordinator not bootstrapped, transaction aborted) leaves
  // profileSyncPending=true, which is retried on reconnect/next mutation and
  // surfaced to the UI via getProfileSyncStatus().
  private profileSyncPending = false;
  private profileSyncLastError: string | null = null;
  /** Guards concurrent drain loops for the pending profile sync state. */
  private profileSyncPumping = false;

  // ── Name service ──────────────────────────────────────────────────────────
  protected nameService?: NameService;

  // ── Transaction Coordinator ───────────────────────────────────────────────
  private _txBootstrap?: AgentTxBootstrapResult;
  /** VRC ceremony participant (local mint + push operations). */
  private _vrcCeremonyParticipant?: VrcCeremonyParticipant;
  /** VRC receive participant (inbound store_remote_vrc operations). */
  private _vrcReceiveParticipant?: VrcReceiveParticipant;
  /** Receives the peer's personhood ack via the coordinator (ack_delivery leg). */
  private _personhoodAckParticipant?: PersonhoodAckReceiveParticipant;
  private _credentialFactory?: CredentialFactoryImpl;

  // ── CRE ExchangeEngine (Phase 5 — watermark-driven resync driver) ────────
  /** Agent-light engine: outbox push + ack-gated resync + periodic ticker. */
  protected exchangeEngine?: ExchangeEngine;

  // ── Event handlers ───────────────────────────────────────────────────────
  private messageHandlers: Array<(msg: IncomingMessage) => void> = [];
  private relationshipChangeHandlers: Array<(record: RelationshipRecord) => void> = [];
  private networkChangeHandlers: Array<(changedFields: string[]) => void> = [];
  private connectionEventHandlers: Array<(event: ConnectionEvent) => void> = [];
  /**
   * Observers of a delivered credential.
   *
   * Separate from the four above because it fires from a *participant* rather than from a runtime module: the
   * credential receive participant is the only thing that sees a delivery, so it reports upward and this list
   * fans the report out.
   */
  private credentialReceivedHandlers: Array<(credential: PersistedCredentialEvent) => void> = [];
  /** Observers of a community arriving, or its governance changing. @see onCommunityChanged */
  private communityChangedHandlers: Array<(community: PersistedCommunityEvent) => void> = [];
  /** Observers of a governance-change proposal arriving. @see onGovernanceProposal */
  private governanceProposalHandlers: Array<(proposal: PersistedProposalEvent) => void> = [];
  /** Observers of ceremony progress (a founding co-signature landing). @see onCeremonyEvent */
  private ceremonyEventHandlers: Array<(event: PersistedCeremonyEvent) => void> = [];
  private relationshipPollInterval?: ReturnType<typeof setInterval>;
  private ceremonyDriverTimer?: ReturnType<typeof setInterval>;

  // ── Private constructor — use concrete subclass create()/unlock() ─────────
  protected constructor(config: AgentConfig, registry: AgentRegistry) {
    this.name = config.name;
    this.passphrase = config.passphrase;
    this.port = config.port ?? 0;
    this.registry = registry;
    this.bootstrapUrl = config.bootstrapUrl;
    // Default the network/group until the first-run setup wizard supplies the
    // VTN the agent is joining. 'p2pts' matches the namespace used during
    // utility-server setup.
    this.net = config.net ?? 'p2pts';
    this.didMethod = config.didMethod ?? this.createDefaultDidMethod();
  }

  // ---------------------------------------------------------------------------
  // Abstract hooks — implemented by concrete subclass
  // ---------------------------------------------------------------------------

  /** Create a default DidMethod for this agent type when none is provided in config. */
  protected abstract createDefaultDidMethod(): DidMethod;

  /**
   * Generate crypto identity: create keys, DID, and DID document.
   * The subclass ONLY handles cryptographic operations. BaseAgent owns
   * metadata construction, database persistence, and keystore storage.
   */
  protected abstract generateCryptoIdentity(): Promise<CryptoIdentityResult>;

  /**
   * Store any method-specific keys in the keystore during create.
   * Called after BaseAgent has already stored the core ed25519 + x25519 keys.
   */
  protected abstract storeMethodSpecificKeys(
    keystore: SqliteKeyStore,
    crypto: CryptoIdentityResult,
  ): Promise<void>;

  /**
   * Load any method-specific state from the keystore during unlock.
   * Called after BaseAgent has already loaded the core identity and
   * resolved the DID document.
   */
  protected abstract loadMethodSpecificState(keystore: SqliteKeyStore): Promise<void>;

  /** Wire up any method-specific services after start() opens databases. */
  protected abstract wireUpAfterStart(): Promise<void>;

  /** Rebuild the DID document with live transport info for OOBI generation. */
  protected abstract buildDidDocumentWithTransport(params: {
    peerId: string;
    multiaddrs: string[];
  }): DidDocument;

  // ---------------------------------------------------------------------------
  // Concrete identity methods — owned by BaseAgent
  // ---------------------------------------------------------------------------

  /**
   * Initialize identity: call subclass crypto generator, then construct
   * AgentMeta, persist to the database, and store keys in the keystore.
   *
   * This is the SINGLE place where agent metadata is constructed and persisted.
   * Subclasses only provide crypto identity data via {@link generateCryptoIdentity}.
   */
  protected async initIdentity(): Promise<void> {
    // This agent's own directory (database + keystore) must exist before any
    // file is opened under it.
    this.registry.ensureAgentDir(this.name);

    // 1. Subclass generates crypto identity (keys, DID, document, method).
    const crypto = await this.generateCryptoIdentity();
    const vid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, crypto.signingKeyPair.publicKey);

    this.identity = {
      cesrVid: vid,
      did: crypto.did,
      didDocument: crypto.document,
      signingKeyPair: crypto.signingKeyPair,
      agreementKeyPair: crypto.agreementKeyPair,
      // The DID document publishes these as #key-mldsa / #key-kem, so the RUNTIME
      // identity must carry them too — otherwise a freshly created agent (which
      // runs initIdentity, not loadIdentity) cannot ML-DSA-sign its OOBI or use
      // the hybrid KEM until it is unlocked.
      mlDsa65KeyPair: crypto.mlDsa65KeyPair,
      hybridKemKeyPair: crypto.hybridKemKeyPair,
    };

    // 2. Construct agent metadata (identities + did_documents rows are
    //    created later when start() opens the AgentDatabase).
    this.meta = {
      name: this.name,
      vid,
      did: crypto.did,
      createdAt: Math.floor(Date.now() / 1000),
      dataDir: this.registry.getAgentDir(this.name),
      method: crypto.method,
      bootstrapUrl: this.bootstrapUrl,
    };

    // 3. Store keys in the private keystore database (separate DB file).
    const keystore = new SqliteKeyStore(this.registry.getKeystorePath(this.name));
    await keystore.storeKeyPairAsync(vid, 'ed25519', crypto.signingKeyPair, this.passphrase);
    await keystore.storeKeyPairAsync(vid, 'x25519', crypto.agreementKeyPair, this.passphrase);
    // Post-quantum roots of trust (H4): the DID document ALREADY publishes these
    // as #key-mldsa / #key-kem, so storing them is what makes the agent's runtime
    // identity match the identity it advertises. Without this the pair existed in
    // the document and nowhere else: `loadIdentity()` logged "no ML-DSA-65 key"
    // for a brand-new agent, OOBI introductions could not be signed, and
    // confidential traffic could never use the hybrid KEM.
    if (crypto.mlDsa65KeyPair) {
      await keystore.storeKeyPairAsync(vid, 'ml_dsa_65', crypto.mlDsa65KeyPair, this.passphrase);
    }
    if (crypto.hybridKemKeyPair) {
      await keystore.storeKeyPairAsync(vid, 'mlkem768_x25519', crypto.hybridKemKeyPair, this.passphrase);
    }
    await this.storeMethodSpecificKeys(keystore, crypto);
    keystore.close();

    // Phase 2: Push public identity to utility server via TSP for distributed storage.
    // Private keys NEVER leave the device — only the DID, DID document, and
    // public keys are sent. This is handled by the IdentityPushParticipant
    // during the TSP connection setup.
    if (this.tspBridge.isConnected()) {
      this.pushIdentityToUtilityServer().then((ok: boolean) => {
        if (!ok) {
          logger.error('[Agent] Startup identity push not acknowledged — state retained for retry.');
        }
      });
    }
  }

  /**
   * Load identity: read keys from keystore, resolve DID document, and load
   * any method-specific state.
   */
  protected async loadIdentity(): Promise<void> {
    const keystore = new SqliteKeyStore(this.registry.getKeystorePath(this.name));
    const signingKeyPair = await keystore.retrieveKeyPairAsync(this.meta.vid, 'ed25519', this.passphrase);
    const agreementKeyPair = await keystore.retrieveKeyPairAsync(this.meta.vid, 'x25519', this.passphrase);

    // Post-quantum roots of trust. ABSENT for identities created before PQ
    // provisioning: the keystore simply has no such key, which is reported (not an
    // error) — such an identity can still form relationships and exchange
    // confidential traffic classically, it just cannot ML-DSA-sign its rotations.
    const mlDsa65KeyPair = await this.tryLoadKeyPair(keystore, this.meta.vid, 'ml_dsa_65');
    const hybridKemKeyPair = await this.tryLoadKeyPair(keystore, this.meta.vid, 'mlkem768_x25519');
    if (!mlDsa65KeyPair) {
      logger.warn(
        `[Agent] identity ${this.meta.vid.slice(0, 12)}... has no ML-DSA-65 key — ` +
        `PQ root-of-trust signing is unavailable for it (no OOBI introduction signature, ` +
        `no rotation signature, classical-only confidential traffic). Either the identity was ` +
        `created before PQ keys were persisted, or it was provisioned through a path that did ` +
        `not store them; re-create it to provision one.`,
      );
    }

    const didDocument = this.didMethod.resolve(this.meta.did);
    didDocument.id = this.meta.did;

    this.identity = {
      cesrVid: this.meta.vid,
      did: this.meta.did,
      didDocument,
      signingKeyPair,
      agreementKeyPair,
      mlDsa65KeyPair,
      hybridKemKeyPair,
    };

    await this.loadMethodSpecificState(keystore);
    keystore.close();
  }

  /**
   * Load a key pair from the keystore, returning `undefined` when the keystore
   * holds no such key. Any OTHER failure (e.g. a decryption error) is rethrown —
   * only genuine absence is tolerated, so a corrupt keystore cannot be mistaken
   * for a missing post-quantum key.
   */
  private async tryLoadKeyPair(
    keystore: SqliteKeyStore,
    vid: string,
    keyType: string,
  ): Promise<{ secretKey: Uint8Array; publicKey: Uint8Array } | undefined> {
    try {
      return await keystore.retrieveKeyPairAsync(vid, keyType, this.passphrase);
    } catch (err) {
      if (/no key found/i.test((err as Error)?.message ?? '')) return undefined;
      throw err;
    }
  }

  // ---------------------------------------------------------------------------
  // Static: list / delete
  // ---------------------------------------------------------------------------

  /**
   * List all agents, sorted by creation time (oldest first). Scans the
   * per-agent directories under P2PTS_HOME/vta/.
   */
  static list(registry: AgentRegistry = defaultRegistry): AgentSummary[] {
    return registry.listAgents();
  }

  /**
   * Permanently delete an agent (removes its own directory).
   */
  static delete(name: string, registry: AgentRegistry = defaultRegistry): void {
    registry.deleteAgent(name);
  }

  // ---------------------------------------------------------------------------
  // start() — boot the real libp2p node and all services
  // ---------------------------------------------------------------------------

  /**
   * Start the Agent: boot a real libp2p node, Libp2pTransport, RelationshipManager.
   */
  async start(onStatus?: (message: string) => void): Promise<void> {
    if (this.libp2pNode) {
      throw new Error('Agent.start: already started');
    }

    // A fresh (or re-)start re-arms the reconnect machinery.
    this.stopped = false;

    // Boot a real libp2p node on the configured port range.
    this.libp2pNode = await this.createLibp2pNodeOnPortRange(onStatus);

    // Wire up raw connection lifecycle events (peer:connect / peer:disconnect)
    this.wireConnectionEvents(this.libp2pNode);

    // Update the identity's DID document with the live transport info.
    const peerId = this.libp2pNode.peerId.toString();
    const multiaddrs = this.libp2pNode.getMultiaddrs().map(a => a.toString());

    // Rebuild the DID document with transport info for OOBI generation.
    const docWithTransport = this.buildDidDocumentWithTransport({ peerId, multiaddrs });
    docWithTransport.id = this.identity.did;
    this.identity = { ...this.identity, didDocument: docWithTransport };

    // Boot the transport. Use injected instance if provided, otherwise create default.
    this.transport = this.transport ?? new Libp2pTransport(this.libp2pNode);
    await this.transport.start();

    // Open THIS agent's own database (P2PTS_HOME/vta/<agentKey>/). Each agent is
    // isolated in its own directory — there is no shared database. Pass the
    // agent's identity so it's resolved into the identities + did_documents FK graph.
    this.registry.ensureAgentDir(this.name);
    this.db = new AgentDatabase(
      this.registry.getDbPath(this.name),
      this.registry.getKeystorePath(this.name),
      {
        did: this.identity.did,
        method: this.didMethod.methodName,
        name: this.name,
        peerId: this.libp2pNode.peerId.toString(),
        cesrVid: this.identity.cesrVid,
        didDocumentJson: JSON.stringify(this.identity.didDocument),
      },
    );

    // Wire the relationship store from the shared database.
    this.store = this.db.relationshipStore;

    // Reconcile the identity's active libp2p endpoint on every login/start:
    // the node key above may differ from the last session's recorded endpoint
    // (re-key / device change), so record the LIVE peer now and retire any
    // superseded endpoints for this identity. This is what keeps the peer
    // identity in sync across app restarts.
    this.db.resolver.updatePeerId(this.identity.did, this.libp2pNode.peerId.toString());

    // Prune stale outbound-pending records from previous sessions.
    const pruned = this.store.pruneStaleOutbound(this.identity.did, 300);
    if (pruned > 0) {
      logger.info(`[Agent] Pruned ${pruned} stale outbound-pending relationship(s) from previous session.`);
    }

    // Purge any leftover SELF-referencing relationship row (local == remote).
    // A pre-guard self-connect attempt wrote one of these and it should never
    // show up as a pending line in the relationships UI.
    if (this.store.get(this.identity.did, this.identity.did)) {
      this.store.deleteRecord(this.identity.did, this.identity.did);
      logger.info('[Agent] Purged leftover self-relationship row from a previous session.');
    }

    // Boot the RelationshipManager.
    // The onBidirectional callback handles post-handshake setup (reconnect).
    // VRC minting is now deferred to the personhood ceremony — not auto-issued here.
    this.manager = new RelationshipManager({
      transport: this.transport,
      store: this.store,
      identity: this.identity,
      didMethod: this.didMethod,
      /**
       * Anchored document lookup for the OOBI introduction check (H2).
       *
       * Consulted only when the peer's DID cannot be resolved locally AND no key
       * is pinned — i.e. a FIRST contact with a did:scid:vh peer, which is
       * otherwise unverifiable. The anchor is our own utility server: its answer
       * arrives over the already-authenticated TSP relationship, so a tampered
       * OOBI cannot forge it the way it could forge a document embedded in the
       * artifact itself.
       */
      resolvePeerDocument: async (did: string) => {
        const engine = this.exchangeEngine;
        if (!engine || !this.tspBridge.isConnected()) return undefined;
        try {
          const result = await engine.pull(
            { requester: this.buildRequesterIdentity(), filters: { did } },
            'identity-lookup',
            'server:us-1',
            this.createServerTransport(),
          );
          return didDocumentFromLookup(result);
        } catch (err) {
          logger.warn(
            `[Agent] identity-lookup for ${did.slice(0, 24)}… failed: ${(err as Error)?.message ?? err}`,
          );
          return undefined;
        }
      },
      onBidirectional: (remoteDid) => {

        // Establish a persistent libp2p connection after the handshake.
        // NAT'd peers rely on circuit-relay; without an explicit dial the
        // relay reservation from the handshake may lapse, leaving no live
        // transport for subsequent TSP_GEN messages.
        setTimeout(() => {
          this.reconnectPeer(remoteDid).catch((err: unknown) => {
            logger.warn(`[Agent] post-handshake reconnectPeer failed for ${remoteDid.slice(0, 12)}...: ${(err as Error)?.message ?? err}`);
          });
        }, 500);
      },
    });

    // ── TSP bridge wiring (peer-to-peer capable) ─────────────────────────
    // The bridge is the ONLY writer of the TspClientModule's send function
    // (`TspBridge.init` → `tspClient.init`) and the ONLY router that turns an
    // inbound TSP_GEN protocol envelope into a coordinator dispatch
    // (`TspBridge.handleInbound` returns false while its `tspClient` is null).
    // It must therefore be wired as soon as the RelationshipManager exists —
    // NOT lazily from `configureUtilityServer()`, which never runs when no
    // utility server is discovered. Without this wiring a pure peer-to-peer
    // agent has `sendFn === null`, so EVERY `TspClientModule.request()` throws
    // `TspClientModule.request: not initialized. Call init() first.`, every
    // ceremony coordinator leg that reaches the peer (ack_delivery,
    // peer_delivery) aborts, and the 60 s ack window closes with the ceremony
    // still at the gate — the relationship + ceremony state is then torn down
    // and the peers have to start over. Inbound peer tx_prepare /
    // tx_commit_result envelopes would likewise fall through to the chat
    // dispatch instead of reaching the coordinator, so the sending peer could
    // never receive a tx_prepare_result either.
    //
    // Re-wiring from `configureUtilityServer()` is intentional and harmless:
    // `init()` is idempotent (same manager + client, plus the OOBI) and it does
    // not reset the `connected` flag.
    this.tspBridge.init({
      manager: this.manager,
      tspClient: this.tspClient,
    });

    this.manager.start();

    // Wire up the message handler.
    this.manager.onGenMessage((remoteDid, body, confidential) => {
      // ── TSP protocol routing ────────────────────────────────────────
      // Route inbound protocol messages (tx_*, identity_lookup_result,
      // name_register_result, ...) through the TSP bridge so the
      // transaction coordinator and request/response matching can handle them.
      // This runs for EVERY inbound message — from the utility server OR a
      // peer agent — regardless of whether the utility-server bridge is up. A
      // peer-initiated tx_prepare (store_remote_vrc) therefore always reaches
      // the agent's coordinator, not only when the util bridge is live.
      this.tspBridge.handleInbound(body, remoteDid, async (msg) => {
        // ── Transaction Coordinator routing ──────────────────────────
        // Route tx_prepare, tx_commit, tx_abort, tx_inquiry to the agent's
        // transaction coordinator, which dispatches to the registered
        // participants (VtcReceiveParticipant, VrcReceiveParticipant, ...).
        if (isTxProtocol(msg.protocol) && this._txBootstrap) {
          try {
            const txMsg = msg.payload as TxWireMessage;

            // F-010 / R1: authority from a SIGNED operation document, not from the
            // transport that carried it. `remoteDid` is the envelope sender, and the
            // proof's actor must BE that sender (checked inside proofRefusalResponse).
            //
            // BEFORE dedup on purpose: a refused prepare must not consume its
            // (txId, messageId) key, or the sender's corrected retry would be swallowed
            // as a replay of the refused attempt.
            // The sender here is the UTILITY SERVER, which signs with its PERMANENT TSP VID
            // rather than with an identity key — so its VID cannot be derived from the keys
            // this agent holds and must be looked up from the value the server publishes in
            // `identities.vid` (see ensureServerVta). Unknown → undefined, and the verifier
            // reports the binding `indeterminate`, never a false `invalid`.
            let senderVid: string | undefined;
            try {
              const row = this.db?.getDbHandle?.()
                ?.prepare(
                  `SELECT i.vid AS vid FROM identities i
                     JOIN did_documents d ON d.identity_uuid = i.uuid
                    WHERE d.did = ? AND i.vid IS NOT NULL LIMIT 1`,
                )
                .get(remoteDid) as { vid?: string | null } | undefined;
              senderVid = row?.vid ?? undefined;
            } catch { senderVid = undefined; }

            const refusal = proofRefusalResponse(txMsg, { senderVid });
            if (refusal) {
              return {
                protocol: refusal.kind,
                correlationId: msg.correlationId,
                payload: refusal,
              };
            }

            // H7: deduped entry point. A replay is recognised and dropped WITHOUT
            // re-invoking the coordinator, and is reported as handled so it does not
            // fall through to the chat path (a replayed 2PC message is not chat).
            const { duplicate, response } = await this._txBootstrap.handleInboundTxMessage(txMsg);
            if (duplicate) {
              return { protocol: '__handled__', payload: null };
            }
            if (response) {
              // Send the response back to the sender (server or peer agent).
              return {
                protocol: response.kind,
                correlationId: msg.correlationId,
                payload: response,
              };
            }
          } catch (e) {
            logger.error('[BaseAgent] tx message handler error:', (e as Error).message);
          }
          return { protocol: '__handled__', payload: null };
        }
        return null; // Not a known handler — dispatch to chat
      }).then(handled => {
        if (handled) return; // Protocol message — don't dispatch to chat
        return this._handleNonProtocolInbound(remoteDid, body, confidential);
      }).catch(() => {
        this._handleNonProtocolInbound(remoteDid, body, confidential);
      });
    });

    // Wire the VTC/VRC store from the shared database.
    this.vtcApiModule.init(this.db.vtcStore);

    // ── Transaction Coordinator ────────────────────────────────────────
    // Bootstrap the agent's transaction coordinator. This is ALWAYS available
    // — there is no fallback to legacy code paths. All agent↔server and
    // agent↔agent communication flows through the coordinator.
    try {
      this._txBootstrap = await bootstrapAgentTxCoordinator(
        this.ds,
        {
          agentDid: this.identity.did,
          // Per-agent transaction database. Several agents launched from the same
          // working directory used to share one `data/tx/tx-coordinator.db` — one
          // transaction log, one tx_participant_state and one tx_outbox — so a
          // reconnect drain could deliver, or mark delivered, another agent's
          // entries. `this.name` is the registry key selected by AGENT_NAME.
          agentName: this.name,
          // Resolve the path through THIS agent's registry so it honours the
          // registry's P2PTS_HOME. Passing only `agentName` would fall back to
          // the process-global P2PTS_HOME and leak a tx DB into the real user
          // home whenever a caller used a non-default registry (e.g. tests).
          dbPath: this.registry.getTxDbPath(this.name),
          // Durable outbox wire. Two payload shapes:
          //   · `{ protocol: 'exchange:<name>', payload }` — a CRE push. This is
          //     delivered as a coordinator 2PC (tx_prepare/commit) so the server's
          //     ExchangePushParticipant applies it durably; returns true only on
          //     a committed outcome. `server:` destinations resolve to the live
          //     server VID at send time (VID may change across restarts).
          //   · a raw Uint8Array body — a plain TSP_GEN protocol message.
          // Returns false on any failure so the outbox retains the entry and
          // retries on the next reconnect drain — never silently dropped.
          send: async (destination, payload) => {
            if (!this.manager || !this._txBootstrap) return false;
            const targetVid = String(destination).startsWith('server:')
              ? this.tspBridge.getUtilityServerDid()
              : (destination as string);
            if (!targetVid) return false;
            try {
              const msg = payload as { protocol?: string; payload?: unknown } | Uint8Array | null;
              const protocol =
                msg && typeof msg === 'object' && 'protocol' in msg
                  ? (msg as { protocol: string }).protocol
                  : undefined;
              if (protocol && protocol.startsWith('exchange:')) {
                const transport = this.createServerTransport();
                const serverPart = new RemoteParticipant(`peer:${targetVid}`, transport);
                const result = await this._txBootstrap.manager.run(async (tx) => {
                  tx.enlist(serverPart, [
                    { op: protocol, params: { payload: (msg as { payload: unknown }).payload } },
                  ]);
                });
                return result.outcome === 'committed';
              }
              if (payload instanceof Uint8Array) {
                await this.manager.sendMessage(targetVid, payload);
                return true;
              }
              return false;
            } catch (err) {
              logger.warn(
                `[Agent] durable outbox send failed to ${String(destination).slice(0, 12)}...: ` +
                  `${(err as Error)?.message ?? err}`,
              );
              return false;
            }
          },
          // Announce a delivered credential so the bus can carry it. Without this the ONLY way to notice a
          // credential arriving is to poll the local table, which is what `nav.js` and `credentials.html` did.
          onCredentialPersisted: (credential) => {
            for (const handler of this.credentialReceivedHandlers) {
              try { handler(credential); } catch (err) {
                logger.warn(`[Agent] credential-received handler failed: ${(err as Error)?.message ?? err}`);
              }
            }
          },
          // Announce a community record arriving (or its governance changing). Without this the ONLY way to
          // notice is to poll — which is what `communities.html` and `rules.html` did for their lists.
          onCommunityPersisted: (community) => {
            for (const handler of this.communityChangedHandlers) {
              try { handler(community); } catch (err) {
                logger.warn(`[Agent] community-changed handler failed: ${(err as Error)?.message ?? err}`);
              }
            }
          },
          // Announce a governance proposal arriving, so the Rules page learns of it unaided.
          onGovernanceProposalPersisted: (proposal) => {
            for (const handler of this.governanceProposalHandlers) {
              try { handler(proposal); } catch (err) {
                logger.warn(`[Agent] governance-proposal handler failed: ${(err as Error)?.message ?? err}`);
              }
            }
          },
          // Announce ceremony progress. Nothing else observes a co-signature landing, so without this the only
          // way to notice a founding advance is to poll the server's ceremony log.
          onCeremonyEventPersisted: (event) => {
            for (const handler of this.ceremonyEventHandlers) {
              try { handler(event); } catch (err) {
                logger.warn(`[Agent] ceremony-event handler failed: ${(err as Error)?.message ?? err}`);
              }
            }
          },
        },
      );
      logger.info('[Agent] transaction coordinator bootstrapped');

      // Wire the durable outbox into the TSP client so enqueue() persists
      // before send and replays undelivered messages on reconnect.
      this.tspClient.setOutbox(this._txBootstrap.outbox);

      // ── CRE ExchangeEngine (Phase 5) ─────────────────────────────────────
      // One watermark-driven resync + periodic driver replaces per-feature
      // timers. Agent-light deployment: outbox push + ack-gating. The ticker
      // only drives recordsets with `periodic(ms)` resync, gated on connection.
      // Phase 7: `resolvePeerEndpoint` is the P2P (Hybrid → P2P) hook — it may
      // return a participant transport for a peer-targeted pull (rcard/registry/
      // credential) to go directly to the peer's libp2p address. It returns null
      // today, keeping all pulls on the server path (no behavior change).
      // Phase C: engine construction is unconditional — the exchange path is
      // the only push/read path (the flag and its legacy branches are gone).
      {
        this.exchangeEngine = new ExchangeEngine({
          db: this.ds,
          outbox: this._txBootstrap.outbox,
          watermark: this._txBootstrap.txDataSource,
          isConnected: () => this.tspBridge.isConnected(),
          resolvePeerEndpoint: (peerDid) => {
            // Future: resolve `peerDid` → TspParticipantTransport over the
            // live relationship. Null = use the server path.
            void peerDid;
            return null;
          },
        });
        this.exchangeEngine.startTicker(15_000);
        logger.info('[Agent] exchange engine + watermark ticker started');

        // Phase B: wire the 'identity' recordset materializer to this agent's
        // own public identity state so exchangeEngine.push() (ack-gating +
        // watermark) drives the identity/R-Card push. buildIdentityPushPayload
        // reads profiles + claims + credentials at push time — send-time
        // materialization, never a stored snapshot. ExchangePushParticipant
        // unwraps a single-element array server-side.
        registerMaterializer('identity', async () => {
          const payload = await this.buildIdentityPushPayload();
          return [payload];
        });
        logger.info('[Agent] identity recordset materializer registered');
      }

      // Reflect the current server-connection state on the outbox watch
      // (defaults to 'down' at startup — no drain until the server connects).
      this.syncServerConnectionWatch();

      // ── Credential Factory ───────────────────────────────────────────
      this._credentialFactory = new CredentialFactoryImpl(this.ds);
      logger.info('[Agent] credential factory initialized');

      // ── VRC Ceremony Participants ─────────────────────────────────────
      // Register participants for VRC ceremony operations on the coordinator.
      // These handle mint_vrc (local VRC minting) and store_remote_vrc
      // (receiving a peer's VRC during reflection).
      if (this.db) {
        this._vrcCeremonyParticipant = new VrcCeremonyParticipant(
          `peer:${this.identity.did}`,
          this.ds,
          this._txBootstrap.txDataSource,
          this.db.resolver,
        );
        this._vrcCeremonyParticipant.setIdentity(this.identity);
        this._txBootstrap.coordinator.registerParticipant(this._vrcCeremonyParticipant);
        logger.info('[Agent] VRC ceremony participant registered');

        this._vrcReceiveParticipant = new VrcReceiveParticipant(
          `peer:${this.identity.did}`,
          this.ds,
          this._txBootstrap.txDataSource,
          this.db.vtcStore,
          this.db.resolver,
        );
        this._txBootstrap.coordinator.registerParticipant(this._vrcReceiveParticipant);
        logger.info('[Agent] VRC receive participant registered');

        // Receiving half of the ceremony's ack_delivery leg. Registered under the
        // same `peer:{vid}` pid as the other local participants; the coordinator
        // routes by `handlesOperation`.
        this._personhoodAckParticipant = new PersonhoodAckReceiveParticipant(
          `peer:${this.identity.did}`,
          this._txBootstrap.txDataSource,
          this.identity.did,
          (remoteDid) => this._handleRemoteAckRecorded(remoteDid),
        );
        this._txBootstrap.coordinator.registerParticipant(this._personhoodAckParticipant);
        logger.info('[Agent] personhood ack participant registered');
      }

      // Register a compensation handler for VRC credential rollback
      this._txBootstrap.compensation.register({
        type: 'delete_minted_vrc',
        async execute() {
          // The VrcCeremonyParticipant handles this in its abort() method.
          // This is a no-op stand-in — the actual undo logic lives in the
          // participant's replayUndo() which is called from abort().
        },
      });
    } catch (err) {
      logger.error('[Agent] FATAL: failed to bootstrap transaction coordinator:', (err as Error)?.message);
      throw err;
    }

    // Wire up method-specific services (e.g., rotation log store for ScidVhAgent).
    await this.wireUpAfterStart();

    // Bootstrap integration: register with bootstrap server and discover peers.
    // Delegate to ConnectivityModule.
    await this.connectivityModule.connectToBootstrap({
      libp2pNode: this.libp2pNode,
      multiaddrs: this.getMultiaddrs(),
      onStatus,
      // Bootstrap-facing designation: the configured user name (available from
      // first contact, before name registration) and the network/group.
      agentName: this.name,
      net: this.net,
      // Flag this peer as a TEST peer when a test runner is driving us (Node's
      // `--test` sets NODE_TEST_CONTEXT) or when explicitly opted in via
      // P2PTS_TEST_PEER=1. Test agents are killed without a clean disconnect, so
      // the bootstrap TTL-prunes them instead of accumulating dead records —
      // see bootstrap/db/peer-db.ts. A normal (production) run sets neither.
      test:
        process.env.P2PTS_TEST_PEER === '1' ||
        process.env.NODE_TEST_CONTEXT !== undefined,
    });

    // Start the VRC ceremony retry driver — periodically advances any ceremony
    // that is not complete/failed but is due for another coordinator leg.
    this.startCeremonyDriver();

    // Start the connectivity supervisor. Deliberately AFTER connectToBootstrap
    // and NOT conditional on its success: an agent that boots while the
    // bootstrap server is unreachable must retry in the background rather than
    // stay in LAN-only mode forever.
    this.startConnectivitySupervisor();

    // Start polling for relationship changes (every 200ms).
    this.startRelationshipPolling();
  }

  /** Start periodic ceremony driver ticks (retries incomplete VRC ceremonies). */
  private startCeremonyDriver(): void {
    if (this.ceremonyDriverTimer) return;
    this.ceremonyDriverTimer = setInterval(() => {
      this.runCeremonyDriver().catch((err) =>
        logger.error('[Agent] ceremony driver tick error:', (err as Error)?.message ?? err),
      );
    }, 4_000);
    if (typeof this.ceremonyDriverTimer.unref === 'function') {
      this.ceremonyDriverTimer.unref();
    }
    logger.info('[Agent] VRC ceremony driver started');
  }

  // ---------------------------------------------------------------------------
  // Connection lifecycle events (peer:connect / peer:disconnect)
  // ---------------------------------------------------------------------------

  private wireConnectionEvents(node: Libp2p): void {
    const nodeAny = node as unknown as {
      addEventListener: (name: string, cb: (evt: { detail: unknown }) => void) => void;
      getConnections?: (peerId: unknown) => Array<{
        remoteAddr?: { toString(): string };
        direction?: string;
      }>;
    };

    nodeAny.addEventListener('peer:connect', (evt) => {
      const peerId = (evt.detail as { toString(): string }).toString();
      let remoteAddr: string | undefined;
      let direction: 'inbound' | 'outbound' = 'outbound';

      try {
        const conns = nodeAny.getConnections?.(evt.detail) ?? [];
        const conn = conns[0];
        if (conn) {
          remoteAddr = conn.remoteAddr?.toString();
          direction = conn.direction === 'inbound' ? 'inbound' : 'outbound';
        }
      } catch {
        // Best-effort — connection may already be gone by the time we inspect it.
      }

      const event: ConnectionEvent = {
        peerId,
        kind: 'open',
        direction,
        method: describeConnectionMethod(remoteAddr),
        remoteAddr,
        timestamp: Date.now(),
      };
      for (const handler of this.connectionEventHandlers) {
        handler(event);
      }

      // Utility-server reconnect: when its transport peer comes back up, clear
      // any backoff state and re-verify the TSP bridge (relationship is durable,
      // so connect() marks us connected again).
      // Delivery of any VTCs queued while offline is handled exclusively by the
      // utility-server queue push on reconnect (exchange:vtc-membership) — the push is the
      // single delivery path for offline agents.
      if (this.isServerTransportPeer(peerId)) {
        logger.info(`[Agent] utility-server transport peer connected: ${peerId.slice(0, 12)}...`);
        this.serverReconnectAttempt = 0;
        this.lastConnectivityError = undefined;
        // A pending reconnect is now redundant — cancel it so the supervisor
        // does not re-dial a connection that just came back (and so the status
        // stops reporting 'reconnecting' while we are in fact connected).
        this.clearServerReconnectTimer();
        if (this.tspBridge && !this.tspBridge.isConnected()) {
          this.tspBridge.connect()
            .then(() => this.syncServerConnectionWatch())
            .catch((err: unknown) =>
              logger.warn(`[Agent] post-reconnect tspBridge.connect failed: ${(err as Error)?.message ?? err}`),
            );
        }
      }
    });

    nodeAny.addEventListener('peer:disconnect', (evt) => {
      const peerId = (evt.detail as { toString(): string }).toString();
      const event: ConnectionEvent = {
        peerId,
        kind: 'close',
        direction: 'outbound',
        method: 'disconnected',
        timestamp: Date.now(),
      };
      for (const handler of this.connectionEventHandlers) {
        handler(event);
      }

      // Utility-server disconnect: mark the TSP bridge DOWN and schedule a
      // reconnect with exponential backoff so isConnected() reflects reality
      // and the connection is re-established automatically.
      if (this.isServerTransportPeer(peerId)) {
        logger.info(`[Agent] utility-server transport peer DISCONNECTED: ${peerId.slice(0, 12)}...`);
        this.tspBridge?.markDisconnected();
        this.syncServerConnectionWatch();
        this.scheduleServerReconnect();
      }
    });
  }

  onConnectionEvent(handler: (event: ConnectionEvent) => void): void {
    this.connectionEventHandlers.push(handler);
  }

  /**
   * Whether the given libp2p transport peer is the utility server. Resolved from
   * the TSP bridge's server VID → relationship → remoteTransport.peerId.
   */
  private isServerTransportPeer(peerId: string): boolean {
    if (!this.tspBridge) return false;
    const serverPeerId = this.tspBridge.getServerTransportPeerId();
    return !!serverPeerId && serverPeerId === peerId;
  }

  /**
   * Reflect the TSP bridge's server-connection state onto the durable-outbox
   * watch. The watch flips 'up'/'down' so the outbox drains undelivered entries
   * exactly when the utility-server connection comes back (never while down).
   * No-op before the transaction coordinator is bootstrapped.
   *
   * Phase 5: on 'up', also drive the engine's watermark resync for `on-connect`
   * recordsets — ack-gating inside the engine skips any recordset whose
   * materialized payload is unchanged since the last sync.
   */
  private syncServerConnectionWatch(): void {
    if (!this._txBootstrap) return;
    const up = this.tspBridge.isConnected();
    this._txBootstrap.watch.set(up ? 'up' : 'down');
    // On reconnect the outbox drain + the fast-path push run; any offline row is
    // superseded, so a future offline window starts with a fresh push.

    // Phase 5 — watermark-driven catch-up on reconnect.
    if (up && this.exchangeEngine) {
      void this.exchangeEngine.resync('server:us-1', {
        requester: this.buildRequesterIdentity(),
      }, this.createServerTransport()).catch((err) =>
        logger.warn(`[Agent] exchange resync on-connect failed: ${(err as Error)?.message ?? err}`),
      );
    }
  }

  /** Build the exchange requester identity for this agent (self-only pulls/pushes). */
  private buildRequesterIdentity(): { realDid: string; uuid: string; role: string } | undefined {
    return this.identity
      ? { realDid: this.identity.did, uuid: this.getLocalIdentityUuid(), role: 'vta' }
      : undefined;
  }

  /**
   * Schedule a reconnect to the utility server with exponential backoff
   * (1s → 2s → 4s → … capped at 30s).
   *
   * NEVER TERMINAL. The previous implementation stopped after 10 attempts and
   * waited for an unrelated inbound `peer:connect` to re-arm it, which meant a
   * relay-session expiry could leave the agent permanently unable to reach the
   * server. Recovery now continues for as long as the agent runs; the
   * supervisor tick is a second re-arm path if this timer is ever lost.
   *
   * Uses reconnectPeer() which refreshes bootstrap peers and dials direct →
   * relay → last-known addrs, then re-verifies the TSP bridge relationship.
   */
  private scheduleServerReconnect(): void {
    if (this.stopped) return; // never (re-)arm a stopped agent
    if (this.serverReconnectTimer) return; // a reconnect is already pending

    const attempt = ++this.serverReconnectAttempt;
    const delayMs = Math.min(1000 * Math.pow(2, attempt - 1), 30_000);
    logger.info(`[Agent] utility-server reconnect scheduled in ${delayMs}ms (attempt ${attempt})`);

    this.serverReconnectTimer = setTimeout(() => {
      this.serverReconnectTimer = undefined;
      this.reconnectToUtilityServer()
        .then(() => {
          this.serverReconnectAttempt = 0;
          this.lastConnectivityError = undefined;
        })
        .catch((err: unknown) => {
          this.lastConnectivityError = (err as Error)?.message ?? String(err);
          logger.warn(
            `[Agent] utility-server reconnect attempt ${attempt} failed: ${this.lastConnectivityError}`,
          );
          // Keep trying forever with a capped backoff.
          this.scheduleServerReconnect();
        });
    }, delayMs);
  }

  /** Cancel a pending reconnect (e.g. the connection came back on its own). */
  private clearServerReconnectTimer(): void {
    if (this.serverReconnectTimer) {
      clearTimeout(this.serverReconnectTimer);
      this.serverReconnectTimer = undefined;
    }
  }

  /**
   * Establish the utility server from bootstrap DISCOVERY, for the case where the
   * agent has never been configured with one.
   *
   * Why this exists: `configureUtilityServer()` is called exactly once, at
   * agent-activation time (`agent-app/web/server.ts`), from whatever
   * `getDiscoveredPeers()` held at that instant. An agent started BEFORE the
   * utility server registers on the bootstrap server therefore sees zero
   * `utility_server` peers, never configures one, and `reconnectToUtilityServer()`
   * then throws `no utility server VID to reconnect to` on every subsequent tick
   * — forever. The agent sits in `layer: 'unreachable'` with a live relay
   * connection and a perfectly good server peer one discovery query away, and name
   * registration stays permanently unavailable with no path to recovery.
   *
   * The bootstrap discovery payload carries everything a strict OOBI needs
   * (`peerType`, `vid`, `did`, `multiaddrs` — see `bootstrap-client.ts`), so the
   * recovery is just "look again, then connect".
   *
   * @returns true when a utility server was found and the connection established.
   */
  private async establishUtilityServerFromDiscovery(): Promise<boolean> {
    const candidates = this.getDiscoveredPeers().filter(
      (p) => p.peerType === 'utility_server' && p.did && (p.vid || p.peerId),
    );
    if (candidates.length === 0) return false;

    // Prefer a peer the bootstrap reports as reachable; fall back to the first.
    const us = candidates.find((p) => p.reachable) ?? candidates[0];
    // `vid` is the permanent CESR Slot-A key (survives a did:scid:vh log roll);
    // the OOBI contract names it `cesrVid`. `peerId` is only a fallback for a
    // server that registered without a VID.
    const cesrVid = us.vid || us.peerId;

    logger.info(
      `[Agent] no utility server configured — attempting discovery-based connect ` +
      `to ${us.peerId.slice(0, 12)}... (${us.multiaddrs.length} addr(s))`,
    );

    const oobi = encodeOobi({
      cesrVid,
      peerId: us.peerId,
      multiaddrs: us.multiaddrs,
      did: us.did!,
    });
    await this.configureUtilityServer({ utilityServerOobi: oobi });
    logger.info('[Agent] discovery-based utility-server connect succeeded');
    return true;
  }

  /**
   * Perform the actual utility-server reconnection: resolve the server VID,
   * dial it (direct/relay via connectivityModule.reconnectPeer), and re-verify
   * the TSP bridge so isConnected() flips back to true.
   */
  private async reconnectToUtilityServer(): Promise<void> {
    if (this.stopped) return; // torn down mid-flight — do nothing
    const serverDid = this.tspBridge.getUtilityServerDid();
    if (!serverDid) {
      // Never configured (as opposed to configured-then-down). Try to establish
      // one from bootstrap discovery before declaring failure — see
      // establishUtilityServerFromDiscovery() for why this matters.
      const established = await this.establishUtilityServerFromDiscovery();
      if (established) return;
      throw new Error('no utility server VID to reconnect to (and none discovered)');
    }
    await this.reconnectPeer(serverDid);
    // reconnectPeer re-dials the transport; re-verify the durable relationship.
    await this.tspBridge.connect();
    this.syncServerConnectionWatch();
    // Re-assert this agent's identity/key state on the server. A reconnect is
    // exactly when a stale or duplicate server-side row (which the ack-gated
    // regular push skips forever) can be repaired, and it is cheap.
    void this.forceIdentityPush('reconnect');
    logger.info(`[Agent] utility server reconnected (isConnected=${this.tspBridge.isConnected()})`);
  }

  // ---------------------------------------------------------------------------
  // Connectivity supervisor
  // ---------------------------------------------------------------------------

  /**
   * Start the connectivity supervisor — the single owner of recovery for
   * bootstrap reachability, the circuit-relay reservation and the
   * utility-server connection.
   *
   * Started unconditionally in start(), including when the initial bootstrap
   * registration FAILED: recovery used to be armed only from a
   * `peer:disconnect` event, so an agent that booted while the bootstrap server
   * was down (or unreachable) stayed in "LAN-only mode" forever with no retry.
   */
  private startConnectivitySupervisor(): void {
    if (this.connectivitySupervisorTimer) return;

    this.connectivitySupervisorTimer = setInterval(() => {
      void this.runConnectivityTick();
    }, BaseAgent.CONNECTIVITY_TICK_MS);
    if (typeof this.connectivitySupervisorTimer.unref === 'function') {
      this.connectivitySupervisorTimer.unref();
    }
    logger.info('[Agent] connectivity supervisor started');
  }

  /** Stop the supervisor and any pending reconnect (shutdown only). */
  private stopConnectivitySupervisor(): void {
    if (this.connectivitySupervisorTimer) {
      clearInterval(this.connectivitySupervisorTimer);
      this.connectivitySupervisorTimer = undefined;
    }
    this.clearServerReconnectTimer();
  }

  /**
   * One supervisor pass.
   *
   * Order matters: the bootstrap server is the coordination plane (discovery +
   * relay), so it is repaired first — without it, no peer address can be
   * refreshed and the utility-server reconnect below has nothing useful to
   * dial.
   *
   * Each step is independently guarded so one failure cannot skip the others.
   */
  private async runConnectivityTick(): Promise<void> {
    if (this.connectivityTickInFlight) return;
    if (!this.libp2pNode || !this.transport) return;

    this.connectivityTickInFlight = true;
    try {
      // ── 1. Bootstrap reachability ──────────────────────────────────────
      if (!this.connectivityModule.isBootstrapConnected()) {
        logger.info('[Agent] supervisor: bootstrap not connected — re-registering');
        try {
          await this.connectivityModule.reRegisterWithBootstrap({
            libp2pNode: this.libp2pNode,
            multiaddrs: this.getMultiaddrs(),
          });
        } catch (err) {
          // Next tick retries. Not fatal: LAN/direct relationships still work.
          logger.warn(
            `[Agent] supervisor: bootstrap re-registration failed: ${(err as Error)?.message ?? err}`,
          );
        }
      }

      // ── 2. Relay grants about to expire ───────────────────────────────
      // Done BEFORE the down-check: a session that is still "connected" but
      // about to be cut off by the relay is exactly the case this prevents.
      await this.refreshExpiringRelayConnections();

      // ── 3. Utility-server connection ──────────────────────────────────
      if (this.tspBridge.getUtilityServerDid() && !this.tspBridge.isConnected()) {
        // Only when no reconnect is already pending — the peer:disconnect
        // handler owns the fast path; this is the safety net.
        if (!this.serverReconnectTimer) {
          logger.info('[Agent] supervisor: utility-server bridge is down — reconnecting');
          this.scheduleServerReconnect();
        }
      }
    } catch (err) {
      this.lastConnectivityError = (err as Error)?.message ?? String(err);
      logger.warn(`[Agent] supervisor tick error: ${this.lastConnectivityError}`);
    } finally {
      this.connectivityTickInFlight = false;
    }
  }

  /**
   * Pre-emptively re-dial relayed connections whose grant is nearly exhausted.
   *
   * WHY: the relay server enforces a per-relayed-connection duration and byte
   * grant (`relayMaxDuration` / `relayMaxData` in
   * bootstrap/server/bootstrap-server.ts). When the grant runs out the relay
   * ABORTS the HOP/STOP streams and the connection dies abruptly; every
   * recovery after that point is post-mortem. A fresh dial gets a FRESH grant,
   * so re-dialing slightly before the limit keeps the session alive instead of
   * losing it.
   *
   * Only connections mappable back to a relationship are refreshed — those are
   * the ones we can re-dial, and each carries the remote identity key needed by
   * reconnectPeer().
   */
  private async refreshExpiringRelayConnections(): Promise<void> {
    if (this.relayRefreshInFlight) return;
    if (!this.store || !this.identity) return;

    const expiring = expiringRelayConnections(this.connectivityModule.getRelayHealth());
    if (expiring.length === 0) return;

    this.relayRefreshInFlight = true;
    try {
      for (const relay of expiring) {
        const remoteDid = this.remoteDidForPeerId(relay.peerId);
        if (!remoteDid) {
          // A relayed connection to a peer we hold no relationship with (e.g.
          // an in-flight handshake). Its next send re-dials on demand.
          continue;
        }

        const seconds = relay.secondsRemaining;
        logger.info(
          `[Agent] supervisor: relay session to ${relay.peerId.slice(0, 12)}... ` +
            (seconds != null ? `expires in ~${seconds}s` : 'is out of transfer grant') +
            ' — re-dialing for a fresh relay grant',
        );

        try {
          await this.reconnectPeer(remoteDid);
        } catch (err) {
          // Keep refreshing the others; this one is covered reactively by the
          // peer:disconnect path (or the next tick) if it does expire.
          logger.warn(
            `[Agent] supervisor: relay refresh for ${relay.peerId.slice(0, 12)}... failed: ` +
              `${(err as Error)?.message ?? err}`,
          );
        }
      }
    } finally {
      this.relayRefreshInFlight = false;
    }
  }

  /**
   * Map a libp2p peer ID back to the identity reference the relationship store
   * is keyed by — the utility server's DID, or a peer's remote DID.
   *
   * (Named `remoteDid…` because every value it returns is a DID, even though the
   * utility-server case historically travelled as a VID.)
   */
  private remoteDidForPeerId(peerId: string): string | undefined {
    if (!this.store || !this.identity) return undefined;

    if (this.tspBridge.getServerTransportPeerId() === peerId) {
      return this.tspBridge.getUtilityServerDid() ?? undefined;
    }

    for (const record of this.store.list(this.identity.did)) {
      if (record.remoteTransport?.peerId === peerId) {
        return record.remoteDid ?? undefined;
      }
    }
    return undefined;
  }

  // ---------------------------------------------------------------------------
  // Bootstrap integration — delegated to ConnectivityModule
  // ---------------------------------------------------------------------------

  async refreshBootstrapPeers(onStatus?: (message: string) => void): Promise<DiscoveredPeer[]> {
    if (!this.libp2pNode) {
      return [];
    }
    return this.connectivityModule.refreshBootstrapPeers({
      libp2pNode: this.libp2pNode,
      onStatus,
    });
  }

  /**
   * Live connectivity status for this agent — the single authoritative view
   * used by the status route, the TUI and gated-feature error messages.
   *
   * Derived on every call from observable state (connection table, live relay
   * grants, bridge flag), never from a cached boolean, so it cannot drift the
   * way `bootstrapConnected` / `relayListenerEstablished` did.
   */
  getConnectivityStatus(): ConnectivityStatus {
    const relay = this.connectivityModule.getRelayHealth();
    return deriveConnectivityStatus({
      bootstrapConnected: this.connectivityModule.isBootstrapConnected(),
      utilityServerConnected:
        this.tspBridge.isConnected() && !!this.tspBridge.getUtilityServerDid(),
      relay,
      hasRelayReservation: relay.hasReservation || this.connectivityModule.hasRelayReservation(),
      reconnecting: this.connectivityTickInFlight || !!this.serverReconnectTimer,
      consecutiveFailures: this.serverReconnectAttempt,
      lastError: this.lastConnectivityError,
    });
  }

  /**
   * Error text for a feature that needs the utility server but cannot have it
   * right now. Names the failed layer and what happens next, instead of the
   * context-free "Not connected to utility server." that users could not act on.
   */
  private connectivityFailureMessage(operation: string): string {
    return describeConnectivityFailure(this.getConnectivityStatus(), operation);
  }

  isBootstrapConnected(): boolean {
    return this.connectivityModule.isBootstrapConnected();
  }

  getBootstrapRelayAddr(): string | undefined {
    return this.connectivityModule.getBootstrapRelayAddr();
  }

  getDiscoveredPeers(): DiscoveredPeer[] {
    return this.connectivityModule.getDiscoveredPeers();
  }

  async reRegisterWithBootstrap(onStatus?: (message: string) => void): Promise<void> {
    if (!this.libp2pNode) {
      throw new Error('Agent.reRegisterWithBootstrap: agent not started. Call start() first.');
    }
    await this.connectivityModule.reRegisterWithBootstrap({
      libp2pNode: this.libp2pNode,
      multiaddrs: this.getMultiaddrs(),
      onStatus,
    });
  }

  // ---------------------------------------------------------------------------
  // Network detection — delegated to ConnectivityModule
  // ---------------------------------------------------------------------------

  getNetworkProfile(): NetworkProfile | undefined {
    return this.connectivityModule.getNetworkProfile();
  }

  isNetworkChanged(): boolean {
    return this.connectivityModule.isNetworkChanged(this.getMultiaddrs());
  }

  getClientSourceAddr(): string | undefined {
    return this.connectivityModule.getClientSourceAddr();
  }

  onNetworkChange(handler: (changedFields: string[]) => void): void {
    this.networkChangeHandlers.push(handler);
  }

  /**
   * Observe a credential delivered to this agent (a VIC/VMC/VEC pushed from the utility server and persisted
   * locally).
   *
   * Registration is additive and non-throwing: one observer failing never stops the others, and never fails the
   * 2PC leg that delivered the credential.
   */
  onCredentialReceived(handler: (credential: PersistedCredentialEvent) => void): void {
    this.credentialReceivedHandlers.push(handler);
  }

  /**
   * Observe a community record arriving from the utility server (a `vtc-membership` push), or its governance
   * changing (a `governance` push — the signal that an approved governance change was applied).
   *
   * Registration is additive and non-throwing, exactly like {@link onCredentialReceived}.
   */
  onCommunityChanged(handler: (community: PersistedCommunityEvent) => void): void {
    this.communityChangedHandlers.push(handler);
  }

  /**
   * Observe a governance-change proposal arriving (mirrored from the server's durable fan-out).
   *
   * Registration is additive and non-throwing, exactly like {@link onCredentialReceived}.
   */
  onGovernanceProposal(handler: (proposal: PersistedProposalEvent) => void): void {
    this.governanceProposalHandlers.push(handler);
  }

  /**
   * Observe ceremony progress — the server telling this agent that a founding co-signature landed.
   *
   * The nudge carries no log content; an observer re-reads `/api/ceremony-log` for what it renders. Registration
   * is additive and non-throwing, exactly like {@link onCredentialReceived}.
   */
  onCeremonyEvent(handler: (event: PersistedCeremonyEvent) => void): void {
    this.ceremonyEventHandlers.push(handler);
  }

  // ---------------------------------------------------------------------------
  // libp2p node boot
  // ---------------------------------------------------------------------------

  /**
   * Load the per-identity libp2p node seed from the keystore, creating and
   * persisting it on first run.
   *
   * The seed is keyed by the identity DID (stable across rotations) and stored
   * under {@link NODE_SEED_KEY_TYPE}. It is deliberately NOT derived from the
   * identity signing key: that key is advanced by rotation and the
   * name-registration "atomic key flip", which previously made the libp2p Peer
   * ID change on every re-login and broke utility-server reply routing.
   */
  private async getOrCreateNodeSeed(): Promise<Uint8Array> {
    const keystore = new SqliteKeyStore(this.registry.getKeystorePath(this.name));
    try {
      const existing = await keystore
        .retrieveKeyPairAsync(this.identity.did, NODE_SEED_KEY_TYPE, this.passphrase)
        .catch(() => undefined);
      if (existing) {
        return existing.secretKey;
      }

      const seed = new Uint8Array(randomBytes(32));
      const publicKey = (await keys.generateKeyPairFromSeed('Ed25519', seed)).publicKey.raw;
      await keystore.storeKeyPairAsync(
        this.identity.did,
        NODE_SEED_KEY_TYPE,
        { secretKey: seed, publicKey },
        this.passphrase,
      );
      logger.info('[Agent] persisted new libp2p node seed (Peer ID stable across logins)');
      return seed;
    } finally {
      keystore.close();
    }
  }

  private async createLibp2pNodeOnPortRange(onStatus?: (message: string) => void): Promise<Libp2p> {
    const candidatePorts = this.port && this.port !== 0 ? [this.port] : AGENT_PORT_RANGE;

    // Seed the node key from the PERSISTED per-identity seed so the transport
    // Peer ID is stable across logins/restarts. Seeding from the signing key
    // made the Peer ID change every session (rotation / key-flip), which left
    // the utility server routing replies to a dead peer and stalled the
    // identity push for ~2×30s.
    const nodeSeed = await this.getOrCreateNodeSeed();
    const privateKey = await keys.generateKeyPairFromSeed('Ed25519', nodeSeed);

    // Phase 7: Import circuit relay and WebSocket transports for NAT traversal
    const { circuitRelayTransport } = await import('@libp2p/circuit-relay-v2');
    const { webSockets } = await import('@libp2p/websockets');

    let lastErr: unknown;
    for (const port of candidatePorts) {
      try {
        onStatus?.(`Attempting to listen on port ${port}...`);
        const node = await createLibp2p({
          privateKey,
          addresses: { listen: [`/ip4/0.0.0.0/tcp/${port}`] },
          transports: [tcp(), webSockets(), circuitRelayTransport()],
          streamMuxers: [yamux()],
          connectionEncrypters: [noise()],
          connectionManager: {
            // Hardening (B3): bound the connection table and prune it so
            // half-open/stale connections don't linger and get served to
            // dialProtocol() as dead streams ("Cannot write to a stream
            // that is closed").
            maxConnections: 128,
            maxParallelDials: 32,
            dialTimeout: 10_000,
            addressDialTimeout: 6_000,
          },
          services: {
            identify: identify(),
            // B3: ping detects liveness — libp2p automatically closes/prunes
            // connections that fail a configured number of pings.
            ping: (await import('@libp2p/ping')).ping(),
          },
        });
        onStatus?.(`Listening on port ${port}.`);
        return node;
      } catch (err) {
        lastErr = err;
        onStatus?.(`Port ${port} unavailable, trying next port...`);
      }
    }

    throw new Error(
      `Agent.start: unable to bind to any port in range ${AGENT_PORT_RANGE_LABEL}: ` +
      `${(lastErr as Error)?.message ?? 'unknown error'}`,
    );
  }

  // ---------------------------------------------------------------------------
  // stop() — graceful shutdown
  // ---------------------------------------------------------------------------

  async stop(): Promise<void> {
    // Block any in-flight reconnect from re-arming its timer forever after
    // this agent is torn down (the zombie "agent not started" loop).
    this.stopped = true;
    this.stopRelationshipPolling();
    // Stop the connectivity supervisor and any pending reconnect/refresh.
    this.stopConnectivitySupervisor();
    this.serverReconnectAttempt = 0;
    if (this.ceremonyDriverTimer) {
      clearInterval(this.ceremonyDriverTimer);
      this.ceremonyDriverTimer = undefined;
    }
    // Stop the CRE exchange ticker (Phase 5 driver).
    this.exchangeEngine?.stopTicker();
    this.exchangeEngine = undefined;

    // Shut down the transaction coordinator (janitor timer + tx-coordinator.db).
    // Without this, switching VTAs (POST /api/activate stops the old agent then
    // starts the new one) left the previous VTA's tx janitor/outbox running.
    if (this._txBootstrap) {
      await this._txBootstrap.shutdown();
      this._txBootstrap = undefined;
    }

    if (this.transport) {
      await this.transport.stop();
      this.transport = undefined;
    }
    if (this.libp2pNode) {
      await this.libp2pNode.stop();
      this.libp2pNode = undefined;
    }
    if (this.db) {
      this.db.close();
      this.db = undefined;
    }
    this.store = undefined;
    this.manager = undefined;

    // Destroy extracted modules
    this.connectivityModule.destroy();
    this.vtcApiModule.destroy();
  }

  // ---------------------------------------------------------------------------
  // Identity accessors
  // ---------------------------------------------------------------------------

  getVid(): string {
    return this.identity.cesrVid;
  }

  getDid(): string {
    return this.identity.did;
  }

  getName(): string {
    return this.name;
  }

  /**
   * This agent's OWN SQLite database handle (its per-agent database under
   * P2PTS_HOME/vta/<agentKey>/). Throws if the agent has not started.
   */
  getDbHandle(): ReturnType<AgentDatabase['getDbHandle']> {
    if (!this.db) throw new Error('Agent.getDbHandle: agent not started');
    return this.db.getDbHandle();
  }

  getCredentialFactory(): CredentialFactoryImpl {
    if (!this._credentialFactory) throw new Error('agent not started');
    return this._credentialFactory;
  }

  getMeta(): AgentMeta {
    return this.meta;
  }

  // ---------------------------------------------------------------------------
  // OOBI generation
  // ---------------------------------------------------------------------------

  generateOobi(): string {
    if (!this.libp2pNode) {
      throw new Error('Agent.generateOobi: agent not started. Call start() first.');
    }
    const oobi = {
      cesrVid: this.identity.cesrVid,
      peerId: this.libp2pNode.peerId.toString(),
      multiaddrs: this.libp2pNode.getMultiaddrs().map(a => a.toString()),
      did: this.identity.did,
    };
    // Sign the OUT-OF-BAND INTRODUCTION with the PQ root of trust when the
    // identity has one (G7e). This is exactly the high-value, long-lived,
    // asynchronous statement ML-DSA-65 is reserved for: the OOBI is copied by
    // hand and is what establishes who the peer is before any TSP message flows.
    // Identities created before PQ provisioning emit the unsigned 4-item form,
    // which peers still accept.
    if (this.identity.mlDsa65KeyPair) {
      return encodeOobi(signOobi(oobi, this.identity.mlDsa65KeyPair.secretKey));
    }
    return encodeOobi(oobi);
  }

  getMultiaddrs(): string[] {
    if (!this.libp2pNode) return [];
    return this.libp2pNode.getMultiaddrs().map(a => a.toString());
  }

  getPeerId(): string {
    if (!this.libp2pNode) return '';
    return this.libp2pNode.peerId.toString();
  }

  signMessage(message: string): string {
    if (!this.identity?.signingKeyPair) {
      throw new Error('signMessage: no signing key pair available (VTA not yet activated)');
    }
    const digest = new TextEncoder().encode(message);
    const sig = signEd25519(digest, this.identity.signingKeyPair.secretKey);
    return Buffer.from(sig).toString('base64');
  }

  // ---------------------------------------------------------------------------
  // Relationship management
  // ---------------------------------------------------------------------------

  async connectToPeer(encodedOobi: string): Promise<void> {
    if (!this.manager || !this.store) {
      throw new Error('Agent.connectToPeer: agent not started. Call start() first.');
    }

    const oobi = decodeOobi(encodedOobi);

    // Connecting to yourself is never valid — reject early, before any
    // relationship state or RFI is created, so a pending self-connection line
    // can never appear in the UI. Also sweep any leftover self-pending row left
    // by a previous attempt (this.store.deleteRecord is a no-op if none exists).
    if (oobi.cesrVid === this.identity.cesrVid || oobi.did === this.identity.did) {
      try {
        this.store.deleteRecord(this.identity.did, this.identity.did);
      } catch { /* best-effort cleanup */ }
      throw new Error('Cannot connect to yourself — share this OOBI with a peer instead.');
    }

    // The strict 4-item OOBI carries the peer's real DID; the stub is keyed by it.
    const existing = this.store.get(this.identity.did, oobi.did);
    if (existing) {
      if (existing.direction === 'bidirectional' && existing.status === 'established') {
        const remoteDid = existing.remoteDid ?? oobi.did;

        // Load the ceremony session once so both the "already have a
        // relationship" gate and the stale-expiry gate can share it.
        let session: VrcCeremonySession | null = null;
        if (this._txBootstrap) {
          session = await this._getCeremonyContext().ceremonyStore.getByPair(this.identity.did, remoteDid);
        }

        // A fully completed relationship must NEVER be re-created: surface an
        // acknowledgment-required error and keep the caller in the pre-paste
        // state. No RFI is sent. "Completed" means the ceremony finished:
        //   - `personhood_status = 'verified'` (written at ceremony completion), or
        //   - the ceremony session reached phase 'complete', or
        //   - the exchanged VRC pair exists in the credentials table.
        // The session/credential fallbacks matter: `setPersonhoodStatus`
        // silently no-ops when the remote DID fails to resolve, so an
        // otherwise-finished ceremony can leave personhood_status NULL.
        const completed =
          existing.personhoodStatus === 'verified' ||
          session?.phase === 'complete' ||
          this.hasExchangedVrcs(existing.remoteEd25519Key);

        if (completed) {
          this.store.updateTransport(this.identity.did, remoteDid, {
            peerId: oobi.peerId,
            multiaddrs: oobi.multiaddrs,
          });
          // Best-effort notice to the OTHER agent so it ALSO shows the
          // "you already have a relationship" popup with a Close button.
          await this.notifyDuplicateConnect(remoteDid);
          throw new RelationshipAlreadyExistsError(existing, this.getRemoteDisplayName(remoteDid));
        }

        // Established but the personhood ceremony never completed. If the ack
        // deadline passed (still stuck at the "I know this person" gate),
        // clear the connection state so a fresh OOBI exchange + connect can
        // succeed. Otherwise the ceremony is still pending — refresh the peer's
        // transport and keep it (no duplicate RFI).
        if (this._txBootstrap) {
          if (isCeremonyStale(existing, session)) {
            const ctx = this._getCeremonyContext();
            await teardownCeremony(ctx, remoteDid);
            // Fall through to a fresh sendRfi below.
          } else {
            this.store.updateTransport(this.identity.did, remoteDid, {
              peerId: oobi.peerId,
              multiaddrs: oobi.multiaddrs,
            });
            return;
          }
        } else {
          // No transaction coordinator available — keep the existing pending
          // relationship untouched (no duplicate RFI, no teardown).
          this.store.updateTransport(this.identity.did, remoteDid, {
            peerId: oobi.peerId,
            multiaddrs: oobi.multiaddrs,
          });
          return;
        }
      } else {
        // Pending handshake (outbound RFI sent / inbound RFI received) — no-op.
        return;
      }
    }

    await this.manager.sendRfi(encodedOobi);
  }

  /**
   * True when a RelationshipCredential (VRC) pair for this local ↔ remote
   * relationship already exists in the credentials table (either direction).
   * The most robust signal that the personhood ceremony completed and the VRCs
   * were exchanged — works even if personhood_status was never back-filled or
   * the ceremony-session row is missing.
   *
   * Matches identities by their Ed25519 public-key BYTES (the same
   * canonicalization the utility server uses): an ephemeral did:peer:4 stub
   * row and the real VTA row for the same agent share those key bytes, so the
   * check works regardless of which identity row the relationship vs the
   * credential references.
   */
  private hasExchangedVrcs(remoteEd25519Key?: Uint8Array): boolean {
    try {
      if (!this.db || !this.identity.signingKeyPair) return false;
      const localEd = this.identity.signingKeyPair.publicKey;
      const remoteEd = remoteEd25519Key;
      if (!localEd || localEd.length === 0 || !remoteEd || remoteEd.length === 0) return false;
      const edLocal = Buffer.from(localEd);
      const edRemote = Buffer.from(remoteEd);
      const row = this.db.getDbHandle().prepare(`
        SELECT COUNT(*) AS c FROM credentials c
        WHERE c.vc_type = 'vrc' AND c.status NOT IN ('revoked', 'expired')
          AND (
            (c.issuer_identity_uuid IN (
               SELECT k.identity_uuid FROM keys k
               WHERE k.key_type = 'ed25519' AND k.rotation_version = 0 AND k.public_key = ?)
             AND c.subject_identity_uuid IN (
               SELECT k.identity_uuid FROM keys k
               WHERE k.key_type = 'ed25519' AND k.rotation_version = 0 AND k.public_key = ?))
            OR
            (c.issuer_identity_uuid IN (
               SELECT k.identity_uuid FROM keys k
               WHERE k.key_type = 'ed25519' AND k.rotation_version = 0 AND k.public_key = ?)
             AND c.subject_identity_uuid IN (
               SELECT k.identity_uuid FROM keys k
               WHERE k.key_type = 'ed25519' AND k.rotation_version = 0 AND k.public_key = ?))
          )
      `).get(edLocal, edRemote, edRemote, edLocal) as { c: number };
      return (row?.c ?? 0) > 0;
    } catch {
      return false;
    }
  }

  /**
   * Best-effort TSP_GEN notice to an already-connected peer that the local user
   * just tried to re-run an OOBI exchange + connect. The peer shows the same
   * "You already have a relationship with <name>" popup with a Close button.
   */
  private async notifyDuplicateConnect(remoteDid: string): Promise<void> {
    try {
      if (!this.manager) return;
      const body = new TextEncoder().encode(JSON.stringify({
        action: 'duplicate_connect_notice',
        from: this.identity.did,
        name: this.getName?.() || null,
      }));
      await this.manager.sendMessage(remoteDid, body);
      logger.info(`[Agent] ⚠ duplicate-connect notice SENT to ${remoteDid.slice(0, 24)}... (peer should show the popup)`);
    } catch (err) {
      logger.warn(`[Agent] duplicate-connect notice not delivered to ${remoteDid.slice(0, 24)}...: ${(err as Error)?.message}`);
    }
  }

  /** Resolve a remote identity's display name from the local identities table. */
  private getRemoteDisplayName(remoteDid: string): string | null {
    if (!this.db) return null;
    try {
      const row = this.db.getDbHandle().prepare(
        `SELECT i.name AS name FROM identities i
         JOIN did_documents d ON d.identity_uuid = i.uuid AND d.did = ?`,
      ).get(remoteDid) as { name: string | null } | undefined;
      return row?.name?.trim() ? row.name : null;
    } catch {
      return null;
    }
  }

  async connectToDiscoveredPeer(discoveredPeer: DiscoveredPeer): Promise<void> {
    if (!this.manager || !this.store || !this.libp2pNode) {
      throw new Error('Agent.connectToDiscoveredPeer: agent not started. Call start() first.');
    }

    const existing = this.store.list(this.identity.did).find(
      r => r.status === 'established' && r.remoteTransport?.peerId === discoveredPeer.peerId,
    );
    if (existing) {
      this.store.updateTransport(this.identity.did, existing.remoteDid, {
        peerId: discoveredPeer.peerId,
        multiaddrs: discoveredPeer.multiaddrs,
      });
      return;
    }

    if (discoveredPeer.multiaddrs.length > 0) {
      try {
        await (this.libp2pNode.peerStore as any).patch(discoveredPeer.peerId, {
          multiaddrs: discoveredPeer.multiaddrs,
        });
      } catch {
        // Ignore peer store errors
      }
    }

    // Only emit an OOBI when the discovered peer carries BOTH a VID and a
    // real DID (strict 4-item format). Without a real DID no strict OOBI is
    // constructible; the peer introduces itself via its own OOBI/RFA.
    const discVid = discoveredPeer.vid;
    if (!discVid || !discoveredPeer.did) return;

    const syntheticOobi = encodeOobi({
      cesrVid: discVid,
      peerId: discoveredPeer.peerId,
      multiaddrs: discoveredPeer.multiaddrs,
      did: discoveredPeer.did,
    });

    await this.manager.sendRfi(syntheticOobi);
  }

  async reconnectPeer(remoteDid: string, onStatus?: (message: string) => void): Promise<void> {
    if (!this.transport || !this.store || !this.libp2pNode) {
      throw new Error('Agent.reconnectPeer: agent not started. Call start() first.');
    }
    const record = this.store.get(this.identity.did, remoteDid);
    if (!record || !record.remoteTransport) {
      throw new Error(`Agent.reconnectPeer: no relationship record for ${remoteDid.slice(0, 12)}...`);
    }

    await this.connectivityModule.reconnectPeer({
      transport: this.transport,
      libp2pNode: this.libp2pNode,
      store: this.store,
      localDid: this.identity.did,
      remoteDid,
      recordRemoteTransport: record.remoteTransport,
      onStatus,
    });
  }

  listRelationships(): RelationshipRecord[] {
    if (!this.store) return [];
    return this.store.list(this.identity.did);
  }

  getRelationship(remoteDid: string): RelationshipRecord | undefined {
    if (!this.store) return undefined;
    return this.store.get(this.identity.did, remoteDid);
  }

  /**
   * Durable ceremony-saga status for a peer, surfaced to the UI.
   *
   * Returns a SYNTHESIZED personhood view when no `vrc_ceremonies` row exists
   * yet. The saga row is created lazily on the first "I know this person"
   * press, but the 60s ack window is already running from
   * `relationships.created_at`; without this synthesis neither display could
   * render the countdown until somebody pressed (which is exactly why the UI
   * previously had to run a browser-side timer of its own).
   *
   * Returns null only when there is no relationship record for the peer.
   */
  async getCeremonyStatus(
    remoteDid: string,
  ): Promise<{
    phase: string;
    failedStep: string | null;
    lastError: string | null;
    attempt: number;
    complete: boolean;
    localAcked: boolean;
    remoteAcked: boolean;
    /** Server-owned 60s personhood-ack window driving the UI countdown. */
    ack: CeremonyAckView;
    /** The utility archive was handed to the durable outbox/push pipeline
     *  (no server reachable). The ceremony is still complete peer-to-peer. */
    archiveDeferred: boolean;
  } | null> {
    if (!this._txBootstrap || !this.store) return null;
    const rec = this.store.get(this.identity.did, remoteDid);
    if (!rec) return null;
    // Canonicalize to the stored record's DID (the caller may pass either the
    // relationship key or the peer's current DID).
    const canonicalDid = rec.remoteDid ?? remoteDid;
    const store = new VrcCeremonyStore(this._txBootstrap.txDataSource);
    const session = await store.getByPair(this.identity.did, canonicalDid);
    const ack = buildCeremonyAckView(rec, session);
    if (!session) {
      // Nobody has pressed yet — no saga row — but the window is open.
      return {
        phase: 'personhood',
        failedStep: null,
        lastError: null,
        attempt: 0,
        complete: false,
        localAcked: false,
        remoteAcked: false,
        ack,
        archiveDeferred: false,
      };
    }
    return {
      phase: session.phase,
      failedStep: session.failedStep ?? session.currentStep,
      lastError: session.lastError,
      attempt: session.attempt,
      complete: session.phase === 'complete',
      localAcked: session.localAcked,
      remoteAcked: session.remoteAcked,
      ack,
      archiveDeferred: session.archiveDeferred,
    };
  }

  /**
   * Reset the in-progress personhood ceremony for a peer so a fresh OOBI
   * exchange + connect can be attempted.
   *
   * This mirrors what `expireStaleCeremonies` does when the 60s ack deadline
   * passes: `teardownCeremony` deletes the ceremony session row and the
   * relationship row (firing `onCeremonyExpired` so UI state is cleared). The
   * remote identity stub is retained for an idempotent retry.
   *
   * Only a ceremony still stuck at the personhood gate is reset — once both
   * acks are in and the VRC saga has left the gate (minting/sharing) or the
   * ceremony completed, it is left alone so an in-flight completion is never
   * torn down.
   */
  async resetPersonhoodCeremony(
    remoteDid: string,
  ): Promise<{ success: boolean; error?: string; reset?: boolean }> {
    if (!this.db || !this.store || !this._txBootstrap) {
      return { success: false, error: 'Agent is not ready.' };
    }
    const record = this.store.get(this.identity.did, remoteDid);
    if (!record) return { success: true, reset: false };
    const ctx = this._getCeremonyContext();
    const session = await ctx.ceremonyStore.getByPair(this.identity.did, record.remoteDid);
    if (!session || session.phase === 'complete') return { success: true, reset: false };
    // Still at the personhood gate = still waiting for BOTH "I know this
    // person" acks. If the ceremony already advanced past mutual
    // acknowledgment (or both acks are already recorded), let it finish.
    const atGate = session.phase === 'personhood' && !(session.localAcked && session.remoteAcked);
    if (!atGate) {
      return { success: false, error: 'Ceremony is no longer pending — not reset.' };
    }
    ctx.remotePeerVid = record.remoteDid;
    await teardownCeremony(ctx, record.remoteDid);
    return { success: true, reset: true };
  }

  async disconnectPeer(remoteDid: string): Promise<void> {
    if (!this.store) {
      throw new Error('Agent.disconnectPeer: agent not started. Call start() first.');
    }
    const record = this.store.get(this.identity.did, remoteDid);
    if (!record || !record.remoteTransport) {
      throw new Error(`Agent.disconnectPeer: no relationship record for ${remoteDid.slice(0, 12)}...`);
    }

    this.store.updateTransport(this.identity.did, remoteDid, {
      peerId: record.remoteTransport.peerId,
      multiaddrs: [],
    });

    if (this.libp2pNode) {
      try {
        const conns = (this.libp2pNode as any).getConnections(record.remoteTransport.peerId);
        for (const conn of conns) {
          await conn.close();
        }
      } catch {
        // Ignore connection close errors
      }
    }
  }

  /**
   * Live libp2p connections to a peer, for diagnostics.
   *
   * The counterpart to `disconnectPeer`, which uses the same `getConnections` call to CLOSE them. Promoted
   * 2026-10-09 so `relationships.debug()` can report connection state without the adapter reaching into the
   * raw node (`deps.libp2pNode as any`).
   *
   * Never throws and never returns `null`: this feeds a debug view, where "not connected" is a normal answer
   * rather than a failure — so an unstarted agent, a missing node and a caught error all report `[]`.
   */
  getPeerConnections(peerId: string): Array<{ remoteAddr: string | null; direction: string | null; status: string | null }> {
    if (!this.libp2pNode || !peerId) return [];
    try {
      const node = this.libp2pNode as unknown as {
        getConnections?: (p: string) => Array<{
          remoteAddr?: { toString(): string };
          direction?: string;
          status?: string;
        }>;
      };
      const conns = node.getConnections?.(peerId) ?? [];
      return conns.map((c) => ({
        remoteAddr: c.remoteAddr?.toString() ?? null,
        direction: c.direction ?? null,
        status: c.status ?? null,
      }));
    } catch {
      return [];
    }
  }

  // ---------------------------------------------------------------------------
  // Messaging
  // ---------------------------------------------------------------------------

  async sendMessage(remoteDid: string, body: Uint8Array, onStatus?: (message: string) => void): Promise<void> {
    if (!this.manager) {
      throw new Error('Agent.sendMessage: agent not started. Call start() first.');
    }
    await this.manager.sendMessage(remoteDid, body, onStatus);
  }

  async sendConfidentialMessage(remoteDid: string, body: Uint8Array, onStatus?: (message: string) => void): Promise<void> {
    if (!this.manager) {
      throw new Error('Agent.sendConfidentialMessage: agent not started. Call start() first.');
    }
    await this.manager.sendConfidentialMessage(remoteDid, body, onStatus);
  }

  // ---------------------------------------------------------------------------
  // Internal: dispatch inbound message to chat handlers
  // ---------------------------------------------------------------------------

  /**
   * Dispatch a non-protocol inbound message to all registered chat handlers.
   * Extracted from the onGenMessage handler so both the TSP-routing path and
   * the personhood/fallback path can share the same dispatch logic.
   */
  private dispatchToChat(remoteDid: string, body: Uint8Array, confidential: boolean): void {
    const msg: IncomingMessage = {
      remoteDid, body, confidential, receivedAt: Date.now(),
    };
    for (const handler of this.messageHandlers) {
      handler(msg);
    }
  }

  // ---------------------------------------------------------------------------
  // Event registration
  // ---------------------------------------------------------------------------

  onMessage(handler: (msg: IncomingMessage) => void): void {
    this.messageHandlers.push(handler);
  }

  onRelationshipChange(handler: (record: RelationshipRecord) => void): void {
    this.relationshipChangeHandlers.push(handler);
  }

  // ---------------------------------------------------------------------------
  // Personhood auto-response handlers (DTG RelationshipCredential)
  // ---------------------------------------------------------------------------

  private async _handlePersonhoodChallenge(
    remoteDid: string,
    parsed: { action: string; nonce: string; identityUuid: string },
  ): Promise<void> {
    if (!this.identity || !this.manager) return;
    const { signPersonhoodChallenge } = await import('@p2p-trust-stack/core/services/verified-channel.js');
    const response = signPersonhoodChallenge(parsed.nonce, this.identity.signingKeyPair.secretKey, parsed.identityUuid);
    const payload = new TextEncoder().encode(JSON.stringify(response));
    try { await this.manager.sendMessage(remoteDid, payload); } catch (err) {
      logger.error(`[Agent] Failed to send personhood response: ${(err as Error)?.message ?? err}`);
    }
  }

  private async _handlePersonhoodResponse(
    remoteDid: string,
    parsed: { action: string; nonce: string; signature: string; identityUuid: string },
  ): Promise<void> {
    if (!this.db || !this.store) return;
    const record = this.store.get(this.identity.did, remoteDid);
    if (!record?.remoteEd25519Key) { logger.warn(`[Agent] Personhood response: no Ed25519 key for ${remoteDid.slice(0,12)}`); return; }
    const { verifyAndIssueDtgRelationshipCredential } = await import('@p2p-trust-stack/core/services/verified-channel.js');
    const dbHandle = this.db.getDbHandle();
    // Query relationships table directly — RelationshipStore.get() may not have
    // deserialized remoteTransport from the JSON column yet.
    const localIdent = dbHandle.prepare("SELECT i.uuid FROM identities i JOIN did_documents dd ON dd.identity_uuid = i.uuid WHERE dd.did = ? AND i.custody = 'local'").get(this.identity.did) as { uuid: string } | undefined;
    // Resolve the SPECIFIC remote peer this response came from — not "the first
    // relationship this local VTA holds". A local VTA can hold several VRC
    // relationships (one per remote VTA in a multi-VTA app); the previous
    // unfiltered `SELECT remote_identity_uuid FROM relationships WHERE
    // local_identity_uuid = ...` returned whichever row came first and issued
    // the DTG RelationshipCredential against the wrong subject on the 2nd+.
    // `remoteDid` here is the sender's VID/DID, resolved the same way the
    // RelationshipStore.get() call above already resolved it (so it succeeds
    // whenever `record` is non-null — even before the remote's DID document is
    // promoted to primary).
    const remoteIdent = this.db.resolver.lookupByDid(remoteDid)
      ?? this.db.resolver.lookupByVid(remoteDid);
    if (!localIdent || !remoteIdent) { logger.warn('[Agent] Could not resolve identity UUIDs for DTG VRC'); return; }
    const vmId = this.identity.didDocument?.verificationMethod?.[0]?.id ?? `${this.identity.did}#key-1`;
    const peerDidRow = dbHandle.prepare('SELECT d.did FROM did_documents d WHERE d.identity_uuid = ? AND d.is_primary = 1').get(remoteIdent.identityUuid) as { did: string } | undefined;
    const result = await verifyAndIssueDtgRelationshipCredential({
      db: this.ds,
      response: { action: 'personhood_response', nonce: parsed.nonce, signature: parsed.signature, identityUuid: parsed.identityUuid },
      challengerIdentityUuid: localIdent.uuid, responderIdentityUuid: remoteIdent.identityUuid,
      responderEd25519PublicKey: record.remoteEd25519Key,
      issuerDid: this.identity.did, subjectDid: peerDidRow?.did ?? remoteDid,
      issuerVerificationMethod: vmId, issuerSecretKey: this.identity.signingKeyPair.secretKey,
    });
    if (result.verified) {
      logger.info(`[Agent] ✅ DTG VRC issued for ${remoteDid.slice(0,12)}... (vrcUuid=${result.vrcUuid})`);
      // Store the VRC locally so the agent has it for offline VRC resolution.
      if (result.vrcUuid) {
        try {
          const credRow = dbHandle.prepare(
            'SELECT w3c_vc_json FROM credentials WHERE uuid = ?'
          ).get(result.vrcUuid) as { w3c_vc_json: string | null } | undefined;
          if (credRow?.w3c_vc_json) {
            this.db.vtcStore.storeReceivedDtgVrc(
              credRow.w3c_vc_json,
              this.identity.did,
              peerDidRow?.did ?? remoteDid,
            );
            logger.info(`[Agent] VRC stored locally for ${remoteDid.slice(0,12)}...`);
          }
        } catch (err) {
          logger.warn(`[Agent] Failed to store VRC locally: ${(err as Error)?.message ?? err}`);
        }
      }
    }
    else logger.warn(`[Agent] ❌ DTG VRC failed: ${result.reason}`);
  }

  /**
   * Handle an incoming personhood_ack message (mutual acknowledgment ceremony).
   * Routes through the ceremony state machine in src/relationship/ceremony.ts.
   *
   * COMPATIBILITY RECEIVER ONLY. The authoritative inbound path is the
   * `personhood_ack` OPERATION handled by PersonhoodAckReceiveParticipant (a
   * coordinator transaction, which is what gives the sender a durable
   * commit/abort result). This raw TSP_GEN entry point is kept so a peer on an
   * older build can still be understood; it records the same flag and changes no
   * ceremony semantics of its own.
   */
  private _handlePersonhoodCeremony(remoteDid: string, msg: PersonhoodAckMessage): void {
    if (!this.db || !this.store || !this.manager) return;
    const ctx = this._getCeremonyContext();
    ctx.remotePeerVid = remoteDid;
    handlePersonhoodAck(ctx, remoteDid, msg)
      .then(() => this._emitCeremonyAckChange(remoteDid))
      .catch(err =>
        logger.error('[Agent] handlePersonhoodAck failed:', (err as Error)?.message ?? err),
      );
  }

  /**
   * Handle an inbound `duplicate_connect_notice` TSP_GEN: a peer pasted an OOBI
   * and pressed Connect for a relationship that is already verified. Fire the
   * registered handlers (TUI popup / web SSE push) so THIS agent also shows the
   * "You already have a relationship with <name>" popup with a Close button.
   */
  private _handleDuplicateConnectNotice(
    remoteDid: string,
    parsed: { action: string; from?: string; name?: string },
  ): void {
    const rec = this.store?.get(this.identity.did, remoteDid);
    // Canonicalize to the stored record's DID when we have one.
    const canonicalDid = rec?.remoteDid ?? parsed.from ?? remoteDid;
    const who = parsed.name?.trim() || canonicalDid.slice(0, 24);
    logger.info(`[Agent] ⚠ Duplicate OOBI connect attempted by ${who}... (${canonicalDid.slice(0, 24)}...) — relationship already exists`);
    // Persist a pending notice so the web UI can surface the popup via its
    // /api/relationships POLL (no SSE required — the dashboard already polls
    // every 2 s). Consumed by getDuplicateConnectNotice (one-shot).
    this.duplicateConnectNotices.set(canonicalDid, {
      remoteName: parsed.name ?? null,
      at: Date.now(),
    });
    for (const handler of this.duplicateConnectNoticeHandlers) {
      try {
        handler(canonicalDid, parsed.name ?? null);
      } catch (err) {
        logger.error('[Agent] duplicate-connect-notice handler error:', (err as Error)?.message ?? err);
      }
    }
  }

  /**
   * Read (and consume) a pending duplicate-connect notice for a peer.
   * One-shot: after this returns, the notice is cleared so the popup is shown
   * exactly once on the next UI poll.
   */
  getDuplicateConnectNotice(remoteDid: string): { remoteName: string | null; at: number } | undefined {
    const entry = this.duplicateConnectNotices.get(remoteDid);
    if (entry) this.duplicateConnectNotices.delete(remoteDid);
    return entry;
  }

  /**
   * Route non-protocol inbound messages (plain TSP_GEN chat/personhood JSON).
   * Runs when the TSP protocol router did not handle the message.
   */
  private _handleNonProtocolInbound(remoteDid: string, body: Uint8Array, confidential: boolean): void {
    // ── Personhood auto-response ────────────────────────────────────
    try {
      const parsed = JSON.parse(new TextDecoder().decode(body));
      if (parsed.action === 'personhood_challenge' && parsed.nonce) {
        this._handlePersonhoodChallenge(remoteDid, parsed);
        return;
      }
      if (parsed.action === 'personhood_response' && parsed.nonce) {
        this._handlePersonhoodResponse(remoteDid, parsed);
        return;
      }
      // ── Personhood ceremony acknowledgment ───────────────────────
      if (parsed.action === 'personhood_ack' && parsed.from) {
        this._handlePersonhoodCeremony(remoteDid, parsed as PersonhoodAckMessage);
        return;
      }
      // ── Duplicate OOBI connect notice ────────────────────────────
      // A peer pasted an OOBI + pressed Connect for an already-verified
      // relationship. Surfacing it HERE means BOTH agents show the
      // "you already have a relationship" popup with a Close button.
      if (parsed.action === 'duplicate_connect_notice' && parsed.from) {
        this._handleDuplicateConnectNotice(remoteDid, parsed as { action: string; from?: string; name?: string });
        return;
      }
    } catch { /* not JSON or not personhood */ }

    // Personhood done — this is chat. Key the inbox by the sender's REAL DID
    // (the same key the chat UI polls and the local outbox uses), not the
    // ephemeral VID from the envelope. Without this, the remote side stores
    // incoming chat under the sender VID while the UI queries by DID → messages
    // arrive in the inbox but never display.
    const rec = this.store?.get(this.identity.did, remoteDid);
    this.dispatchToChat(rec?.remoteDid ?? remoteDid, body, confidential);
  }

  /** Build the ceremony context wired to this agent's infrastructure. */
  private _getCeremonyContext(): CeremonyContext {
    const hasTx = !!(this._txBootstrap && this.manager && this.db);
    const serverDid = this.tspBridge?.getUtilityServerDid();

    return {
      store: this.store!,
      db: this.db!.getDbHandle(),
      resolver: this.db!.resolver,
      identity: this.identity,
      sendMessage: async (remoteDid, body) => {
        await this.manager!.sendMessage(remoteDid, body);
      },
      onPromptToAcknowledge: (remoteDid, _fromDid) => {
        for (const handler of this.ceremonyPromptHandlers) {
          handler(remoteDid);
        }
      },
      onCeremonyComplete: (remoteDid) => {
        logger.info(`[Agent] 🎉 Ceremony complete with ${remoteDid.slice(0, 12)}...`);
        for (const handler of this.ceremonyCompleteHandlers) {
          handler(remoteDid);
        }
      },
      onCeremonyFailed: (remoteDid, step, error) => {
        logger.error(`[Agent] 🚫 Ceremony failed at step ${step} with ${remoteDid.slice(0, 12)}...: ${error}`);
        for (const handler of this.ceremonyFailedHandlers) {
          handler(remoteDid, step, error);
        }
      },
      onCeremonyExpired: (remoteDid) => {
        logger.info(`[Agent] ⏱ Ceremony expired for ${remoteDid.slice(0, 24)}... — connection reset. Re-paste the OOBI to retry.`);
        for (const handler of this.ceremonyExpiredHandlers) {
          handler(remoteDid);
        }
      },

      // ── Transaction-coordinator enclosure ────────────────────────────
      ceremonyStore: this._txBootstrap!
        ? new VrcCeremonyStore(this._txBootstrap.txDataSource)
        : (undefined as unknown as VrcCeremonyStore),
      txManager: hasTx ? this._txBootstrap!.manager : (undefined as unknown as TransactionManager),
      createLocalVrcParticipant: hasTx && this._vrcCeremonyParticipant
        ? () => this._vrcCeremonyParticipant!
        : undefined,
      peerTransport: hasTx ? this.createPeerTransport() : undefined,
      serverTransport: hasTx && serverDid ? this.createServerTransport() : undefined,
      serverPid: serverDid ? `peer:${serverDid}` : undefined,
      remotePeerVid: undefined, // Set at call time by _handlePersonhoodCeremony / acknowledgeRemotePeer
    };
  }

  // Ceremony event handlers (set by TUI/Web layers)
  private ceremonyPromptHandlers: Array<(remoteDid: string) => void> = [];
  private ceremonyCompleteHandlers: Array<(remoteDid: string) => void> = [];
  private ceremonyFailedHandlers: Array<(remoteDid: string, step: string, error: string) => void> = [];

  /** Register a handler for when a personhood acknowledgment prompt is needed. */
  onCeremonyPrompt(handler: (remoteDid: string) => void): void {
    this.ceremonyPromptHandlers.push(handler);
  }

  /** Register a handler for when the ceremony completes (VRC issued). */
  onCeremonyComplete(handler: (remoteDid: string) => void): void {
    this.ceremonyCompleteHandlers.push(handler);
  }

  /** Register a handler for when the ceremony fails at a specific step. */
  onCeremonyFailed(handler: (remoteDid: string, step: string, error: string) => void): void {
    this.ceremonyFailedHandlers.push(handler);
  }

  private ceremonyExpiredHandlers: Array<(remoteDid: string) => void> = [];

  /** Register a handler for when an uncompleted personhood ceremony expires. */
  onCeremonyExpired(handler: (remoteDid: string) => void): void {
    this.ceremonyExpiredHandlers.push(handler);
  }

  private ceremonyAckChangeHandlers: Array<(remoteDid: string) => void> = [];

  /**
   * Register a handler for when a personhood acknowledgment is recorded on
   * EITHER side (the local press, or an inbound peer ack).
   *
   * The web layer pushes this over SSE so the other display updates at once
   * instead of waiting for its next /api/relationships poll.
   */
  onCeremonyAckChange(handler: (remoteDid: string) => void): void {
    this.ceremonyAckChangeHandlers.push(handler);
  }

  /**
   * Emit an ack-state change for a peer, keyed by the peer's DID — the key the
   * UI rows are keyed by (and what the ceremony callbacks also report).
   *
   * This is a UI NOTIFICATION ONLY and is deliberately best-effort: the durable
   * truth is the `vrc_ceremonies` row plus the coordinator legs, and the UI
   * re-reads it on every poll. It is never part of the ceremony state machine,
   * so a dropped notification costs at most one poll interval.
   */
  private _emitCeremonyAckChange(remoteDid: string): void {
    // Canonicalize to the stored record's DID (the caller may pass either key).
    const canonicalDid = this.store?.get(this.identity.did, remoteDid)?.remoteDid ?? remoteDid;
    for (const handler of this.ceremonyAckChangeHandlers) {
      try {
        handler(canonicalDid);
      } catch (err) {
        logger.error('[Agent] ceremony ack-change handler error:', (err as Error)?.message ?? err);
      }
    }
  }

  /**
   * React to the peer's personhood ack being durably committed locally by the
   * `ack_delivery` coordinator leg: push the UI notification and, when the LOCAL
   * user has not pressed yet, prompt them — the same behavior
   * `handlePersonhoodAck` provides on the legacy inbound TSP_GEN path.
   */
  private _handleRemoteAckRecorded(remoteDid: string): void {
    this._emitCeremonyAckChange(remoteDid);
    const rec = this.store?.get(this.identity.did, remoteDid);
    if (rec && rec.personhoodStatus === undefined) {
      logger.info(`[Agent] ${remoteDid.slice(0, 12)}... acknowledged — prompting the local user.`);
      for (const handler of this.ceremonyPromptHandlers) {
        try {
          handler(remoteDid);
        } catch (err) {
          logger.error('[Agent] ceremony prompt handler error:', (err as Error)?.message ?? err);
        }
      }
    }
  }

  private duplicateConnectNoticeHandlers: Array<(remoteDid: string, remoteName: string | null) => void> = [];

  /** Pending one-shot duplicate-connect notices keyed by remote DID (web UI poll reads + consumes). */
  private readonly duplicateConnectNotices = new Map<string, { remoteName: string | null; at: number }>();

  /** Register a handler for when an already-connected peer attempts a duplicate OOBI connect. */
  onDuplicateConnectNotice(handler: (remoteDid: string, remoteName: string | null) => void): void {
    this.duplicateConnectNoticeHandlers.push(handler);
  }

  /** Initiate the ceremony: local user presses "I know this person." */
  async acknowledgeRemotePeer(remoteDid: string): Promise<void> {
    if (!this.db || !this.store || !this.manager) return;
    const ctx = this._getCeremonyContext();
    ctx.remotePeerVid = remoteDid;
    await acknowledgePeer(ctx, remoteDid);
    // localUserAcknowledges re-checks and advances if the remote already acked.
    await localUserAcknowledges(ctx, remoteDid);
    // Tell the UI (both displays: ours directly, the peer's via SSE) that the
    // ack state moved.
    this._emitCeremonyAckChange(remoteDid);
  }

  /**
   * List VRC-connected peer identities from the local database.
   * Used by the VTC co-admin checklist to show the HUMAN peers this agent has
   * an established VRC relationship with — without needing the utility server.
   *
   * Sources peers DIRECTLY from the `relationships` table keyed on the local
   * identity's UUID (the relational identity key). This guarantees the offered
   * co-admin `uuid` is exactly the `remote_identity_uuid` that
   * `createCommunityCeremony` resolves strictly, so a checked candidate always
   * matches a relationship record and can be delivered.
   *
   * Only deliverable HUMAN VTA peers are returned:
   * - `i.role = 'vta'` AND `i.subject_kind = 'human'` — excludes organizations
   *   and infrastructure rows (the utility server is tagged 'organization').
   * - an Ed25519 key must be present — required to derive the co-admin's CESR
   *   VID for delivery.
   * - `remote_transport` must be present — required for the libp2p/TSP peerId.
   * These are exactly the preconditions `createCommunityCeremony` enforces.
   */
  getVrcConnectedPeers(): Array<{ name: string | null; did: string; uuid: string }> {
    if (!this.db) return [];
    const myUuid = this.getLocalIdentityUuid();
    const dbHandle = this.db.getDbHandle();
    const rows = dbHandle.prepare(`
      SELECT r.remote_identity_uuid AS uuid, dd.did AS did, i.name AS name,
             i.uuid AS identityUuid, k.public_key AS ed25519Key
      FROM relationships r
      JOIN identities i ON i.uuid = r.remote_identity_uuid
      LEFT JOIN keys k ON k.identity_uuid = i.uuid AND k.key_type = 'ed25519' AND k.rotation_version = 0
      LEFT JOIN did_documents dd ON dd.identity_uuid = i.uuid AND dd.is_primary = 1
      WHERE r.local_identity_uuid = ?
        AND r.direction = 'bidirectional'
        AND r.status = 'established'
        AND r.remote_transport IS NOT NULL
        AND i.role = 'vta'
        AND i.subject_kind = 'human'
        AND k.public_key IS NOT NULL
      ORDER BY i.name
    `).all(myUuid) as Array<{ uuid: string; name: string | null; did: string | null; identityUuid: string; ed25519Key: Uint8Array | null }>;

    logger.info(
      `[Agent] getVrcConnectedPeers: found ${rows.length} deliverable human VRC peers for uuid=${myUuid.slice(0, 12)}...`,
    );

    // Workstream A / full-C: with the strict 4-item OOBI, relationship rows are
    // keyed by the peer's REAL DID identity from the first RFI, and the identity
    // copy carries the login name + libp2p peer_id. Therefore the relationship's
    // remote_identity_uuid IS the authoritative identity — no key-byte
    // canonicalization is needed. The CESR VID prefix remains a display-only
    // fallback for genuinely unnamed peers.
    return rows.map((r) => {
      let name = r.name;
      if (!name && r.ed25519Key && r.ed25519Key.length > 0) {
        try {
          name = `${cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, r.ed25519Key).slice(0, 16)}…`;
        } catch { name = null; }
      }
      return { uuid: r.uuid, name, did: r.did ?? r.uuid };
    });
  }

  // ---------------------------------------------------------------------------
  // Internal: relationship change polling
  // ---------------------------------------------------------------------------

  private lastRelationshipSnapshot: Map<string, string> = new Map();

  private startRelationshipPolling(): void {
    this.relationshipPollInterval = setInterval(() => {
      if (!this.store) return;
      const records = this.store.list(this.identity.did);
      for (const record of records) {
        const key = record.remoteDid;
        const snapshot = `${record.direction}:${record.status}`;
        const prev = this.lastRelationshipSnapshot.get(key);
        if (prev !== snapshot) {
          this.lastRelationshipSnapshot.set(key, snapshot);
          for (const handler of this.relationshipChangeHandlers) {
            handler(record);
          }
        }
      }
    }, 200);
  }

  private stopRelationshipPolling(): void {
    if (this.relationshipPollInterval) {
      clearInterval(this.relationshipPollInterval);
      this.relationshipPollInterval = undefined;
    }
  }

  // ---------------------------------------------------------------------------
  // VTC / VRC — delegated to VtcApiModule
  // ---------------------------------------------------------------------------

  /**
   * Initiate VTC/VTN creation on the utility server via the ceremony
   * coordinator (TSP). The CeremonyCoordinatorParticipant handles:
   *   1. ceremony_begin — creates a ceremony_proposals record
   *   2. ceremony_approve — records a co-signature; the community crystallizes
   *      only once EVERY declared founding admin has co-signed it
   *   3. ceremony_query — polls for final status
   *
   * Naming a co-admin is a REQUEST to administer, not a grant: the named
   * identity's own agent must co-sign the proposal hash before the community
   * exists (the `crystallize-quorum-*` policy rules compare `approval_count`
   * against the declared admin count). A ceremony that is durably begun but
   * still short of that quorum is returned as
   * `{ success: true, awaitingCoSignatures: true }` — NOT as a failure.
   *
   * On success, the AgentDeliveryQueue delivers the VTC data to all
   * founding admins via TSP. The ceremony record is stored on the utility
   * server, so error recovery (ceremony_reset, ceremony_reconcile) is
   * always available.
   */
  async createCommunityCeremony(params: {
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
  }> {
    if (!this.identity) {
      return { success: false, error: 'Agent not started.' };
    }
    if (!this.tspBridge.isConnected()) {
      return { success: false, error: this.connectivityFailureMessage('create the community') };
    }
    const serverDid = this.tspBridge.getUtilityServerDid();
    if (!serverDid) {
      return { success: false, error: 'No utility server VID.' };
    }
    if (!this._txBootstrap) {
      return { success: false, error: 'Transaction coordinator not bootstrapped.' };
    }

    const myUuid = this.getLocalIdentityUuid();
    const transport = new TspParticipantTransport(
      async (dest, protocol, payload, timeoutMs) => {
        return await this.tspClient.request(dest, protocol as any, payload, timeoutMs);
      },
      { isConnected: () => this.tspBridge.isConnected(), serverDid },
    );
    const remote = new RemoteParticipant('server:us-1', transport);

    // The agent generates the ceremonyId so it can query/approve it after.
    // The server uses this idempotency-keyed ID (rejects if it already exists).
    const ceremonyId = randomUUID();

    try {
      // Phase 1: Begin the ceremony (durably creates ceremony_proposals row)
      const beginResult = await this._txBootstrap.manager.run(async (tx) => {
        tx.enlist(remote, [{
          op: 'ceremony_begin',
          params: {
            ceremonyId,
            proposerUuid: myUuid,
            name: params.name,
            kind: params.kind ?? 'vtc',
            threshold: params.threshold ?? 1,
            adminUuids: params.coadminUuids,
            parentCommunityUuid: params.parentCommunityUuid,
          },
        }]);
      });
      if (beginResult.outcome !== 'committed') {
        // Surface the server's own reason (e.g. a rejected proposal) instead of a
        // generic message — the query is cheap and bounded by short timeouts.
        return {
          success: false,
          ceremonyId,
          error: await this.ceremonyFailureReason(
            ceremonyId,
            `Failed to begin ceremony (${beginResult.outcome}).`,
          ),
        };
      }

      // Phase 2: Self-approve (creator is one of the founding admins).
      // When the approval count reaches the threshold, the server crystallizes
      // the ceremony (creates the VTC + enqueues delivery to all admins).
      //
      // The approval must carry a REAL Ed25519 signature over the proposal's
      // canonical hash — the server's GovernanceGuard verifies exactly that
      // (`validateCrystallization`). So we read the hash back from the server
      // first, then sign it. No more placeholder 'self-approve'.
      let proposalHash: string | undefined;
      try {
        const q = await remote.query('ceremony_query', { ceremonyId }) as { proposalHash?: string };
        proposalHash = q?.proposalHash;
      } catch (err) {
        return {
          success: false,
          ceremonyId,
          error: `Could not read the ceremony proposal hash to sign: ${(err as Error)?.message ?? err}`,
        };
      }
      if (!proposalHash) {
        return {
          success: false,
          ceremonyId,
          error: await this.ceremonyFailureReason(
            ceremonyId,
            'Could not read the ceremony proposal hash to sign.',
          ),
        };
      }
      const approvalSignature = this.signMessage(proposalHash);

      const approveResult = await this._txBootstrap.manager.run(async (tx) => {
        tx.enlist(remote, [{
          op: 'ceremony_approve',
          params: {
            ceremonyId,
            approverUuid: myUuid,
            signature: approvalSignature,
          },
        }]);
      });
      if (approveResult.outcome !== 'committed') {
        return {
          success: false,
          ceremonyId,
          error: await this.ceremonyFailureReason(
            ceremonyId,
            `Failed to approve ceremony (${approveResult.outcome}).`,
          ),
        };
      }

      // Phase 2b: a still-PENDING ceremony is the NORMAL outcome when founding
      // admins other than the creator were named. Crystallization requires every
      // declared admin to co-sign, so the creator's own approval can no longer
      // found the community on everyone's behalf. Report it as a distinct
      // outcome — the ceremony is durably begun and the named admins see it in
      // their own "Pending Approvals" list — instead of polling for a terminal
      // state that only THEIR signatures can produce.
      const afterApprove = await this.queryCeremony(ceremonyId, {
        timeoutMs: CEREMONY_POLL_DEFAULTS.queryTimeoutMs,
        connectivityTimeoutMs: CEREMONY_POLL_DEFAULTS.connectivityTimeoutMs,
      });
      if (afterApprove.status === 'pending') {
        const approvalsRequired = afterApprove.adminUuids?.length ?? 0;
        const approvalsReceived = afterApprove.approvalCount ?? 0;
        if (approvalsRequired > approvalsReceived) {
          logger.info(
            `[Agent] ceremony ${ceremonyId.slice(0, 8)} awaiting co-signatures ` +
            `(${approvalsReceived}/${approvalsRequired})`,
          );
          return {
            success: true,
            ceremonyId,
            awaitingCoSignatures: true,
            approvalsReceived,
            approvalsRequired,
          };
        }
      }

      // Phase 3: Wait for the ceremony to reach a terminal state
      // (crystallized | failed | expired). This makes the create button
      // transactional — it returns a definite success or failure, not a
      // fire-and-forget.
      //
      // The policy is time-budgeted (see tx/ceremony-poll.js): the first query
      // runs IMMEDIATELY — the server crystallizes synchronously inside
      // ceremony_approve's prepare(), so a committed approve has usually already
      // crystallized — each attempt is bounded by short timeouts, a definitive
      // error returns at once, and the loop cannot outlive `totalBudgetMs`.
      const pollResult = await awaitCeremonyTerminal({
        query: () => this.queryCeremony(ceremonyId, {
          timeoutMs: CEREMONY_POLL_DEFAULTS.queryTimeoutMs,
          connectivityTimeoutMs: CEREMONY_POLL_DEFAULTS.connectivityTimeoutMs,
        }),
        totalBudgetMs: CEREMONY_POLL_DEFAULTS.totalBudgetMs,
        pollDelayMs: CEREMONY_POLL_DEFAULTS.pollDelayMs,
        onProgress: (attempt, result) => {
          logger.info(
            `[Agent] VTC ceremony ${ceremonyId.slice(0, 8)} poll #${attempt}: ` +
            `${result.status ?? result.error ?? 'no data'}`,
          );
        },
      });

      switch (pollResult.outcome) {
        case 'crystallized':
          logger.info(
            `[Agent] VTC ceremony ${ceremonyId.slice(0, 8)} crystallized after ` +
            `${pollResult.attempts} poll(s) — queue will deliver VTC data`,
          );
          return { success: true, ceremonyId };
        case 'pending':
          // Poll budget expired with the ceremony still pending — i.e. still short
          // of co-signatures. That is not a failure of creation; the ceremony is
          // durable and resumable via `ceremonyId`.
          return {
            success: true,
            ceremonyId,
            awaitingCoSignatures: true,
            error: pollResult.error,
          };
        case 'failed':
        case 'expired':
        default:
          return { success: false, ceremonyId, error: pollResult.error };
      }

    } catch (err) {
      logger.error('[Agent] createCommunityCeremony failed:', (err as Error)?.message ?? err);
      return { success: false, ceremonyId, error: (err as Error)?.message ?? String(err) };
    }
  }

  /**
   * Best-effort read of the server's own failure reason for a ceremony that did
   * not commit, so the caller reports something true instead of a generic
   * message. Bounded by the short poll timeouts; degrades to `fallback`.
   */
  private async ceremonyFailureReason(ceremonyId: string, fallback: string): Promise<string> {
    try {
      const q = await this.queryCeremony(ceremonyId, {
        timeoutMs: CEREMONY_POLL_DEFAULTS.queryTimeoutMs,
        connectivityTimeoutMs: CEREMONY_POLL_DEFAULTS.connectivityTimeoutMs,
      });
      return q.errorReason || q.error || fallback;
    } catch {
      return fallback;
    }
  }

  /**
   * Query a community ceremony status by ceremonyId via TSP. Uses the
   * participant's read-only query() channel (returns status + errorReason).
   *
   * `opts` overrides the per-attempt transport budgets. The poll loop passes
   * short ones (see `CEREMONY_POLL_DEFAULTS`) so a single hung attempt cannot
   * consume the whole poll budget; callers that omit them keep the transport
   * defaults (30 s request / 15 s connectivity).
   */
  async queryCeremony(ceremonyId: string, opts?: {
    timeoutMs?: number;
    connectivityTimeoutMs?: number;
  }): Promise<{
    status?: string; errorReason?: string | null; error?: string;
    /** Distinct, verified co-signatures recorded so far (server `approvalCount`). */
    approvalCount?: number;
    /** The declared founding admin uuid set (server `adminUuids`). */
    adminUuids?: string[];
  }> {
    if (!this.tspBridge.isConnected() || !this._txBootstrap) {
      return { error: this.connectivityFailureMessage('check the ceremony status') };
    }
    const serverDid = this.tspBridge.getUtilityServerDid();
    if (!serverDid) return { error: 'No utility server VID.' };
    const transport = new TspParticipantTransport(
      async (dest, protocol, payload, timeoutMs) => {
        return await this.tspClient.request(dest, protocol as any, payload, timeoutMs);
      },
      {
        isConnected: () => this.tspBridge.isConnected(),
        serverDid,
        ...(opts?.timeoutMs != null ? { defaultTimeoutMs: opts.timeoutMs } : {}),
        ...(opts?.connectivityTimeoutMs != null
          ? { connectivityTimeoutMs: opts.connectivityTimeoutMs }
          : {}),
      },
    );
    const remote = new RemoteParticipant('server:us-1', transport);
    try {
      const data = await remote.query('ceremony_query', { ceremonyId }) as {
        status?: string;
        errorReason?: string | null;
        error?: string;
        approvalCount?: number;
        adminUuids?: string[];
      };
      return data || { error: 'No ceremony data returned.' };
    } catch (err) {
      return { error: (err as Error)?.message ?? String(err) };
    }
  }

  /**
   * List pending ceremonies this identity is a founding admin of, so a co-founder
   * can co-sign. When a community's approver threshold (M) is > 1, the creator's
   * single approval is NOT enough — each additional approver lists the proposal
   * here and signs it with `approveCeremony`. Discovery only; the server still
   * verifies the signature and the admin set on approval.
   */
  async listPendingCeremonies(): Promise<Array<Record<string, unknown>>> {
    const rows = await this.tryQueryUtilityServer('ceremony_pending_for', {
      adminUuid: this.getLocalIdentityUuid(),
    });
    return Array.isArray(rows) ? (rows as Array<Record<string, unknown>>) : [];
  }

  /**
   * Read the ceremony TASK LOG from the utility server: every ceremony run, named from
   * the step types it contains, newest first.
   *
   * The agent app is where communities are created and managed, so its Communities page
   * is the surface for this — the utility server is used for VTNs and does not carry a
   * second copy of the view.
   *
   * Returns [] when there is no server link: an absent log must look like "nothing yet",
   * not like a broken page.
   */
  async listCeremonyLog(): Promise<Array<Record<string, unknown>>> {
    const res = await this.tryQueryUtilityServer('ceremony_log_threads') as
      { threads?: unknown } | null;
    return Array.isArray(res?.threads) ? (res!.threads as Array<Record<string, unknown>>) : [];
  }

  /** One ceremony run's recorded steps, in the order they happened. */
  async getCeremonyLog(threadId: string): Promise<Array<Record<string, unknown>>> {
    const res = await this.tryQueryUtilityServer('ceremony_log_thread', { threadId }) as
      { steps?: unknown } | null;
    return Array.isArray(res?.steps) ? (res!.steps as Array<Record<string, unknown>>) : [];
  }

  /**
   * Run a request/response query against this agent's utility server over TSP.
   *
   * The single seam for agent→server protocols (`name_check`, `namespace_info`, `vtc_invite`, `vtc_accept`,
   * `ceremony_*`, …). Building the transport means touching `_txBootstrap`, `tspBridge` and `tspClient`, so
   * building it ONCE here is what keeps that private state out of every caller — the adapter had five
   * hand-built copies of it, which accounted for 20 of its `deps.agent as any` reaches.
   *
   * Throws `UtilityServerUnavailableError` (`code: 'utility_server_unavailable'`) when there is no usable
   * server link, so a caller can tell a retryable transport condition from a server-side failure. A
   * protocol-level failure is re-thrown with the server's own message.
   */
  async queryUtilityServer<T = unknown>(
    protocol: string,
    payload: Record<string, unknown> = {},
  ): Promise<T> {
    if (!this.tspBridge.isConnected() || !this._txBootstrap || !this.tspBridge.getUtilityServerDid()) {
      throw new UtilityServerUnavailableError(`run the '${protocol}' query`);
    }
    const remote = new RemoteParticipant('server:us-1', this.createServerTransport());
    return await remote.query(protocol, payload) as T;
  }

  /**
   * Best-effort variant: `null` instead of a throw.
   *
   * For read-only bridge queries where "the server could not answer" is a normal, renderable state (an empty
   * ceremony log) rather than something the caller must branch on.
   */
  private async tryQueryUtilityServer(
    op: string,
    params: Record<string, unknown> = {},
  ): Promise<unknown> {
    try {
      return await this.queryUtilityServer(op, params);
    } catch {
      return null;
    }
  }

  /**
   * Co-sign a pending ceremony: read the proposal hash from the server, sign it
   * with THIS identity's Ed25519 key, and submit the approval.
   *
   * This is what makes an approver threshold > 1 reachable, and it is why the
   * wording changed from "signature threshold" to "number of approvers": each
   * approver contributes a REAL signature, and the server verifies every one
   * (`GovernanceGuard.validateCrystallization`) before crystallizing.
   */
  async approveCeremony(ceremonyId: string): Promise<{ success: boolean; status?: string; error?: string }> {
    if (!this.identity) return { success: false, error: 'Agent not started.' };
    if (!this.tspBridge.isConnected() || !this._txBootstrap) {
      return { success: false, error: this.connectivityFailureMessage('approve the ceremony') };
    }
    const serverDid = this.tspBridge.getUtilityServerDid();
    if (!serverDid) return { success: false, error: 'No utility server VID.' };
    const transport = new TspParticipantTransport(
      async (dest, protocol, payload, timeoutMs) => {
        return await this.tspClient.request(dest, protocol as any, payload, timeoutMs);
      },
      { isConnected: () => this.tspBridge.isConnected(), serverDid },
    );
    const remote = new RemoteParticipant('server:us-1', transport);

    let proposalHash: string | undefined;
    try {
      const q = await remote.query('ceremony_query', { ceremonyId }) as { proposalHash?: string };
      proposalHash = q?.proposalHash;
    } catch (err) {
      return { success: false, error: (err as Error)?.message ?? String(err) };
    }
    if (!proposalHash) {
      return { success: false, error: 'Could not read the ceremony proposal hash to sign.' };
    }

    const signature = this.signMessage(proposalHash);
    const res = await this._txBootstrap.manager.run(async (tx) => {
      tx.enlist(remote, [{
        op: 'ceremony_approve',
        params: { ceremonyId, approverUuid: this.getLocalIdentityUuid(), signature },
      }]);
    });
    if (res.outcome !== 'committed') {
      return { success: false, error: `Approval was not committed (${res.outcome}).` };
    }
    const after = await remote.query('ceremony_query', { ceremonyId }) as { status?: string };
    return { success: true, status: after?.status };
  }

  /**
   * Reset a failed ceremony so it can be retried.
   */
  async resetCeremony(ceremonyId: string): Promise<{ success: boolean; error?: string }> {
    if (!this.tspBridge.isConnected() || !this._txBootstrap) {
      return { success: false, error: this.connectivityFailureMessage('reset the ceremony') };
    }
    const serverDid = this.tspBridge.getUtilityServerDid();
    if (!serverDid) return { success: false, error: 'No utility server VID.' };
    const transport = new TspParticipantTransport(
      async (dest, protocol, payload, timeoutMs) => {
        return await this.tspClient.request(dest, protocol as any, payload, timeoutMs);
      },
      { isConnected: () => this.tspBridge.isConnected(), serverDid },
    );
    const remote = new RemoteParticipant('server:us-1', transport);
    try {
      const result = await this._txBootstrap.manager.run(async (tx) => {
        tx.enlist(remote, [{ op: 'ceremony_reset', params: { ceremonyId } }]);
      });
      if (result.outcome === 'committed') return { success: true };
      return { success: false, error: `Reset failed: ${result.outcome}` };
    } catch (err) {
      return { success: false, error: (err as Error)?.message ?? String(err) };
    }
  }

  // ---------------------------------------------------------------------------
  // Governance changes (Phase B) — a community rule/threshold change needs
  // multi-admin consent. The utility server owns the proposal lifecycle (scope
  // resolution, hashing, durable fan-out, crystallization); the agent proposes,
  // reads the pending set, and co-signs.
  // ---------------------------------------------------------------------------

  /**
   * Propose a governance change to a community. The server resolves the approval
   * scope, hashes the proposal, and fans it out durably to every required approver.
   * The proposer self-approves (proposing IS consenting).
   */
  async proposeGovernanceChange(params: {
    communityUuid: string;
    change: GovernanceChange;
    scope?: ApprovalScope;
    minApprovals?: number;
  }): Promise<{ success: boolean; proposalId?: string; status?: string; error?: string }> {
    if (!this.identity) return { success: false, error: 'Agent not started.' };
    if (!this.tspBridge.isConnected() || !this._txBootstrap) {
      return { success: false, error: this.connectivityFailureMessage('propose a governance change') };
    }
    const serverDid = this.tspBridge.getUtilityServerDid();
    if (!serverDid) return { success: false, error: 'No utility server VID.' };

    const transport = new TspParticipantTransport(
      async (dest, protocol, payload, timeoutMs) => this.tspClient.request(dest, protocol as any, payload, timeoutMs),
      { isConnected: () => this.tspBridge.isConnected(), serverDid },
    );
    const remote = new RemoteParticipant('server:us-1', transport);
    const proposalId = randomUUID();

    try {
      const res = await this._txBootstrap.manager.run(async (tx) => {
        tx.enlist(remote, [{
          op: 'gov_change_begin',
          params: {
            proposalId,
            communityUuid: params.communityUuid,
            proposerUuid: this.getLocalIdentityUuid(),
            change: params.change,
            scope: params.scope ?? 'admins',
            minApprovals: params.minApprovals,
          },
        }]);
      });
      if (res.outcome !== 'committed') {
        return { success: false, proposalId, error: `Failed to begin the proposal (${res.outcome}).` };
      }
      const mine = await this.approveGovernanceChange(proposalId);
      return { success: true, proposalId, status: mine.status };
    } catch (err) {
      return { success: false, proposalId, error: (err as Error)?.message ?? String(err) };
    }
  }

  /** Co-sign a pending governance-change proposal: read the hash, sign, submit. */
  async approveGovernanceChange(proposalId: string): Promise<{
    success: boolean;
    status?: string;
    error?: string;
    /** Signatures recorded on the server after this approval. */
    approvalCount?: number;
    /** How many of those VERIFY — the number crystallization is decided on. */
    verifiedApproverCount?: number;
    /** Distinct approvers the proposal needs. */
    requiredApproverCount?: number;
  }> {
    if (!this.identity) return { success: false, error: 'Agent not started.' };
    if (!this.tspBridge.isConnected() || !this._txBootstrap) {
      return { success: false, error: this.connectivityFailureMessage('approve the proposal') };
    }
    const serverDid = this.tspBridge.getUtilityServerDid();
    if (!serverDid) return { success: false, error: 'No utility server VID.' };

    const transport = new TspParticipantTransport(
      async (dest, protocol, payload, timeoutMs) => this.tspClient.request(dest, protocol as any, payload, timeoutMs),
      { isConnected: () => this.tspBridge.isConnected(), serverDid },
    );
    const remote = new RemoteParticipant('server:us-1', transport);

    let proposalHash: string | undefined;
    try {
      const q = await remote.query('gov_change_query', { proposalId }) as { proposalHash?: string; error?: string };
      if (q?.error) return { success: false, error: q.error };
      proposalHash = q?.proposalHash;
    } catch (err) {
      return { success: false, error: (err as Error)?.message ?? String(err) };
    }
    if (!proposalHash) return { success: false, error: 'Could not read the proposal hash to sign.' };

    const signature = this.signMessage(proposalHash);
    const res = await this._txBootstrap.manager.run(async (tx) => {
      tx.enlist(remote, [{
        op: 'gov_change_approve',
        params: { proposalId, approverUuid: this.getLocalIdentityUuid(), signature },
      }]);
    });
    if (res.outcome !== 'committed') {
      return { success: false, error: `Approval was not committed (${res.outcome}).` };
    }
    // Report the numbers that decide crystallization, so a caller can tell "recorded" from
    // "counted" — a signature the server cannot verify leaves the proposal pending.
    const after = await remote.query('gov_change_query', { proposalId }) as {
      status?: string; approvalCount?: number; verifiedApproverCount?: number; requiredApproverCount?: number;
    };
    return {
      success: true,
      status: after?.status,
      approvalCount: after?.approvalCount,
      verifiedApproverCount: after?.verifiedApproverCount,
      requiredApproverCount: after?.requiredApproverCount,
    };
  }

  /**
   * Pending governance-change proposals this VTA is an eligible approver for.
   * Authoritative read from the utility server; falls back to the local mirror the
   * durable `exchange:governance-proposal` fan-out maintains when the server is down.
   */
  async listPendingGovernanceChanges(): Promise<GovernanceChangeProposalView[]> {
    if (!this.identity) return [];
    if (this.tspBridge.isConnected() && this._txBootstrap) {
      const serverDid = this.tspBridge.getUtilityServerDid();
      if (serverDid) {
        const transport = new TspParticipantTransport(
          async (dest, protocol, payload, timeoutMs) => this.tspClient.request(dest, protocol as any, payload, timeoutMs),
          { isConnected: () => this.tspBridge.isConnected(), serverDid },
        );
        const remote = new RemoteParticipant('server:us-1', transport);
        try {
          const res = await remote.query('gov_change_pending_for', {
            approverUuid: this.getLocalIdentityUuid(),
          }) as { proposals?: GovernanceChangeProposalView[] };
          if (res?.proposals) return res.proposals;
        } catch { /* fall back to the local mirror */ }
      }
    }
    return this.listMirroredGovernanceChanges();
  }

  /** The local mirror of pending proposals (offline copy maintained by the fan-out). */
  async listMirroredGovernanceChanges(): Promise<GovernanceChangeProposalView[]> {
    const txDb = this._txBootstrap?.txDataSource;
    if (!txDb) return [];
    try {
      const pending = await new GovernanceChangeStore(txDb).listPending();
      return pending.map((p) => ({
        proposalId: p.proposalId,
        communityUuid: p.communityUuid,
        communityDid: p.communityDid,
        scope: p.scope,
        requiredApproverCount: p.requiredApproverCount,
        proposalHash: p.proposalHash,
        change: p.change,
        expiresAt: p.expiresAt,
      }));
    } catch {
      return [];
    }
  }


  /**
   * Issue a VRC from a known VTC to a subject.
   *
   * `vtcDid` is a DID (the VTC is resolved through `VtcStore.getGovernanceDoc`,
   * which keys by DID). `subjectVid`/`signers[].vid` are CESR-encoded Ed25519
   * public keys; see `VtcApiModule.issueVrc` for the boundary note on
   * `issuerVid`.
   */
  issueVrc(params: {
    vtcDid: string;
    subjectVid: CesrVid;
    claim: VrcClaim;
    signers: Array<{ vid: CesrVid; signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array } }>;
    expiresAt?: number;
  }): Vrc {
    return this.vtcApiModule.issueVrc(params);
  }

  /**
   * Issue a VRC to a subject, signed with this identity's own keypair.
   *
   * Custody, not capability — see `AgentHandle.issueVrcForSelf`. `subjectVid` defaults to self (the self-issue
   * case); the signer is always this identity, so the result carries exactly one signature and will not satisfy
   * a community whose admin threshold exceeds 1. That refusal belongs to the caller (`credentials.issue()`
   * compares the bundle against the governance doc) — this method reports what happened, it does not judge it.
   *
   * Throws when there is no keypair rather than returning an unsigned credential: an empty bundle is
   * indistinguishable from one whose co-signatures failed, and the domain tells those apart by inspecting it.
   */
  issueVrcForSelf(params: {
    vtcDid: string;
    subjectVid?: CesrVid;
    claim: VrcClaim;
    expiresAt?: number;
  }): Vrc {
    const keyPair = this.identity?.signingKeyPair;
    const selfVid = this.identity?.cesrVid;
    if (!keyPair || !selfVid) {
      throw new Error('BaseAgent.issueVrcForSelf: no active identity — activate an identity first.');
    }
    // `LocalIdentity.cesrVid` is a plain `string` (the type is only branded where the codec is used), but it is
    // built by `cesrEncode` above, so branding it here is a statement of fact rather than a cast.
    const cesrVid = asCesrVid(selfVid, 'identity.cesrVid', 'BaseAgent.issueVrcForSelf');
    return this.vtcApiModule.issueVrc({
      vtcDid: params.vtcDid,
      subjectVid: params.subjectVid ?? cesrVid,
      claim: params.claim,
      signers: [{ vid: cesrVid, signingKeyPair: keyPair }],
      expiresAt: params.expiresAt,
    });
  }

  verifyVrc(vrc: Vrc): VrcVerifyResult {
    return this.vtcApiModule.verifyVrc(vrc);
  }

  listVtcGovernanceDocs(): VtcGovernanceDoc[] {
    return this.vtcApiModule.listVtcGovernanceDocs();
  }

  listCommunities(): VtcGovernanceDoc[] {
    return this.vtcApiModule.listVtcGovernanceDocs();
  }

  listVrcsForSelf(): Vrc[] {
    return this.vtcApiModule.listVrcsForSubject(this.identity.cesrVid);
  }

  /**
   * Upsert a VTC/VTN received from a remote node (utility server).
   * Called from the web server's VTC-creation response path.
   */
  async upsertRemoteVtc(payload: Record<string, unknown>): Promise<void> {
    await this.vtcApiModule.upsertRemoteVtc({
      identityUuid: payload.identityUuid as string,
      did: payload.did as string,
      name: payload.name as string,
      role: payload.role as string,
      adminThresholdM: payload.adminThresholdM as number,
      adminThresholdN: payload.adminThresholdN as number,
      parentCommunityUuid: payload.parentCommunityUuid as string | null,
      adminUuids: payload.adminUuids as string[],
      vtcGovernanceDigest: (payload.vtcGovernanceDigest as string | null | undefined) ?? null,
      allowedClaimTypes: (payload.allowedClaimTypes as string[] | undefined) ?? [],
    });
  }

  /** List communities directly from local identities table. */
  listCommunitiesFromDb() {
    // `?.` belongs on `this.db`, not on `getDbHandle`: the database handle is absent until the agent is
    // STARTED, and the `if (!dbHandle) return []` below is the intent. Guarding only the inner call made this
    // throw a TypeError on an unstarted agent instead of returning the empty list it promises.
    const dbHandle = (this.db as any)?.getDbHandle?.() || (this.db as any)?.db;
    if (!dbHandle) return [];
    // A community is authoritative by its presence in `governance`, NOT by a
    // role tag on the identity: the creator's own mint path historically
    // stored the community identity as role='vta' while the receive path used
    // 'vtc'. Driving the list from `governance` (joined to the identity for
    // name/did) makes every community show regardless of that role tag.
    // Resolve the local VTA's uuid so we can surface MY role per community
    // (the UI gates member-management actions like "Invite Member" on it).
    let myUuid: string | null = null;
    try { myUuid = this.getLocalIdentityUuid(); } catch { /* agent not fully started */ }

    const rows = dbHandle.prepare(
      `SELECT i.uuid, i.name, i.role, COALESCE(dd.did, g.community_identity_uuid) AS did,
              g.admin_threshold_m, g.admin_threshold_n,
              (SELECT m.role FROM memberships m
                WHERE m.community_identity_uuid = i.uuid
                  AND m.member_identity_uuid = ?
                LIMIT 1) AS my_role
       FROM governance g
       JOIN identities i ON i.uuid = g.community_identity_uuid
       LEFT JOIN did_documents dd ON dd.identity_uuid = i.uuid AND dd.is_primary = 1
       ORDER BY i.name`
    ).all(myUuid ?? '') as Array<{ uuid: string; name: string | null; role: string; did: string; admin_threshold_m: number | null; admin_threshold_n: number | null; my_role: string | null }>;
    return rows.map(r => ({
      uuid: r.uuid,
      name: r.name || '(unnamed)',
      role: r.role === 'vtn' ? 'vtn' : 'vtc',
      adminThresholdM: r.admin_threshold_m,
      adminThresholdN: r.admin_threshold_n,
      did: r.did,
      myRole: r.my_role ?? null,
    }));
  }

  /** Get a single VTC/VTN governance doc by community DID. */
  getCommunityByDid(did: string): VtcGovernanceDoc | undefined {
    return this.vtcApiModule.getCommunityByDid(did);
  }

  // ---------------------------------------------------------------------------
  // Profiles & Claims — delegated to src/services/profiles.ts via AgentDatabase
  // ---------------------------------------------------------------------------

  private getLocalIdentityUuid(): string {
    const dbHandle = this.db!.getDbHandle();
    const row = dbHandle.prepare(
      'SELECT i.uuid FROM identities i JOIN did_documents dd ON dd.identity_uuid = i.uuid WHERE dd.did = ? AND i.role = ? AND i.custody = ?'
    ).get(this.identity.did, 'vta', 'local') as { uuid: string } | undefined;
    if (!row) throw new Error('Local identity not found in DB');
    return row.uuid;
  }

  private get ds(): SqliteDataSource {
    if (!this.db) throw new Error('Agent not started');
    return SqliteDataSource.fromExisting(this.registry.getDbPath(this.name));
  }

  async createProfile(input: { label: string; purpose?: string; visibility?: string }): Promise<ProfileRow> {
    const profile = await profilesService.createProfile(this.ds, {
      identityUuid: this.getLocalIdentityUuid(),
      label: input.label,
      purpose: input.purpose,
      visibility: (input.visibility as any) ?? 'private',
    });
    this.syncProfilesToUtilityServer();
    return profile;
  }

  async listProfiles(): Promise<ProfileRow[]> {
    if (!this.db) return [];
    try {
      return await profilesService.listProfiles(this.ds, this.getLocalIdentityUuid());
    } catch { return []; }
  }

  async updateProfile(uuid: string, input: { label?: string; purpose?: string | null; visibility?: string; setDefault?: boolean }): Promise<ProfileRow> {
    const profile = await profilesService.updateProfile(this.ds, uuid, input as any);
    this.syncProfilesToUtilityServer();
    return profile;
  }

  async removeProfile(uuid: string): Promise<void> {
    await profilesService.removeProfile(this.ds, uuid);
    this.syncProfilesToUtilityServer();
  }

  async addProfileClaim(input: { profileUuid: string; claimKey: string; claimValue?: string | null; disclosure?: string }): Promise<any> {
    const claim = await profilesService.addClaim(this.ds, input as any);
    this.syncProfilesToUtilityServer();
    return claim;
  }

  async updateProfileClaim(claimUuid: string, input: { claimValue?: string | null; disclosure?: string }): Promise<any> {
    const claim = await profilesService.updateClaim(this.ds, claimUuid, input as any);
    this.syncProfilesToUtilityServer();
    return claim;
  }

  async removeProfileClaim(claimUuid: string): Promise<void> {
    await profilesService.removeClaim(this.ds, claimUuid);
    this.syncProfilesToUtilityServer();
  }

  async listProfileClaims(profileUuid: string): Promise<any[]> {
    if (!this.db) return [];
    return profilesService.listClaims(this.ds, profileUuid);
  }

  async getProfileCard(profileUuid: string, requestedKeys?: string[]): Promise<ProfileCard> {
    return profilesService.getProfileCard(this.ds, profileUuid, requestedKeys);
  }

  // ---------------------------------------------------------------------------
  // Rotation methods (default: not supported — override in ScidVhAgent)
  // ---------------------------------------------------------------------------

  async rotate(_params: {
    nextSigningPublicKey: Uint8Array;
    witnessAttestations?: Vrc[];
  }): Promise<RotationLogEntry> {
    throw new Error(
      `rotate() not supported by method '${this.didMethod.methodName}'. ` +
      `Use a rotating DidMethod (e.g., ScidVhMethod) via ScidVhAgent.`,
    );
  }

  getNextSigningKeyPair(): Ed25519KeyPair | undefined {
    return undefined;
  }

  listRotationLog(): RotationLogEntry[] {
    return [];
  }

  // ---------------------------------------------------------------------------
  // Name registration
  // ---------------------------------------------------------------------------

  /**
   * Initialize the NameService after the database is open.
   * Called from wireUpAfterStart() in subclasses that support name binding.
   */
  protected initNameService(): void {
    if (!this.db) return;
    this.nameService = new NameService({
      didMethod: this.didMethod,
      resolveDid: (did: string) => this.didMethod.resolve(did),
    });
  }

  async registerName(params: {
    name: string;
    namespace: string;
    /** Optional agent-local profile uuid to attach as this name's primary R-Card. */
    profileUuid?: string;
  }): Promise<{ success: boolean; reason?: string }> {
    if (!this.db) {
      throw new Error('Agent.registerName: agent not started. Call start() first.');
    }
    if (!this.nameService) {
      this.initNameService();
    }
    if (!this.nameService) {
      return { success: false, reason: 'NameService not available for this agent type' };
    }

    const currentLog = this.listRotationLog();
    const outgoingSigningKeyPair = this.identity.signingKeyPair;
    const nextSigningKeyPair = this.getNextSigningKeyPair();
    const nextSigningPublicKey = nextSigningKeyPair?.publicKey;

    if (!nextSigningPublicKey) {
      return { success: false, reason: 'No pre-committed next signing key available for rotation' };
    }

    // ── Idempotency: a name THIS identity already holds is not an error ────
    //
    // Re-running registration for a name that is already in this identity's own
    // alsoKnownAs — a UI retry, or a caller retrying because the 2PC response was
    // lost — used to reach computeSpeculativeRotation() and fail with
    // `SpeculativeRotation: name "vta:…" is already claimed`: the agent's own
    // committed claim read back as if a stranger held it. The field log showed
    // exactly that (a successful ceremony immediately followed by
    // "✗ registerName failed: SpeculativeRotation: name … is already claimed").
    // The requested end state is already true, so report success.
    //
    // Checked BEFORE the utility-server gate on purpose: "this name is already
    // mine" is a local fact and needs no server round trip, so a re-registration
    // cannot be turned into a connectivity error.
    //
    // A name held by a DIFFERENT identity is unaffected: it never appears in this
    // identity's rotation log, so the 2PC prepare still votes "taken".
    const latestRotationEntry = currentLog[currentLog.length - 1];
    const ownedNames = latestRotationEntry?.didDocument?.alsoKnownAs ?? [];
    if (ownedNames.includes(buildNameUri(params.namespace, params.name))) {
      logger.info(
        `[Agent:name] ✓ name 'vta:${params.namespace}:${params.name}' is already registered ` +
        `to this identity — treating re-registration as a no-op`,
      );
      return { success: true };
    }

    // ── Require utility server connection ──────────────────────────────
    // Name registration requires the utility server to verify availability
    // and maintain the shared namespace registry.  Without it, we cannot
    // guarantee uniqueness and must fail with a user-visible message.
    if (!this.tspBridge.isConnected()) {
      logger.info(`[Agent:name] utility server not connected — cannot register name`);
      return {
        success: false,
        reason: this.connectivityFailureMessage('register this name'),
      };
    }

    const serverDid = this.tspBridge.getUtilityServerDid();
    if (!serverDid) {
      return {
        success: false,
        reason: 'Utility server connection is not fully established. Please try again later.',
      };
    }

    // ── Require transaction coordinator ─────────────────────────────────
    if (!this._txBootstrap) {
      return {
        success: false,
        reason: 'Transaction coordinator not available. Please restart the agent.',
      };
    }

    try {
      logger.info(
        `[Agent:name] registerName: transaction-coordinated ceremony for ` +
        `vta:${params.namespace}:${params.name} (DID: ${this.identity.did})`,
      );

      // ── Step 1: Compute speculative rotation entry ────────────────────
      // The rotation entry is fully computed (signed, digest computed) but
      // NOT written to the rotation log. It is held in memory and passed to
      // the transaction coordinator. If the transaction commits, the entry
      // is finalized; if it aborts, the entry is discarded.
      const speculativeRotation = new SpeculativeRotationService();
      // Live TSP transport endpoint to carry into the new rotation entry's DID
      // document. didMethod.resolve() reconstructs documents from the rotation
      // log, which omits `service` (peerId/multiaddrs) unless we include it here
      // — without it the agent cannot resolve its own name after registration,
      // and the DID document pushed to the utility server would also lack the
      // endpoint for remote resolution. Prefer the in-memory transport document's
      // service endpoint; fall back to the node's live peerId/multiaddrs.
      const transportEndpoint =
        (this.identity.didDocument as any)?.service?.[0]?.serviceEndpoint ??
        (this.getPeerId()
          ? { peerId: this.getPeerId(), multiaddrs: this.getMultiaddrs() }
          : undefined);
      const speculative = await speculativeRotation.computeSpeculativeRotation({
        name: params.name,
        namespace: params.namespace,
        did: this.identity.did,
        currentLog,
        outgoingSigningKeyPair,
        // Self-commit: advance the did:scid:vh log with the SAME key rather than
        // rotating. This keeps the transport VID (identity.vid) stable across name
        // registration — per ToIP, the TSP VID is a persistent session pointer and
        // must not change when the JSON log (name/alsoKnownAs) changes. Genuine
        // rotation remains available via nextSigningPublicKey.
        newSigningKeyPair: outgoingSigningKeyPair,
        nextSigningPublicKey,
        transport: transportEndpoint,
      });

      logger.info(
        `[Agent:name] speculative rotation entry computed ` +
        `(version ${speculative.rotationEntry.version}, name '${speculative.nameUri}' in alsoKnownAs)`,
      );

      // ── Step 2: Run the transaction-coordinated ceremony ──────────────
      // Uses the shared-core registerNameViaCoordinator() which:
      //   - Creates a RemoteParticipant for the utility server
      //   - Creates an AgentNameRegistrationParticipant for local finalization
      //   - Runs the 2PC through the transaction coordinator
      const transport = this.createServerTransport();
      const rotationLogStore: RotationLogStore = {
        appendEntry: async (did: string, entry: RotationLogEntry) => {
          const dbHandle = this.db!.getDbHandle();
          const { RotationLogStore: Rls } = await import('@p2p-trust-stack/core/did/rotation-log-store.js');
          const store = new Rls(dbHandle, this.db!.resolver);
          store.appendEntry(did, entry);
        },
      };

      // R-Card linkage: resolve the name's primary card profile. The server
      // links name_registry.profile_uuid/profile_id at registration-commit time
      // by LABEL (agent and server profile ids differ), so we pass the label of
      // the explicitly selected profile, else the default profile, else the
      // first profile.
      let primaryProfileLabel: string | undefined;
      try {
        const profileList = await profilesService.listProfiles(this.ds, this.getLocalIdentityUuid());
        const chosen = typeof params.profileUuid === 'string'
          ? profileList.find(p => p.uuid === params.profileUuid) ?? null
          : null;
        const primary = chosen ?? profileList.find(p => p.isDefault) ?? profileList[0] ?? null;
        primaryProfileLabel = primary?.label ?? undefined;
        if (primaryProfileLabel) {
          logger.info(`[Agent:name] primary R "${params.namespace}:${params.name}" → profile "${primaryProfileLabel}"`);
        } else {
          logger.info(`[Agent:name] no profile to link as R-Card for ${params.namespace}:${params.name}`);
        }
      } catch (err) {
        logger.error(`[Agent:name] failed to resolve primary R: ${(err as Error)?.message}`);
      }

      // Include the current profiles so the server's identity_push (same 2PC)
      // can link profile_uuid even if a later profile drag never fires.
      const profilesForPush = await this.collectProfilesPayload();

      const result = await registerNameViaCoordinator(
        this._txBootstrap.manager,
        transport,
        'server:us-1',
        {
          name: params.name,
          namespace: params.namespace,
          did: this.identity.did,
          profileUuid: params.profileUuid,
          primaryProfileLabel,
          speculative,
          // Workstream E.3: fold the identity_push into the SAME 2PC (document,
          // keys, and name_registry become atomic on the server). Since name
          // registration now SELF-COMMITS (no key rotation), the agent's current
          // signing/agreement keys are unchanged — carry those so the server
          // ingests the same generation as our keystore (transport VID stable).
          identityPushPayload: (() => {
            const key = outgoingSigningKeyPair;
            const agreement = ed25519ToX25519(key.secretKey);
            return {
              realDid: this.identity.did,
              identityUuid: this.getLocalIdentityUuid(),
              name: this.name,
              subjectKind: 'human',
              didDocument: speculative.didDocument,
              publicKeys: {
                ed25519: Buffer.from(key.publicKey).toString('base64'),
                x25519: Buffer.from(agreement.publicKey).toString('base64'),
              },
              peerId: this.getPeerId(),
              // Live dialable addresses for the server's member re-dial stage
              // (peer_endpoints.multiaddrs) — see IdentityPushPayload.multiaddrs.
              multiaddrs: this.getMultiaddrs(),
              // Fold the current profiles into the SAME 2PC so the server can
              // link name_registry.profile_uuid atomically at registration time.
              profiles: profilesForPush.length > 0 ? profilesForPush : undefined,
            };
          })(),
          appDb: this.ds,
          txDb: this._txBootstrap.txDataSource,
          rotationStore: rotationLogStore,
          onFinalize: async (finalizeParams: FinalizeRotationParams) => {
            // Update the agent's in-memory identity with the new DID document
            const currentDoc = this.identity.didDocument as any;
            const updatedDoc = {
              ...finalizeParams.didDocument,
              // Preserve service endpoints from the transport document
              service: currentDoc.service,
            } as DidDocument;
            this.identity = {
              ...this.identity,
              didDocument: updatedDoc,
            };
            logger.info(
              `[Agent:name] agent identity updated with new DID document ` +
              `(alsoKnownAs added, service preserved)`,
            );

            // Persist the updated DID document to the local database
            await this.ds.run(
              `UPDATE did_documents SET document_json = ?, updated_at = ? WHERE identity_uuid = ? AND is_primary = 1`,
              JSON.stringify(updatedDoc),
              Math.floor(Date.now() / 1000),
              this.getLocalIdentityUuid(),
            );
            logger.info(`[Agent:name] DID document persisted to local database`);

            // E.3: identity_push is folded into the SAME 2PC (see
            // registerNameViaCoordinator above), so the separate push below is no
            // longer the load-bearing path and is removed.
            // (No separate identity_push — the server already applied it in the
            // same transaction. Startup continues to push full profiles/creds.)
          },
        },
      );

      if (result.success) {
        logger.info(`[Agent:name] ✓ name registration committed`);
        // The registration rolled the did:scid:vh log (alsoKnownAs appended).
        // Push the refreshed log NOW so the server holds it and the public
        // resolver can serve a verified resolution instead of a cached snapshot.
        this.scheduleIdentityPushAfterRoll('name-registration');
        return { success: true };
      }

      logger.info(`[Agent:name] ✗ name registration aborted`);
      return {
        success: false,
        reason: result.reason ?? 'Name registration could not be completed. The name may have been taken by another user.',
      };
    } catch (err) {
      logger.error(
        `[Agent:name] ✗ registerName failed: ${(err as Error).message}`,
      );
      return { success: false, reason: (err as Error).message };
    }
  }

  async resolveName(nameUri: string): Promise<PeerTarget | undefined> {
    if (!this.db) {
      throw new Error('Agent.resolveName: agent not started. Call start() first.');
    }

    // Parse requested claim keys from name URI suffix (e.g., vta:ns:name/key1,key2)
    const { parseNameUri } = await import('@p2p-trust-stack/core/did/name-uri.js');
    let baseUri = nameUri;
    let requestedKeys: string[] = [];
    const slashIdx = nameUri.indexOf('/');
    if (slashIdx >= 0) {
      baseUri = nameUri.substring(0, slashIdx);
      requestedKeys = nameUri.substring(slashIdx + 1).split(',').map(k => k.trim()).filter(k => k.length > 0);
    }
    const parsed = parseNameUri(baseUri);

    // Helper: look up R-Card for a DID from our local DB
    const lookupLocalRCard = async (did: string): Promise<object | undefined> => {
      try {
        const { findByRealDid } = await import('@p2p-trust-stack/core/db/repositories/identities-repo.js');
        const identity = await findByRealDid(this.ds, did);
        if (!identity) return undefined;
        const profiles = await profilesService.listProfiles(this.ds, identity.uuid);
        if (profiles.length === 0) return undefined;
        if (requestedKeys.length > 0) {
          return profilesService.getProfileCard(this.ds, profiles[0].uuid, requestedKeys);
        }
        return profilesService.getProfileCard(this.ds, profiles[0].uuid);
      } catch { return undefined; }
    };

    // 1. Check local name_registry cache
    const dbHandle = this.db.getDbHandle();
    const local = resolveNameFromLocalDb(baseUri, dbHandle, (did) => this.didMethod.resolve(did));
    if (local) {
      const rCard = await lookupLocalRCard(local.did);
      if (rCard) (local as any).rCard = rCard;
      return local;
    }

    // 2. If connected to utility server, try coordinator-based name_resolve
    if (this.tspBridge.isConnected() && this._txBootstrap) {
      const serverDid = this.tspBridge.getUtilityServerDid();
      if (serverDid) {
        try {
          const transport = this.createServerTransport();
          const result = await resolveNameViaCoordinator(
            this._txBootstrap.manager,
            transport,
            'server:us-1',
            parsed.namespace,
            parsed.name,
            requestedKeys,
            // CRE (Phase 3): requester identity routes the pull through the
            // registry recordset (exchange:registry).
            { realDid: this.identity.did, uuid: this.getLocalIdentityUuid(), role: 'vta' },
          );
          logger.info(`[Agent:name] resolveName: coordinator result found=${result.found} did=${result.did?.slice(0, 30)}...`);
          if (result.found && result.did) {
            const doc = await this.resolveRemoteNameDidDocument(result.did, result.didDocument as Record<string, unknown> | undefined);
            if (!doc) {
              logger.warn(`[Agent:name] resolveName: no DID document resolvable for ${result.did.slice(0, 30)}...`);
              return undefined;
            }
            const { extractPeerTarget } = await import('@p2p-trust-stack/core/did/name-resolver.js');
            const target = extractPeerTarget(doc as any, result.did);
            if (target) {
              // Prefer the server-resolved R-Card. The server is the canonical
              // repository of this name's profile; the local DB only helps for
              // offline/known peers (and was the source of the asymmetry where
              // a server-resolvable card never showed for remote peers).
              //
              // When claim keys were requested, only trust the server card if it
              // actually carries the requested (discretionary) claims; otherwise
              // the server card (which would hide them) must not shadow the
              // keys-passing local lookup.
              const serverCard = (result as any).rCard as { claims?: Array<{ key: string }> } | undefined;
              const serverMissingKeys = requestedKeys.length > 0 && serverCard?.claims
                ? !requestedKeys.every(k => serverCard.claims?.some(c => c.key === k))
                : false;
              const rCard = (!serverCard || serverMissingKeys) ? await lookupLocalRCard(result.did) : serverCard;
              if (rCard) (target as any).rCard = rCard;
            }
            logger.info(`[Agent:name] resolveName: result=${target ? `peerId=${target.peerId.slice(0,12)}` : 'not found'} hasCard=${!!(target as any)?.rCard}`);
            return target;
          }
        } catch (err) {
          logger.warn(`[Agent] coordinator name_resolve failed: ${(err as Error).message}`);
        }
      }
    }

    return undefined;
  }

  /**
   * Resolve a remote DID (returned by a coordinator name_resolve) to a DID
   * document suitable for endpoint extraction.
   *
   * Resolution order:
   *   1. The coordinator-supplied didDocument (authoritative server copy).
   *   2. The async DidResolver over the local rotation-log source — this
   *      reconstructs a did:scid:vh document by replaying its chain when we
   *      already hold the log locally.
   *   3. The persisted `did_documents.document_json` row, which carries the
   *      live TSP transport endpoint that scid:vh rotation-log entries omit.
   *
   * This is the one place DID resolution and agent-name resolution converge:
   * name resolution hands us a DID and we must find its current endpoint. It
   * does NOT alter name binding semantics (alsoKnownAs/VRC remain untouched).
   */
  private async resolveRemoteNameDidDocument(
    did: string,
    coordinatorDoc?: Record<string, unknown>,
  ): Promise<import('@p2p-trust-stack/core/did/types.js').DidDocument | undefined> {
    if (coordinatorDoc) return coordinatorDoc as unknown as import('@p2p-trust-stack/core/did/types.js').DidDocument;

    // Local chain replay for did:scid:vh (or offline did:peer:4 via resolver).
    try {
      const resolver = new DidResolver({ logSource: new LocalRotationLogSource(this.db!.rotationLogStore) });
      const result = await resolver.resolve(did);
      if (result.didDocument) return result.didDocument;
    } catch { /* fall through to persisted document */ }

    // Persisted did_documents JSON (live TSP endpoint).
    try {
      const { findByRealDid } = await import('@p2p-trust-stack/core/db/repositories/did-documents-repo.js');
      const row = await findByRealDid(this.ds, did);
      if (row?.documentJson) {
        return JSON.parse(row.documentJson) as import('@p2p-trust-stack/core/did/types.js').DidDocument;
      }
    } catch { /* ignore malformed document */ }

    return undefined;
  }

  async revokeName(params: {
    name: string;
    namespace: string;
  }): Promise<{ success: boolean; reason?: string }> {
    if (!this.db) {
      throw new Error('Agent.revokeName: agent not started. Call start() first.');
    }
    if (!this.nameService) {
      this.initNameService();
    }
    if (!this.nameService) {
      return { success: false, reason: 'NameService not available for this agent type' };
    }

    const nameUri = buildNameUri(params.namespace, params.name);
    const currentLog = this.listRotationLog();
    const outgoingSigningKeyPair = this.identity.signingKeyPair;
    const nextSigningKeyPair = this.getNextSigningKeyPair();
    const nextSigningPublicKey = nextSigningKeyPair?.publicKey;

    if (!nextSigningPublicKey) {
      return { success: false, reason: 'No pre-committed next signing key available for rotation' };
    }

    try {
      // 1. Create rotation entry removing the name from alsoKnownAs
      await this.nameService.revokeName({
        nameUri,
        currentLog,
        outgoingSigningKeyPair,
        newSigningKeyPair: nextSigningKeyPair!,
        nextSigningPublicKey,
      });

      // 2. If connected to utility server, send coordinator-based name_revoke
      if (this.tspBridge.isConnected() && this._txBootstrap) {
        const serverDid = this.tspBridge.getUtilityServerDid();
        if (serverDid) {
          try {
            const transport = this.createServerTransport();
            const result = await revokeNameViaCoordinator(
              this._txBootstrap.manager,
              transport,
              'server:us-1',
              params.namespace,
              params.name,
              this.identity.did,
              { type: 'alsoKnownAs', didDocument: this.identity.didDocument },
            );
            if (!result.success) {
              return { success: false, reason: result.reason ?? 'Name revocation rejected by utility server' };
            }
          } catch (err) {
            return { success: false, reason: `Coordinator name_revoke failed: ${(err as Error).message}` };
          }
        }
      }

      // 3. Update local cache
      const dbHandle = this.db.getDbHandle();
      const now = Math.floor(Date.now() / 1000);
      dbHandle.prepare(
        'UPDATE name_registry SET revoked_at = ? WHERE namespace = ? AND name = ? AND revoked_at IS NULL',
      ).run(now, params.namespace, params.name);

      // The revocation rolled the did:scid:vh log (alsoKnownAs). Push the
      // refreshed log now so the server can serve a verified resolution.
      this.scheduleIdentityPushAfterRoll('name-revocation');

      return { success: true };
    } catch (err) {
      return { success: false, reason: (err as Error).message };
    }
  }

  async listNames(): Promise<NameEntry[]> {
    if (!this.nameService) {
      this.initNameService();
    }
    if (!this.nameService) return [];
    return this.nameService.listNames(this.identity.did);
  }

  // ---------------------------------------------------------------------------
  // Phase H: Utility server TSP connection
  // ---------------------------------------------------------------------------

  /**
   * Configure and establish a TSP connection to a utility server.
   *
   * After the agent is started and the RelationshipManager is running,
   * this wires up the TspBridge with the utility server's OOBI, connects
   * via RFI/RFA handshake, and initializes the RecoveryModule.
   *
   * @param params.utilityServerOobi  The utility server's OOBI string.
   */
  async configureUtilityServer(params: { utilityServerOobi: string }): Promise<void> {
    if (!this.manager) {
      throw new Error(
        'Agent.configureUtilityServer: agent not started. Call start() first.',
      );
    }

    this.utilityServerOobi = params.utilityServerOobi;

    // Wire the TSP bridge through the RelationshipManager
    this.tspBridge.init({
      manager: this.manager,
      tspClient: this.tspClient,
      utilityServerOobi: this.utilityServerOobi,
    });

    // Establish the bidirectional relationship with the utility server
    try {
      const serverDid = await this.tspBridge.connect();
      logger.info(
        `[Agent] Connected to utility server: ${serverDid.slice(0, 12)}...`,
      );
      this.syncServerConnectionWatch();

      // Initialize the recovery module now that we have a connection
      this.recoveryModule.init(this.tspClient, serverDid, this.identity.did);
      // Wire the participant transport so fetchRecoveryState/lookupIdentity can
      // route through the exchange pulls (exchange:recovery / exchange:identity-lookup).
      if (this._txBootstrap) {
        this.recoveryModule.wireCoordinator(this._txBootstrap.manager, this.createServerTransport());
      }

      // Push identity data to the utility server over TSP
      await this.pushIdentityToUtilityServer();

      // Also force ONE un-gated push: the regular path above is ack-gated, so a
      // server-side row damaged after the last successful sync (the TSPv3
      // doc-linkage duplicate-key era) would never be repaired by an unchanged
      // payload. Fire-and-forget — a repair must never delay or fail a connect.
      void this.forceIdentityPush('configureUtilityServer');

      // If a profile mutation happened while disconnected, the push above
      // cleared the pending state on success; otherwise drain the retries
      // now that we're connected again.
      if (this.profileSyncPending) await this.pumpProfileSync();

      // NOTE: community sync is intentionally NOT retriggered here.
      // VTC records are delivered by the utility server's queue push
      // (exchange:vtc-membership) only, so the push is the single delivery path.
    } catch (err) {
      logger.error(
        `[Agent] Failed to connect to utility server: ${(err as Error)?.message ?? err}`,
      );
      throw err;
    }
  }

  /**
   * Whether the agent has an active TSP connection to a utility server.
   */
  isUtilityServerConnected(): boolean {
    return this.tspBridge.isConnected() && this.recoveryModule.isInitialized();
  }

  /**
   * Get the utility server's VID if connected.
   */
  getUtilityServerDid(): string | null {
    return this.tspBridge.getUtilityServerDid();
  }

  // ---------------------------------------------------------------------------
  // Phase H: TSP-based identity push (replaces REST pushVtaToUtilityServer)
  // ---------------------------------------------------------------------------

  /**
   * Create a TSP participant transport for reaching the utility server.
   *
   * The transport wraps the agent's TspClientModule.request() and waits for
   * the utility server's circuit-relay tunnel to be established before
   * sending transaction messages (per tx-coordinator-usage.md §5).
   */
  private createServerTransport(): TspParticipantTransport {
    return new TspParticipantTransport(
      async (dest, protocol, payload, timeoutMs) => {
        const response = await this.tspClient.request(dest, protocol as any, payload, timeoutMs);
        return response;
      },
      {
        // Connectivity is deliberately pid-INSENSITIVE here: every caller of this
        // factory uses a `server:*` pid, and all of them route to the single
        // utility-server link, so the bridge's one flag is the correct signal.
        // That flag is safely scoped — `markDisconnected()` is only called for the
        // server's own transport peer (`isServerTransportPeer`), so an unrelated
        // peer disconnect cannot stall these legs. Peer legs use
        // `peerTransport()`/`TspParticipantTransport` with a `peer:{did}` pid.
        isConnected: (_pid: string) => this.tspBridge.isConnected(),
        serverDid: this.tspBridge.getUtilityServerDid() ?? undefined,
      },
    );
  }

  /** Cached, persistent peer transport — reused across the whole ceremony. */
  private _peerTransport: TspParticipantTransport | null = null;

  /**
   * Return a participant transport that reaches a PEER AGENT directly (over
   * the relationship manager), not the utility server. Used for the
   * agent→agent VRC reflection leg (`store_remote_vrc`) and kept alive for the
   * duration of the ceremony. No serverDid is set (so `peer:{vid}` destinations
   * route to the peer). A connectivity pre-flight waits for the peer's libp2p
   * circuit-relay tunnel to be established before each coordinated send, so the
   * coordinator only dispatches the VRC once the peer is actually reachable.
   */
  private createPeerTransport(): TspParticipantTransport {
    if (this._peerTransport) return this._peerTransport;
    const requestFn = async (
      dest: string,
      protocol: string,
      payload: unknown,
      timeoutMs?: number,
    ) => {
      const response = await this.tspClient.request(dest, protocol as any, payload, timeoutMs);
      return response;
    };
    // Per-peer state-change tracker so connectivity is logged only on
    // transitions (false→true / true→false), never on every 500 ms poll.
    const lastConnectivity = new Map<string, boolean>();

    // F-010 / R1: install this agent's operation-proof signer ONCE. The transport reads
    // the module-level signer by default, so every coordinator path — including the
    // per-call transports built in the ceremony and web-server routes — attaches a
    // signed operation document without each site having to remember. (The VID *is* the
    // Ed25519 public key, so a peer verifies it offline.)
    if (this.identity?.signingKeyPair && this.meta?.vid) {
      setLocalOperationSigner({
        actorVid: this.meta.vid,
        secretKey: this.identity.signingKeyPair.secretKey,
      });
    }

    this._peerTransport = new TspParticipantTransport(requestFn, {
      isConnected: (pid) => {
        // pid is 'peer:{key}' where key may be the peer's DID or VID. The whole
        // remainder is the identity key (a DID contains colons, so never
        // split on ':'). get() accepts both DID and VID.
        const vid = pid.startsWith('peer:') ? pid.slice(5) : pid;
        const record = this.store?.get(this.identity.did, vid);
        const peerId = record?.remoteTransport?.peerId;
        const hasDialableAddr = !!peerId
          && Array.isArray(record?.remoteTransport?.multiaddrs)
          && record.remoteTransport.multiaddrs.length > 0;
        const activelyConnected = peerId ? (this.transport?.isConnected?.(peerId) ?? false) : false;

        // ── PROCESS CONTRACT ────────────────────────────────────────────────
        // DIAL-ON-DEMAND, NOT PERSISTENT-CONNECTION, transport model:
        // the underlying `Libp2pTransport.send()` is "dial + write + close" —
        // it opens a fresh protocol stream per message and does NOT keep an open
        // connection between messages (messages route through a mediator circuit-
        // relay `/p2p-circuit` tunnel). It follows the DEFINITIVE process:
        //   1. early size check,
        //   2. dialProtocol(peerId, TSP_PROTOCOL) with runOnLimitedConnection:true
        //      (mandatory for relayed connections),
        //   3. write + close.
        // Consequence: requiring an ALREADY-OPEN connection here is wrong — the
        // very send that would (re)establish the tunnel is gated behind this
        // check, so no connection would ever appear to satisfy it (the `false`
        // flap / 15 s stall / log flood seen on WAN). The peer is therefore
        // considered CONNECTABLE whenever we hold a peerId + a dialable
        // (relay/circuit) address; the actual send dials on demand. An active
        // open connection also counts, but is not required.
        const connected = activelyConnected || hasDialableAddr;

        if (lastConnectivity.get(vid) !== connected) {
          lastConnectivity.set(vid, connected);
          logger.info(
            `[ceremony] peer-transport connectivity for ${vid.slice(0, 12)}... ` +
            `peerId=${peerId?.slice(0, 12) ?? 'none'} connected=${connected} ` +
            `(state-change; ${connected ? 'dialable/connected' : 'no dialable address'})`,
          );
        }
        return connected;
      },
    });
    logger.info('[ceremony] persistent peer transport created');
    return this._peerTransport;
  }

  /**
   * Run one pass of the ceremony retry driver: advance every incomplete VRC
   * ceremony that is due for a retry on this agent.
   */
  private async runCeremonyDriver(): Promise<void> {
    if (!this.db || !this.store || !this.manager || !this._txBootstrap) return;
    const ctx = this._getCeremonyContext();
    try {
      ctx.remotePeerVid = undefined; // peer legs set per concurrent ceremony at call time
      const advanced = await advanceDueSessions(ctx, this.identity.did);
      if (advanced > 0) {
        logger.info(`[Agent] ceremony driver advanced ${advanced} session(s)`);
      }
      // A session's phase is DERIVED from its leg flags, so it can become
      // 'complete' on a write that is not part of the driver's own leg walk —
      // most importantly the inbound `store_remote_vrc` leg, which flips
      // `peer_vrc_received` on the RECEIVER side (VrcReceiveParticipant) and
      // derives 'complete' when this agent had already delivered its VRC.
      // `advanceDueSessions` skips complete sessions entirely, so without this
      // sweep such a session stays complete in the saga while the relationship
      // still reads 'acknowledged' and `onCeremonyComplete` never fires — the
      // ceremony looks finished but the UI never leaves the waiting state.
      // The sweep is idempotent (guarded by `personhood_status`), so it fires
      // the completion exactly once and also heals sessions left stuck by an
      // older build.
      const finalized = await finalizeCompletedCeremonies(ctx, this.identity.did);
      if (finalized > 0) {
        logger.info(`[Agent] ceremony driver finalised ${finalized} completed ceremony(s)`);
      }
      // Expire ceremonies that never got BOTH "I know this person" acks within
      // the deadline: clears the connection attempt so a fresh OOBI exchange +
      // connect can be retried and completed.
      const expired = await expireStaleCeremonies(ctx, this.identity.did);
      if (expired > 0) {
        logger.info(`[Agent] ceremony driver expired ${expired} stale personhood ceremony(s)`);
      }
    } catch (err) {
      logger.error(`[Agent] ceremony driver error: ${(err as Error)?.message ?? err}`);
    }
  }

  /**
   * Push this agent's public identity data to the utility server over TSP.
   *
   * This is the TSP/durable-outbox replacement for the legacy REST
   * pushVtaToUtilityServer(). When the CRE ExchangeEngine is available it runs
   * the push through `engine.push('identity')`: the registered identity
   * materializer computes the payload at push time, the durable outbox carries
   * it as an `exchange:identity` coordinator 2PC, and ack-gating skips the send
   * when the payload digest is unchanged since the last sync. Without the
   * engine (CRE disabled) the identical `exchange:identity` outbox entry is
   * enqueued directly (no ack-gating).
   *
   * On ANY failure — including not being connected — it records the state in
   * profileSyncPending/profileSyncLastError so the work is retried
   * (pumpProfileSync) and surfaced to the UI instead of being silently dropped.
   */
  async pushIdentityToUtilityServer(): Promise<boolean> {
    const serverDid = this.tspBridge.getUtilityServerDid();

    // ── Not connected / no server VID ───────────────────────────────────
    if (!this.tspBridge.isConnected() || !serverDid) {
      this.profileSyncPending = true;
      this.profileSyncLastError = this.connectivityFailureMessage('push this identity');
      logger.warn(`[Agent] ${this.profileSyncLastError}`);
      // Durability: nothing is pre-enqueued here. On reconnect the fast-path
      // push (below) materializes FRESH state and enqueues it, so a write made
      // while offline is captured at reconnect time — never silently dropped.
      return false;
    }

    try {
      const pushPayload = await this.buildIdentityPushPayload();
      const profiles = (pushPayload.profiles as unknown[] | undefined) ?? [];
      const credentials = (pushPayload.credentials as unknown[] | undefined) ?? [];

      // ── CRE path (Phase 2 + Phase B): ExchangeEngine.push ─────────────
      // Materializes via the 'identity' recordset materializer, enqueues the
      // protocol object to the durable outbox (WireSend → coordinator 2PC),
      // and ack-gates when the payload is unchanged since the last sync.
      if (this.exchangeEngine && this._txBootstrap) {
        const transport = this.createServerTransport();
        const result = (await this.exchangeEngine.push(
          { requester: this.buildRequesterIdentity() },
          'identity',
          'server:us-1',
          transport,
        )) as SendReceipt | null;

        if (result === null) {
          // Ack-gated: an identical payload was already durably synced (the
          // server holds this exact state, or an identical row is pending in
          // the outbox awaiting the reconnect drain).
          this.profileSyncPending = false;
          this.profileSyncLastError = null;
          logger.info(`[Agent] Identity push gated (unchanged, already synced): ${this.identity.did} (profiles: ${profiles.length}, credentials: ${credentials.length})`);
          return true;
        }
        if (result.status === 'accepted') {
          this.profileSyncPending = false;
          this.profileSyncLastError = null;
          // Mark THIS entry delivered — it is the one the server actually
          // committed. Do NOT blanket-mark other server rows: a row left
          // 'pending' was genuinely never committed server-side, and must not
          // be promoted to 'delivered' (false-positive bug guard).
          await this._txBootstrap.outbox.markDelivered(result.entryId);
          logger.info(`[Agent] Identity push committed to utility server (exchange:identity via exchange engine): ${this.identity.did} (profiles: ${profiles.length}, credentials: ${credentials.length})`);
          return true;
        }
        this.profileSyncPending = true;
        this.profileSyncLastError = 'identity push not committed (outbox deferred)';
        logger.warn(`[Agent] ${this.profileSyncLastError}`);
        return false;
      }

      // ── Defensive durable outbox path (engine unavailable) ─────────────────
      // Same exchange:identity wire op, direct enqueue (no ack-gating). Only
      // reachable if start() built the tx-bootstrap but the engine construction
      // was skipped — a safety net, not a legacy branch (Phase C).
      if (this._txBootstrap) {
        const body = { protocol: 'exchange:identity', payload: pushPayload };
        const receipt = await this._txBootstrap.outbox.enqueue('server:us-1', body);
        if (receipt.status === 'accepted') {
          this.profileSyncPending = false;
          this.profileSyncLastError = null;
          // Mark THIS entry delivered (see note above).
          await this._txBootstrap.outbox.markDelivered(receipt.entryId);
          logger.info(`[Agent] Identity push committed to utility server (exchange:identity): ${this.identity.did} (profiles: ${profiles.length}, credentials: ${credentials.length})`);
          return true;
        }
        this.profileSyncPending = true;
        this.profileSyncLastError = 'identity push not committed (outbox deferred)';
        logger.warn(`[Agent] ${this.profileSyncLastError}`);
        return false;
      }

      this.profileSyncPending = true;
      this.profileSyncLastError = 'Transaction coordinator not bootstrapped — identity push deferred';
      logger.warn(`[Agent] ${this.profileSyncLastError}`);
      return false;
    } catch (err) {
      this.profileSyncPending = true;
      this.profileSyncLastError = `Failed to push identity via TSP: ${(err as Error)?.message ?? err}`;
      logger.error(`[Agent] ${this.profileSyncLastError}`);
      return false;
    }
  }

  /**
   * Build the full identity push payload (identity record + profiles/claims +
   * credentials/signatures) — shared by the CRE durable path and the legacy 2PC.
   */
  private async buildIdentityPushPayload(): Promise<Record<string, unknown>> {
    // Collect profile data for R-Card sync
    const profiles = await this.collectProfilesPayload();

    // Collect credential data for DTG sync
    let credentials: any[] = [];
    let credentialSignatures: any[] = [];
    try {
      const identityId = this.getLocalIdentityUuid();
      const dbHandle = this.db!.getDbHandle();

      const credRows = dbHandle.prepare(`
        SELECT * FROM credentials
        WHERE issuer_identity_uuid = ? OR subject_identity_uuid = ?
        ORDER BY uuid
      `).all(identityId, identityId) as any[];
      logger.info(`[Agent:push] collected ${credRows.length} credentials for identity ${identityId}`);

      for (const c of credRows) {
        credentials.push({
          uuid: c.uuid,
          vcType: c.vc_type,
          issuerIdentityUuid: c.issuer_identity_uuid,
          subjectIdentityUuid: c.subject_identity_uuid,
          w3cVcJson: c.w3c_vc_json,
          claim: c.claim,
          status: c.status,
          thresholdRequired: c.threshold_required,
          validFrom: c.valid_from,
          validUntil: c.valid_until,
          credentialDigest: c.credential_digest,
          createdAt: c.created_at,
        });

        const sigRows = dbHandle.prepare(`
          SELECT cs.*, i.uuid as signer_uuid
          FROM credential_signatures cs
          JOIN identities i ON i.uuid = cs.signer_identity_uuid
          WHERE cs.credential_uuid = ?
        `).all(c.uuid) as any[];
        for (const s of sigRows) {
          credentialSignatures.push({
            credentialUuid: c.uuid,
            signerIdentityUuid: s.signer_uuid,
            signature: Buffer.from(s.signature).toString('base64'),
            signedAt: s.signed_at,
          });
        }
      }
    } catch (err) {
      logger.error(`[Agent:push] Failed to collect credentials: ${(err as Error).message}`);
    }

    return {
      realDid: this.identity.did,
      identityUuid: this.getLocalIdentityUuid(),
      name: this.name,
      subjectKind: 'human' as const,
      didDocument: this.identity.didDocument,
      // The full did:scid:vh rotation log, so the server can persist it and the
      // public resolver can serve a VERIFIED resolution (source: 'log') instead
      // of a cached snapshot. This is also what makes a log ROLL change the
      // payload digest, so the exchange engine's ack-gate lets the push through
      // instead of suppressing it as "unchanged".
      rotationLog: this.rotationLogForPush(),
      publicKeys: {
        ed25519: Buffer.from(this.identity.signingKeyPair.publicKey).toString('base64'),
        x25519: Buffer.from(this.identity.agreementKeyPair.publicKey).toString('base64'),
      },
      peerId: this.getPeerId(),
      // Live dialable addresses. The utility server stores these in
      // `peer_endpoints.multiaddrs` and dials them to (re)reach this agent
      // (ConnectivitySupervisor member re-dial); without them an agent endpoint
      // has no direct address and only the relay path is ever attempted.
      multiaddrs: this.getMultiaddrs(),
      profiles: profiles.length > 0 ? profiles : undefined,
      credentials: credentials.length > 0 ? credentials : undefined,
      credentialSignatures: credentialSignatures.length > 0 ? credentialSignatures : undefined,
    };
  }

  /**
   * The current rotation log in wire JSON form, or `undefined` when empty.
   *
   * Serialized rather than raw because the durable outbox persists payloads via
   * JSON: a raw `Uint8Array` field would not survive that round-trip (it comes
   * back as `{"0":…,"1":…}`). `rotationEntryToJson` base64-encodes every byte
   * field, and the server's `rotationEntryFromJson` is its exact inverse.
   */
  private rotationLogForPush(): RotationEntryJson[] | undefined {
    try {
      const log = this.listRotationLog();
      if (!log || log.length === 0) return undefined;
      return log.map((entry) => rotationEntryToJson(entry));
    } catch (err) {
      logger.warn(`[Agent:push] could not read rotation log: ${(err as Error)?.message ?? err}`);
      return undefined;
    }
  }

  /**
   * Push this identity — including its rotation log — to the utility server
   * after a LOCAL rotation-log roll.
   *
   * ## Why this exists
   *
   * A roll (a key rotation, a name claim, or a name revocation) appends an entry
   * to the local `did:scid:vh` log. Nothing previously told the server: the
   * periodic identity push carried the refreshed DID DOCUMENT but never the LOG,
   * so the server could only ever serve a cached snapshot for this DID, and a
   * third party resolving it got `source: 'cache'` — even when the document
   * itself (e.g. `alsoKnownAs`) was current.
   *
   * This enqueues the push immediately:
   *   - Online  — `pushIdentityToUtilityServer()` puts it in the DURABLE OUTBOX
   *               and the coordinator 2PC delivers it. The payload digest now
   *               changes on every roll, so the exchange engine's ack-gate no
   *               longer suppresses it as "unchanged".
   *   - Offline — the reconnect fast-path re-materializes FRESH state (log
   *               included), so the roll is neither lost nor sent stale.
   *
   * Fire-and-forget by contract: never throws, never blocks the caller. A
   * rotation must not fail because the server happens to be unreachable.
   */
  protected scheduleIdentityPushAfterRoll(reason: string): void {
    logger.info(`[Agent:push] rotation log changed (${reason}) — pushing identity + log to utility server`);
    void this.pushIdentityToUtilityServer()
      .then((ok: boolean) => {
        if (!ok) {
          logger.info(`[Agent:push] rotation-log push deferred (${reason}) — will retry on reconnect`);
        }
      })
      .catch((err: unknown) => {
        logger.warn(`[Agent:push] rotation-log push failed (${reason}): ${(err as Error)?.message ?? err}`);
      });
  }

  // ---------------------------------------------------------------------------
  // Phase H: Recovery
  // ---------------------------------------------------------------------------
  // Profile sync — retried, not fire-and-forget
  // ---------------------------------------------------------------------------

  /**
   * Force ONE un-gated `exchange:identity` push (2PC) to the utility server.
   *
   * ## Why this exists
   *
   * The only writer that can repair the server's copy of this agent's identity —
   * including its verification key — is the identity push, and **every regular
   * path to it is ACK-GATED**: `ExchangeEngine.commitPush()` compares the
   * materialized payload digest against `exchange_watermark.last_pushed_digest`
   * for (recordset, peer) and returns without enqueuing when they match, and it
   * records that digest as soon as the bytes reach the durable outbox.
   *
   * Consequence: once the server's row has been damaged — the TSPv3 doc-linkage
   * divergence that left two `keys.ed25519` rows, or a document-derived key the
   * agent does not sign with, surfacing as `tspOpen: signature verification
   * failed` and 30 s timeouts for that one agent — the agent's payload is
   * UNCHANGED, so it is gated forever and the damage never heals, however long the
   * agent runs or however often it reconnects.
   *
   * This runs the same 2PC as the CRE path but WITHOUT the watermark gate, so
   * identical-but-authoritative state still reaches the server. Server-side it is
   * idempotent: `createRemoteVta` upserts, `syncRemotePublicKeys` converges on one
   * active key row, and the document is promoted rather than duplicated.
   *
   * Fire-and-forget by contract: never throws, never blocks a connect, and
   * single-flighted so a reconnect storm cannot stack pushes.
   */
  private async forceIdentityPush(reason: string): Promise<boolean> {
    if (this._forceIdentityPushInFlight) {
      logger.info(`[Agent] forced identity push already in flight — skipping (${reason})`);
      return false;
    }
    if (!this._txBootstrap || !this.tspBridge.isConnected()) return false;
    const serverDid = this.tspBridge.getUtilityServerDid();
    if (!serverDid || !this.identity) return false;

    this._forceIdentityPushInFlight = true;
    try {
      const payload = await this.buildIdentityPushPayload();
      const transport = this.createServerTransport();
      const serverPart = new RemoteParticipant(`peer:${serverDid}`, transport);
      const result = await this._txBootstrap.manager.run(async (tx) => {
        tx.enlist(serverPart, [{ op: 'exchange:identity', params: { payload } }]);
      });

      if (result.outcome === 'committed') {
        logger.info(
          `[Agent] forced identity push committed (${reason}) — server identity/key state re-asserted: ${this.identity.did}`,
        );
        this.profileSyncPending = false;
        this.profileSyncLastError = null;
        return true;
      }
      logger.warn(
        `[Agent] forced identity push NOT committed (${reason}): outcome=${result.outcome} — ` +
        `the regular push path will retry`,
      );
      return false;
    } catch (err) {
      logger.warn(
        `[Agent] forced identity push failed (${reason}): ${(err as Error)?.message ?? err}`,
      );
      return false;
    } finally {
      this._forceIdentityPushInFlight = false;
    }
  }

  /** Single-flight guard for {@link forceIdentityPush}. */
  private _forceIdentityPushInFlight = false;


  /** Push profile data only — called after every profile mutation. */
  private syncProfilesToUtilityServer(): void {
    this.profileSyncPending = true;
    void this.pumpProfileSync();
  }

  /**
   * Drain the pending profile/identity sync state: repeatedly push until the
   * server acknowledges (committed) or the state is left pending for the next
   * reconnect/mutation to retry. Idempotent by design (identity_push upserts),
   * so an overlapping pump from a concurrent mutation is safe.
   */
  private async pumpProfileSync(): Promise<void> {
    if (this.profileSyncPumping) return;
    this.profileSyncPumping = true;
    try {
      // A small cap prevents an infinite loop on a permanently failing server;
      // the state stays pending and is retried on the next reconnect/mutation.
      for (let attempt = 0; attempt < 3 && this.profileSyncPending; attempt += 1) {
        const ok = await this.pushIdentityToUtilityServer();
        if (ok) return; // push cleared the pending state
        if (attempt < 2) await new Promise((r) => setTimeout(r, 500));
      }
    } finally {
      this.profileSyncPumping = false;
    }
  }

  /**
   * Current profile/R-Card sync state, for UI surfaces (profiles screen,
   * dashboard, connect screen). pending=true means the utility server has NOT
   * yet acknowledged the latest profile state (dropped while disconnected,
   * coordinator unavailable, or a 2PC abort) and a retry is pending.
   */
  getProfileSyncStatus(): { pending: boolean; lastError: string | null } {
    return { pending: this.profileSyncPending, lastError: this.profileSyncLastError };
  }

  /**
   * Collect all profiles + claims for this agent's active identity so they can
   * ride in an identity_push payload (R-Card data sync).
   */
  private async collectProfilesPayload(): Promise<
    Array<{ label: string; purpose?: string; visibility: string; claims: Array<{ claimKey: string; claimValue: string | null; valueType: string; disclosure: string }> }>
  > {
    const profiles: Array<{ label: string; purpose?: string; visibility: string; claims: Array<{ claimKey: string; claimValue: string | null; valueType: string; disclosure: string }> }> = [];
    try {
      const identityId = this.getLocalIdentityUuid();
      const profileList = await profilesService.listProfiles(this.ds, identityId);
      logger.info(`[Agent:push] collected ${profileList.length} profiles for identity ${identityId}`);
      for (const p of profileList) {
        const claims = await profilesService.listClaims(this.ds, p.uuid);
        logger.info(`[Agent:push]   profile uuid=${p.uuid} label="${p.label}" claims=${claims.length}`);
        profiles.push({
          label: p.label,
          purpose: p.purpose ?? undefined,
          visibility: p.visibility,
          claims: claims.map(c => ({
            claimKey: c.claimKey,
            claimValue: c.claimValue,
            valueType: c.valueType,
            disclosure: c.disclosure,
          })),
        });
      }
    } catch (err) {
      logger.error(`[Agent:push] Failed to collect profiles: ${(err as Error).message}`, (err as Error).stack);
    }
    return profiles;
  }

  // ---------------------------------------------------------------------------

  /**
   * Fetch the full public identity state from the utility server for recovery.
   *
   * Only public data is returned — private keys, passphrases, and messages
   * are NEVER included. The user must regenerate keys on a new device.
   *
   * Requires a TSP connection to the utility server (established via
   * configureUtilityServer).
   */
  async fetchRecoveryState(timeoutMs?: number): Promise<import('./modules/recovery.js').RecoveryState | null> {
    if (!this.recoveryModule.isInitialized()) {
      throw new Error(
        'Agent.fetchRecoveryState: recovery module not initialized. ' +
        'Call configureUtilityServer() first.',
      );
    }
    return this.recoveryModule.fetchRecoveryState(timeoutMs);
  }

  /**
   * Look up any identity's public data from the utility server's history repository.
   *
   * Requires a TSP connection to the utility server.
   */
  async lookupIdentity(
    did: string,
    timeoutMs?: number,
  ): Promise<import('@p2p-trust-stack/core/tx/services/identity-service.js').IdentityLookupResultPayload> {
    if (!this.recoveryModule.isInitialized()) {
      throw new Error(
        'Agent.lookupIdentity: recovery module not initialized. ' +
        'Call configureUtilityServer() first.',
      );
    }
    const result = await this.recoveryModule.lookupIdentity(did, timeoutMs);
    return result ?? { found: false };
  }
}
