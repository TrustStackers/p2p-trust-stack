// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * ScidVhAgent — concrete Agent implementation for did:scid:vh DID method (Phase 4).
 */

import type { DidMethod } from '@p2p-trust-stack/core/did/did-method.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';
import { buildDidPeer4Document } from '@p2p-trust-stack/core/did/create.js';
import { ScidVhMethod, type ScidVhMethodCreateResult } from '@p2p-trust-stack/core/did/scid-vh-method.js';
import { cesrEncode, CESR_CODES } from '@p2p-trust-stack/core/crypto/cesr.js';
import { generateEd25519KeyPair, ed25519ToX25519, type Ed25519KeyPair } from '@p2p-trust-stack/core/crypto/primitives.js';
import type { RotationLogEntry } from '@p2p-trust-stack/core/did/rotation-types.js';
import type { Vrc } from '@p2p-trust-stack/core/vtc/types.js';

import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';

import { AgentRegistry, defaultRegistry } from './agent-registry.js';
import { AgentDatabase } from './agent-database.js';
import type { AgentConfig } from './types.js';
import { BaseAgent, type CryptoIdentityResult } from './base-agent.js';
import { ContextManager, listProvisionedApps, type AppCredentialBundle } from './context-manager.js';
import { exportSeedPhrase, importSeedPhrase } from '@p2p-trust-stack/core/crypto/seed-phrase.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';


// ---------------------------------------------------------------------------
// ScidVhAgent
// ---------------------------------------------------------------------------

export class ScidVhAgent extends BaseAgent {
  // ── Method-specific state ────────────────────────────────────────────────

  /** The underlying ScidVhMethod (cast from the base DidMethod type). */
  private get scidVhMethod(): InstanceType<typeof ScidVhMethod> {
    return this.didMethod as InstanceType<typeof ScidVhMethod>;
  }

  /**
   * The pre-committed "next" signing key pairs (keypair 1+). Populated by
   * create()/unlock() and consumed by rotate().
   */
  protected nextSigningKeyPairs: Ed25519KeyPair[] | undefined;

  /** The outgoing (previous) signing key pair, used to sign rotation entries. */
  protected outgoingSigningKeyPair: Ed25519KeyPair | undefined;

  /**
   * The genesis rotation log entries, stashed during create() because the
   * RotationLogStore isn't available until start(). Persisted in
   * wireUpAfterStart().
   */
  private pendingGenesisLog: RotationLogEntry[] | undefined;

  // ---------------------------------------------------------------------------
  // Abstract hook implementations
  // ---------------------------------------------------------------------------

  protected createDefaultDidMethod(): DidMethod {
    return new ScidVhMethod({ store: undefined });
  }

  /**
   * Generate crypto identity for ScidVh: create keys, DID, DID document,
   * and pre-committed next key pairs. Cryptographic operations only — no
   * metadata, no database writes (those happen in BaseAgent.initIdentity).
   */
  protected async generateCryptoIdentity(): Promise<CryptoIdentityResult> {
    const result = (await this.didMethod.create()) as ScidVhMethodCreateResult;

    // Track the next signing key pairs and outgoing key pair for rotation support.
    this.nextSigningKeyPairs = result.nextSigningKeyPairs;
    this.outgoingSigningKeyPair = result.signingKeyPair;

    // Stash the genesis log entries — the store isn't available at this
    // point in generateCryptoIdentity(). They are persisted immediately
    // in storeMethodSpecificKeys() during initIdentity().
    this.pendingGenesisLog = result.log;

    return {
      signingKeyPair: result.signingKeyPair,
      agreementKeyPair: result.agreementKeyPair,
      did: result.did,
      document: result.document,
      method: 'scid-vh',
      // Carried so initIdentity() can persist them: `ScidVhMethod.create()`
      // already publishes both as #key-mldsa / #key-kem, and a rotation would
      // lose the ability to ML-DSA-sign if the secret were never stored.
      mlDsa65KeyPair: result.mlDsa65KeyPair,
      hybridKemKeyPair: result.hybridKemKeyPair,
    };
  }

  /**
   * Store the pre-committed "next" signing key pairs for future rotations.
   * Called by BaseAgent after it has already stored the core ed25519 + x25519 keys.
   */
  protected async storeMethodSpecificKeys(
    keystore: SqliteKeyStore,
    crypto: CryptoIdentityResult,
  ): Promise<void> {
    if (this.nextSigningKeyPairs && this.nextSigningKeyPairs.length > 0) {
      const vid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, crypto.signingKeyPair.publicKey);
      for (let i = 0; i < this.nextSigningKeyPairs.length; i++) {
        const label = i === 0 ? 'ed25519-next' : `ed25519-next-${i}`;
        await keystore.storeKeyPairAsync(vid, label, this.nextSigningKeyPairs[i], this.passphrase);
      }
    }

    // Persist genesis rotation log immediately during initIdentity,
    // not deferred to wireUpAfterStart(). This eliminates the window
    // where the genesis log is in-memory-only and resolve() can fail
    // because the rotation_log table has no entries.
    if (this.pendingGenesisLog && this.pendingGenesisLog.length > 0) {
      try {
        const dbPath = this.registry.getDbPath(this.name);
        const keystorePath = this.registry.getKeystorePath(this.name);
        const tempDb = new AgentDatabase(dbPath, keystorePath, {
          did: this.identity.did,
          method: this.meta.method,
          name: this.meta.name,
          peerId: '',
          cesrVid: this.identity.cesrVid,
          didDocumentJson: JSON.stringify(this.identity.didDocument),
        });

        this.scidVhMethod.setStore(tempDb.rotationLogStore);

        for (const entry of this.pendingGenesisLog) {
          tempDb.rotationLogStore.appendEntry(this.identity.did, entry);
        }

        this.pendingGenesisLog = undefined;
        tempDb.close();
        logger.info('[ScidVhAgent] Genesis rotation log persisted during initIdentity');
      } catch (err) {
        logger.warn(
          '[ScidVhAgent] Failed to persist genesis rotation log during initIdentity: ' +
          ((err as Error)?.message ?? err) + '. wireUpAfterStart() will retry.',
        );
      }
    }
  }

  /**
   * Load the pre-committed next signing key pairs and track them for rotation.
   * Called by BaseAgent after loading core identity.
   */
  protected async loadMethodSpecificState(keystore: SqliteKeyStore): Promise<void> {
    const nextKeyPair = await keystore.retrieveKeyPairAsync(
      this.meta.vid, 'ed25519-next', this.passphrase,
    ).catch(() => undefined);
    if (nextKeyPair) {
      this.nextSigningKeyPairs = [nextKeyPair];
    }

    this.outgoingSigningKeyPair = this.identity.signingKeyPair;
  }

  protected async wireUpAfterStart(): Promise<void> {
    const rotationLogStore = this.db!.rotationLogStore;
    this.scidVhMethod.setStore(rotationLogStore);

    // NOTE: The genesis log was already persisted during initIdentity()
    // (in storeMethodSpecificKeys). The pendingGenesisLog field should
    // already be undefined. If it's not (e.g., the initIdentity persist
    // failed), append now as a fallback.
    if (this.pendingGenesisLog && this.pendingGenesisLog.length > 0) {
      for (const entry of this.pendingGenesisLog) {
        rotationLogStore.appendEntry(this.identity.did, entry);
      }
      this.pendingGenesisLog = undefined;
    }

    // Try to resolve from the rotation log. If the chain validation fails
    // (e.g., due to a race condition during first-time setup), fall back
    // to the current identity document rather than crashing startup.
    let resolvedDoc: DidDocument;
    try {
      resolvedDoc = this.didMethod.resolve(this.identity.did);
    } catch (err) {
      logger.warn(
        '[ScidVhAgent] resolve() failed after genesis log append: ' +
        ((err as Error)?.message ?? err) + '. Using existing identity document.',
      );
      resolvedDoc = this.identity.didDocument;
    }

    // Preserve service endpoints from the transport document (built by
    // buildDidDocumentWithTransport during start()).  didMethod.resolve()
    // reconstructs the DID document from rotation entries, which don't
    // include service endpoints with peerId/multiaddrs.
    const currentDoc = this.identity.didDocument as any;
    this.identity = {
      ...this.identity,
      didDocument: {
        ...resolvedDoc,
        service: currentDoc.service,
      } as DidDocument,
    };
  }

  protected buildDidDocumentWithTransport(params: {
    peerId: string;
    multiaddrs: string[];
  }): DidDocument {
    const base = buildDidPeer4Document(
      this.identity.signingKeyPair.publicKey,
      this.identity.agreementKeyPair.publicKey,
      { peerId: params.peerId, multiaddrs: params.multiaddrs },
    );
    const resolved = this.identity.didDocument;
    return {
      ...base,
      id: resolved.id ?? base.id,
      alsoKnownAs: resolved.alsoKnownAs,
      parameters: resolved.parameters,
    };
  }

  // ---------------------------------------------------------------------------
  // Static factories
  // ---------------------------------------------------------------------------

  static async create(
    config: AgentConfig,
    registry: AgentRegistry = defaultRegistry,
  ): Promise<ScidVhAgent> {
    if (registry.agentExists(config.name)) {
      throw new Error(`ScidVhAgent.create: agent "${config.name}" already exists. Use unlock() to load it.`);
    }

    const agent = new ScidVhAgent(config, registry);
    await agent.initIdentity();
    return agent;
  }

  static async unlock(
    config: AgentConfig,
    registry: AgentRegistry = defaultRegistry,
  ): Promise<ScidVhAgent> {
    if (!registry.agentExists(config.name)) {
      throw new Error(`ScidVhAgent.unlock: agent "${config.name}" not found. Use create() to create it.`);
    }
    const meta = registry.listAgents().find(m => m.name === config.name);
    if (!meta) {
      throw new Error(`ScidVhAgent.unlock: agent "${config.name}" not found.`);
    }

    const agent = new ScidVhAgent(config, registry);
    agent.meta = meta;

    const unlockDb = new AgentDatabase(registry.getDbPath(config.name), registry.getKeystorePath(config.name));
    try {
      agent.scidVhMethod.setStore(unlockDb.rotationLogStore);
      await agent.loadIdentity();
    } finally {
      // Released here for the same reason as the `tempDb` in `initIdentity()`: the store is
      // needed only to resolve the identity at unlock time, and `wireUpAfterStart()` swaps in
      // the LIVE database's store on start(). Holding this second connection to the agent's
      // database for the agent's whole lifetime is invisible on POSIX, but on Windows it makes
      // the agent's directory undeletable (`EBUSY`) even after `stop()` — which is what broke
      // `npm test` on Windows. `finally` also covers the wrong-passphrase path, where no agent
      // is returned for anyone else to close.
      unlockDb.close();
    }
    return agent;
  }

  // ---------------------------------------------------------------------------
  // Static: list / delete (delegate to base)
  // ---------------------------------------------------------------------------

  static list(registry: AgentRegistry = defaultRegistry) {
    return BaseAgent.list(registry);
  }

  static delete(name: string, registry: AgentRegistry = defaultRegistry): void {
    BaseAgent.delete(name, registry);
  }

  // ---------------------------------------------------------------------------
  // ScidVh-specific methods
  // ---------------------------------------------------------------------------

  async rotate(params: {
    nextSigningPublicKey: Uint8Array;
    witnessAttestations?: Vrc[];
  }): Promise<RotationLogEntry> {
    if (!this.db) {
      throw new Error('ScidVhAgent.rotate: agent not started. Call start() first.');
    }

    const rotationLogStore = this.db.rotationLogStore;

    const currentLog = rotationLogStore.getLog(this.identity.did);
    if (currentLog.length === 0) {
      throw new Error('ScidVhAgent.rotate: no rotation log entries found');
    }

    const outgoingSigningKeyPair = this.outgoingSigningKeyPair;
    const newSigningKeyPair = this.nextSigningKeyPairs?.[0];

    if (!outgoingSigningKeyPair) {
      throw new Error('ScidVhAgent.rotate: no outgoing signing key pair tracked');
    }
    if (!newSigningKeyPair) {
      throw new Error('ScidVhAgent.rotate: no next signing key pair tracked (call create() first)');
    }

    const entry = await this.scidVhMethod.rotate({
      currentLog,
      outgoingSigningKeyPair,
      newSigningKeyPair,
      nextSigningPublicKey: params.nextSigningPublicKey,
      witnessAttestations: params.witnessAttestations ?? [],
      transport: this.transport ? {
        peerId: this.getPeerId(),
        multiaddrs: this.getMultiaddrs(),
      } : undefined,
    });

    this.outgoingSigningKeyPair = newSigningKeyPair;

    const brandNewNextPair = generateEd25519KeyPair();
    this.nextSigningKeyPairs = [brandNewNextPair];

    const newAgreementKeyPair = ed25519ToX25519(newSigningKeyPair.secretKey);

    const resolvedDoc = this.didMethod.resolve(this.identity.did);
    const newVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, newSigningKeyPair.publicKey);

    this.identity = {
      cesrVid: newVid,
      did: resolvedDoc.id!,
      didDocument: resolvedDoc,
      signingKeyPair: newSigningKeyPair,
      agreementKeyPair: newAgreementKeyPair,
    };

    const keystore = new SqliteKeyStore(this.registry.getKeystorePath(this.name));
    await keystore.storeKeyPairAsync(newVid, 'ed25519', newSigningKeyPair, this.passphrase);
    await keystore.storeKeyPairAsync(newVid, 'x25519', newAgreementKeyPair, this.passphrase);
    await keystore.storeKeyPairAsync(newVid, 'ed25519-next', brandNewNextPair, this.passphrase);
    keystore.close();

    this.meta = { ...this.meta, vid: newVid, did: resolvedDoc.id! };

    // The rotation appended a new entry to the did:scid:vh log. Push the
    // refreshed log now so the server can serve a verified resolution instead of
    // a cached snapshot (fire-and-forget; retried on reconnect if offline).
    this.scheduleIdentityPushAfterRoll('key-rotation');

    return entry;
  }

  getNextSigningKeyPair(): Ed25519KeyPair | undefined {
    return this.nextSigningKeyPairs?.[0];
  }

  listRotationLog(): RotationLogEntry[] {
    if (this.db) {
      return this.db.rotationLogStore.getLog(this.identity.did);
    }
    return [];
  }

  // ---------------------------------------------------------------------------
  // Phase 2: Seed phrase (cross-device key transfer)
  // ---------------------------------------------------------------------------

  exportSeedPhrase(): string {
    const result = exportSeedPhrase(this.identity.signingKeyPair);
    return result.mnemonic;
  }

  async importSeedPhraseToKeystore(
    mnemonic: string,
    passphrase: string,
  ): Promise<void> {
    // Validate and extract seed, then reconstruct Ed25519 keypair.
    const signingKeyPair = await importSeedPhrase(
      mnemonic,
      async (seed) => {
        // Reconstruct Ed25519 keypair from a 32-byte seed.
        // In Ed25519, the secret key is the 32-byte seed concatenated with
        // the 32-byte public key (SHA-512 of seed, clamped).
        const { createPrivateKey } = await import('node:crypto');
        const key = createPrivateKey({
          key: { kty: 'OKP', crv: 'Ed25519', d: Buffer.from(seed).toString('base64url') },
          format: 'jwk',
        });
        const publicJwk = key.export({ format: 'jwk' }) as { x: string };
        const pubKey = Buffer.from(publicJwk.x, 'base64url');
        const sk = new Uint8Array(64);
        sk.set(seed, 0);
        sk.set(pubKey, 32);
        return { secretKey: sk, publicKey: new Uint8Array(pubKey) };
      },
    );
    const keystore = new SqliteKeyStore(this.registry.getKeystorePath(this.name));
    const vid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, signingKeyPair.publicKey);
    await keystore.storeKeyPairAsync(vid, 'ed25519', signingKeyPair, passphrase);
    keystore.close();
  }

  // ---------------------------------------------------------------------------
  // Phase 3: Context Registry (multi-app provisioning)
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Phase 3: Context Registry (multi-app provisioning)
  //
  // FIX (2026-10-09): every one of these passed NO home to `ContextManager`, so `getP2ptsPaths(undefined)`
  // fell through to `resolveP2ptsHome()` — the GLOBAL P2PTS_HOME — instead of the home this agent actually
  // lives in. A context is per-agent state, so on a multi-home setup (which the stack supports: every
  // `createAgentStack({ home })`) contexts from different homes shared one directory, and a context provisioned
  // under an isolated home leaked into the developer's real one. The agent already knows its home via its
  // registry; it just was not being asked.
  // ---------------------------------------------------------------------------

  async provisionApp(
    contextId: string,
    options?: {
      allowedKeyIds?: string[];
      expiresAt?: number;
      deviceLocal?: boolean;
    },
  ): Promise<AppCredentialBundle> {
    const mgr = new ContextManager(contextId, this.registry.getP2ptsHome());
    const bundle = await mgr.provision(
      this.identity.signingKeyPair,
      this.identity.agreementKeyPair,
      {
        ...options,
        passphrase: this.passphrase,
      },
    );
    bundle.contextDid = this.identity.did;
    return bundle;
  }

  async revokeApp(contextId: string): Promise<void> {
    const mgr = new ContextManager(contextId, this.registry.getP2ptsHome());
    await mgr.revoke();
  }

  listProvisionedApps() {
    return listProvisionedApps(this.registry.getP2ptsHome());
  }
}

// (end of ScidVhAgent)

// (end of ScidVhAgent)
