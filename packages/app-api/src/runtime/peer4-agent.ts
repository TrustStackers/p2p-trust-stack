/**
 * Peer4Agent — concrete Agent implementation for did:peer:4 DID method.
 *
 * The simplest agent type: one identity = one key pair, no rotation, no
 * verified history. All identity operations are fully offline and deterministic.
 *
 * This is the default agent type when no didMethod is specified in AgentConfig.
 *
 * Peer4Agent ONLY handles cryptographic identity generation. All metadata
 * construction and database persistence is owned by BaseAgent.
 */

import { buildDidPeer4Document } from '@p2p-trust-stack/core/did/create.js';
import { DidPeer4Method } from '@p2p-trust-stack/core/did/did-peer4-method.js';
import type { DidMethod } from '@p2p-trust-stack/core/did/did-method.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';

import type { AgentConfig } from './types.js';
import { BaseAgent, type CryptoIdentityResult } from './base-agent.js';
import { AgentRegistry, defaultRegistry } from './agent-registry.js';
import type { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';


// ---------------------------------------------------------------------------
// Peer4Agent
// ---------------------------------------------------------------------------

export class Peer4Agent extends BaseAgent {
  // ---------------------------------------------------------------------------
  // Abstract hook implementations
  // ---------------------------------------------------------------------------

  protected createDefaultDidMethod(): DidMethod {
    return new DidPeer4Method();
  }

  /**
   * Generate crypto identity for did:peer:4: create keys, DID, and DID document.
   * All cryptographic operations only — no metadata, no database writes.
   */
  protected async generateCryptoIdentity(): Promise<CryptoIdentityResult> {
    const result = await this.didMethod.create();
    return {
      signingKeyPair: result.signingKeyPair,
      agreementKeyPair: result.agreementKeyPair,
      did: result.did,
      document: result.document,
      method: 'peer4',
      // Carried so initIdentity() can persist them: the document already
      // publishes #key-mldsa / #key-kem.
      mlDsa65KeyPair: result.mlDsa65KeyPair,
      hybridKemKeyPair: result.hybridKemKeyPair,
    };
  }

  /**
   * did:peer:4 has no method-specific keys to store during create.
   * BaseAgent already stores ed25519 + x25519 keys.
   */
  protected async storeMethodSpecificKeys(_keystore: SqliteKeyStore, _crypto: CryptoIdentityResult): Promise<void> {
    // No-op: did:peer:4 has no extra keys.
  }

  /**
   * did:peer:4 has no method-specific state to load during unlock.
   */
  protected async loadMethodSpecificState(_keystore: SqliteKeyStore): Promise<void> {
    // No-op: did:peer:4 tracks no extra state beyond the core identity.
  }

  protected async wireUpAfterStart(): Promise<void> {
    // Peer4Agent has no method-specific services to wire up after start().
  }

  protected buildDidDocumentWithTransport(params: {
    peerId: string;
    multiaddrs: string[];
  }): DidDocument {
    return buildDidPeer4Document(
      this.identity.signingKeyPair.publicKey,
      this.identity.agreementKeyPair.publicKey,
      { peerId: params.peerId, multiaddrs: params.multiaddrs },
    );
  }

  // ---------------------------------------------------------------------------
  // Static factories
  // ---------------------------------------------------------------------------

  /**
   * Create a new Peer4Agent with a fresh did:peer:4 identity.
   */
  static async create(
    config: AgentConfig,
    registry: AgentRegistry = defaultRegistry,
  ): Promise<Peer4Agent> {
    // Check if the agent's own directory/database already exists.
    if (registry.agentExists(config.name)) {
      throw new Error(`Peer4Agent.create: agent "${config.name}" already exists. Use unlock() to load it.`);
    }

    const agent = new Peer4Agent(config, registry);
    await agent.initIdentity();
    return agent;
  }

  /**
   * Unlock an existing Peer4Agent by loading and decrypting its keys from the database.
   */
  static async unlock(
    config: AgentConfig,
    registry: AgentRegistry = defaultRegistry,
  ): Promise<Peer4Agent> {
    // Each agent owns its own database — resolve its metadata by name.
    if (!registry.agentExists(config.name)) {
      throw new Error(`Peer4Agent.unlock: agent "${config.name}" not found. Use create() to create it.`);
    }

    const meta = registry.listAgents().find(m => m.name === config.name);
    if (!meta) {
      throw new Error(`Peer4Agent.unlock: agent "${config.name}" not found.`);
    }

    const agent = new Peer4Agent(config, registry);
    agent.meta = meta;
    await agent.loadIdentity();
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
}