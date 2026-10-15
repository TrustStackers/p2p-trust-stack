// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `identity` domain — lifecycle, identity read-back, and signing.
 *
 * Wraps the existing runtime (`runtime/agent.ts`, `runtime/agent-registry.ts`, `runtime/agent-database.ts`)
 * and the `src/services/vta.ts` creation service. **No new behaviour**: every operation here is the same
 * sequence the reference web adapter performs today, moved behind a typed, DTO-returning method.
 *
 * Two deliberate differences from the adapter, both recorded rather than silent:
 *
 * 1. **`list()` resolves each agent's `id`/`subjectKind`/`custody` from that agent's OWN database.** The
 *    adapter queried the *active* agent's database for every summary, so the fields were only ever correct
 *    for the active agent and null for the rest. The layer does it correctly; the adapter picks this up in P3.
 * 2. **The identity-row lookup uses `identities-repo`, not raw SQL.** The adapter inlines a `SELECT ... JOIN`
 *    through `getActiveDb()`; that is exactly the coupling this layer removes.
 *
 * Every mutating method emits on success (design §3.4: "a caller never needs to poll to learn that its own
 * action completed").
 */
import { AgentDatabase } from '../runtime/agent-database.js';
import { createAgent, unlockAgent } from '../runtime/agent.js';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { createVta } from '@p2p-trust-stack/core/services/vta.js';
import { importSeedPhrase } from '@p2p-trust-stack/core/crypto/seed-phrase.js';
import { generateEd25519KeyPairFromSeed } from '@p2p-trust-stack/core/crypto/primitives.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import type { SubjectKind } from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { requireAgent, type DomainContext } from './context.js';
import { NotImplementedError, UtilityServerUnavailableError } from '../errors.js';
import type {
  ActivateResultDto,
  AgentMetaDto,
  AgentSummaryDto,
  CreatedIdentityDto,
  DeactivateResultDto,
  IdentityDto,
  IdentityLookupDto,
  IdentityRowDto,
  RecoveryStateDto,
  SignResultDto,
} from '../dto/identity.js';

/** Options for creating an identity through the API. */
export interface CreateIdentityOpts {
  name: string;
  passphrase: string;
  /** Defaults to `'human'`. */
  subjectKind?: SubjectKind;
}

/** Options for importing an existing identity from its seed phrase. */
export interface ImportIdentityOpts {
  name: string;
  mnemonic: string;
  passphrase: string;
}

/** Options for activating (unlocking + starting) an identity. */
export interface ActivateIdentityOpts {
  name: string;
  passphrase: string;
}

export interface IdentityApi {
  /** The active identity, or `{ active: false }`. Never throws for "no agent". */
  current(): Promise<IdentityDto>;
  /** Sign an arbitrary message with the active VTA's Ed25519 key. */
  sign(message: string): Promise<SignResultDto>;
  /** Every agent the registry knows about. */
  list(): Promise<AgentSummaryDto[]>;
  /** Create a new VTA identity (own directory, database and keystore). */
  create(opts: CreateIdentityOpts): Promise<CreatedIdentityDto>;
  /** Reconstruct a VTA identity from its 24-word seed phrase and register it locally. */
  import(opts: ImportIdentityOpts): Promise<CreatedIdentityDto>;
  /** Unlock and start an identity, making it the active agent. */
  activate(opts: ActivateIdentityOpts): Promise<ActivateResultDto>;
  /** Stop the active agent and return to the un-activated state. */
  deactivate(): Promise<DeactivateResultDto>;
  /** Recovery state for this identity, as reported by the utility server. */
  recoveryState(): Promise<RecoveryStateDto | null>;
  /** Look up another identity's public data by DID. */
  lookup(did: string): Promise<IdentityLookupDto>;
}

const MIN_PASSPHRASE_LENGTH = 8;

/** Build the `identity` domain over a stack context. */
export function createIdentityApi(ctx: DomainContext): IdentityApi {
  /** Map the runtime's persisted metadata to the DTO (explicit fields, no spread of the raw record). */
  function toMetaDto(
    m: { name: string; vid: string; did: string; createdAt: number; method: string; dataDir: string; bootstrapUrl?: string },
    subjectKind?: string | null,
  ): AgentMetaDto {
    return {
      name: m.name,
      vid: m.vid,
      did: m.did,
      createdAt: m.createdAt,
      method: m.method,
      dataDir: m.dataDir,
      ...(m.bootstrapUrl !== undefined ? { bootstrapUrl: m.bootstrapUrl } : {}),
      // Filled from the identity row — see the field's note in dto/identity.ts.
      ...(subjectKind !== undefined ? { subjectKind } : {}),
    };
  }

  /**
   * Read the identity row behind a DID out of the agent's own database, via the repository rather than raw
   * SQL. Best-effort: a lookup failure yields null so identity read-back still works.
   */
  async function readIdentityRow(agentName: string, did: string): Promise<IdentityRowDto | null> {
    let ds: SqliteDataSource | null = null;
    try {
      ds = ctx.host.storageFor(agentName) as SqliteDataSource;
      const row = await identitiesRepo.findByRealDid(ds, did);
      if (!row) return null;
      return {
        uuid: row.uuid,
        role: row.role,
        subjectKind: row.subjectKind,
        custody: row.custody,
        name: row.name,
        createdAt: row.createdAt,
      };
    } catch {
      return null;
    } finally {
      if (ds) await ds.close();
    }
  }

  return {
    async current(): Promise<IdentityDto> {
      const agent = ctx.getAgent();
      if (!agent) return { active: false };
      const name = agent.getName();
      const did = agent.getDid();
      const row = await readIdentityRow(name, did);
      return {
        active: true,
        name,
        vid: agent.getVid(),
        did,
        multiaddrs: agent.getMultiaddrs(),
        peerId: agent.getPeerId(),
        meta: toMetaDto(agent.getMeta(), row?.subjectKind),
        identity: row,
      };
    },

    async sign(message: string): Promise<SignResultDto> {
      const agent = requireAgent(ctx, 'sign');
      return { signature: agent.signMessage(message) };
    },

    async list(): Promise<AgentSummaryDto[]> {
      const summaries = ctx.registry.listAgents();
      const out: AgentSummaryDto[] = [];
      for (const s of summaries) {
        const row = await readIdentityRow(s.name, s.did);
        out.push({
          ...toMetaDto(s, row?.subjectKind),
          ...(row ? { id: row.uuid, subjectKind: row.subjectKind, custody: row.custody } : { custody: 'local' }),
        });
      }
      return out;
    },

    async create(opts: CreateIdentityOpts): Promise<CreatedIdentityDto> {
      const { name, passphrase } = opts;
      if (!name) throw new Error('name is required');
      if (!passphrase || passphrase.length < MIN_PASSPHRASE_LENGTH) {
        throw new Error(`passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
      }
      if (ctx.registry.agentExists(name)) throw new Error(`an agent named "${name}" already exists`);

      const result = await createVtaInOwnDir(ctx, name, passphrase, opts.subjectKind ?? 'human');
      ctx.bus.emit('identity.created', { name, did: result.did, at: Date.now() });
      return result;
    },

    async import(opts: ImportIdentityOpts): Promise<CreatedIdentityDto> {
      const { name, mnemonic, passphrase } = opts;
      if (!name || !mnemonic || !passphrase) throw new Error('name, mnemonic and passphrase are required');
      if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
        throw new Error(`passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
      }
      if (ctx.registry.agentExists(name)) throw new Error(`an agent named "${name}" already exists`);

      const signingKeyPair = await importSeedPhrase(mnemonic, async (seed) =>
        generateEd25519KeyPairFromSeed(seed),
      );
      const identitySeed = signingKeyPair.secretKey.slice(0, 32);

      const result = await createVtaInOwnDir(ctx, name, passphrase, 'human', identitySeed);
      ctx.bus.emit('identity.created', { name, did: result.did, at: Date.now() });
      return result;
    },

    async activate(opts: ActivateIdentityOpts): Promise<ActivateResultDto> {
      const { name, passphrase } = opts;
      if (!name || !passphrase) throw new Error('name and passphrase are required');

      const config = {
        name,
        passphrase,
        ...(ctx.host.transport ? { transport: ctx.host.transport } : {}),
        ...(ctx.host.keystore ? { keystore: ctx.host.keystore } : {}),
      };

      const agent = ctx.registry.agentExists(name)
        ? await unlockAgent(config, ctx.registry)
        : await createAgent(config, ctx.registry);

      await agent.start();
      await ctx.setAgent(agent);

      const activated = { name: agent.getName(), vid: agent.getVid(), did: agent.getDid() };
      ctx.bus.emit('identity.activated', { name: activated.name, did: activated.did, at: Date.now() });
      return { ok: true, agent: activated };
    },

    async deactivate(): Promise<DeactivateResultDto> {
      const agent = ctx.getAgent();
      if (!agent) return { ok: true };
      const name = agent.getName();
      await agent.stop();
      await ctx.setAgent(null);
      ctx.bus.emit('identity.deactivated', { name, at: Date.now() });
      return { ok: true };
    },

    async recoveryState(): Promise<RecoveryStateDto | null> {
      const agent = requireAgent(ctx, 'read recovery state');
      if (agent.isUtilityServerConnected && !agent.isUtilityServerConnected()) {
        throw new UtilityServerUnavailableError('read recovery state');
      }
      if (!agent.fetchRecoveryState) {
        throw new NotImplementedError('recovery state', 'P4');
      }
      return agent.fetchRecoveryState();
    },

    async lookup(did: string): Promise<IdentityLookupDto> {
      const agent = requireAgent(ctx, 'look up an identity');
      if (!did) throw new Error('did is required');
      if (!agent.lookupIdentity) {
        throw new NotImplementedError('identity lookup', 'P4');
      }
      return agent.lookupIdentity(did);
    },
  };
}

/**
 * Create a VTA in its own directory, database and keystore.
 *
 * The order matters and is inherited from the adapter: the schema must be migrated (which `AgentDatabase`'s
 * constructor does) *before* `createVta` writes the identity, otherwise it fails with
 * "no such table: identities".
 */
async function createVtaInOwnDir(
  ctx: DomainContext,
  name: string,
  passphrase: string,
  subjectKind: SubjectKind,
  identitySeed?: Uint8Array,
): Promise<CreatedIdentityDto> {
  ctx.registry.ensureAgentDir(name);
  const dbPath = ctx.registry.getDbPath(name);
  const keystorePath = ctx.registry.getKeystorePath(name);

  const agentDb = new AgentDatabase(dbPath, keystorePath);
  let ds: SqliteDataSource | null = null;
  try {
    ds = SqliteDataSource.fromExisting(dbPath);
    const result = await createVta(ds, {
      name,
      subjectKind,
      passphrase,
      peerId: undefined,
      nodeId: undefined,
      keystorePath,
      ...(identitySeed ? { identitySeed } : {}),
    });
    return {
      name,
      did: result.didDocument.did,
      uuid: result.identity.uuid,
      publicKeys: { ed25519: result.publicKeys.ed25519, x25519: result.publicKeys.x25519 },
    };
  } finally {
    if (ds) await ds.close();
    agentDb.close();
  }
}
