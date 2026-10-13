/**
 * The `Host` seam — the one place the layer touches something platform-specific.
 *
 * Everything above this interface is transport-, storage- and key-store-agnostic. A Host supplies the three
 * things that differ per platform, mirroring the proven `TspTransport` seam (`src/transport/types.ts`):
 *
 * | Concern   | Node (today)                    | A future non-Node host        |
 * |-----------|---------------------------------|-------------------------------|
 * | transport | libp2p (TCP/WS/relay)           | a relay transport             |
 * | storage   | `node:sqlite`, one DB per agent | an in-WebView / native store  |
 * | keystore  | `SqliteKeyStore` (AES + Argon2) | an OS secure store            |
 *
 * **Scope (design §3.7):** only `NodeHost` exists and is exercised. Browser and native bindings are
 * *deferred* and out of scope for this work — they are named here only to show the seam is correctly shaped.
 * Specifying it now is what makes a later binding additive rather than a rewrite.
 */
import type { TspTransport } from '@p2p-trust-stack/core/transport/types.js';
import type { KeyStore } from '@p2p-trust-stack/core/keystore/types.js';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { AgentMetaDto } from '../dto/identity.js';
import type { AgentConfig } from '../runtime/types.js';
import type { AgentHandle } from '../runtime/handle.js';

/**
 * An agent's storage, provisioned and ready to be written to.
 *
 * Returned by `Host.provisionStorage()`. The paths are exposed because `createVta` needs the keystore path to
 * store the new identity's keypair — the host knows the layout, so it says where things are rather than making
 * the caller reconstruct the convention.
 */
export interface ProvisionedAgentStorage {
  /** The agent's own directory under `P2PTS_HOME/vta/<agentKey>/`. */
  dataDir: string;
  /** `…/p2pts-database.db` — the P2PTS schema database. */
  dbPath: string;
  /** `…/p2pts-keystore.db` — a separate file holding the encrypted key material. */
  keystorePath: string;
  /** Open and migrated. **The caller closes it.** */
  dataSource: DataSource;
}

export interface Host {
  /** Identifier for diagnostics, e.g. `'node'`. */
  readonly name: string;

  /** Root data directory (P2PTS_HOME). */
  readonly home: string;

  /**
   * Transport to hand a newly created/unlocked agent, or `undefined` to let the runtime build its own
   * (the Node default: a real libp2p node).
   */
  readonly transport?: TspTransport;

  /** Key store to hand a newly created/unlocked agent, or `undefined` for the runtime default. */
  readonly keystore?: KeyStore;

  /**
   * Open an agent's own database as a `DataSource`.
   *
   * Each agent owns its database (`P2PTS_HOME/vta/<agentKey>/p2pts-database.db`) — there is no shared
   * database. Only valid for an agent whose directory has been created (i.e. created or started at least
   * once); callers that need to create one should go through the `identity` domain.
   */
  storageFor(agentName: string): DataSource;

  /**
   * Create (if absent) and open an agent's storage — the directory, the database with its schema migrated, and
   * the keystore path.
   *
   * This exists because the adapter used to assemble it itself: it reached `AgentRegistry` for three paths
   * (`ensureAgentDir`, `getDbPath`, `getKeystorePath`) and constructed an `AgentDatabase` just to run the
   * migrations before writing an identity row. All of that is the host's own layout knowledge, so it belongs
   * here — and `createVta` needs the keystore path, which is why the paths are returned rather than hidden.
   *
   * Distinct from `storageFor`, which only OPENS an existing agent's database: this one creates the directory
   * and applies the P2PTS schema, which is what a freshly created agent needs before anything writes to it.
   *
   * **The caller closes `dataSource`.**
   */
  provisionStorage(agentName: string): Promise<ProvisionedAgentStorage>;

  /**
   * Every agent under this host's home, from the per-agent directories.
   *
   * Deliberately **no database is opened**: this is the listing a picker shows before any agent is active, so it
   * reads only what `P2PTS_HOME/vta/<agentKey>/` itself says. `identity.list()` is the richer call — it opens
   * each agent's database to resolve `id`/`subjectKind`/`custody` — and is the one to use once a stack exists.
   */
  listAgents(): AgentMetaDto[];

  /**
   * Remove an agent's directory and everything in it.
   *
   * **Irreversible.** The identity, its keys and its database all live in that one directory, which is what
   * makes per-agent isolation cheap to delete — and equally what makes this a destructive operation with no
   * undo. Callers confirm first.
   */
  deleteAgent(name: string): void;

  /** Whether an agent with this name exists in this host's home. */
  agentExists(name: string): boolean;

  /**
   * Create a new agent in this host's home.
   *
   * The lifecycle lives on the Host because the Host owns `home` and the per-agent layout — a caller that has a
   * Host can therefore work with agents without also holding a registry. `AgentConfig` is imported as a
   * **type only**, so this stays a pure type seam.
   */
  createAgent(config: AgentConfig): Promise<AgentHandle>;

  /** Unlock an existing agent in this host's home. */
  unlockAgent(config: AgentConfig): Promise<AgentHandle>;
}
