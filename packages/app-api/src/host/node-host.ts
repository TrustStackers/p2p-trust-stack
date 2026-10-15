// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `NodeHost` — the only `Host` implementation in scope (design §3.7).
 *
 * It does not invent anything: every piece it supplies already exists and is used by the reference app
 * today — `resolveP2ptsHome()` for the data directory, `AgentRegistry` for the per-agent paths, and
 * `SqliteDataSource` for the per-agent database. The point of this file is to make those choices
 * *addressable from one place* so a future host can substitute them.
 */
import { resolveP2ptsHome } from '@p2p-trust-stack/core/platform/p2pts-home.js';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { AgentRegistry } from '../runtime/agent-registry.js';
import { AgentDatabase } from '../runtime/agent-database.js';
import { createAgent, unlockAgent } from '../runtime/agent.js';
import type { TspTransport } from '@p2p-trust-stack/core/transport/types.js';
import type { KeyStore } from '@p2p-trust-stack/core/keystore/types.js';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { AgentConfig } from '../runtime/types.js';
import type { AgentHandle } from '../runtime/handle.js';
import type { AgentMetaDto } from '../dto/identity.js';
import type { Host, ProvisionedAgentStorage } from './types.js';

export interface NodeHostOptions {
  /** P2PTS_HOME override. Defaults to `resolveP2ptsHome()` (env var, else the platform default). */
  home?: string;
  /** Registry to use. Defaults to a new `AgentRegistry(home)`. */
  registry?: AgentRegistry;
  /** Transport override for agents created/unlocked through this host. */
  transport?: TspTransport;
  /** Key-store override for agents created/unlocked through this host. */
  keystore?: KeyStore;
}

/** Build the Node host binding. */
export function createNodeHost(opts: NodeHostOptions = {}): Host {
  const home = opts.home ?? resolveP2ptsHome();
  // NOTE: `AgentRegistry`'s signature is (dbPath?, keystorePath?, p2ptsHome?) — the home is the **third**
  // parameter. Passing it first silently falls back to `resolveP2ptsHome()`, which writes agents into the
  // user's real P2PTS_HOME instead of the requested one. Do not "simplify" this call.
  const registry = opts.registry ?? new AgentRegistry(undefined, undefined, home);

  return {
    name: 'node',
    home,
    transport: opts.transport,
    keystore: opts.keystore,
    storageFor(agentName: string): DataSource {
      return SqliteDataSource.fromExisting(registry.getDbPath(agentName));
    },
    async provisionStorage(agentName: string): Promise<ProvisionedAgentStorage> {
      // The directory first: `AgentDatabase` opens two files inside it, so it must exist.
      const dataDir = registry.ensureAgentDir(agentName);
      const dbPath = registry.getDbPath(agentName);
      const keystorePath = registry.getKeystorePath(agentName);

      // `AgentDatabase` is constructed for its MIGRATION side effect and closed immediately: it runs the P2PTS
      // schema on open, which is what a freshly created agent needs before anything writes an identity row. A
      // bare `SqliteDataSource` would open the file with no tables and fail with "no such table: identities" —
      // the exact failure the adapter's comment recorded when it did this itself.
      const bootstrapping = new AgentDatabase(dbPath, keystorePath);
      bootstrapping.close();

      return { dataDir, dbPath, keystorePath, dataSource: SqliteDataSource.fromExisting(dbPath) };
    },
    listAgents(): AgentMetaDto[] {
      return registry.listAgents().map((a) => ({
        name: a.name,
        vid: a.vid,
        did: a.did,
        createdAt: a.createdAt,
        method: a.method,
        dataDir: a.dataDir,
        ...(a.bootstrapUrl ? { bootstrapUrl: a.bootstrapUrl } : {}),
      }));
    },
    deleteAgent(name: string): void {
      registry.deleteAgent(name);
    },
    agentExists(name: string): boolean {
      return registry.agentExists(name);
    },
    createAgent(config: AgentConfig): Promise<AgentHandle> {
      return createAgent(config, registry);
    },
    unlockAgent(config: AgentConfig): Promise<AgentHandle> {
      return unlockAgent(config, registry);
    },
  };
}
