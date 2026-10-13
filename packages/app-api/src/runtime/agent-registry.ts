/**
 * AgentRegistry — per-agent data layout under P2PTS_HOME.
 *
 * ## Data layout under P2PTS_HOME
 *
 *   P2PTS_HOME/
 *   ├── vta/
 *   │   ├── <agentKey>/               ← ONE directory PER AGENT (isolated)
 *   │   │   ├── p2pts-database.db      ← that identity's data
 *   │   │   ├── p2pts-keystore.db      ← that identity's encrypted private keys
 *   │   │   └── tx-coordinator.db      ← that identity's tx log + outbox
 *   │   └── <agentKey-B>/ …
 *   ├── contexts/<contextId>/         ← Per-app per-device derived context data
 *   │   ├── context-keystore.db
 *   │   └── context-database.db
 *   ├── names/
 *   └── config.yaml
 *
 * `<agentKey>` is a filesystem-safe form of the agent NAME (see
 * `sanitizeAgentName`). It is IMMUTABLE once created — the authoritative
 * DID/UUID lives inside the per-agent database, so a name change must not
 * rename the directory.
 *
 * ## Agent listing
 *
 * Agents are enumerated by scanning P2PTS_HOME/vta/* for directories that hold
 * a `p2pts-database.db` and reading each one's single local identity. There is
 * no shared database and no `agents` table.
 */

import { existsSync, rmSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import type { AgentMeta } from './types.js';
import {
  resolveP2ptsHome,
  ensureP2ptsHome,
  getP2ptsPaths,
  getVtaPaths,
  ensureVtaDir,
  listVtaAgentDirs,
  getContextPaths,
  ensureContextDir,
  type P2ptsPaths,
} from '@p2p-trust-stack/core/platform/p2pts-home.js';

// ---------------------------------------------------------------------------
// VtaRegistry — manages the VTA-level (user root) identity data
// ---------------------------------------------------------------------------

/**
 * VtaRegistry is the single authority for where each agent's files live on the
 * device: `P2PTS_HOME/vta/<agentKey>/`. Each agent is isolated in its own
 * directory (database + keystore + tx-coordinator DB).
 */
export class VtaRegistry {
  /** The shared P2PTS_HOME paths (contexts/, names/, config.yaml). */
  readonly paths: P2ptsPaths;

  /**
   * @param p2ptsHome  Optional override for P2PTS_HOME.
   *                   Defaults to `resolveP2ptsHome()`.
   */
  constructor(p2ptsHome?: string) {
    const home = p2ptsHome ?? resolveP2ptsHome();
    this.paths = getP2ptsPaths(home);
  }

  /** Ensure the shared P2PTS_HOME directory tree exists. */
  ensureDirectories(): void {
    ensureP2ptsHome(this.paths.p2ptsHome);
  }

  // -- Shared path accessors ------------------------------------------------

  getP2ptsHome(): string { return this.paths.p2ptsHome; }
  /** Parent directory holding one subdirectory per agent. */
  getVtaDir(): string { return this.paths.vtaDir; }
  getConfigPath(): string { return this.paths.configPath; }

  // -- Per-agent path accessors ---------------------------------------------

  /** The agent's own directory: P2PTS_HOME/vta/<agentKey>/. */
  getAgentDir(agentName: string): string {
    return getVtaPaths(agentName, this.paths.p2ptsHome).agentDir;
  }

  /** The agent's database: P2PTS_HOME/vta/<agentKey>/p2pts-database.db. */
  getDbPath(agentName: string): string {
    return getVtaPaths(agentName, this.paths.p2ptsHome).dbPath;
  }

  /** The agent's keystore: P2PTS_HOME/vta/<agentKey>/p2pts-keystore.db. */
  getKeystorePath(agentName: string): string {
    return getVtaPaths(agentName, this.paths.p2ptsHome).keystorePath;
  }

  /** The agent's tx-coordinator DB: P2PTS_HOME/vta/<agentKey>/tx-coordinator.db. */
  getTxDbPath(agentName: string): string {
    return getVtaPaths(agentName, this.paths.p2ptsHome).txDbPath;
  }

  /** Ensure the agent's directory exists (idempotent). Returns its path. */
  ensureAgentDir(agentName: string): string {
    return ensureVtaDir(agentName, this.paths.p2ptsHome);
  }

  // -- Agent listing / lookup / delete --------------------------------------

  /**
   * List every local agent by scanning P2PTS_HOME/vta/* for per-agent databases
   * and reading each one's single local (role=vta, custody=local) identity.
   * Sorted by creation time (oldest first).
   */
  listAgents(): AgentMeta[] {
    const out: AgentMeta[] = [];
    for (const agentKey of listVtaAgentDirs(this.paths.p2ptsHome)) {
      const dbPath = this.getDbPath(agentKey);
      let db: InstanceType<typeof DatabaseSync> | undefined;
      try {
        db = new DatabaseSync(dbPath, { readOnly: true });
        const row = db.prepare(`
          SELECT i.name, i.created_at, i.vid, dd.did, dd.method
          FROM identities i
          JOIN did_documents dd ON dd.identity_uuid = i.uuid AND dd.is_primary = 1
          WHERE i.role = 'vta' AND i.custody = 'local'
          ORDER BY i.created_at ASC
          LIMIT 1
        `).get() as {
          name: string | null;
          created_at: number | null;
          vid: string | null;
          did: string;
          method: string;
        } | undefined;
        if (row) {
          out.push({
            name: row.name ?? 'unknown',
            // Current CESR VID mirrors the keystore label (replaces the old
            // metadata.cesrVid JSON cache). Fall back to the real DID for rows
            // created before the column existed.
            vid: row.vid ?? row.did,
            did: row.did,
            createdAt: row.created_at ?? 0,
            dataDir: this.getAgentDir(agentKey),
            method: row.method || 'peer4',
          });
        }
      } catch {
        // Missing/unreadable tables in this directory — skip it.
      } finally {
        db?.close();
      }
    }
    return out.sort((a, b) => a.createdAt - b.createdAt);
  }

  /**
   * Check whether an agent directory holding a database already exists for the
   * given name (each agent owns exactly one directory).
   */
  agentExists(name: string): boolean {
    return existsSync(getVtaPaths(name, this.paths.p2ptsHome).dbPath);
  }

  /**
   * Permanently delete an agent: removes its entire directory — database,
   * keystore, tx-coordinator DB and WAL/journal sidecars.
   */
  deleteAgent(name: string): void {
    rmSync(this.getAgentDir(name), { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// ContextRegistry — manages per-app per-device context data
// ---------------------------------------------------------------------------

/**
 * ContextRegistry manages data scoped to a specific app context.
 *
 * Each app context lives under P2PTS_HOME/contexts/<contextId>/ and has its
 * own keystore (HKDF-derived keys) and database (app-scoped relationships,
 * messages, profiles).
 */
export class ContextRegistry {
  /** The context identifier (e.g., "agent-tui", "fiduciary-ai"). */
  readonly contextId: string;
  /** Full path to the context directory. */
  readonly contextDir: string;
  /** Path to the context keystore database. */
  readonly keystorePath: string;
  /** Path to the context database. */
  readonly dbPath: string;

  /**
   * @param contextId  The context identifier.
   * @param p2ptsHome   Optional P2PTS_HOME override.
   */
  constructor(contextId: string, p2ptsHome?: string) {
    this.contextId = contextId;
    const paths = getContextPaths(contextId, p2ptsHome);
    this.contextDir = paths.contextDir;
    this.keystorePath = paths.keystorePath;
    this.dbPath = paths.dbPath;
  }

  /** Ensure the context directory tree exists. */
  ensureDirectories(): void {
    ensureContextDir(this.contextId);
  }

  /** Check if the context keystore exists on disk. */
  keystoreExists(): boolean {
    try {
      const { existsSync } = require('node:fs');
      return existsSync(this.keystorePath);
    } catch {
      return false;
    }
  }

  /** Check if the context database exists on disk. */
  dbExists(): boolean {
    try {
      const { existsSync } = require('node:fs');
      return existsSync(this.dbPath);
    } catch {
      return false;
    }
  }
}

// ---------------------------------------------------------------------------
// Backward-compatible AgentRegistry facade
// ---------------------------------------------------------------------------

/**
 * AgentRegistry is the default entry point: it delegates to {@link VtaRegistry}
 * and exposes per-agent path accessors. All path accessors now take the agent
 * NAME, because each agent owns its own directory.
 */
export class AgentRegistry {
  private readonly vta: VtaRegistry;

  /**
   * @param _dbPath       Deprecated/ignored — kept for constructor-arity compat.
   * @param _keystorePath Deprecated/ignored — kept for constructor-arity compat.
   * @param p2ptsHome     Optional P2PTS_HOME override.
   */
  constructor(
    _dbPath?: string,
    _keystorePath?: string,
    p2ptsHome?: string,
  ) {
    this.vta = new VtaRegistry(p2ptsHome);
    this.vta.ensureDirectories();
  }

  getP2ptsHome(): string { return this.vta.getP2ptsHome(); }
  /** Parent directory holding one subdirectory per agent. */
  getVtaDir(): string { return this.vta.getVtaDir(); }
  /** @deprecated Use {@link getAgentDir}. Retained as the parent data root. */
  getDataDir(): string { return this.vta.getVtaDir(); }

  /** The agent's own directory: P2PTS_HOME/vta/<agentKey>/. */
  getAgentDir(name: string): string { return this.vta.getAgentDir(name); }
  /** The agent's database path. */
  getDbPath(name: string): string { return this.vta.getDbPath(name); }
  /** The agent's keystore path. */
  getKeystorePath(name: string): string { return this.vta.getKeystorePath(name); }
  /** The agent's tx-coordinator DB path. */
  getTxDbPath(name: string): string { return this.vta.getTxDbPath(name); }
  /** Ensure the agent's directory exists (idempotent). */
  ensureAgentDir(name: string): string { return this.vta.ensureAgentDir(name); }

  listAgents(): AgentMeta[] { return this.vta.listAgents(); }

  agentExists(name: string): boolean { return this.vta.agentExists(name); }

  deleteAgent(name: string): void { this.vta.deleteAgent(name); }
}

// ---------------------------------------------------------------------------
// Legacy default singleton — still works but now uses P2PTS_HOME
// ---------------------------------------------------------------------------

export const defaultRegistry = new AgentRegistry();