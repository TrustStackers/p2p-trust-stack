// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * AgentDatabase — SQLite database manager for a single agent's data.
 *
 * ## Data layout (P2PTS_HOME)
 *
 *   P2PTS_HOME/vta/<agentKey>/     ← ONE directory PER AGENT (isolated on disk)
 *   ├── p2pts-database.db          ← THIS agent: identities, did_documents,
 *   │                                 rotation_log, keys, governance, credentials
 *   └── p2pts-keystore.db          ← THIS agent's private keys (encrypted)
 *
 *   P2PTS_HOME/contexts/<contextId>/
 *   ├── context-database.db       ← CONTEXT: relationships, messages, profiles
 *   └── context-keystore.db       ← HKDF-derived signing + agreement keys
 *
 * The caller passes the agent's OWN database + keystore paths (see
 * `getVtaPaths(agentName)`); this class holds no shared-path knowledge.
 *
 * ## Constructor modes
 *
 * 1. **Single-DB mode**:
 *    `new AgentDatabase(vtaDbPath, keystorePath, identityParams?)`
 *    — context DB falls back to the agent DB.
 *
 * 2. **Split-DB mode**:
 *    `new AgentDatabase(vtaDbPath, keystorePath, identityParams?, contextDbPath?)`
 *    — context-scoped stores (relationships, messages, profiles) use contextDbPath.
 *
 * ## Identity FK graph
 *
 * The agent resolves its own DID into the `identities` row (role=vta,
 * custody=local) and `did_documents` row at construction time. All
 * downstream stores (RelationshipStore, VtcStore, RotationLogStore)
 * use integer FK references (identity_id, did_document_id) via the
 * IdentityResolver, matching the utility server's data model.
 */

import { DatabaseSync } from 'node:sqlite';
import { openDatabase } from '@p2p-trust-stack/core/db/connection.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';

import { IdentityResolver } from '@p2p-trust-stack/core/services/identity-resolver.js';
import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { RelationshipStore } from '@p2p-trust-stack/core/relationship/store.js';
import { VtcStore } from '@p2p-trust-stack/core/vtc/store.js';
import { RotationLogStore } from '@p2p-trust-stack/core/did/rotation-log-store.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';

// ---------------------------------------------------------------------------
// Resolve shared migrations directory
// ---------------------------------------------------------------------------

const MIGRATIONS_DIR = getMigrationsDir();

// ---------------------------------------------------------------------------
// AgentIdentityParams
// ---------------------------------------------------------------------------

export interface AgentIdentityParams {
  did: string;
  method: string;
  name: string;
  peerId: string;
  /** CESR-encoded VID (Ed25519 public key), persisted in metadata for keystore lookups. */
  cesrVid?: string;
  didDocumentJson?: string;
}

// ---------------------------------------------------------------------------
// AgentDatabase
// ---------------------------------------------------------------------------

export class AgentDatabase {
  /** Shared VTA-level database (identities, did_documents, rotation_log, keys, governance). */
  private db: DatabaseSync;

  /** Context-level database (relationships, messages, profiles) — may be the same as db. */
  private contextDb: DatabaseSync;

  /** Private keystore database handle (if opened here). */
  private keystoreDb?: DatabaseSync;

  /** DID→identity_id resolver for FK relationships. */
  readonly resolver: IdentityResolver;

  /** Encrypted key pair storage — separate DB file, private keys only. */
  readonly keyStore: SqliteKeyStore;

  /** Relationship records backed by migration `relationships` table. */
  readonly relationshipStore: RelationshipStore;

  /** VTC governance + VRC credentials backed by `governance` + `credentials`. */
  readonly vtcStore: VtcStore;

  /** Key rotation history backed by `rotation_log` table. */
  readonly rotationLogStore: RotationLogStore;

  /**
   * @param vtaDbPath      Path to THIS agent's P2PTS schema database
   *                       (P2PTS_HOME/vta/<agentKey>/p2pts-database.db).
   * @param keystorePath   Path to the private keystore database (separate file).
   * @param identityParams Optional — resolve local identity into FK graph.
   * @param contextDbPath  Optional — separate context-scoped database for
   *                       relationships, messages, profiles. Falls back to
   *                       vtaDbPath if not provided (single-DB mode).
   */
  constructor(
    vtaDbPath: string,
    keystorePath: string,
    identityParams?: AgentIdentityParams,
    contextDbPath?: string,
  ) {
    // Open the shared VTA-level P2PTS schema database.
    this.db = openDatabase(vtaDbPath);

    // Run all P2PTS schema migrations on the shared DB (idempotent).
    const applied = runMigrations(this.db, MIGRATIONS_DIR);
    if (applied.length > 0) {
      logger.info(`[AgentDatabase] Applied ${applied.length} migration(s) to shared DB: ${applied.join(', ')}`);
    }

    // Open context DB (or fall back to shared DB for legacy single-DB mode).
    if (contextDbPath && contextDbPath !== vtaDbPath) {
      this.contextDb = openDatabase(contextDbPath);
      const ctxApplied = runMigrations(this.contextDb, MIGRATIONS_DIR);
      if (ctxApplied.length > 0) {
        logger.info(`[AgentDatabase] Applied ${ctxApplied.length} migration(s) to context DB: ${ctxApplied.join(', ')}`);
      }
    } else {
      this.contextDb = this.db;
    }

    // Identity resolver — bridges DID strings ↔ integer FKs.
    // Uses the shared DB for identity resolution (identities + did_documents are always shared).
    this.resolver = new IdentityResolver(this.db);

    // Resolve the local agent identity into the FK graph.
    if (identityParams) {
      this.resolver.resolveLocalIdentity({
        did: identityParams.did,
        method: identityParams.method,
        name: identityParams.name,
        peerId: identityParams.peerId,
        cesrVid: identityParams.cesrVid,
        didDocumentJson: identityParams.didDocumentJson,
      });
    }

    // Private keystore — completely separate database file.
    this.keyStore = new SqliteKeyStore(keystorePath);

    // Stores — RelationshipStore uses the context DB, others use the shared DB.
    this.relationshipStore = new RelationshipStore(this.contextDb, this.resolver);
    this.vtcStore = new VtcStore(this.db, this.resolver);
    this.rotationLogStore = new RotationLogStore(this.db, this.resolver);
  }

  // ---------------------------------------------------------------------------
  // Database handles
  // ---------------------------------------------------------------------------

  /**
   * Return the underlying DatabaseSync handle for the shared VTA-level database.
   * Used by AgentRegistry.listAgents() and other direct queries on identities,
   * did_documents, rotation_log, keys, governance, credentials.
   */
  getDbHandle(): DatabaseSync {
    return this.db;
  }

  /**
   * Return the context-level DatabaseSync handle.
   * In legacy single-DB mode this is the same as getDbHandle().
   * In split-DB mode this is the context-scoped database.
   */
  getContextDbHandle(): DatabaseSync {
    return this.contextDb;
  }

  /**
   * Whether split-DB mode is active (context DB is separate from shared DB).
   */
  isSplitDbMode(): boolean {
    return this.contextDb !== this.db;
  }

  /** Close all database connections. */
  close(): void {
    if (this.contextDb !== this.db) {
      this.contextDb.close();
    }
    this.db.close();
    if (this.keystoreDb) {
      this.keystoreDb.close();
    }
    this.keyStore.close();
  }

  /** True if the underlying shared database connection is still open. */
  isOpen(): boolean {
    return (this.db as any).open ?? true;
  }
}