// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * SqliteDataSource — wraps `node:sqlite` `DatabaseSync` in the `DataSource` interface.
 *
 * This is the test-only DataSource implementation. It wraps every synchronous
 * SQLite call in `Promise.resolve()` so the caller can use `await` uniformly
 * regardless of backend.
 *
 * Used exclusively by tests (in-memory databases for fast CI). Not available
 * as a production runtime option — the utility server requires YugabyteDB for
 * serializable isolation across instances.
 */

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { DataSource, QueryResult } from './data-source.js';

export class SqliteDataSource implements DataSource {
  #db: InstanceType<typeof DatabaseSync>;

  /**
   * @param dbPath  File path or `:memory:`.
   */
  constructor(dbPath: string) {
    if (dbPath !== ':memory:') {
      mkdirSync(dirname(dbPath), { recursive: true });
    }
    this.#db = new DatabaseSync(dbPath);
    this.#db.exec('PRAGMA foreign_keys = ON');
    this.#db.exec('PRAGMA journal_mode = WAL');
  }

  /**
   * Open a second connection to the same database file as an existing handle.
   *
   * SQLite in WAL mode supports concurrent readers/writers across multiple
   * connections to the same file, so this is safe. The caller retains
   * ownership of the original handle.
   *
   * Used by the agent-app to bridge its synchronous SQLite handles into
   * the `DataSource`-based services and repositories.
   *
   * @param dbPath  The same file path used by the existing handle.
   */
  static fromExisting(dbPath: string): SqliteDataSource {
    return new SqliteDataSource(dbPath);
  }

  /**
   * Access the underlying `DatabaseSync` instance for legacy migration runners
   * or any code that hasn't been ported to `DataSource` yet.
   *
   * Prefer using the DataSource methods. This escape hatch exists to minimize
   * the blast radius of the async migration.
   */
  getRawDb(): InstanceType<typeof DatabaseSync> {
    return this.#db;
  }

  // ── DataSource implementation ──────────────────────────────────────────

  async all<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T[]> {
    const stmt = this.#db.prepare(sql);
    return stmt.all(...(params as never[])) as T[];
  }

  async get<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T | null> {
    const stmt = this.#db.prepare(sql);
    const row = stmt.get(...(params as never[])) as T | undefined;
    return row ?? null;
  }

  async run(sql: string, ...params: unknown[]): Promise<QueryResult> {
    const stmt = this.#db.prepare(sql);
    const result = stmt.run(...(params as never[]));
    return {
      changes: Number(result.changes),
      lastInsertRowid: Number(result.lastInsertRowid),
    };
  }

  async exec(sql: string): Promise<void> {
    this.#db.exec(sql);
  }

  async transaction<T>(fn: (ds: DataSource) => Promise<T>): Promise<T> {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const result = await fn(this);
      this.#db.exec('COMMIT');
      return result;
    } catch (err) {
      this.#db.exec('ROLLBACK');
      throw err;
    }
  }

  async close(): Promise<void> {
    this.#db.close();
  }
}