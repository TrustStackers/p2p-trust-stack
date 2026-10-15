// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * DataSource — database backend abstraction for the utility server.
 *
 * All methods are async (Promise-based) so the same interface can be backed
 * by synchronous SQLite (wrapped in Promises), async PostgreSQL/YugabyteDB,
 * or any future backend.
 *
 * The interface mirrors the `node:sqlite` `DatabaseSync` API shape so the
 * migration from raw `DatabaseSync` to `DataSource` is mechanical:
 *   - `db.prepare(sql).get(...)`        → `await db.get(sql, ...)`
 *   - `db.prepare(sql).all(...)`        → `await db.all(sql, ...)`
 *   - `db.prepare(sql).run(...)`        → `await db.run(sql, ...)`
 *   - `db.exec(sql)`                    → `await db.exec(sql)`
 */

export interface QueryResult {
  /** Number of rows affected (INSERT/UPDATE/DELETE). */
  changes: number;
  /**
   * Last inserted row ID.
   * SQLite returns `number`; PostgreSQL/YugabyteDB returns `string` or `number`
   * depending on the column type. Callers should cast with `Number(...)`.
   */
  lastInsertRowid?: number | string;
}

export interface DataSource {
  /**
   * Execute a SELECT-style query and return all result rows.
   *
   * @param sql  SQL string with `?` placeholders.
   * @param params  Positional parameter values (replaces `?` placeholders in order).
   * @returns Array of row objects (empty array if no rows match).
   */
  all<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T[]>;

  /**
   * Execute a SELECT-style query and return the first row, or `null` if no row matches.
   *
   * @param sql  SQL string with `?` placeholders.
   * @param params  Positional parameter values.
   * @returns First matching row object, or `null`.
   */
  get<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T | null>;

  /**
   * Execute a mutation (INSERT / UPDATE / DELETE) and return result metadata.
   *
   * @param sql  SQL string with `?` placeholders.
   * @param params  Positional parameter values.
   * @returns Result with `changes` (rows affected) and optionally `lastInsertRowid`.
   */
  run(sql: string, ...params: unknown[]): Promise<QueryResult>;

  /**
   * Execute multi-statement SQL (for migrations, bulk setup).
   * Not parameterized — raw SQL only.
   *
   * @param sql  One or more SQL statements separated by semicolons.
   */
  exec(sql: string): Promise<void>;

  /**
   * Execute a callback within a serializable transaction.
   *
   * YugabyteDB: `BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE`
   * SQLite:     `BEGIN IMMEDIATE`
   *
   * If the callback throws, the transaction is rolled back.
   * If the transaction aborts due to serialization conflict (YugabyteDB),
   * the implementation retries with exponential backoff.
   *
   * @param fn  Callback receiving a `DataSource` that operates within the transaction.
   * @returns The value returned by `fn`.
   */
  transaction<T>(fn: (ds: DataSource) => Promise<T>): Promise<T>;

  /**
   * Close the underlying connection pool or database handle.
   * After calling `close()`, no further queries should be made.
   */
  close(): Promise<void>;
}