/**
 * DataSourceLogSink — durable LogSink backed by a DataSource (SQLite).
 *
 * Implements the LogSink interface from the reference design using the
 * project's DataSource abstraction. This is the production persistence
 * backend for the TransactionLog, replacing the reference's MemoryLogSink.
 *
 * The DataSource passed in should point to the dedicated tx-coordinator.db,
 * NOT the application database.
 */

import type { DataSource } from '../db/data-source.js';
import type { LogEntry } from './types.js';

/** Pluggable persistence backend for the transaction log. */
export interface LogSink {
  append(entry: LogEntry): void | Promise<void>;
  /** All entries for a transaction, ordered by seq. */
  read(txId: string): LogEntry[] | Promise<LogEntry[]>;
  /** All transaction ids that have been started. */
  txIds(): string[] | Promise<string[]>;
}

/**
 * DataSource-backed LogSink.
 *
 * Persists log entries to the `tx_log` table in the coordinator's dedicated
 * SQLite database. The DataSource must already have the schema applied
 * (see schema.ts).
 */
export class DataSourceLogSink implements LogSink {
  private readonly ds: DataSource;

  constructor(ds: DataSource) {
    this.ds = ds;
  }

  async append(entry: LogEntry): Promise<void> {
    await this.ds.run(
      `INSERT OR REPLACE INTO tx_log (seq, tx_id, event, timestamp, payload)
       VALUES (?, ?, ?, ?, ?)`,
      entry.seq,
      entry.txId,
      entry.event,
      entry.timestamp,
      entry.payload != null ? JSON.stringify(entry.payload) : null,
    );
  }

  async read(txId: string): Promise<LogEntry[]> {
    const rows = await this.ds.all<{
      seq: number;
      tx_id: string;
      event: string;
      timestamp: number;
      payload: string | null;
    }>(
      'SELECT seq, tx_id, event, timestamp, payload FROM tx_log WHERE tx_id = ? ORDER BY seq',
      txId,
    );

    return rows.map((row) => ({
      seq: row.seq,
      txId: row.tx_id,
      event: row.event,
      timestamp: row.timestamp,
      payload: row.payload != null ? JSON.parse(row.payload) : undefined,
    }));
  }

  async txIds(): Promise<string[]> {
    const rows = await this.ds.all<{ tx_id: string }>(
      'SELECT DISTINCT tx_id FROM tx_log ORDER BY tx_id',
    );
    return rows.map((r) => r.tx_id);
  }
}