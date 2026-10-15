// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * TransactionLog — durable append-only record of a transaction's lifecycle.
 *
 * Adapted from reference-tx/transaction-log.ts. Uses a pluggable LogSink
 * (backed by DataSourceLogSink in production) for durability.
 *
 * The durability contract: the coordinator must persist its DECISION (commit or
 * abort) BEFORE broadcasting it. This log is the recovery source.
 */

import type { LogEntry } from './types.js';
import type { LogSink } from './tx-log-sink.js';
import { logger } from '../util/logger.js';

/**
 * A transaction log. `append` is ordered; `read` returns the ordered sequence
 * of events for recovery.
 */
export class TransactionLog {
  private counter = 0;
  private readonly sink: LogSink;

  constructor(sink: LogSink) {
    this.sink = sink;
  }

  async append(txId: string, event: string, payload?: unknown): Promise<number> {
    const entry: LogEntry = {
      seq: ++this.counter,
      txId,
      event,
      timestamp: Date.now(),
      payload,
    };
    await this.sink.append(entry);
    logger.debug(`[tx-log] ${txId.slice(0, 8)} seq=${entry.seq} ${event}${payload ? ' payload=' + JSON.stringify(payload).slice(0, 80) : ''}`);
    return entry.seq;
  }

  async read(txId: string): Promise<LogEntry[]> {
    return this.sink.read(txId);
  }

  async txIds(): Promise<string[]> {
    return this.sink.txIds();
  }

  /** True if the log records event==='committed' (the commit decision was durably written). */
  async hasDecision(txId: string, decision: 'committed' | 'aborted'): Promise<boolean> {
    const entries = await this.read(txId);
    return entries.some((e) => e.event === decision);
  }

  /** The most recent event for a transaction, or null. */
  async last(txId: string): Promise<LogEntry | null> {
    const entries = await this.read(txId);
    return entries.length > 0 ? entries[entries.length - 1] : null;
  }
}