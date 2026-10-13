/**
 * Exchange watermark — per (recordSet, peer) last-synced-at tracking in the
 * per-node tx-coordinator.db (`exchange_watermark` table, added in Phase 0).
 *
 * Phase 5 completes the watermark-driven resync driver; this module provides the
 * read/bump primitives used by the engine's ack() today and the driver tomorrow.
 */
import type { DataSource } from '../db/data-source.js';
import { sha256 } from '../crypto/primitives.js';

export interface WatermarkRow {
  last_synced_at: number;
  last_pushed_digest: string | null;
}

export async function readWatermark(
  ds: DataSource,
  recordSet: string,
  peer: string,
): Promise<number | null> {
  const row = await ds.get<{ last_synced_at: number }>(
    'SELECT last_synced_at FROM exchange_watermark WHERE record_set = ? AND peer = ?',
    recordSet,
    peer,
  );
  return row?.last_synced_at ?? null;
}

/** Read both the synced-at timestamp and the last-pushed digest. */
export async function readWatermarkFull(
  ds: DataSource,
  recordSet: string,
  peer: string,
): Promise<WatermarkRow | null> {
  const row = await ds.get<{ last_synced_at: number; last_pushed_digest: string | null }>(
    'SELECT last_synced_at, last_pushed_digest FROM exchange_watermark WHERE record_set = ? AND peer = ?',
    recordSet,
    peer,
  );
  return row ?? null;
}

export async function bumpWatermark(
  ds: DataSource,
  recordSet: string,
  peer: string,
  ts = Date.now(),
  digest?: string,
): Promise<void> {
  if (digest !== undefined) {
    await ds.run(
      `INSERT INTO exchange_watermark (record_set, peer, last_synced_at, last_pushed_digest)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(record_set, peer) DO UPDATE SET
         last_synced_at = excluded.last_synced_at,
         last_pushed_digest = excluded.last_pushed_digest`,
      recordSet,
      peer,
      ts,
      digest,
    );
  } else {
    await ds.run(
      `INSERT INTO exchange_watermark (record_set, peer, last_synced_at) VALUES (?, ?, ?)
       ON CONFLICT(record_set, peer) DO UPDATE SET last_synced_at = excluded.last_synced_at`,
      recordSet,
      peer,
      ts,
    );
  }
}

/** Stable digest of the materialized+projected payload rows for ack-gating. */
export function payloadDigest(rows: readonly Record<string, unknown>[]): string {
  return Buffer.from(
    sha256(new TextEncoder().encode(JSON.stringify(rows))),
  ).toString('hex');
}
