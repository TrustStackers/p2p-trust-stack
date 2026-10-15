// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * H6 — the exchange watermark must record a HANDOFF, not an enqueue.
 *
 * The defect: `commitPush` wrote the payload digest at ENQUEUE time, so the
 * ack-gate treated "we queued it" as "the peer has it". A delivery that failed
 * permanently then suppressed every later push of the same state, even though the
 * peer never received those bytes. The outbox retained and retried the entry, so
 * this was never data loss — but the watermark over-claimed and a re-materialized
 * identical payload was silently gated away.
 *
 * The fix records the digest only on a DELIVERY-SIDE transition, and adds an
 * in-flight guard so the periodic driver cannot grow the outbox without bound
 * while a peer is unreachable. "Delivery-side" here means the strongest signal the
 * outbox actually has today — `sent`, i.e. the transport accepted the frame (for a
 * `server:` destination, a committed server-side 2PC is the durable ack: see
 * `markServerEntriesDelivered`). `ExchangeEngine.ack()` — the true
 * delivered/committed hook — has NO production callers yet; an end-to-end layer
 * receipt is H8/F1, and until it exists this is the honest ceiling.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/exchange/watermark-on-delivery.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { rmSync } from 'node:fs';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { TX_SCHEMA_SQL, applyTxSchemaAdditions } from '../../src/tx/schema.js';
import {
  registerMaterializer,
  ExchangeEngine,
  bumpWatermark,
} from '../../src/exchange/index.js';
import { readWatermarkFull } from '../../src/exchange/watermark.js';

const PEER = 'server:us-1';

async function withTempDb<T>(fn: (ds: SqliteDataSource) => Promise<T>): Promise<T> {
  const file = `/tmp/wm-handoff-${randomUUID()}.db`;
  const ds = new SqliteDataSource(file);
  try {
    await ds.exec(TX_SCHEMA_SQL);
    // Production applies the additive columns on every boot; TX_SCHEMA_SQL alone
    // is not the runtime schema, because its `CREATE TABLE IF NOT EXISTS` leaves
    // an existing table untouched. (The same drift left four ack-gating tests in
    // exchange.test.ts throwing "no such column: owner" until H19.)
    await applyTxSchemaAdditions(ds);
    return await fn(ds);
  } finally {
    await ds.close();
    rmSync(file, { force: true });
  }
}

/** The outbox rows for this destination, newest first. */
async function entries(ds: SqliteDataSource): Promise<Array<{ state: string }>> {
  return ds.all<{ state: string }>(
    'SELECT state FROM tx_outbox WHERE destination = ? ORDER BY created_at DESC',
    PEER,
  );
}

// ---------------------------------------------------------------------------
// 1. In flight: gated, but NOT claimed as delivered
// ---------------------------------------------------------------------------

test('H6: an entry that is only QUEUED gates a duplicate without claiming delivery', async () => {
  await withTempDb(async (ds) => {
    const { ConnectionWatch, DurableOutbox } = await import('../../src/tx/index.js');
    const payloadVersion = 1;
    registerMaterializer('identity', async () => [{ did: 'did:example:alice', updatedAt: payloadVersion }]);

    const watch = new ConnectionWatch();
    let sends = 0;
    const outbox = new DurableOutbox(ds, async () => { sends += 1; return true; }, watch);
    // Connection DOWN: `enqueue` persists and attempts delivery, which leaves the
    // entry `pending` — nothing has been handed to the transport.
    watch.set('down');
    const engine = new ExchangeEngine({ db: ds, outbox, watermark: ds, isConnected: () => true });

    await engine.push({}, 'identity', PEER, {} as never);
    assert.deepEqual(
      (await entries(ds)).map((e) => e.state),
      ['pending'],
      'precondition: one pending entry (queued, never handed over)',
    );
    assert.equal(sends, 0, 'nothing was handed over while the connection was down');

    const wm = await readWatermarkFull(ds, 'identity', PEER);
    assert.equal(wm?.last_pushed_digest ?? null, null, 'a merely-queued payload must NOT be recorded as pushed');

    // Identical re-materialization (what the ticker does every interval).
    await engine.push({}, 'identity', PEER, {} as never);
    assert.equal(
      (await entries(ds)).length,
      1,
      'the periodic driver must not accumulate duplicate entries while an identical one is queued',
    );
    assert.equal(
      (await readWatermarkFull(ds, 'identity', PEER))?.last_pushed_digest ?? null,
      null,
      'still no delivery claim',
    );
  });
});

// ---------------------------------------------------------------------------
// 2. Handed off: now the digest is recorded — and the gate reads it
// ---------------------------------------------------------------------------

test('H6: once the frame is accepted the digest is recorded, and the next push is gated', async () => {
  await withTempDb(async (ds) => {
    const { ConnectionWatch, DurableOutbox } = await import('../../src/tx/index.js');
    const payloadVersion = 1;
    registerMaterializer('identity', async () => [{ did: 'did:example:alice', updatedAt: payloadVersion }]);

    const watch = new ConnectionWatch();
    let sends = 0;
    const outbox = new DurableOutbox(ds, async () => { sends += 1; return true; }, watch);
    watch.set('down');
    const engine = new ExchangeEngine({ db: ds, outbox, watermark: ds, isConnected: () => true });

    await engine.push({}, 'identity', PEER, {} as never);
    assert.equal(sends, 0);

    // Reconnect and drain: the pending entry is handed to the transport.
    watch.set('up');
    await outbox.drain();
    assert.equal(sends, 1, 'the drain handed the payload over');
    assert.deepEqual((await entries(ds)).map((e) => e.state), ['sent']);

    // Next identical materialization: the gate now reads the HANDOFF digest.
    await engine.push({}, 'identity', PEER, {} as never);
    const wm = await readWatermarkFull(ds, 'identity', PEER);
    assert.ok(wm?.last_pushed_digest, 'the accepted frame must be recorded as the last pushed digest');
    assert.equal(sends, 1, 'no second send for an unchanged payload');

    // With the digest recorded the gate no longer needs the outbox at all: a third
    // identical push stays gated even if the entry were pruned.
    await ds.run('DELETE FROM tx_outbox');
    await engine.push({}, 'identity', PEER, {} as never);
    assert.equal(sends, 1, 'the digest alone gates the unchanged payload');
  });
});

// ---------------------------------------------------------------------------
// 3. THE regression this fix is for
// ---------------------------------------------------------------------------

test('H6: a PERMANENTLY FAILED delivery does not gate a later push of the same state', async () => {
  await withTempDb(async (ds) => {
    const { ConnectionWatch, DurableOutbox } = await import('../../src/tx/index.js');
    let payloadVersion = 1;
    registerMaterializer('identity', async () => [{ did: 'did:example:alice', updatedAt: payloadVersion }]);

    const watch = new ConnectionWatch();
    let attempts = 0;
    // Every send is refused → the outbox marks the entry `failed` (terminal).
    const outbox = new DurableOutbox(ds, async () => { attempts += 1; return false; }, watch);
    watch.set('up');
    const engine = new ExchangeEngine({ db: ds, outbox, watermark: ds, isConnected: () => true });

    await engine.push({}, 'identity', PEER, {} as never);
    assert.equal(attempts, 1, 'the first push was attempted');
    assert.deepEqual((await entries(ds)).map((e) => e.state), ['failed']);
    assert.equal(
      (await readWatermarkFull(ds, 'identity', PEER))?.last_pushed_digest ?? null,
      null,
      'a failed handoff must never be recorded as pushed',
    );

    // Re-push the SAME state. Before the fix this was gated away — the watermark
    // said "pushed" because it had merely been ENQUEUED — so the peer could never
    // receive it. It must be attempted again.
    await engine.push({}, 'identity', PEER, {} as never);
    assert.equal(attempts, 2, 'the peer must still receive a payload it never got');
    assert.equal(
      (await readWatermarkFull(ds, 'identity', PEER))?.last_pushed_digest ?? null,
      null,
      'still not claimed as delivered',
    );

    // A changed payload behaves normally.
    payloadVersion = 2;
    await engine.push({}, 'identity', PEER, {} as never);
    assert.equal(attempts, 3, 'a changed payload is pushed as usual');
  });
});

// ---------------------------------------------------------------------------
// 4. Cadence: gating still refreshes the timestamp (no ticker re-logging)
// ---------------------------------------------------------------------------

test('H6: a gated push still refreshes the cadence timestamp', async () => {
  await withTempDb(async (ds) => {
    const { ConnectionWatch, DurableOutbox } = await import('../../src/tx/index.js');
    registerMaterializer('identity', async () => [{ did: 'did:example:alice' }]);

    const watch = new ConnectionWatch();
    const outbox = new DurableOutbox(ds, async () => true, watch);
    watch.set('up');
    const engine = new ExchangeEngine({ db: ds, outbox, watermark: ds, isConnected: () => true });

    // Pre-age the watermark so the cadence would otherwise consider it due.
    await bumpWatermark(ds, 'identity', PEER, Date.now() - 120_000);

    await engine.push({}, 'identity', PEER, {} as never); // first: handoff + digest
    await engine.push({}, 'identity', PEER, {} as never); // second: gated

    const wm = await readWatermarkFull(ds, 'identity', PEER);
    assert.ok(
      wm && Date.now() - wm.last_synced_at < 60_000,
      'a gated attempt must still refresh last_synced_at, or the periodic driver re-checks every tick',
    );
  });
});


