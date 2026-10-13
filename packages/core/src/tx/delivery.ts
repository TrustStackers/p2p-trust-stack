/**
 * Delivery reliability layer (Layer 1).
 *
 *   - DurableOutbox: persist-before-send, truthful SendReceipt, retry.
 *   - DurableInbox:  persist-before-respond, idempotency-key dedup, layer receipts.
 *   - Dispatcher:    single inbound demux by correlationId.
 *   - ConnectionWatch: observable connection state (re-fires on change).
 *
 * Adapted from reference-tx/delivery.ts. The production version persists
 * outbox and inbox entries to the tx-coordinator.db SQLite database via
 * the DataSource interface, rather than using in-memory Maps.
 */

import { randomUUID } from 'node:crypto';
import type { DataSource } from '../db/data-source.js';
import type {
  ConnState,
  LayerReceipt,
  OutboxState,
  SendReceipt,
} from './types.js';

// ---------------------------------------------------------------------------
// Pluggable interfaces
// ---------------------------------------------------------------------------

/** Pluggable low-level send that returns true only when the next hop accepts the bytes. */
export type WireSend = (destination: string, payload: unknown) => Promise<boolean>;

/** A handler invoked exactly once per idempotency key. */
export type InboxHandler = (payload: unknown) => void | Promise<void>;

/**
 * **F-028:** do two fingerprints describe the same document?
 *
 * A missing fingerprint on EITHER side is "cannot compare" → treated as equal. That
 * direction is deliberate: rows written before the column existed carry NULL, and
 * declaring a conflict on the strength of absent information would reject legitimate
 * replays of everything delivered by a pre-upgrade build.
 */
function comparesEqual(recorded: string | null | undefined, supplied: string | undefined): boolean {
  if (recorded === null || recorded === undefined) return true;
  if (supplied === undefined) return true;
  return recorded === supplied;
}

// ---------------------------------------------------------------------------
// ConnectionWatch
// ---------------------------------------------------------------------------

/** Minimal observable watch for connection state (re-fires on change). */
export class ConnectionWatch {
  private state: ConnState = 'down';
  private readonly subs = new Set<(s: ConnState) => void>();

  get value(): ConnState {
    return this.state;
  }

  set(value: ConnState): void {
    if (value === this.state) return; // re-fire only on change
    this.state = value;
    for (const s of this.subs) s(value);
  }

  subscribe(fn: (s: ConnState) => void): () => void {
    this.subs.add(fn);
    fn(this.state); // immediate current value
    return () => this.subs.delete(fn);
  }
}

// ---------------------------------------------------------------------------
// DurableOutbox (SQLite-backed)
// ---------------------------------------------------------------------------

/**
 * Durable outbox: persist-before-send with retry and truthful SendReceipt.
 *
 * Entries are persisted to the `tx_outbox` table in the coordinator SQLite
 * database. On reconnect, `drain()` replays all undelivered entries.
 *
 * ## Ownership
 *
 * `tx_outbox` is keyed by `entry_id` only, and — before the per-agent database
 * split — several agents launched from the same working directory shared one
 * `data/tx/tx-coordinator.db`. `drain()` then read EVERY owner's undelivered
 * entries and tried to deliver them through ITS transport, and the reconnect
 * promotion marked other agents' `server:%` rows delivered. Passing `owner`
 * scopes both the drain and that promotion to this coordinator's entries.
 */
export class DurableOutbox {
  private readonly ds: DataSource;
  private readonly send: WireSend;
  private readonly watch: ConnectionWatch;
  private readonly now: () => number;
  /** Coordinator identity that owns rows written by this instance (null = unowned/legacy). */
  private readonly owner: string | null;

  constructor(
    ds: DataSource,
    send: WireSend,
    watch: ConnectionWatch,
    opts: { now?: () => number; owner?: string } = {},
  ) {
    this.ds = ds;
    this.send = send;
    this.watch = watch;
    this.now = opts.now ?? (() => Date.now());
    this.owner = opts.owner ?? null;
  }

  /** Persist an entry, then attempt to deliver. Returns a truthful receipt. */
  async enqueue(destination: string, payload: unknown): Promise<SendReceipt> {
    const entryId = randomUUID();
    const now = this.now();

    // Persist BEFORE send
    await this.ds.run(
      `INSERT INTO tx_outbox (entry_id, destination, payload, state, attempts, deliver_by, created_at, owner)
       VALUES (?, ?, ?, 'pending', 0, ?, ?, ?)`,
      entryId,
      destination,
      JSON.stringify(payload),
      now + 30_000,
      now,
      this.owner,
    );

    console.log(`[tx-outbox] enqueued ${entryId.slice(0, 8)} → ${destination.slice(0, 12)}...`);
    return this.deliver(entryId);
  }

  private async deliver(entryId: string): Promise<SendReceipt> {
    const row = await this.ds.get<{
      entry_id: string;
      destination: string;
      payload: string;
      state: string;
      attempts: number;
    }>('SELECT entry_id, destination, payload, state, attempts FROM tx_outbox WHERE entry_id = ?', entryId);

    if (!row) return { status: 'unconfirmed', entryId };

    if (this.watch.value !== 'up') {
      return { status: 'unconfirmed', entryId };
    }

    const newAttempts = row.attempts + 1;
    await this.ds.run(
      'UPDATE tx_outbox SET attempts = ? WHERE entry_id = ?',
      newAttempts, entryId,
    );

    const payload = JSON.parse(row.payload);
    const accepted = await this.send(row.destination, payload);

    if (accepted) {
      await this.ds.run(
        "UPDATE tx_outbox SET state = 'sent' WHERE entry_id = ?",
        entryId,
      );
      console.log(`[tx-outbox] ${entryId.slice(0, 8)} accepted by next hop`);
      return { status: 'accepted', entryId };
    }

    await this.ds.run(
      "UPDATE tx_outbox SET state = 'failed' WHERE entry_id = ?",
      entryId,
    );
    console.log(`[tx-outbox] ${entryId.slice(0, 8)} failed (attempt ${newAttempts})`);
    return { status: 'unconfirmed', entryId };
  }

  /** Mark an entry delivered when a layer receipt arrives. */
  async markDelivered(entryId: string): Promise<void> {
    await this.ds.run(
      "UPDATE tx_outbox SET state = 'delivered' WHERE entry_id = ?",
      entryId,
    );
  }

  /**
   * Retry all of THIS owner's entries not yet delivered (e.g. on reconnect).
   *
   * Owner-scoped: entries written by another coordinator in a shared database
   * (the pre-split layout) must not be delivered through this one's transport —
   * their destinations/payloads belong to a different agent and would fail, or
   * worse, be mis-attributed.
   */
  async drain(): Promise<void> {
    const rows = await this.ds.all<{ entry_id: string }>(
      "SELECT entry_id FROM tx_outbox WHERE state != 'delivered' AND COALESCE(owner, '') = COALESCE(?, '')",
      this.owner,
    );
    if (rows.length > 0) {
      console.log(`[tx-outbox] draining ${rows.length} undelivered entry(s)`);
    }
    for (const row of rows) {
      await this.deliver(row.entry_id);
    }
  }

  async stateOf(entryId: string): Promise<OutboxState | undefined> {
    const row = await this.ds.get<{ state: string }>(
      'SELECT state FROM tx_outbox WHERE entry_id = ?',
      entryId,
    );
    return row?.state as OutboxState | undefined;
  }

  /**
   * Find a NON-FAILED entry for exactly this payload to this destination.
   *
   * Used by the exchange gate to answer "is this payload already queued, handed
   * over, or delivered?" without re-enqueueing it — the periodic driver would
   * otherwise add an identical entry every tick while a peer is unreachable.
   *
   * Compare-to-'failed' is deliberate and load-bearing: after a PERMANENT failure
   * the payload must be enqueueable again (the peer never received it), so
   * `failed` rows are invisible here. `delivered` rows ARE returned, because a
   * delivered entry whose digest was never recorded (rows written before the
   * watermark-on-delivery fix, or promoted by `markServerEntriesDelivered`) must
   * still satisfy the gate rather than be re-sent forever.
   *
   * Payload identity is the stored JSON: the outbox serializes with
   * `JSON.stringify`, so the caller must pass the same object shape it enqueues.
   */
  async findByPayload(
    destination: string,
    payload: unknown,
  ): Promise<{ entryId: string; state: OutboxState } | undefined> {
    const row = await this.ds.get<{ entry_id: string; state: string }>(
      `SELECT entry_id, state FROM tx_outbox
        WHERE destination = ? AND payload = ? AND state != 'failed'
        ORDER BY created_at DESC LIMIT 1`,
      destination,
      JSON.stringify(payload),
    );
    return row ? { entryId: row.entry_id, state: row.state as OutboxState } : undefined;
  }
}

/**
 * Promote THIS owner's `sent` → `delivered` rows for `server:*` destinations.
 *
 * A committed exchange push to a `server:` destination IS a durable ack (the 2PC
 * committed server-side), so the entry is done and the next reconnect drain must
 * not re-send the same snapshot.
 *
 * OWNER-scoped: in the pre-split shared database an unowned `UPDATE … WHERE
 * state='sent' AND destination LIKE 'server:%'` promoted EVERY agent's rows,
 * marking another agent's undelivered entries as delivered without them ever
 * having been sent.
 */
export async function markServerEntriesDelivered(
  ds: DataSource,
  owner?: string | null,
): Promise<void> {
  await ds.run(
    `UPDATE tx_outbox SET state = 'delivered'
      WHERE state = 'sent' AND destination LIKE 'server:%'
        AND COALESCE(owner, '') = COALESCE(?, '')`,
    owner ?? null,
  );
}

// ---------------------------------------------------------------------------
// DurableInbox (SQLite-backed, persist-before-respond, dedup)
// ---------------------------------------------------------------------------

/**
 * Durable inbox: persist-before-respond with idempotency-key dedup.
 *
 * Keys are persisted to the `tx_inbox` table BEFORE the handler is invoked,
 * so a crash between receive and apply is recoverable — on replay the key
 * is already known and the handler is not re-invoked.
 */
export class DurableInbox {
  private readonly ds: DataSource;
  private readonly handler: InboxHandler;

  /**
   * `handler` is optional because there are two ways to use the inbox:
   *  - `handle(key, payload)` drives a fixed handler given at construction (the
   *    original shape);
   *  - `handleOnce(key, run)` runs a caller-supplied closure and hands its result
   *    back, for inbound protocol paths that must answer the peer (H7 — a 2PC
   *    handler must reply on first delivery and stay silent on a replay).
   */
  constructor(ds: DataSource, handler: InboxHandler = () => {}) {
    this.ds = ds;
    this.handler = handler;
  }

  /**
   * Handle an inbound (idempotencyKey, payload). Dedups by key; a replay is
   * acknowledged without re-invoking the handler. Returns a layer receipt.
   *
   * **F-028:** with a `fingerprint` (a digest of the document), a repeat carrying a
   * DIFFERENT document is reported as a **conflict** rather than being acknowledged as
   * success. Without one, the previous behaviour applies — a missing or absent
   * fingerprint is treated as "cannot compare", never as a mismatch, because inventing
   * a conflict from missing information would break legitimate replays.
   */
  async handle(
    idempotencyKey: string,
    payload: unknown,
    opts: { fingerprint?: string } = {},
  ): Promise<LayerReceipt & { conflict?: boolean }> {
    // Check if already seen (durably)
    const existing = await this.ds.get<{ delivered_at: number; payload_digest: string | null }>(
      'SELECT delivered_at, payload_digest FROM tx_inbox WHERE idempotency_key = ?',
      idempotencyKey,
    );
    if (existing) {
      if (!comparesEqual(existing.payload_digest, opts.fingerprint)) {
        console.warn(
          `[tx-inbox] CONFLICT ${idempotencyKey.slice(0, 8)}: a different document arrived under a key ` +
          'already delivered — not re-applied, not acknowledged',
        );
        return { idempotencyKey, deliveredAt: existing.delivered_at, conflict: true };
      }
      return { idempotencyKey, deliveredAt: existing.delivered_at };
    }

    // Persist BEFORE respond: record the key prior to invoking the handler
    const deliveredAt = Date.now();
    await this.ds.run(
      'INSERT INTO tx_inbox (idempotency_key, delivered_at, payload_digest) VALUES (?, ?, ?)',
      idempotencyKey,
      deliveredAt,
      opts.fingerprint ?? null,
    );

    console.log(`[tx-inbox] delivering ${idempotencyKey.slice(0, 8)} (first delivery)`);
    await this.handler(payload);

    return { idempotencyKey, deliveredAt };
  }

  /**
   * Dedup an inbound message while returning the caller's own outcome (H7).
   *
   * Same persist-before-respond discipline as `handle()` — the key is written
   * BEFORE `run` executes, so a crash between receive and apply is still recoverable —
   * but the closure's result is handed back instead of being discarded, which is what
   * a protocol handler needs in order to reply.
   *
   * **F-028:** pass a `fingerprint` (a digest of the document being delivered) and a
   * repeat under the same key with a DIFFERENT one is reported as a **conflict**
   * instead of being acknowledged as success. The audit's wording is exact: *"return
   * the original result on a repeated key; do not acknowledge a different document as
   * success."* Without it, `{duplicate: true}` claimed "already delivered" for a
   * document that had never been delivered at all.
   *
   * A conflict never runs the handler and never overwrites the row, so the original
   * delivery's record survives and a later replay of the ORIGINAL still dedups.
   */
  async handleOnce<T>(
    idempotencyKey: string,
    run: () => Promise<T>,
    opts: { fingerprint?: string } = {},
  ): Promise<{ duplicate: boolean; conflict: boolean; result: T | null }> {
    const existing = await this.ds.get<{ delivered_at: number; payload_digest: string | null }>(
      'SELECT delivered_at, payload_digest FROM tx_inbox WHERE idempotency_key = ?',
      idempotencyKey,
    );
    if (existing) {
      const sameDocument = comparesEqual(existing.payload_digest, opts.fingerprint);
      if (!sameDocument) {
        console.warn(
          `[tx-inbox] CONFLICT ${idempotencyKey.slice(0, 8)}: a different document arrived under a ` +
          `key already delivered at ${existing.delivered_at} — not re-applied, not acknowledged`,
        );
        return { duplicate: false, conflict: true, result: null };
      }
      return { duplicate: true, conflict: false, result: null };
    }

    const deliveredAt = Date.now();
    await this.ds.run(
      'INSERT INTO tx_inbox (idempotency_key, delivered_at, payload_digest) VALUES (?, ?, ?)',
      idempotencyKey,
      deliveredAt,
      opts.fingerprint ?? null,
    );

    console.log(`[tx-inbox] delivering ${idempotencyKey.slice(0, 8)} (first delivery)`);
    return { duplicate: false, conflict: false, result: await run() };
  }

  async hasSeen(idempotencyKey: string): Promise<boolean> {
    const row = await this.ds.get<{ delivered_at: number }>(
      'SELECT delivered_at FROM tx_inbox WHERE idempotency_key = ?',
      idempotencyKey,
    );
    return row !== null;
  }
}

// ---------------------------------------------------------------------------
// Dispatcher — single inbound demux by correlationId
// ---------------------------------------------------------------------------

interface PendingRequest {
  resolve: (payload: unknown) => void;
  reject: (err: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
}

export class Dispatcher {
  private readonly pending = new Map<string, PendingRequest>();
  private readonly send: (destination: string, msg: unknown) => Promise<void>;

  constructor(send: (destination: string, msg: unknown) => Promise<void>) {
    this.send = send;
  }

  /** Send a request with a correlation id and await the correlated reply. */
  async request(destination: string, msg: unknown, timeoutMs = 30_000): Promise<unknown> {
    const correlationId = randomUUID();
    const envelope = { correlationId, msg };

    const promise = new Promise<unknown>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(correlationId);
        reject(new Error(`request ${correlationId} timed out`));
      }, timeoutMs);
      this.pending.set(correlationId, { resolve, reject, timeout });
    });

    await this.send(destination, envelope);
    return promise;
  }

  /**
   * Route an inbound envelope. If it carries a correlationId matching a pending
   * request, resolve that waiter; otherwise return null for a normal handler.
   */
  handleInbound(envelope: unknown): unknown {
    const e = envelope as { correlationId?: string; msg?: unknown };
    if (e.correlationId && this.pending.has(e.correlationId)) {
      const entry = this.pending.get(e.correlationId)!;
      clearTimeout(entry.timeout);
      this.pending.delete(e.correlationId);
      entry.resolve(e.msg);
      return { __dispatched: true };
    }
    return null;
  }

  destroy(): void {
    for (const [, entry] of this.pending) {
      clearTimeout(entry.timeout);
      entry.reject(new Error('dispatcher shutting down'));
    }
    this.pending.clear();
  }
}