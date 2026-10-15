// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * ExchangeEngine — the single orchestrator over the existing transport
 * primitives. One implementation, two deployments:
 *   - Agent (light): outbox push + resync-on-connect + pull.
 *   - Server (full): ExchangeQueryParticipant (pull), ExchangePushParticipant
 *     (inbound upserts), queue-row fan-out via the injected ExchangeFanoutStore
 *     (AgentDeliveryQueue), pubsub broadcast, watermark ticker.
 *
 * The exchange path is unconditional — the CRE_ENABLED feature flag and its
 * conditional branches were removed (the catalog is the only path).
 */
import type { DataSource } from '../db/data-source.js';
import { randomUUID } from 'node:crypto';
import { RemoteParticipant } from '../tx/index.js';
import type { ParticipantTransport } from '../tx/index.js';
import type { DurableOutbox } from '../tx/index.js';
import { getMaterialize, getRecordSet, RECORD_SETS } from './catalog.js';
import { ExchangeError } from './types.js';
import type {
  ExchangeContext,
  ExchangeEvent,
  ExchangeEventType,
  ExchangeFanoutStore,
  ExchangePubsubTransport,
  ExchangeRequest,
  RecordSetName,
  ResyncPolicy,
} from './types.js';
import { bumpWatermark, payloadDigest, readWatermark, readWatermarkFull } from './watermark.js';
import { logger } from '../util/logger.js';

/** Columns that must never ride the exchange (N6 hard invariant). */
export const FORBIDDEN_PROJECTION_KEYS: readonly string[] = [
  'encrypted_secret_key',
  'secret_key',
  'signing_secret_key',
  'salt',
  'nonce',
];

/**
 * N6 privacy validator — hard-refuses any materialized row that exposes a
 * forbidden secret column, so a generic query engine can never exfiltrate
 * keys/salts/nonces even if a materializer is written carelessly.
 */
export function assertSafeProjection(rows: readonly Record<string, unknown>[], defName: string): void {
  for (const row of rows) {
    if (row && typeof row === 'object') {
      for (const key of Object.keys(row)) {
        if (FORBIDDEN_PROJECTION_KEYS.includes(key.toLowerCase())) {
          throw new ExchangeError(
            'invalid_projection',
            `recordset '${defName}' leaked forbidden column '${key}'`,
          );
        }
      }
    }
  }
}

export interface ExchangeEngineDeps {
  /** Application DB (used by push/fanout materializers). */
  db: DataSource;
  /** Durable outbox (agent side) for push-event delivery. */
  outbox?: DurableOutbox;
  /** Watermark DB — defaults to `db`; per-node tx-coordinator.db in practice. */
  watermark?: DataSource;
  /**
   * Optional connection-state gate for the periodic ticker: when provided, the
   * tick only runs resync while `isConnected(peer)` is true. Absent, the ticker
   * runs regardless (best-effort; push() itself is transport-bound).
   */
  isConnected?: (peer: string) => boolean;
  /**
   * Phase 7 — P2P endpoint resolution (Hybrid → P2P). When present, `pull()` for
   * peer-targeted recordsets resolves the target's endpoint to a ParticipantTransport
   * instead of assuming the server. The transport (`TspParticipantTransport` /
   * libp2p) is unchanged; only the endpoint changes. Absent, pulls go to `server`.
   */
  resolvePeerEndpoint?: (peerDid: string, name: RecordSetName) => ParticipantTransport | null;
  /**
   * Phase E — optional pubsub transport for `delivery: 'pubsub'` recordsets
   * (utilities/broadcast fan-out via `fanout()`). Absent, `fanout()` is a no-op
   * returning []. The server wires this to the libp2p replication topic.
   */
  pubsub?: ExchangePubsubTransport;
  /**
   * Server-side queue-row fan-out store (AgentDeliveryQueue implements this).
   * When present, `enqueueFanout()` enqueues one durable pending row per target
   * member (REF only — re-materialized at send time by deliverOne). Absent,
   * `enqueueFanout()` throws `not_wired`.
   */
  fanoutStore?: ExchangeFanoutStore;
}

export interface ExchangePullOptions {
  name: RecordSetName;
  req: ExchangeRequest;
  peer: string;
  transport: ParticipantTransport;
}

/**
 * Phase E — build semantic `ExchangeEvent` rows from a recordset's materialized
 * rows. Used by `ExchangeEngine.fanout()` and by server ceremony wiring to
 * emit post-commit events (RFC §9). Deterministic: each row → one event.
 */
export async function buildExchangeEvents(
  _db: DataSource,
  name: RecordSetName,
  rows: readonly Record<string, unknown>[],
  eventType: ExchangeEventType = 'change',
  nodeId?: string,
): Promise<ExchangeEvent[]> {
  const timestamp = Date.now();
  return rows.map((row) => ({
    eventUuid: randomUUID(),
    recordSet: name,
    eventType,
    // Prefer an explicit row/entity id (communityUuid, credentialUuid, uuid),
    // falling back to a stable digest of the row so every row still gets one.
    rowUuid:
      String(row.communityUuid ?? row.credentialUuid ?? row.uuid ?? '') ||
      payloadDigest([row]),
    timestamp,
    nodeId,
  }));
}

/**
 * Standalone client-side computed read — `RemoteParticipant.query('exchange:<name>', req)`.
 *
 * Returns the unwrapped `data` payload (or throws `ExchangeError` on a denied /
 * failed pull). Usable without constructing an `ExchangeEngine` — the agent's
 * module-level callers (name-service, RecoveryModule) route through this.
 */
export async function exchangePull(opts: ExchangePullOptions): Promise<unknown> {
  const def = getRecordSet(opts.name);
  if (def.transport.delivery !== 'pull') {
    throw new ExchangeError('permanent', `recordset '${opts.name}' is not pull-deliverable`);
  }
  const remote = new RemoteParticipant(opts.peer, opts.transport);
  const res = await remote.query(
    `exchange:${opts.name}`,
    { ...opts.req } as unknown as Record<string, unknown>,
  );
  if (res && typeof res === 'object' && (res as { ok?: boolean }).ok === false) {
    const e = (res as { error?: { code?: string; message?: string } }).error;
    throw new ExchangeError(
      (e?.code as ExchangeError['code']) ?? 'permanent',
      e?.message ?? `exchange pull '${opts.name}' denied by peer`,
    );
  }
  return (res as { data?: unknown })?.data;
}

export class ExchangeEngine {
  private readonly db: DataSource;
  private readonly outbox?: DurableOutbox;
  private readonly watermarkDs: DataSource;
  private readonly isConnected?: (peer: string) => boolean;
  private readonly resolvePeerEndpoint?: (peerDid: string, name: RecordSetName) => ParticipantTransport | null;
  private readonly pubsub?: ExchangePubsubTransport;
  private readonly fanoutStore?: ExchangeFanoutStore;
  private ticker: ReturnType<typeof setInterval> | null = null;

  constructor(deps: ExchangeEngineDeps) {
    this.db = deps.db;
    this.outbox = deps.outbox;
    this.pubsub = deps.pubsub;
    this.fanoutStore = deps.fanoutStore;
    this.watermarkDs = deps.watermark ?? deps.db;
    this.isConnected = deps.isConnected;
    this.resolvePeerEndpoint = deps.resolvePeerEndpoint;
  }

  /**
   * Commit a computed (materialized + projected) payload for a recordset to the
   * durable outbox, applying **ack-gating** (Phase 5 step 4): if the payload's
   * digest is identical to the last one synced for (recordset, peer), the
   * enqueue is skipped — bounding volume to actual changes.
   *
   * Returns `{ receipt }` on a real enqueue, or `{ gated: true, digest, rows }`
   * when skipped as unchanged. Shared by `push()`, `fanout()`, and `resync()`.
   */
  private async commitPush(
    name: RecordSetName,
    peer: string,
    req: ExchangeRequest,
    transport: ParticipantTransport,
  ): Promise<{ receipt: unknown } | { gated: true; digest: string; rows: Record<string, unknown>[] }> {
    if (!this.outbox) {
      throw new ExchangeError('permanent', `recordset '${name}' push requires a durable outbox`);
    }
    const materialize = getMaterialize(name);
    const ctx: ExchangeContext = { ...req, transport };
    const rows = await materialize(this.db, ctx);
    assertSafeProjection(rows, name);
    const digest = payloadDigest(rows);

    // ── Gate 1: unchanged since the last HANDOFF/DELIVERY ────────────────────
    // `last_pushed_digest` means "the peer has this" (see Gate 2 below and ack()).
    // It used to mean "we enqueued this", which is why a permanent delivery
    // failure left the gate claiming success and suppressed every later
    // re-materialization of the same state.
    const prior = await readWatermarkFull(this.watermarkDs, name, peer);
    if (prior?.last_pushed_digest === digest) {
      // Unchanged since last successful sync — skip the redundant push. Also
      // refresh the CADENCE timestamp (NOT the digest) so the periodic driver
      // re-checks at the declared `periodic(ms)` cadence instead of treating the
      // recordset as perpetually due: without this refresh every ticker interval
      // re-materialized (and re-logged) the payload — the source of the repeated
      // `[Agent:push] collected …` output at ticker cadence, not the 60s heartbeat.
      await bumpWatermark(this.watermarkDs, name, peer);
      return { gated: true, digest, rows };
    }

    // Outbox entry body is the RAW protocol object, not encoded bytes. The
    // DurableOutbox persists via JSON serialization, so on dequeue the WireSend
    // receives the parsed object — a real Uint8Array can never survive that
    // round-trip. The agent's WireSend dispatches any body whose `protocol`
    // starts with `exchange:` to the transaction coordinator as a 2PC op; a
    // byte payload would fall through to the raw TSP_GEN branch (never applied
    // server-side), silently losing the push.
    const body = { protocol: `exchange:${name}`, payload: rows };

    // ── Gate 2: this exact payload is already queued, sent, or delivered ─────
    // Two different situations, deliberately not merged:
    //
    //  * `pending` — already queued, nothing has been handed to the transport
    //    yet. Gate WITHOUT touching the digest: this is not a delivery claim, and
    //    if the entry later fails permanently the payload must be pushable again.
    //  * `sent` / `delivered` — the transport accepted the bytes (for a `server:`
    //    destination, a committed 2PC IS the durable ack — see
    //    `markServerEntriesDelivered`). ONLY here is the digest recorded, which is
    //    what makes the gate read a delivery-side value.
    //
    // Either way the cadence timestamp is refreshed so the periodic driver does
    // not re-log this payload at ticker cadence.
    const alreadyQueued = await this.outbox.findByPayload(peer, body);
    if (alreadyQueued) {
      const handedOff = alreadyQueued.state === 'sent' || alreadyQueued.state === 'delivered';
      if (handedOff) {
        // Hop-accept (or a committed server-side 2PC) — record it as the last
        // pushed digest. A true end-to-end receipt is H8/F1: whatever the layer
        // receipt adds later, this is strictly more honest than "we enqueued it".
        await bumpWatermark(this.watermarkDs, name, peer, Date.now(), digest);
      } else {
        await bumpWatermark(this.watermarkDs, name, peer);
      }
      return { gated: true, digest, rows };
    }

    // Nothing outstanding for this payload — enqueue it. NOTE: no digest bump
    // here. Recording it at enqueue was the defect: the watermark then meant
    // "queued", so a permanently failed delivery suppressed every later push of
    // the same state even though the peer never applied it.
    const receipt = await this.outbox.enqueue(peer, body);
    return { receipt };
  }

  /** Client-side computed read — RemoteParticipant.query('exchange:<name>', req). */
  async pull(
    req: ExchangeRequest,
    name: RecordSetName,
    peer: string,
    transport: ParticipantTransport,
  ): Promise<unknown> {
    // Phase 7 — P2P endpoint resolution: a peer-targeted recordset can be pulled
    // directly from the peer when a transport is resolvable (no server mediation).
    // The recordset's `target` + the resolver decide; the transport + query are
    // otherwise identical to the server path.
    const p2pTransport = this.resolvePeerEndpoint
      ? this.resolvePeerEndpoint(peer, name)
      : null;
    const effectiveTransport = p2pTransport ?? transport;
    return exchangePull({ name, req, peer, transport: effectiveTransport });
  }

  /** Client-side durable push — materialize locally, project, enqueue to the outbox. */
  async push(
    req: ExchangeRequest,
    name: RecordSetName,
    peer: string,
    transport: ParticipantTransport,
  ): Promise<unknown> {
    const def = getRecordSet(name);
    if (def.transport.delivery === 'pull') {
      throw new ExchangeError('permanent', `recordset '${name}' is pull-deliverable, not push`);
    }
    const result = await this.commitPush(name, peer, req, transport);
    return 'gated' in result ? null : result.receipt;
  }

  /** Fan-out to a set of recipients (queue-row / per-recipient push). */
  async fanout(
    req: ExchangeRequest,
    name: RecordSetName,
    recipients: string[],
    transport: ParticipantTransport,
  ): Promise<void> {
    const def = getRecordSet(name);
    if (def.transport.delivery === 'queue-row') {
      // Server-side queue-row fanout (pending_agent_deliveries) is wired in
      // Phase 4 — the AgentDeliveryQueue already implements the driver.
      throw new ExchangeError('not_wired', `recordset '${name}' queue-row fanout wired in Phase 4`);
    }
    for (const recipient of recipients) {
      await this.push(req, name, recipient, transport);
    }
  }

  /**
   * Phase E — pubsub broadcast for `delivery: 'pubsub'` utilities recordsets.
   * Materializes the recordset, builds semantic ExchangeEvents, and publishes
   * each over the recordset's topic via the injected pubsub transport. Returns
   * the events published ([] when no pubsub transport is wired). Ack-gating is
   * NOT applied here — events are idempotent on the receiver by eventUuid, so
   * a re-broadcast after a crash is safe (dedup on the other side).
   */
  async broadcast(
    req: ExchangeRequest,
    name: RecordSetName,
    eventType: ExchangeEventType = 'change',
    nodeId?: string,
  ): Promise<ExchangeEvent[]> {
    const def = getRecordSet(name);
    if (def.transport.delivery !== 'pubsub') {
      throw new ExchangeError('permanent', `recordset '${name}' is not pubsub-deliverable`);
    }
    if (!this.pubsub || !def.transport.topic) {
      return [];
    }
    const ctx: ExchangeContext = { ...req };
    const rows = await getMaterialize(name)(this.db, ctx);
    assertSafeProjection(rows, name);
    const events = await buildExchangeEvents(this.db, name, rows, eventType, nodeId);
    for (const event of events) {
      await this.pubsub.publish(
        def.transport.topic,
        new TextEncoder().encode(JSON.stringify({ kind: 'exchange', event })),
      );
    }
    return events;
  }

  /**
   * Server-side queue-row fan-out (utility-server completion workstream).
   *
   * For a recordset fan-out ref (e.g. `{ communityUuid }` / `{ credentialUuid }`):
   *  1. Materializes the set once via the catalog (`getMaterialize`) and N6-guards
   *     it — the fan-out payload is COMMON to all members (D-4 decision), so one
   *     materialization + projection check covers every recipient.
   *  2. Resolves the target member uuids through the injected ExchangeFanoutStore.
   *  3. Enqueues one durable REF row per member via the store (idempotency-keyed).
   *
   * The store stores the REF only — deliverOne re-materializes via the catalog at
   * send time (invariant 1: never a stored snapshot). The materializer result is
   * used for the N6 fail-fast (a leaked secret / missing ref never reaches the queue).
   *
   * Returns the number of rows enqueued ({ queued: n }) and the target uuids for
   * observability.
   */
  async enqueueFanout(
    name: RecordSetName,
    ref: Record<string, unknown>,
  ): Promise<{ queued: number; targets: string[] }> {
    if (!this.fanoutStore) {
      throw new ExchangeError(
        'not_wired',
        `recordset '${name}' queue-row fan-out requires a server fanoutStore (AgentDeliveryQueue)`,
      );
    }

    // CRE packaging: the fan-out payload is materialized via the catalog + N6.
    // This is a VALIDATION pass (the queue stores only the REF; deliverOne
    // re-materializes at send time). When the enqueue runs inside the creating
    // 2PC transaction (vtc-create / ceremony participants) the community row may
    // not be visible yet — mirror the legacy enqueue behavior (silent no-op for
    // missing refs) by degrading materializer errors to a warning. N6 projection
    // violations are the hard invariant and always propagate.
    const materialize = getMaterialize(name);
    try {
      const ctx: ExchangeContext = { filters: ref };
      const rows = await materialize(this.db, ctx);
      assertSafeProjection(rows, name);
    } catch (err) {
      if (err instanceof ExchangeError && err.code === 'invalid_projection') {
        throw err;
      }
      logger.warn(`[exchange] enqueueFanout '${name}' validation skipped: ${(err as Error)?.message ?? err}`);
    }

    const targets = await this.fanoutStore.targets(name, ref);
    let queued = 0;
    for (const memberUuid of targets) {
      const idempotencyKey = await this.fanoutStore.idempotencyKey(name, ref, memberUuid);
      await this.fanoutStore.enqueue(name, memberUuid, ref, idempotencyKey);
      queued++;
    }
    return { queued, targets };
  }

  /** Watermark-driven catch-up on reconnect / tick — Phase 5. */
  async resync(
    peer: string,
    req?: ExchangeRequest,
    transport?: ParticipantTransport,
  ): Promise<string[]> {
    const ctx: ExchangeContext = { ...(req ?? {}) };
    const pushed: string[] = [];
    const visited = new Set<string>();

    for (const def of getDriverDefs()) {
      // Driver-owned defs are on-connect + periodic. On-demand pull recordsets
      // (rcard, registry, recovery, witness, governance-events) are NOT driver
      // owned — skip by RESYNC policy, not by delivery (vtc-membership is a
      // pull-deliverable driver def in Phase E and must still be pushed).
      if (def.resync === 'on-demand') continue;
      if (visited.has(def.name)) continue;
      visited.add(def.name);

      // Push-event (agent→server durable outbox) — the ack-gated path.
      try {
        const result = await this.commitPush(def.name, peer, ctx, transport as ParticipantTransport);
        if ('gated' in result) {
          // Unchanged — skip; watermark already reflects the sync.
          continue;
        }
        pushed.push(def.name);
        void result.receipt;
      } catch (err) {
        // A recordset whose materializer isn't wired locally is owned by the
        // other node (e.g. vtc-membership on the agent is a server push) — skip
        // it silently. Any other failure surfaces but never blocks the driver.
        if (err instanceof ExchangeError && err.code === 'not_wired') continue;
        logger.warn(`[exchange] resync '${def.name}' failed: ${(err as Error)?.message ?? err}`);
      }
    }

    return pushed;
  }

  /**
   * Start the periodic ticker (Phase 5 step 2). One `setInterval` walks the
   * `periodic(ms)` recordsets at their declared cadence (min granularity 1 s),
   * bounded by the configured interval. Replaces per-feature `setInterval`s.
   * Call `stop()` to clear.
   */
  startTicker(intervalMs = 15_000): void {
    if (this.ticker) return;
    this.ticker = setInterval(() => {
      void this.tick();
    }, Math.max(intervalMs, 1_000));
    this.ticker.unref?.();
    logger.info(`[exchange] watermark ticker started (${intervalMs}ms)`);
  }

  /** One tick — drive `periodic(ms)` defs for which the interval has elapsed. */
  async tick(): Promise<void> {
    try {
      const now = Date.now();
      for (const def of getDriverDefs()) {
        if (!isPeriodicPolicy(def.resync)) continue;
        const interval = parsePeriodicMs(def.resync);
        if (interval == null) continue;
        const last = await readWatermark(this.watermarkDs, def.name, 'server:us-1');
        if (last !== null && now - last < interval) continue; // not yet due
        // A live connection is required for an actual push; without one the
        // watermark stays old and the next tick retries (never dropped).
        if (this.isConnected && !this.isConnected('server:us-1')) continue;
        await this.resync('server:us-1', {}, undefined);
        break; // one def per tick keeps the loop fair
      }
    } catch (err) {
      logger.error(`[exchange] tick error: ${(err as Error)?.message ?? err}`);
    }
  }

  /** Stop the periodic ticker. */
  stopTicker(): void {
    if (this.ticker) {
      clearInterval(this.ticker);
      this.ticker = null;
    }
  }

  /** Ack + watermark bump (+ optional outbox markDelivered). */
  async ack(
    _req: ExchangeRequest,
    name: RecordSetName,
    peer: string,
    entryId?: string,
  ): Promise<void> {
    await bumpWatermark(this.watermarkDs, name, peer);
    if (entryId && this.outbox) {
      await this.outbox.markDelivered(entryId);
    }
  }
}

/** Parse a `periodic(<ms>)` cadence into a number of ms (null if not periodic). */
export function parsePeriodicMs(policy: string): number | null {
  const m = /^periodic\((\d+)\)$/.exec(policy);
  if (!m) return null;
  const ms = Number(m[1]);
  return Number.isFinite(ms) ? ms : null;
}

/** True when a resync policy is a `periodic(<ms>)` cadence. */
export function isPeriodicPolicy(policy: ResyncPolicy): boolean {
  return /^periodic\(\d+\)$/.test(policy);
}

/**
 * Recordsets owned by the watermark driver (on-connect + periodic), in catalog
 * order. Periodic cadences match by pattern (`periodic(<ms>)`), not by literal
 * — a literal `'periodic(ms)'` placeholder never matched real cadences, which
 * left the driver structurally idle (Phase D fix).
 */
export function getDriverDefs(): Array<typeof RECORD_SETS[number]> {
  return RECORD_SETS.filter(
    (d) => d.resync === 'on-connect' || isPeriodicPolicy(d.resync),
  );
}
