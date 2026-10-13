/**
 * ExchangePubsubParticipant — server-side bridge between the CRE catalog and
 * the libp2p pubsub replication topic (Phase E).
 *
 * - Publishes semantic `ExchangeEvent`s (from `ExchangeEngine.broadcast()`) for
 *   `delivery: 'pubsub'`, `target: 'utilities'` recordsets (e.g.
 *   `governance-events`).
 * - Subscribes to the topic, dedups inbound events by `eventUuid`, and applies
 *   them through a per-recordset handler. Applying is deliberately
 *   **recordset-scoped** (semantic) rather than table-row-granular like the
 *   legacy ReplicationEvent: the handler for a recordset materializes/upserts
 *   via that recordset's own rules.
 *
 * This class carries NO hard libp2p dependency — the constructor takes a
 * minimal `ExchangePubsubTransport` (subscribe/publish), so it is fully
 * unit-testable with a fake and the server wires the real libp2p transport in
 * bootstrap when `node.services.pubsub` is available.
 */

import type { ExchangeEvent, ExchangePubsubTransport, RecordSetName } from '../types.js';

/** Inbound event dedup cache (same LRU semantics as the legacy ReplicationHandler). */
const DEDUP_TTL_MS = 300_000;
const MAX_DEDUP = 10_000;
const seenEvents = new Map<string, number>();

function isDuplicate(eventUuid: string): boolean {
  const seen = seenEvents.get(eventUuid);
  if (seen && Date.now() - seen < DEDUP_TTL_MS) return true;
  if (seenEvents.size >= MAX_DEDUP) {
    const oldest = [...seenEvents.entries()].sort((a, b) => a[1] - b[1])[0];
    if (oldest) seenEvents.delete(oldest[0]);
  }
  seenEvents.set(eventUuid, Date.now());
  return false;
}

export interface ExchangePubsubParticipantOptions {
  /** Live pubsub transport (libp2p replication topic in production). */
  pubsub: ExchangePubsubTransport;
  /** Topic to subscribe/publish on (defaults to the catalog recordset's topic). */
  defaultTopic: string;
  /** Node id stamped on published events (provenance). */
  nodeId?: string;
}

/**
 * A semantic event apply handler: given a received ExchangeEvent, bring this
 * node's copy of that recordset row up to date. The default impl logs the
 * "changed" signal (the authoritative row is re-materialized on the next
 * queue-row/pull); custom handlers can be registered per recordset.
 */
export type ExchangeEventApplyHandler = (
  event: ExchangeEvent,
) => Promise<void> | void;

export class ExchangePubsubParticipant {
  readonly pid: string;
  private readonly pubsub: ExchangePubsubTransport;
  private readonly defaultTopic: string;
  private readonly nodeId?: string;
  private readonly handlers = new Map<RecordSetName, ExchangeEventApplyHandler>();
  private started = false;

  constructor(pid: string, opts: ExchangePubsubParticipantOptions) {
    this.pid = pid;
    this.pubsub = opts.pubsub;
    this.defaultTopic = opts.defaultTopic;
    this.nodeId = opts.nodeId;
  }

  /** Register an apply handler for a recordset (default: best-effort log). */
  on(name: RecordSetName, handler: ExchangeEventApplyHandler): void {
    this.handlers.set(name, handler ?? (() => undefined));
  }

  /** Subscribe to the topic and route inbound `exchange` events. */
  async start(): Promise<void> {
    if (this.started) return;
    await this.pubsub.subscribe(this.defaultTopic, (data) => {
      void this.route(data);
    });
    this.started = true;
    console.log(`[exchange-pubsub] subscribed to ${this.defaultTopic} (${this.pid})`);
  }

  /** Publish an ExchangeEvent over the topic. */
  async publish(topic: string, event: ExchangeEvent): Promise<void> {
    const withNode = hasNodeId(event) ? event : { ...event, nodeId: this.nodeId };
    await this.pubsub.publish(
      topic,
      new TextEncoder().encode(JSON.stringify({ kind: 'exchange', event: withNode })),
    );
  }

  /** Publish the events for a set of already-built exchange events (server convenience). */
  async publishAll(topic: string, events: ExchangeEvent[]): Promise<void> {
    for (const event of events) await this.publish(topic, event);
  }

  private async route(data: Uint8Array): Promise<void> {
    let parsed: { kind?: string; event?: ExchangeEvent };
    try {
      parsed = JSON.parse(new TextDecoder().decode(data)) as { kind?: string; event?: ExchangeEvent };
    } catch {
      return;
    }
    if (parsed.kind !== 'exchange' || !parsed.event) return;
    const event = parsed.event;

    if (isDuplicate(event.eventUuid)) return;
    const handler = this.handlers.get(event.recordSet);
    if (handler) {
      try {
        await handler(event);
      } catch (err) {
        console.error(`[exchange-pubsub] apply ${event.recordSet}/${event.rowUuid.slice(0, 8)}:`, (err as Error)?.message);
      }
    } else {
      console.log(
        `[exchange-pubsub] received ${event.recordSet} change ${event.rowUuid.slice(0, 8)} (` +
          `${event.eventType}) — no handler registered; authoritative state is re-materialized on next sync`,
      );
    }
  }
}

function hasNodeId(e: ExchangeEvent): boolean {
  return typeof e.nodeId === 'string' && e.nodeId.length > 0;
}