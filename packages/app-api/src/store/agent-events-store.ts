/**
 * The durable event outbox — the `agent_events` table behind the bus.
 *
 * ## Why a separate table (decision D2)
 *
 * The outbox is deliberately its own table rather than a column on the message/state tables: an event log
 * that can be inspected and replayed **on its own** is debuggable in a way a shared table is not. Its rows
 * are the only record of "what the stack announced, in what order".
 *
 * ## Relationship to the in-memory bus window
 *
 * The bus keeps a bounded in-memory window for *synchronous* delivery and immediate replay — that is what
 * lets `on(event, handler, { since })` stay synchronous. This store is the *durable* half: every emitted
 * event is appended here, so history outlives the process.
 *
 * The two are read differently, on purpose:
 *
 * ```ts
 * const sub = stack.on('message.received', handler);        // live, synchronous
 * const { events } = await stack.replayDurable({ since });  // durable history
 * ```
 *
 * Registering **before** reading history is what makes that race-free: a live event that arrives between the
 * two calls carries a sequence number, and the reader can skip anything it already saw. Trying to make one
 * call do both would either block delivery or reorder it.
 *
 * ## Schema notes
 *
 * `agent_events` is written dialect-free (app-supplied `BIGINT` timestamps, no `unixepoch()`, no `BLOB`) so
 * the block is byte-identical in both migration sets — see `src/db/migrations/0012_messages.sql`.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import { matchesFilter, type StackEvent } from '../events/catalog.js';
import type { StoredEvent } from '../client/events.js';
import type { EventStore } from './types.js';

/** A row of `agent_events`, as read back. */
interface AgentEventRow {
  uuid: string;
  sequence: number;
  event_type: string;
  payload_json: string;
  scope_id: string | null;
  occurred_at: number;
}

export type { EventStore };

/** Payload fields used as the row's `scope_id` — the key a `filter` most often narrows on. */
const SCOPE_FIELDS = ['peerDid', 'communityUuid', 'contextId', 'proposalId', 'profileUuid', 'uuid', 'name'];

function scopeOf(payload: unknown): string | null {
  if (payload === null || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;
  for (const field of SCOPE_FIELDS) {
    const v = p[field];
    if (typeof v === 'string') return v;
  }
  return null;
}

/** An `EventStore` backed by the `agent_events` table. */
export function createAgentEventsStore(db: DataSource): EventStore {
  return {
    async append(event: StoredEvent): Promise<void> {
      await db.run(
        `INSERT INTO agent_events (uuid, sequence, event_type, payload_json, scope_id, occurred_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        generateUuid(),
        event.seq,
        event.event,
        JSON.stringify(event.payload),
        scopeOf(event.payload),
        event.at,
      );
    },

    async read(opts): Promise<{ events: StoredEvent[]; truncated: boolean }> {
      const clauses = ['sequence > ?'];
      const params: (string | number)[] = [opts.since];
      if (opts.event) {
        clauses.push('event_type = ?');
        params.push(opts.event);
      }

      // The payload filter is applied in memory below: a filter is an arbitrary set of payload fields, and the
      // table indexes only one of them (`scope_id`). Narrowing on the indexed column first keeps that cheap.
      const scopeValue = opts.filter ? Object.values(opts.filter).find((v) => typeof v === 'string') : undefined;
      if (typeof scopeValue === 'string') {
        clauses.push('scope_id = ?');
        params.push(scopeValue);
      }

      const limit = opts.limit !== undefined ? ` LIMIT ${Math.max(1, Math.floor(opts.limit))}` : '';
      const rows = await db.all<AgentEventRow>(
        `SELECT * FROM agent_events WHERE ${clauses.join(' AND ')} ORDER BY sequence${limit}`,
        ...params,
      );

      const events: StoredEvent[] = [];
      for (const row of rows) {
        let payload: unknown;
        try {
          payload = JSON.parse(row.payload_json);
        } catch {
          continue; // a corrupt row must not break a replay
        }
        if (!matchesFilter(payload, opts.filter)) continue;
        events.push({
          seq: row.sequence,
          event: row.event_type as StackEvent,
          payload: payload as StoredEvent['payload'],
          at: row.occurred_at,
        });
      }

      // A durable log has no window to fall short of, so `truncated` is always false here. The field exists
      // on the interface because the in-memory bus window can genuinely be too small.
      return { events, truncated: false };
    },

    async latestSequence(): Promise<number> {
      const row = await db.get<{ max_seq: number | null }>(
        'SELECT MAX(sequence) AS max_seq FROM agent_events',
      );
      return row?.max_seq ?? 0;
    },

    async prune(keep: number): Promise<number> {
      const n = Math.max(0, Math.floor(keep));
      const row = await db.get<{ cutoff: number | null }>(
        'SELECT MAX(sequence) AS cutoff FROM (SELECT sequence FROM agent_events ORDER BY sequence DESC LIMIT ?)',
        n,
      );
      const cutoff = row?.cutoff;
      if (cutoff === null || cutoff === undefined) return 0;
      const before = await db.get<{ c: number }>(
        'SELECT COUNT(*) AS c FROM agent_events WHERE sequence <= ?',
        cutoff,
      );
      await db.run('DELETE FROM agent_events WHERE sequence <= ?', cutoff);
      return before?.c ?? 0;
    },
  };
}

