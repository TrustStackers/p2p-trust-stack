/**
 * The durable chat transcript store — the `agent_messages` table.
 *
 * Replaces the in-memory `ChatLog`, which documented its own limitation: *"Nothing is written to SQLite or to
 * any file, so an agent logout (or an agent switch) drops every session."* The `agent_messages` table keeps
 * the same entry shape and the same per-session monotonic time, but survives both.
 *
 * The table is separate from the utility server's `messages` table on purpose: that one is
 * DID-document-routed TSP record with a binary payload, while this is the agent's own text transcript keyed
 * by peer DID. See `src/db/migrations/0012_messages.sql`.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';

/** A single transcript entry — the same shape the in-memory `ChatLog` produced. */
export interface TranscriptEntry {
  /** Login name of the agent that authored the entry (local agent or peer). */
  agentName: string;
  /**
   * Epoch milliseconds, **globally** unique and strictly increasing across every conversation.
   *
   * Globally ordered — not merely per session — because `unread({ since })` is a cross-peer cursor. It still
   * satisfies the per-session rule a UI needs for stable DOM ids.
   */
  time: number;
  /** The message text. */
  text: string;
  /** `'me'` = local operator, `'peer'` = remote agent. */
  side: 'me' | 'peer';
  /** True when the message travelled over the confidential (HPKE) path. */
  confidential?: boolean;
}

export interface AppendTranscriptInput {
  agentName: string;
  text: string;
  side: 'me' | 'peer';
  confidential?: boolean;
  /** Caller-supplied timestamp; bumped to keep the session monotonic (as `ChatLog` did). */
  time?: number;
}

export interface MessageStore {
  /** Record one entry, returning the stored entry (its `time` is authoritative). */
  append(peerDid: string, input: AppendTranscriptInput): Promise<TranscriptEntry>;
  /** Read a peer's session, optionally after a cursor and/or capped. */
  list(peerDid: string, opts?: { since?: number; limit?: number }): Promise<TranscriptEntry[]>;
  /** Drop one peer's session; returns how many entries were discarded. */
  clear(peerDid: string): Promise<number>;
  /** Inbound totals since a cursor — the durable form of the old unread badge. */
  unread(opts?: { since?: number }): Promise<{ count: number; senders: number; latestAt: number }>;
}

interface MessageRow {
  uuid: string;
  peer_did: string;
  sequence: number;
  side: string;
  author_name: string;
  body: string;
  confidential: number;
  occurred_at: number;
}

function toEntry(row: MessageRow): TranscriptEntry {
  return {
    agentName: row.author_name,
    time: row.occurred_at,
    text: row.body,
    side: row.side === 'me' ? 'me' : 'peer',
    ...(row.confidential ? { confidential: true } : {}),
  };
}

/** An `MessageStore` backed by the `agent_messages` table. */
export function createAgentMessagesStore(db: DataSource): MessageStore {
  return {
    async append(peerDid, input): Promise<TranscriptEntry> {
      // `time` must be unique and strictly increasing so a UI can derive a stable DOM id and de-duplicate a
      // live push against a transcript re-render. The bound is taken over the WHOLE table, not per session:
      // per-session monotonicity is not enough, because `unread({ since })` is a cross-peer cursor and a
      // message from a peer whose session started earlier would otherwise sort before a cursor that was
      // already taken — and be missed. Global monotonicity implies per-session monotonicity, so the DOM-id
      // guarantee is preserved.
      const last = await db.get<{ seq: number | null; at: number | null }>(
        'SELECT MAX(sequence) AS seq, MAX(occurred_at) AS at FROM agent_messages WHERE peer_did = ?',
        peerDid,
      );
      const globalLast = await db.get<{ at: number | null }>(
        'SELECT MAX(occurred_at) AS at FROM agent_messages',
      );
      const sequence = (last?.seq ?? 0) + 1;
      const previousTime = globalLast?.at ?? 0;
      const requested = input.time ?? Date.now();
      const time = requested > previousTime ? requested : previousTime + 1;

      await db.run(
        `INSERT INTO agent_messages
           (uuid, peer_did, sequence, side, author_name, body, confidential, occurred_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        generateUuid(),
        peerDid,
        sequence,
        input.side,
        input.agentName,
        input.text,
        input.confidential ? 1 : 0,
        time,
      );

      return {
        agentName: input.agentName,
        time,
        text: input.text,
        side: input.side,
        ...(input.confidential ? { confidential: true } : {}),
      };
    },

    async list(peerDid, opts = {}): Promise<TranscriptEntry[]> {
      const clauses = ['peer_did = ?'];
      const params: (string | number)[] = [peerDid];
      if (opts.since !== undefined) {
        clauses.push('sequence > ?');
        params.push(opts.since);
      }
      const limit = opts.limit !== undefined ? ` LIMIT ${Math.max(1, Math.floor(opts.limit))}` : '';
      const rows = await db.all<MessageRow>(
        `SELECT * FROM agent_messages WHERE ${clauses.join(' AND ')} ORDER BY sequence${limit}`,
        ...params,
      );
      return rows.map(toEntry);
    },

    async clear(peerDid): Promise<number> {
      const before = await db.get<{ c: number }>(
        'SELECT COUNT(*) AS c FROM agent_messages WHERE peer_did = ?',
        peerDid,
      );
      await db.run('DELETE FROM agent_messages WHERE peer_did = ?', peerDid);
      return before?.c ?? 0;
    },

    async unread(opts = {}): Promise<{ count: number; senders: number; latestAt: number }> {
      const since = opts.since ?? 0;
      const row = await db.get<{ c: number; senders: number; latest: number | null }>(
        `SELECT COUNT(*) AS c, COUNT(DISTINCT peer_did) AS senders, MAX(occurred_at) AS latest
           FROM agent_messages WHERE side = 'peer' AND occurred_at > ?`,
        since,
      );
      return { count: row?.c ?? 0, senders: row?.senders ?? 0, latestAt: row?.latest ?? 0 };
    },
  };
}
