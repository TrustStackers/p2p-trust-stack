// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `messaging` domain — send, durable transcript, unread totals, clear.
 *
 * Wraps the runtime's `sendMessage` / `sendConfidentialMessage` and replaces the two in-memory buffers the
 * adapter used (`chatLog` and the 500-entry `messageInbox`) with the durable `agent_messages` table, so a
 * transcript survives an agent switch or a restart.
 *
 * `send()` performs the same pre-flight check the adapter did — a missing or one-sided relationship produces a
 * typed `not_ready` error instead of a cryptic transport timeout.
 */
import { requireAgent, type DomainContext } from './context.js';
import { StackError } from '../errors.js';
import { resolvePeerAgentName } from '../runtime/peer-name.js';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { MessageStore, TranscriptEntry } from '../store/message-store.js';

export interface SendResultDto {
  ok: true;
  peerDid: string;
  confidential: boolean;
  /** The transcript entry recorded locally for this send. */
  entry: TranscriptEntry;
}

export interface TranscriptDto {
  peerVid: string;
  peerName: string | null;
  localName: string;
  entries: TranscriptEntry[];
  /** The cursor to pass as `since` next time. */
  cursor: number;
}

export interface UnreadDto {
  unread: number;
  senders: number;
  latestReceivedAt: number;
}

export interface ClearResultDto {
  ok: true;
  peerVid: string;
  cleared: number;
}

export interface MessagingApi {
  /** Send a text or binary message. */
  send(
    peerDid: string,
    body: string | Uint8Array,
    opts?: { confidential?: boolean },
  ): Promise<SendResultDto>;
  /** One peer's durable transcript, oldest first. */
  transcript(peerDid: string, opts?: { since?: number; limit?: number }): Promise<TranscriptDto>;
  /**
   * The newest entry in a peer's transcript, or null.
   *
   * Exists for the notification bridge: a `message.received` event deliberately does **not** carry the message
   * body (it would duplicate every message into the event outbox), so a consumer that needs the text reads it
   * from the transcript. `recordInboundMessage` appends before it emits, so the entry is there by the time a
   * subscriber sees the event.
   */
  latest(peerDid: string): Promise<TranscriptEntry | null>;
  /** Inbound totals since a cursor. */
  unread(opts?: { since?: number }): Promise<UnreadDto>;
  /** Drop one peer's transcript. Other peers are untouched. */
  clear(peerDid: string): Promise<ClearResultDto>;
}

export interface MessagingDeps {
  /** The active agent's database, or null before activation. */
  dataSource(): DataSource | null;
  /** The durable transcript store for the active agent, or null when unavailable. */
  store(): MessageStore | null;
}

/** Build the `messaging` domain. */
export function createMessagingApi(ctx: DomainContext, deps: MessagingDeps): MessagingApi {
  function requireStore(operation: string): MessageStore {
    const store = deps.store();
    if (!store) throw new StackError('no_message_store', `Cannot ${operation}: no durable message store.`);
    return store;
  }

  /** Display label for a peer — their login name when known, else null so a UI falls back to the DID. */
  function peerDisplayName(peerDid: string, remoteEd25519Key?: Uint8Array | null): string | null {
    const ds = deps.dataSource() as SqliteDataSource | null;
    if (!ds) return null;
    try {
      return resolvePeerAgentName(ds.getRawDb(), {
        remoteDid: peerDid,
        remoteEd25519Key: remoteEd25519Key ?? null,
      });
    } catch {
      return null;
    }
  }

  /** Refuse a send that cannot work, with the reason rather than a timeout. */
  function readinessError(peerDid: string): string | null {
    const agent = requireAgent(ctx, 'send a message');
    const record = agent.getRelationship(peerDid);
    if (!record) {
      return `No relationship found with ${peerDid.slice(0, 12)}... — connect first`;
    }
    // A utility server is infrastructure, not a chat peer — it has no chat capability.
    if ((record as { remoteSubjectKind?: string }).remoteSubjectKind === 'organization') {
      return `Cannot send chat to ${peerDid.slice(0, 12)}... — this is a utility server, not a chat peer`;
    }
    if (record.direction !== 'bidirectional' || record.status !== 'established') {
      return `Relationship is not bidirectional/established (${record.direction}/${record.status})`;
    }
    return null;
  }

  return {
    async send(peerDid, body, opts = {}): Promise<SendResultDto> {
      const agent = requireAgent(ctx, 'send a message');
      const confidential = opts.confidential === true;
      const text = typeof body === 'string' ? body : new TextDecoder().decode(body);
      const bytes = typeof body === 'string' ? new TextEncoder().encode(body) : body;

      const notReady = readinessError(peerDid);
      if (notReady) throw new StackError('not_ready', notReady);

      if (confidential) {
        await agent.sendConfidentialMessage(peerDid, bytes);
      } else {
        await agent.sendMessage(peerDid, bytes);
      }

      const entry = await requireStore('record a sent message').append(peerDid, {
        agentName: agent.getName(),
        text,
        side: 'me',
        ...(confidential ? { confidential: true } : {}),
      });

      ctx.bus.emit('message.sent', { peerDid, confidential, bytes: bytes.byteLength, at: entry.time });
      return { ok: true, peerDid, confidential, entry };
    },

    async transcript(peerDid, opts = {}): Promise<TranscriptDto> {
      const agent = requireAgent(ctx, 'read a transcript');
      const store = requireStore('read a transcript');
      const entries = await store.list(peerDid, opts);
      const all = await store.list(peerDid);
      const cursor = all.length > 0 ? all[all.length - 1].time : 0;
      return {
        peerVid: peerDid,
        peerName: peerDisplayName(peerDid, agent.getRelationship(peerDid)?.remoteEd25519Key),
        localName: agent.getName(),
        entries,
        cursor,
      };
    },

    async latest(peerDid: string): Promise<TranscriptEntry | null> {
      requireAgent(ctx, 'read the latest message');
      const store = requireStore('read the latest message');
      const rows = await store.list(peerDid);
      return rows.length > 0 ? rows[rows.length - 1] : null;
    },

    async unread(opts = {}): Promise<UnreadDto> {
      requireAgent(ctx, 'read unread totals');
      const store = requireStore('read unread totals');
      const { count, senders, latestAt } = await store.unread(opts);
      return { unread: count, senders, latestReceivedAt: latestAt };
    },

    async clear(peerDid): Promise<ClearResultDto> {
      requireAgent(ctx, 'clear a transcript');
      const store = requireStore('clear a transcript');
      const cleared = await store.clear(peerDid);
      ctx.bus.emit('chat.cleared', { peerDid, at: Date.now() });
      return { ok: true, peerVid: peerDid, cleared };
    },
  };
}

/**
 * Record an inbound message: persist it, then announce it.
 *
 * Exported separately from the domain because it is called by the **bus wiring**, not by a caller — the
 * runtime's `onMessage` callback drives it. It is also the piece that replaces the adapter's
 * `messageInbox.push` + `broadcastSSE('message', …)`: one durable append, one typed event.
 */
export async function recordInboundMessage(
  ctx: DomainContext,
  deps: MessagingDeps,
  msg: { remoteDid: string; body: Uint8Array; confidential: boolean; receivedAt: number },
): Promise<TranscriptEntry | null> {
  const store = deps.store();
  const agent = ctx.getAgent();
  if (!store || !agent) return null;

  const text = new TextDecoder().decode(msg.body);
  let authorName = 'Peer';
  try {
    const ds = deps.dataSource() as SqliteDataSource | null;
    if (ds) {
      authorName =
        resolvePeerAgentName(ds.getRawDb(), {
          remoteDid: msg.remoteDid,
          remoteEd25519Key: agent.getRelationship(msg.remoteDid)?.remoteEd25519Key ?? null,
        }) ?? 'Peer';
    }
  } catch {
    /* fall back to the generic label */
  }

  const entry = await store.append(msg.remoteDid, {
    agentName: authorName,
    text,
    side: 'peer',
    confidential: msg.confidential,
    time: msg.receivedAt,
  });

  ctx.bus.emit('message.received', {
    peerDid: msg.remoteDid,
    confidential: msg.confidential,
    bytes: msg.body.byteLength,
    at: entry.time,
  });
  return entry;
}

