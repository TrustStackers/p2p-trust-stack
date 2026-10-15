// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * ChatLog — per-peer, in-memory transcript backing the chat UI.
 *
 * ## Scope (deliberately minimal)
 *
 * Each chat session is a list of text entries held in PROCESS MEMORY only.
 * Nothing is written to SQLite or to any file, so an agent logout (or an agent
 * switch) drops every session — that is the intended product behaviour, not a
 * gap. Durable transcripts, group chat, and VTC group chat are explicitly
 * deferred to a later pass.
 *
 * ## Keying and entry shape
 *
 * A session is keyed by the peer's **DID** — the stable, unique key every chat
 * API already uses (`/api/messages/:remoteVid`, `/api/chat/:remoteVid/log`).
 * Every entry then records the **agent login name** of whichever agent authored
 * it, plus the time and the text, so a session is a list of
 * `{ agentName, time, text }` entries as specified. The name is not used as the
 * map key because a peer's name can be absent (never registered) or repeated
 * across namespaces, whereas the DID is unique per peer.
 *
 * ## Times are unique and monotonic per session
 *
 * `append()` never returns a `time` that is <= the previous entry's time in the
 * same session: a caller-supplied timestamp (e.g. a message `receivedAt`) is
 * bumped to `previous + 1` on collision. That lets the UI derive a stable DOM id
 * (`msg-<side>-<time>`) and de-duplicate a live SSE push against a transcript
 * re-render without a second bookkeeping channel.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A single chat transcript entry. */
export interface ChatLogEntry {
  /** Login name of the agent that authored the entry (local agent or peer). */
  agentName: string;
  /** Epoch milliseconds; unique and strictly increasing within a session. */
  time: number;
  /** The message text that was sent locally, or received from the peer. */
  text: string;
  /** UI role: `'me'` = local operator, `'peer'` = remote agent. */
  side: 'me' | 'peer';
  /** True when the message travelled over the confidential (HPKE) path. */
  confidential?: boolean;
}

/** Shape accepted by `ChatLog.append()` — `time` defaults to `Date.now()`. */
export interface ChatLogAppendInput {
  agentName: string;
  text: string;
  side: 'me' | 'peer';
  confidential?: boolean;
  time?: number;
}

// ---------------------------------------------------------------------------
// ChatLog
// ---------------------------------------------------------------------------

export class ChatLog {
  /**
   * Soft cap on entries retained per session (oldest dropped first). Mirrors the
   * 500-entry cap the web server applies to its inbound `messageInbox`, so a
   * long-lived session cannot grow without bound in a process that is never
   * restarted.
   */
  static readonly MAX_ENTRIES_PER_SESSION = 500;

  /** peerDid -> ordered entries. */
  private readonly sessions = new Map<string, ChatLogEntry[]>();

  /**
   * Record one entry for a peer's session, creating the session when absent
   * (this is what makes a cleared session start a fresh list of entries).
   *
   * The returned entry is the stored entry — callers should echo its `time`
   * (e.g. in an SSE payload) so client-side DOM ids agree with a later
   * transcript re-render.
   */
  append(peerDid: string, input: ChatLogAppendInput): ChatLogEntry {
    const entries = this.sessions.get(peerDid) ?? [];
    if (!this.sessions.has(peerDid)) this.sessions.set(peerDid, entries);

    const previous = entries.length > 0 ? entries[entries.length - 1].time : 0;
    const requested = input.time ?? Date.now();
    const time = requested > previous ? requested : previous + 1;

    const entry: ChatLogEntry = {
      agentName: input.agentName,
      time,
      text: input.text,
      side: input.side,
      ...(input.confidential ? { confidential: true } : {}),
    };
    entries.push(entry);

    if (entries.length > ChatLog.MAX_ENTRIES_PER_SESSION) {
      entries.splice(0, entries.length - ChatLog.MAX_ENTRIES_PER_SESSION);
    }
    return entry;
  }

  /** Return a copy of a peer's session (never the live array). */
  list(peerDid: string): ChatLogEntry[] {
    return (this.sessions.get(peerDid) ?? []).map(e => ({ ...e }));
  }

  /** Number of entries retained for a peer (0 when there is no session). */
  size(peerDid: string): number {
    return this.sessions.get(peerDid)?.length ?? 0;
  }

  /**
   * Drop ONE peer's session and return how many entries were discarded.
   * Other peers' sessions are untouched — the chat UI's "Clear History" button
   * is scoped to the conversation currently on screen.
   */
  clear(peerDid: string): number {
    const entries = this.sessions.get(peerDid);
    if (!entries) return 0;
    this.sessions.delete(peerDid);
    return entries.length;
  }

  /** Drop every session (agent logout / agent switch). */
  clearAll(): void {
    this.sessions.clear();
  }

  /** Number of sessions currently retained (diagnostics / tests). */
  sessionCount(): number {
    return this.sessions.size;
  }
}
