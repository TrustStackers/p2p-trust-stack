// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * TspClientModule — agent-side TSP protocol client.
 *
 * Handles sending protocol messages over TSP_GEN and awaiting responses
 * for request/response protocols. Manages a correlation ID registry for
 * matching inbound responses to pending requests.
 *
 * ## Delivery model
 *
 * Outbound messages MUST go through `enqueue()` which provides durable
 * outbox persistence, truthful SendReceipt, and automatic retry on
 * reconnect. See docs/tx-coordinator-usage.md for the full usage rules.
 *
 * `request()` remains available for simple request/response patterns that do
 * not require multi-participant coordination. For multi-step, multi-peer
 * operations, use the TransactionManager (src/tx/manager.ts) instead.
 */

import { randomUUID } from 'node:crypto';
import {
  type ProtocolMessage,
  encodeProtocolMessage,
  decodeProtocolMessage,
} from '@p2p-trust-stack/core/tsp-handlers/types.js';
import type { DurableOutbox } from '@p2p-trust-stack/core/tx/delivery.js';
import type { SendReceipt } from '@p2p-trust-stack/core/tx/types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A pending request that is awaiting a response. */
interface PendingRequest {
  resolve: (response: ProtocolMessage) => void;
  reject: (err: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
}

/** Callback signature for the send function. */
export type TspSendFn = (remoteDid: string, body: Uint8Array) => Promise<void>;

// ---------------------------------------------------------------------------
// TspClientModule
// ---------------------------------------------------------------------------

export class TspClientModule {
  private sendFn: TspSendFn | null = null;
  private readonly pending = new Map<string, PendingRequest>();
  private defaultTimeoutMs = 30_000;
  private outbox: DurableOutbox | null = null;
  private timeoutHook: ((remoteDid: string) => void) | null = null;

  init(sendFn: TspSendFn): void {
    this.sendFn = sendFn;
  }

  /**
   * Install a callback invoked when a request times out with NO response.
   *
   * `remoteDid` is the peer that failed to answer. The expected use is
   * connection invalidation: a half-open / black-holed connection accepts the
   * write silently (so `sendFn` resolves), and only the missing response reveals
   * that the frame never arrived. Without dropping that cached connection the
   * next request reuses it and times out identically — the field log's
   * `tx_prepare` answered, then `tx_commit`, `tx_query` and a peer `tx_prepare`
   * all timing out against the same peer in the same session.
   *
   * The hook is best-effort: it is called synchronously and its failures are its
   * own concern (a rejection cannot mask the timeout the caller is about to see).
   */
  setRequestTimeoutHook(hook: ((remoteDid: string) => void) | null): void {
    this.timeoutHook = hook;
  }

  /**
   * Set the durable outbox for reliable delivery.
   * Once set, `enqueue()` is available.
   */
  setOutbox(outbox: DurableOutbox): void {
    this.outbox = outbox;
  }

  isInitialized(): boolean {
    return this.sendFn !== null;
  }

  // -------------------------------------------------------------------------
  // Outbound — durable enqueue (reliable delivery)
  // -------------------------------------------------------------------------

  /**
   * Enqueue a message for reliable delivery via the durable outbox.
   *
   * The message is persisted to the tx-coordinator.db BEFORE attempting
   * delivery. Returns a truthful SendReceipt indicating whether the next
   * hop accepted the bytes. Undelivered messages are automatically retried
   * on reconnect via the outbox's drain() mechanism.
   *
   * Requires `setOutbox()` to have been called first.
   */
  async enqueue(
    remoteDid: string,
    protocol: string,
    payload: unknown,
  ): Promise<SendReceipt> {
    if (!this.outbox) {
      throw new Error(
        'TspClientModule.enqueue: outbox not set. Call setOutbox() first, ' +
        'or use the deprecated send() for fire-and-forget.',
      );
    }

    const msg: ProtocolMessage = { protocol, payload };
    const body = encodeProtocolMessage(msg);
    return this.outbox.enqueue(remoteDid, body);
  }

  // -------------------------------------------------------------------------
  // Outbound — request/response
  // -------------------------------------------------------------------------

  async request(
    remoteDid: string,
    protocol: string,
    payload: unknown,
    timeoutMs?: number,
  ): Promise<ProtocolMessage> {
    if (!this.sendFn) {
      throw new Error('TspClientModule.request: not initialized. Call init() first.');
    }

    const correlationId = randomUUID();
    const msg: ProtocolMessage = { protocol, correlationId, payload };
    const body = encodeProtocolMessage(msg);

    const timeout = timeoutMs ?? this.defaultTimeoutMs;

    const promise = new Promise<ProtocolMessage>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(correlationId);
        // No response within the window: the peer's cached connection may be a
        // silent black hole (see setRequestTimeoutHook). Let the owner drop it so
        // the retry re-dials instead of failing the same way.
        try {
          this.timeoutHook?.(remoteDid);
        } catch {
          /* the hook must never mask the timeout itself */
        }
        reject(new Error(`TSP request '${protocol}' timed out after ${timeout}ms`));
      }, timeout);

      this.pending.set(correlationId, { resolve, reject, timeout: timer });
    });

    try {
      await this.sendFn(remoteDid, body);
    } catch (err) {
      const entry = this.pending.get(correlationId);
      if (entry) {
        clearTimeout(entry.timeout);
        this.pending.delete(correlationId);
      }
      throw err;
    }

    return promise;
  }

  // -------------------------------------------------------------------------
  // Inbound — dispatch
  // -------------------------------------------------------------------------

  async handleIncoming(
    body: Uint8Array,
    handler?: (msg: ProtocolMessage) => Promise<ProtocolMessage | null>,
  ): Promise<ProtocolMessage | null> {
    let msg: ProtocolMessage;
    try {
      msg = decodeProtocolMessage(body);
    } catch {
      return null; // Not a protocol message — plain chat
    }

    // Response to a pending request?
    if (msg.correlationId && this.pending.has(msg.correlationId)) {
      const entry = this.pending.get(msg.correlationId)!;
      clearTimeout(entry.timeout);
      this.pending.delete(msg.correlationId);
      entry.resolve(msg);
      // Return a sentinel object (not null) so TspBridge.handleInbound()
      // knows this was handled and doesn't fall through to chat dispatch.
      return { protocol: '__handled__', payload: null };
    }

    // Incoming request — delegate to handler if provided
    if (handler) {
      return handler(msg);
    }

    return null;
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  destroy(): void {
    for (const [, entry] of this.pending) {
      clearTimeout(entry.timeout);
      entry.reject(new Error('TSP client shutting down'));
    }
    this.pending.clear();
    this.sendFn = null;
  }
}