// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * A transport address identifying a remote peer.
 */
export interface TransportAddress {
  peerId: string;
  multiaddrs?: string[];
}

/**
 * Minimal transport interface for TSP message delivery.
 *
 * All layers above this (CESR codec, crypto engine, relationship manager)
 * import only TspTransport — never Libp2p directly.
 */
export interface TspTransport {
  /** Start the transport (register protocol handlers, etc.) */
  start(): Promise<void>;

  /** Stop the transport (unregister handlers, close streams) */
  stop(): Promise<void>;

  /**
   * Send a raw TSP message (already CESR-encoded) to a remote address.
   */
  send(message: Uint8Array, remoteAddr: TransportAddress): Promise<void>;

  /**
   * Register a handler for incoming TSP messages.
   * Only one handler is active at a time; calling this again replaces the previous one.
   */
  onMessage(handler: (message: Uint8Array, fromAddr: TransportAddress) => void): void;

  /**
   * Check whether the transport has an active connection to a peer.
   * Used for pre-send connectivity checks before attempting dialProtocol.
   */
  isConnected(peerId: string): boolean;

  /**
   * Get the currently known multiaddrs for a connected peer from the transport layer.
   * Returns undefined if the peer is not connected or address info is unavailable.
   */
  getPeerMultiaddrs(peerId: string): string[] | undefined;

  /**
   * Drop the transport's cached connection(s) and peer-store addresses for
   * `peerId`, so the next send builds a FRESH connection instead of reusing a
   * dead one. Best-effort and optional: implementations that cannot do this
   * simply omit it, and callers must tolerate its absence.
   *
   * Used by the request adapters when a request times out with no response — the
   * one failure mode a write cannot detect, because a half-open connection
   * accepts writes silently.
   */
  invalidatePeer?(peerId: string, why?: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Libp2pTransport configuration options (Step 5)
// ---------------------------------------------------------------------------

/**
 * Configuration options for Libp2pTransport.
 *
 * All options are optional; sensible defaults are applied when omitted.
 */
export interface Libp2pTransportOptions {
  /**
   * Maximum allowed message size in bytes, applied to both inbound and outbound frames.
   *
   * Inbound frames exceeding this limit cause the stream to be closed.
   * Outbound messages exceeding this limit are rejected before dialing
   * (throws TransportFrameTooLargeError).
   *
   * Default: 1_048_576 (1 MiB).
   */
  maxMessageBytes?: number;

  /**
   * Timeout in milliseconds for the entire send() operation (dial + write + close).
   *
   * If the operation does not complete within this window, the stream is aborted
   * and a TransportTimeoutError is thrown.
   *
   * Default: 10_000 (10 seconds).
   */
  sendTimeoutMs?: number;

  /**
   * Idle timeout in milliseconds for inbound streams.
   *
   * If no frame is received within this window after the last frame (or stream open),
   * the stream is aborted. This prevents resource exhaustion from peers that open
   * a stream but never send any data.
   *
   * Default: 30_000 (30 seconds).
   */
  idleTimeoutMs?: number;
}

// ---------------------------------------------------------------------------
// Typed error classes (Step 5)
// ---------------------------------------------------------------------------

/**
 * Thrown by Libp2pTransport.send() when the dial + write + close sequence
 * does not complete within sendTimeoutMs.
 */
export class TransportTimeoutError extends Error {
  constructor(operation: string, timeoutMs: number) {
    super(`TSP transport timeout during "${operation}" after ${timeoutMs}ms`);
    this.name = 'TransportTimeoutError';
  }
}

/**
 * Thrown by Libp2pTransport.send() when the message exceeds maxMessageBytes.
 * The check is performed before dialing, so no network connection is made.
 */
export class TransportFrameTooLargeError extends Error {
  constructor(actualBytes: number, maxBytes: number) {
    super(`TSP frame too large: ${actualBytes} bytes exceeds limit of ${maxBytes} bytes`);
    this.name = 'TransportFrameTooLargeError';
  }
}
