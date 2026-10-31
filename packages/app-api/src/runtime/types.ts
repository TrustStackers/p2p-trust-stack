// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Agent types — shared type definitions for the Agent module.
 *
 * These types are consumed by the Agent API layer and the TUI.
 * They should NOT import from other agent-internal modules.
 */

import type { DidMethod } from '@p2p-trust-stack/core/did/did-method.js';
import type { TspTransport } from '@p2p-trust-stack/core/transport/types.js';
import type { KeyStore } from '@p2p-trust-stack/core/keystore/types.js';
import type { BootstrapClientEnv } from '@p2p-trust-stack/core/config/bootstrap-env.js';

// ---------------------------------------------------------------------------
// AgentConfig
// ---------------------------------------------------------------------------

/**
 * Configuration for creating or unlocking an Agent.
 */
export interface AgentConfig {
  name: string;
  passphrase: string;
  port?: number;
  didMethod?: DidMethod;
  bootstrapUrl?: string;
  /**
   * The bootstrap server this agent should dial — host + peer ID.
   *
   * The agent is a CLIENT: it holds no seed, only the address and the peer ID to
   * expect. Supplied by the composition root (the startup screen's bootstrap
   * boxes, persisted to `P2PTS_HOME/config.yaml`). When absent, the runtime falls
   * back to this component's `.env`; when neither yields a usable pair the agent
   * runs in LAN-only mode rather than failing to start.
   */
  bootstrapEnv?: BootstrapClientEnv;
  /**
   * The VTN key (namespace) this agent is joining, e.g. 'p2pts'.
   *
   * Sent to the bootstrap as the peer's `net`, so the agent identifies itself by
   * the network it is ACTUALLY using and the bootstrap's peer list shows it.
   * There is deliberately NO default: an agent that has not chosen a VTN yet
   * sends no `net` at all, rather than claiming some other network's key. Set
   * from the login screen's VTN picker.
   */
  net?: string;
  transport?: TspTransport;
  keystore?: KeyStore;
}

// ---------------------------------------------------------------------------
// AgentMeta — persisted in the agents table
// ---------------------------------------------------------------------------

/**
 * Non-secret metadata persisted in the agents table.
 * Readable without unlocking the keystore.
 */
export interface AgentMeta {
  name: string;
  vid: string;
  did: string;
  createdAt: number;
  dataDir: string;
  method: string;
  /** Bootstrap server URL this agent registers with. */
  bootstrapUrl?: string;
}

// ---------------------------------------------------------------------------
// AgentSummary — public listing type
// ---------------------------------------------------------------------------

export type AgentSummary = AgentMeta;

// ---------------------------------------------------------------------------
// IncomingMessage
// ---------------------------------------------------------------------------

export interface IncomingMessage {
  remoteDid: string;
  body: Uint8Array;
  confidential: boolean;
  receivedAt: number;
}

// ---------------------------------------------------------------------------
// ConnectionEvent
// ---------------------------------------------------------------------------

export interface ConnectionEvent {
  peerId: string;
  kind: 'open' | 'close';
  direction: 'inbound' | 'outbound';
  method: string;
  remoteAddr?: string;
  timestamp: number;
}

export type ConnectionEventDirection = 'inbound' | 'outbound';
export type ConnectionEventKind = 'open' | 'close';