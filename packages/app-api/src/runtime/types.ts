/**
 * Agent types — shared type definitions for the Agent module.
 *
 * These types are consumed by the Agent API layer and the TUI.
 * They should NOT import from other agent-internal modules.
 */

import type { DidMethod } from '@p2p-trust-stack/core/did/did-method.js';
import type { TspTransport } from '@p2p-trust-stack/core/transport/types.js';
import type { KeyStore } from '@p2p-trust-stack/core/keystore/types.js';

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
   * Network/group (namespace) this agent is joining, e.g. 'p2pts'. Sent to the
   * bootstrap/relay server as the peer's `net` and used to build the
   * bootstrap-facing name `vta:<net>:<name>`. Defaults to 'p2pts'; the first-run
   * setup wizard will set this from the chosen VTN.
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