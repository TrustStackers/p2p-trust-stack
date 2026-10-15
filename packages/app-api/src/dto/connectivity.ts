// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Connectivity DTOs.
 *
 * Same rule as `dto/identity.ts`: explicit fields, no index signature. Service results that are already
 * purpose-built (not table rows) are aliased with a note rather than re-declared.
 */
import type { ConnectivityStatus } from '@p2p-trust-stack/core/transport/relay-health.js';
import type { DiscoveredPeer } from '@p2p-trust-stack/core/transport/bootstrap-client.js';
import type { NetworkProfile } from '@p2p-trust-stack/core/platform/network-detect.js';

/** Liveness probe. Never requires an active agent. */
export interface HealthDto {
  status: 'ok';
  service: string;
  /** ISO timestamp. */
  time: string;
  agent: { active: boolean; name?: string; vid?: string };
}

/**
 * Readiness probe.
 *
 * A not-ready answer is a **normal** result, not an error: `{ ready: false, reason }`. The adapter maps it
 * to HTTP 503 (that is what a readiness probe is for), but the domain call itself succeeds.
 */
export interface ReadyDto {
  ready: boolean;
  reason?: string;
  agent?: string;
  relationshipCount?: number;
  chatReadyCount?: number;
}

/**
 * The live, layer-aware connectivity view.
 *
 * ALIAS: the runtime's purpose-built `ConnectivityStatus` (derived from observable inputs, not read from a
 * table). Its `relay` field is a nested snapshot type; flattening is not worth the drift risk today.
 */
export type ConnectivityStatusDto = ConnectivityStatus;

/**
 * A peer discovered through the bootstrap server.
 *
 * ALIAS: already a clean discovery result from `src/transport/bootstrap-client.ts`.
 */
export type DiscoveredPeerDto = DiscoveredPeer;

/** Network profile of the running node. */
export interface NetworkProfileDto {
  wanIp?: string;
  lanIps: string[];
  listenPort: number;
  libp2pAddrs: string[];
  capturedAt: number;
}

/** Bootstrap connectivity, with the convenience flags the UI gates on. */
export interface BootstrapStatusDto {
  /** The bootstrap CONTROL connection only — not "everything is fine". Use `connectivity` for that. */
  connected: boolean;
  relayAddr?: string;
  discoveredPeers: DiscoveredPeerDto[];
  connectivity?: ConnectivityStatusDto;
  layer?: string;
  bootstrapConnected: boolean;
  utilityServerConnected?: boolean;
  relayExpiring: boolean;
  degraded?: boolean;
  message?: string;
}

/** Result of forcing a bootstrap peer refresh. */
export interface BootstrapRefreshDto {
  peers: DiscoveredPeerDto[];
  count: number;
}

/** Utility-server link status. */
export interface UtilityServerStatusDto {
  connected: boolean;
  /** The server's DID — the identity the relationship is keyed by (H12). */
  did: string | null;
  /** @deprecated use `did` — the value is a DID, not a CESR VID. Kept for wire compatibility. */
  vid: string | null;
}

/** Result of pushing this identity's public state to the utility server. */
export interface PushIdentityDto {
  ok: boolean;
  /** True when the push is queued on the durable outbox and not yet acknowledged. */
  pending?: boolean;
  /** Why the push was not acknowledged. `null` when the runtime has no error to report. */
  error?: string | null;
}

/** This agent's OOBI, for a peer to connect to. */
export interface OobiDto {
  oobi: string;
}

/**
 * A libp2p connection event, as delivered by the runtime's `onConnectionEvent` callback.
 *
 * `kind` distinguishes open from close; the event *name* on the bus does the same, so subscribers can use
 * either.
 */
export interface ConnectionEventDto {
  peerId: string;
  kind: 'open' | 'close';
  direction: 'inbound' | 'outbound';
  method: string;
  remoteAddr?: string;
  /** Unix ms. */
  timestamp: number;
}

export type { ConnectivityStatus, DiscoveredPeer, NetworkProfile };
