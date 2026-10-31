// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Connectivity DTOs.
 *
 * Same rule as `dto/identity.ts`: explicit fields, no index signature. Service results that are already
 * purpose-built (not table rows) are aliased with a note rather than re-declared.
 */
import type { ConnectivityStatus } from '@p2p-trust-stack/core/transport/relay-health.js';
import type { ConnectivityFailureKind } from '@p2p-trust-stack/core/transport/relay-health.js';
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

/**
 * A VTN an agent could join, as advertised by a utility server in the bootstrap
 * peer directory.
 *
 * One entry per VTN, not per server: several utility servers can serve the same
 * network, and the user is choosing a NETWORK. `vtnKey` is what the agent matches
 * on and registers as its own `net`.
 */
export interface VtnOptionDto {
  /** The VTN key (namespace) — e.g. 'p2pts'. Agents match on this. */
  vtnKey: string;
  /** The VTN's human-readable name (e.g. 'Trust Stackers'), when published. */
  vtnName?: string;
  /** The utility server's peer ID — what the agent dials. */
  peerId: string;
  /** The server's real DID — required for the strict 4-item OOBI. */
  did: string;
  /** The server's CESR-encoded Slot-A VID (peer ID as a fallback). */
  vid: string;
  /** The server's advertised dial addresses. */
  multiaddrs: string[];
  /**
   * The per-peer relay address the bootstrap built for this server
   * (`<relay-prefix>/p2p/<peerId>`), when the bootstrap serves a relay.
   *
   * This is the ONLY address that can work when the agent is on a different
   * network from the server, and it is NOT part of `multiaddrs` — the server's
   * own `buildDialableMultiaddrs()` filters `/p2p-circuit` out of what it
   * advertises. Dropping it here is what made a first cross-network join
   * impossible: the join OOBI carried LAN/NAT addresses only.
   */
  relayAddr?: string;
  /**
   * The bootstrap reports a live circuit-relay reservation for this server, i.e.
   * a relayed HOP aimed at it will be accepted. Authoritative, unlike
   * `reachable` (see `reachableScope`).
   */
  reachableViaRelay?: boolean;
  /**
   * Reachability scope the bootstrap derived from the server's addresses
   * (`wan|dns|relay|lan|loopback|unknown`).
   *
   * Read this instead of `reachable` when the distinction matters: the bootstrap
   * records the address it OBSERVED the server connect from, which for a NAT'd
   * server is a mapped public IP:ephemeral-port that nothing listens on — yet it
   * classifies as `wan`, so `reachable` is true while only the relay works.
   */
  reachableScope?: string;
  /** The bootstrap reports the server as currently reachable. */
  reachable: boolean;
  /** The bootstrap reports a live connection to the server. */
  connected: boolean;
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

export type { ConnectivityStatus, ConnectivityFailureKind, DiscoveredPeer, NetworkProfile };

/**
 * The bootstrap client config a startup screen pre-fills its boxes with.
 *
 * A CLIENT view: host + peer ID, no seed — only the bootstrap server holds one.
 */
export interface BootstrapConfigView {
  host: string;
  peerId: string;
  tcpPort: number;
  wsPort: number;
  /** Where the values came from — the persisted override, the `.env`, or nothing. */
  source: 'config' | 'env' | 'none';
}

/**
 * The bootstrap client config an agent dials — host + peer ID, no seed.
 *
 * ALIAS: the core loader's own type, so a caller that needs to name it (e.g. to
 * build an `AgentConfig`) does not have to reach into the core package.
 */
export type { BootstrapClientEnv } from '@p2p-trust-stack/core/config/bootstrap-env.js';
