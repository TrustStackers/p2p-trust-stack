// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Unit tests for the relay-health / connectivity-status module.
 *
 * These cover the PURE decision logic that decides when a relayed connection
 * must be refreshed and what the agent reports about its connectivity — the
 * part that a relay-session expiry gets wrong when it is not modelled at all.
 *
 * No libp2p node is created here: the readers are exercised through duck-typed
 * fakes, and the snapshot/decision helpers are pure functions.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/transport/relay-health.test.ts
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  RELAY_BYTE_FLOOR,
  RELAY_REFRESH_LEAD_MS,
  deriveConnectivityStatus,
  describeConnectivityFailure,
  describeRelayHealth,
  expiringRelayConnections,
  hasRelayReservation,
  isRelayConnection,
  needsRefresh,
  readConnectionGrant,
  readRelayHealth,
  relayHealthLabel,
  type RelayHealthSnapshot,
} from '../../src/transport/relay-health.js';

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

/** A relayed connection with a LIVE grant, mirroring libp2p's getters. */
function relayedConn(opts: {
  peerId?: string;
  seconds?: number;
  bytes?: bigint;
  direction?: 'inbound' | 'outbound';
}): unknown {
  const state = { seconds: opts.seconds, bytes: opts.bytes };
  return {
    remotePeer: { toString: () => opts.peerId ?? '12D3KooWPEER' },
    remoteAddr: { toString: () => '/dns/relay/tcp/4001/p2p/12D3KooWRELAY/p2p-circuit' },
    direction: opts.direction ?? 'outbound',
    limits: {
      get seconds() {
        return state.seconds;
      },
      get bytes() {
        return state.bytes;
      },
    },
  };
}

/** A direct (non-relayed) connection. */
function directConn(peerId = '12D3KooWDIRECT'): unknown {
  return {
    remotePeer: { toString: () => peerId },
    remoteAddr: { toString: () => '/ip4/192.168.1.5/tcp/24001' },
    direction: 'outbound',
  };
}

/** A node fake whose circuit-relay transport exposes a reservation store. */
function nodeWith(opts: { connections?: unknown[]; reservedPeers?: string[] }): unknown {
  const reserved = new Set(opts.reservedPeers ?? []);
  return {
    getConnections: () => opts.connections ?? [],
    components: {
      transportManager: {
        getTransports: () => [
          {
            reservationStore: {
              hasReservation: (peerId: { toString(): string }) => reserved.has(peerId.toString()),
            },
          },
        ],
      },
    },
  };
}

/** Build a snapshot from grant values (peer IDs/addresses are not under test). */
function snapshot(relayed: Array<{ seconds?: number; bytes?: bigint }>): RelayHealthSnapshot {
  const infos = relayed.map((r) => ({
    peerId: '12D3KooWPEER',
    direction: 'outbound' as const,
    remoteAddr: '/dns/relay/tcp/4001/p2p/12D3KooWRELAY/p2p-circuit',
    secondsRemaining: r.seconds,
    bytesRemaining: r.bytes,
  }));
  const expiries = infos
    .map((i) => i.secondsRemaining)
    .filter((s): s is number => s != null)
    .map((s) => s * 1000);
  return {
    relayed: infos,
    reservations: [],
    hasRelayedConnection: infos.length > 0,
    hasReservation: false,
    soonestExpiryMs: expiries.length > 0 ? Math.min(...expiries) : undefined,
  };
}

// ---------------------------------------------------------------------------
// Connection classification + grant reading
// ---------------------------------------------------------------------------

describe('relay-health: connection classification', () => {
  it('detects a relayed connection from its /p2p-circuit multiaddr', () => {
    assert.equal(isRelayConnection(relayedConn({ seconds: 600 })), true);
  });

  it('detects a relayed connection from a limits object alone', () => {
    const conn = { remoteAddr: { toString: () => '/ip4/1.2.3.4/tcp/1' }, limits: { seconds: 5 } };
    assert.equal(isRelayConnection(conn), true);
  });

  it('treats a plain direct connection as non-relayed', () => {
    assert.equal(isRelayConnection(directConn()), false);
  });

  it('never throws on malformed input', () => {
    assert.equal(isRelayConnection(null), false);
    assert.equal(isRelayConnection(undefined), false);
    assert.equal(isRelayConnection('nope'), false);
    assert.equal(isRelayConnection(42), false);
  });

  it('reads the LIVE grant from limits getters', () => {
    const grant = readConnectionGrant(relayedConn({ seconds: 42, bytes: 1024n }));
    assert.equal(grant.secondsRemaining, 42);
    assert.equal(grant.bytesRemaining, 1024n);
  });

  it('drops nonsense grant values instead of propagating them', () => {
    assert.deepEqual(readConnectionGrant({ limits: {} }), {});
    assert.deepEqual(readConnectionGrant({ limits: { seconds: Number.NaN } }), {});
    assert.deepEqual(readConnectionGrant({ limits: { seconds: -1 } }), {});
    assert.deepEqual(readConnectionGrant({ limits: { bytes: '1024' } }), {});
    assert.deepEqual(readConnectionGrant(null), {});
  });
});

// ---------------------------------------------------------------------------
// Refresh decision
// ---------------------------------------------------------------------------

describe('relay-health: needsRefresh', () => {
  it('is false when nothing is relayed (no grants to expire)', () => {
    assert.equal(needsRefresh(snapshot([])), false);
  });

  it('is false while the grant is comfortably in the future', () => {
    assert.equal(needsRefresh(snapshot([{ seconds: 3600 }])), false);
  });

  it('is true when the grant is inside the lead time', () => {
    assert.equal(needsRefresh(snapshot([{ seconds: 30 }])), true);
  });

  it('is true exactly at the lead-time boundary', () => {
    assert.equal(needsRefresh(snapshot([{ seconds: RELAY_REFRESH_LEAD_MS / 1000 }])), true);
  });

  it('honours a custom lead time', () => {
    assert.equal(needsRefresh(snapshot([{ seconds: 120 }]), { leadMs: 300_000 }), true);
    assert.equal(needsRefresh(snapshot([{ seconds: 120 }]), { leadMs: 60_000 }), false);
  });

  it('is true when the byte grant is at or below the floor', () => {
    assert.equal(needsRefresh(snapshot([{ bytes: RELAY_BYTE_FLOOR }])), true);
    assert.equal(needsRefresh(snapshot([{ bytes: RELAY_BYTE_FLOOR + 1n }])), false);
  });

  it('ignores unlimited grants (undefined seconds/bytes)', () => {
    assert.equal(needsRefresh(snapshot([{}])), false);
  });

  it('triggers on any one of several relayed connections', () => {
    assert.equal(needsRefresh(snapshot([{ seconds: 3600 }, { seconds: 10 }])), true);
  });

  it('returns the expiring subset, not just a boolean', () => {
    const snap = snapshot([{ seconds: 3600 }, { seconds: 10 }]);
    const expiring = expiringRelayConnections(snap);
    assert.equal(expiring.length, 1);
    assert.equal(expiring[0].secondsRemaining, 10);
  });
});


// ---------------------------------------------------------------------------
// Reading a node
// ---------------------------------------------------------------------------

describe('relay-health: readRelayHealth', () => {
  it('splits relayed from direct connections and reports the soonest expiry', () => {
    const node = nodeWith({
      connections: [directConn(), relayedConn({ seconds: 900 }), relayedConn({ seconds: 120 })],
    });
    const health = readRelayHealth(node);
    assert.equal(health.relayed.length, 2);
    assert.equal(health.hasRelayedConnection, true);
    assert.equal(health.soonestExpiryMs, 120_000);
  });

  it('reports no relayed connection for a direct-only node', () => {
    const health = readRelayHealth(nodeWith({ connections: [directConn()] }));
    assert.equal(health.hasRelayedConnection, false);
    assert.equal(health.soonestExpiryMs, undefined);
  });

  it('reads reservation state from the circuit-relay transport', () => {
    const node = nodeWith({ reservedPeers: ['12D3KooWRELAY'] });
    const health = readRelayHealth(node, '12D3KooWRELAY');
    assert.equal(health.hasReservation, true);
    assert.deepEqual(health.reservations, ['12D3KooWRELAY']);
  });

  it('treats an unknown relay peer as "no reservation held"', () => {
    const node = nodeWith({ reservedPeers: ['12D3KooWOTHER'] });
    assert.equal(hasRelayReservation(node, '12D3KooWRELAY'), false);
    assert.equal(hasRelayReservation(node, undefined), false);
  });

  it('degrades to an empty snapshot instead of throwing', () => {
    assert.deepEqual(readRelayHealth(null), {
      relayed: [],
      reservations: [],
      hasRelayedConnection: false,
      hasReservation: false,
    });
    // A node mid-restart (connection manager unavailable) must not break a
    // status call.
    const health = readRelayHealth({
      getConnections: () => {
        throw new Error('stopped');
      },
    });
    assert.equal(health.hasRelayedConnection, false);
  });
});


// ---------------------------------------------------------------------------
// Status derivation
// ---------------------------------------------------------------------------

describe('relay-health: deriveConnectivityStatus', () => {
  const healthyRelay = snapshot([{ seconds: 3600 }]);

  it('reports bootstrap-unreachable first, and marks it degraded', () => {
    const status = deriveConnectivityStatus({
      bootstrapConnected: false,
      utilityServerConnected: false,
      relay: snapshot([]),
      hasRelayReservation: false,
    });
    assert.equal(status.layer, 'bootstrap-unreachable');
    assert.equal(status.degraded, true);
  });

  it('reports reconnecting while a recovery is in flight', () => {
    const status = deriveConnectivityStatus({
      bootstrapConnected: true,
      utilityServerConnected: true,
      relay: healthyRelay,
      hasRelayReservation: true,
      reconnecting: true,
    });
    assert.equal(status.layer, 'reconnecting');
    assert.equal(status.degraded, true);
  });

  it('reports unreachable when the bridge is down, with the failure count', () => {
    const status = deriveConnectivityStatus({
      bootstrapConnected: true,
      utilityServerConnected: false,
      relay: healthyRelay,
      hasRelayReservation: true,
      consecutiveFailures: 3,
      lastError: 'all addresses failed',
    });
    assert.equal(status.layer, 'unreachable');
    assert.equal(status.degraded, true);
    assert.match(status.message, /3 failed attempts/);
    assert.match(status.message, /all addresses failed/);
  });

  it('reports relay-expiring while still connected — NOT degraded', () => {
    const status = deriveConnectivityStatus({
      bootstrapConnected: true,
      utilityServerConnected: true,
      relay: snapshot([{ seconds: 20 }]),
      hasRelayReservation: true,
    });
    assert.equal(status.layer, 'relay-expiring');
    assert.equal(status.degraded, false);
    assert.match(status.message, /refresh/i);
  });

  it('reports connected when everything is healthy', () => {
    const status = deriveConnectivityStatus({
      bootstrapConnected: true,
      utilityServerConnected: true,
      relay: healthyRelay,
      hasRelayReservation: true,
    });
    assert.equal(status.layer, 'connected');
    assert.equal(status.degraded, false);
  });
});


// ---------------------------------------------------------------------------
// Operator/user-facing copy
// ---------------------------------------------------------------------------

describe('relay-health: messages', () => {
  it('describes each relay state in terms of the consequence', () => {
    assert.match(describeRelayHealth(snapshot([])), /only reachable directly/i);
    assert.match(
      describeRelayHealth({ ...snapshot([]), hasReservation: true, reservations: ['r'] }),
      /reservation held/i,
    );
    assert.match(describeRelayHealth(snapshot([{ seconds: 75 }])), /expires in ~75s/);
    assert.match(describeRelayHealth(snapshot([{}])), /no duration grant/i);
  });

  it('labels relay state for status lines', () => {
    assert.equal(relayHealthLabel(snapshot([])), 'direct');
    assert.equal(relayHealthLabel(snapshot([{ seconds: 3600 }])), 'relay');
    assert.equal(relayHealthLabel(snapshot([{ seconds: 5 }])), 'relay-expiring');
  });

  it('names the failed layer and the follow-up in failure copy', () => {
    const bootstrapDown = deriveConnectivityStatus({
      bootstrapConnected: false,
      utilityServerConnected: false,
      relay: snapshot([]),
      hasRelayReservation: false,
    });
    assert.match(
      describeConnectivityFailure(bootstrapDown, 'register this name'),
      /not connected to the relay server/i,
    );

    const down = deriveConnectivityStatus({
      bootstrapConnected: true,
      utilityServerConnected: false,
      relay: snapshot([]),
      hasRelayReservation: false,
      lastError: 'dial timeout',
    });
    const copy = describeConnectivityFailure(down, 'register this name');
    assert.match(copy, /register this name/);
    assert.match(copy, /kept locally/);
    assert.match(copy, /dial timeout/);
  });
});

