/**
 * Personhood-ack window view tests (CeremonyAckView).
 *
 * Guards the SERVER-OWNED 60s mutual-ack window that BOTH agents' displays
 * render: the deadline is derived from `relationships.created_at`, so the two
 * peers count down to the same instant, and the view must be renderable
 * BEFORE either user presses (at which point no `vrc_ceremonies` row exists).
 *
 * Covers:
 *   - Deadline math (unix SECONDS in, epoch ms out) + the env override
 *   - The rendered states: window open / awaiting peer / peer pressed first /
 *     mutual (creating credentials) / expired (cancelled)
 *   - Eligibility: only established bidirectional human relationships have a
 *     window (organizations, verified rows, pending handshakes never do)
 *   - Agreement with `isCeremonyStale`, which remains the authoritative check
 *     that actually tears the connection attempt down
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/relationship/ceremony-ack-view.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCeremonyAckView,
  getCeremonyAckDeadlineMs,
  getCeremonyAckTimeoutMs,
  isCeremonyStale,
  VRC_CEREMONY_ACK_TIMEOUT_MS,
} from '../../src/relationship/ceremony.js';
import type { RelationshipRecord } from '../../src/relationship/types.js';
import type { VrcCeremonySession } from '../../src/tx/vrc-ceremony-store.js';

const NOW_MS = 1_700_000_000_000;

/** A bidirectional established human relationship that is `ageMs` old. */
function record(over: Partial<RelationshipRecord> = {}, ageMs = 0): RelationshipRecord {
  const createdAt = Math.floor((NOW_MS - ageMs) / 1000);
  return {
    localDid: 'did:peer:4:zLocal',
    remoteDid: 'did:peer:4:zRemote',
    direction: 'bidirectional',
    status: 'established',
    createdAt,
    updatedAt: createdAt,
    ...over,
  };
}

/** A mirror ceremony session row (created lazily on the FIRST press). */
function session(over: Partial<VrcCeremonySession> = {}): VrcCeremonySession {
  return {
    sessionId: 'session-1',
    localDid: 'did:peer:4:zLocal',
    remoteDid: 'did:peer:4:zRemote',
    phase: 'personhood',
    localMinted: false,
    sentToPeer: false,
    sentToServer: false,
    peerVrcReceived: false,
    localAcked: false,
    remoteAcked: false,
    currentStep: '',
    failedStep: null,
    attempt: 0,
    nextAttemptAt: null,
    lastError: null,
    createdAt: NOW_MS,
    updatedAt: NOW_MS,
    ...over,
  };
}

// ---------------------------------------------------------------------------
// The window exists before anybody presses (the regression this change fixes)
// ---------------------------------------------------------------------------

test('ack view: window is open and countable BEFORE either side presses', () => {
  const rec = record({}, 2_000); // OOBI pasted + Connect pressed 2s ago
  const view = buildCeremonyAckView(rec, null, NOW_MS);

  assert.equal(view.timeoutMs, VRC_CEREMONY_ACK_TIMEOUT_MS);
  assert.equal(view.deadlineMs, getCeremonyAckDeadlineMs(rec));
  // Exact seconds -> ms conversion from the relationship record.
  assert.equal(view.deadlineMs, rec.createdAt * 1000 + VRC_CEREMONY_ACK_TIMEOUT_MS);
  assert.equal(view.remainingMs, VRC_CEREMONY_ACK_TIMEOUT_MS - 2_000);
  assert.equal(view.localAcked, false);
  assert.equal(view.remoteAcked, false);
  assert.equal(view.mutual, false);
  assert.equal(view.awaitingPeer, false);
  assert.equal(view.active, true, 'countdown must run with no press on either side');
  assert.equal(view.expired, false);
});

// ---------------------------------------------------------------------------
// The states each display renders
// ---------------------------------------------------------------------------

test('ack view: local press hides the button and keeps counting down for the peer', () => {
  const rec = record({}, 5_000);
  const view = buildCeremonyAckView(rec, session({ localAcked: true }), NOW_MS);
  assert.equal(view.active, true);
  assert.equal(view.mutual, false);
  assert.equal(view.awaitingPeer, true, 'the "waiting for the other user" state');
  assert.equal(view.remainingMs, VRC_CEREMONY_ACK_TIMEOUT_MS - 5_000);
});

test('ack view: peer pressed first leaves the button up for the local user', () => {
  const rec = record({}, 3_000);
  const view = buildCeremonyAckView(rec, session({ remoteAcked: true }), NOW_MS);
  assert.equal(view.remoteAcked, true);
  assert.equal(view.localAcked, false);
  assert.equal(view.mutual, false);
  assert.equal(view.awaitingPeer, false, 'the local user still has to press');
  assert.equal(view.active, true, 'button + countdown stay visible for the local user');
});

test('ack view: mutual ack leaves the gate — countdown gone, ceremony proceeding', () => {
  const rec = record({}, 10_000);
  const phases = ['personhood', 'minting', 'sharing'] as const;
  for (const phase of phases) {
    const view = buildCeremonyAckView(
      rec,
      session({ localAcked: true, remoteAcked: true, phase }),
      NOW_MS,
    );
    assert.equal(view.mutual, true);
    assert.equal(view.active, false, 'no countdown while phase=' + phase);
    assert.equal(view.expired, false, 'a progressing ceremony is never cancelled');
  }
});

test('ack view: mutual ack past the deadline is NOT expired (progressing, not cancellable)', () => {
  const rec = record({}, VRC_CEREMONY_ACK_TIMEOUT_MS + 30_000);
  const view = buildCeremonyAckView(
    rec,
    session({ localAcked: true, remoteAcked: true, phase: 'minting' }),
    NOW_MS,
  );
  assert.equal(view.remainingMs, 0);
  assert.equal(view.active, false);
  assert.equal(view.expired, false, 'mutual ack protects the session from the sweep');
});

test('ack view: window passed at the gate reports the cancelled state', () => {
  const rec = record({}, VRC_CEREMONY_ACK_TIMEOUT_MS + 1_000);

  // Nobody pressed: no saga row at all.
  const none = buildCeremonyAckView(rec, null, NOW_MS);
  assert.equal(none.remainingMs, 0);
  assert.equal(none.active, false);
  assert.equal(none.expired, true);

  // Only ONE side pressed — a one-sided press does not save the ceremony.
  const oneSided = buildCeremonyAckView(rec, session({ localAcked: true }), NOW_MS);
  assert.equal(oneSided.expired, true);
  assert.equal(oneSided.active, false);
});

// ---------------------------------------------------------------------------
// Eligibility — which relationships have a window at all
// ---------------------------------------------------------------------------

test('ack view: only established bidirectional human relationships have a window', () => {
  const old = VRC_CEREMONY_ACK_TIMEOUT_MS + 1_000;

  // Pending handshake (no RFA yet) — the ceremony has not started.
  const ineligible: Array<Partial<RelationshipRecord>> = [
    { direction: 'outbound', status: 'pending' },
    { direction: 'inbound', status: 'established' },
  ];
  for (const over of ineligible) {
    const view = buildCeremonyAckView(record(over, old), null, NOW_MS);
    assert.equal(view.active, false);
    assert.equal(view.expired, false, 'non-bidirectional rows are not cancellable');
  }

  // Verified relationship: the ceremony is over for good.
  const verified = buildCeremonyAckView(record({ personhoodStatus: 'verified' }, old), null, NOW_MS);
  assert.equal(verified.active, false);
  assert.equal(verified.expired, false);

  // Infrastructure (utility server) relationship: no personhood ceremony.
  const org = buildCeremonyAckView(record({ remoteSubjectKind: 'organization' }, old), null, NOW_MS);
  assert.equal(org.active, false);
  assert.equal(org.expired, false);
});

// ---------------------------------------------------------------------------
// Agreement with the authoritative sweep
// ---------------------------------------------------------------------------

test('ack view: expiry never lags isCeremonyStale and agrees away from the boundary', () => {
  for (let ageMs = 0; ageMs <= VRC_CEREMONY_ACK_TIMEOUT_MS + 5_000; ageMs += 1_000) {
    const rec = record({}, ageMs);
    const view = buildCeremonyAckView(rec, null, NOW_MS);
    const stale = isCeremonyStale(rec, null, NOW_MS);

    if (stale) {
      // The sweep will clear the connection attempt this tick: the display must
      // already be showing the cancelled state, never a live countdown.
      assert.equal(view.expired, true, 'view must not lag the sweep at age=' + ageMs + 'ms');
      assert.equal(view.active, false);
    }
    if (view.remainingMs > 1_000) {
      // Comfortably inside the window: neither reports expiry. `isCeremonyStale`
      // floors to whole seconds while this view works in ms, so the view may
      // LEAD by up to 1s — the sweep must never lead the display.
      assert.equal(view.expired, false, 'age=' + ageMs + 'ms');
      assert.equal(stale, false, 'age=' + ageMs + 'ms');
    }
  }
});

test('sweep + view: a MUTUAL ack is never stale, even while the phase still reads personhood', () => {
  // The local press mints immediately, but a FAILING mint/publish leg PRESERVES
  // the phase (`recordFailure` keeps current.phase), so a consented pair can sit
  // at phase 'personhood' for the whole backoff ladder. Treating that as an
  // unconfirmed ceremony would delete a relationship BOTH users consented to —
  // and orphan the already-minted VRC — so neither the sweep nor the countdown
  // may consult the phase here. The retry model owns that stage.
  const rec = record({}, VRC_CEREMONY_ACK_TIMEOUT_MS + 45_000);
  const consented = session({ localAcked: true, remoteAcked: true, phase: 'personhood', attempt: 3 });
  const view = buildCeremonyAckView(rec, consented, NOW_MS);
  assert.equal(view.active, false, 'no countdown once both users have confirmed');
  assert.equal(view.expired, false);
  assert.equal(
    isCeremonyStale(rec, consented, NOW_MS),
    false,
    'both users consented — the sweep must not clear the connection',
  );

  // A one-sided press is still at the gate and still expires.
  assert.equal(isCeremonyStale(rec, session({ localAcked: true, attempt: 3 }), NOW_MS), true);
});

test('ack view: honors LP2P_CEREMONY_ACK_TIMEOUT_MS (the window is not hard-coded)', () => {
  const prev = process.env.LP2P_CEREMONY_ACK_TIMEOUT_MS;
  process.env.LP2P_CEREMONY_ACK_TIMEOUT_MS = '7000';
  try {
    const rec = record({}, 2_000);
    const view = buildCeremonyAckView(rec, null, NOW_MS);
    assert.equal(getCeremonyAckTimeoutMs(), 7_000);
    assert.equal(view.timeoutMs, 7_000);
    assert.equal(view.deadlineMs, rec.createdAt * 1000 + 7_000);
    assert.equal(view.remainingMs, 5_000);
  } finally {
    if (prev === undefined) delete process.env.LP2P_CEREMONY_ACK_TIMEOUT_MS;
    else process.env.LP2P_CEREMONY_ACK_TIMEOUT_MS = prev;
  }
});
