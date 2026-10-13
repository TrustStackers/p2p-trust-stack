/**
 * `connectivity` domain tests — driven through the public barrel only.
 *
 * Real agent, real libp2p node (started), throwaway P2PTS_HOME. No bootstrap or utility server is assumed
 * to be reachable, so every assertion here is about the *shape and the failure mode* of the surface rather
 * than about a live network — which is what makes it runnable anywhere.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/trust_app_api/connectivity.test.ts
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createAgentStack, type TrustStack } from '../../src/index.js';

const HOME = mkdtempSync(join(tmpdir(), 'api-connectivity-'));
let stack: TrustStack;

before(async () => {
  stack = await createAgentStack({
    home: HOME,
    agent: { name: 'netizen', passphrase: 'correct horse battery', port: 24011 },
  });
  assert.equal(stack.host.home, HOME, 'isolated home — must never touch the real P2PTS_HOME');
  await stack.start();
});

after(async () => {
  try { await stack.stop(); } catch { /* already stopped */ }
  rmSync(HOME, { recursive: true, force: true });
});

test('health() reports the service and the active agent, and never needs a network', async () => {
  const health = await stack.connectivity.health();
  assert.equal(health.status, 'ok');
  assert.equal(health.service, 'trust-app-api');
  assert.match(health.time, /^\d{4}-\d{2}-\d{2}T/, 'ISO timestamp');
  assert.equal(health.agent.active, true);
  assert.equal(health.agent.name, 'netizen');
  assert.match(health.agent.vid!, /\.\.\.$/, 'the vid is truncated for display');
});

test('ready() reports ready with relationship counts once an agent is active', async () => {
  const ready = await stack.connectivity.ready();
  assert.equal(ready.ready, true);
  assert.equal(ready.agent, 'netizen');
  assert.equal(typeof ready.relationshipCount, 'number');
  assert.equal(typeof ready.chatReadyCount, 'number');
  assert.ok(ready.chatReadyCount! <= ready.relationshipCount!, 'chat-ready is a subset');
});

test('status() returns the bootstrap view, including the layer-aware connectivity snapshot', async () => {
  const status = await stack.connectivity.status();

  assert.equal(typeof status.connected, 'boolean');
  assert.equal(typeof status.bootstrapConnected, 'boolean');
  assert.equal(typeof status.relayExpiring, 'boolean');
  assert.ok(Array.isArray(status.discoveredPeers), 'discoveredPeers is always an array');
  // The live view is what the UI gates on; it should be present for a real agent implementation.
  assert.ok(status.connectivity, 'connectivity snapshot present');
  assert.equal(status.layer, status.connectivity!.layer);
  assert.equal(status.bootstrapConnected, status.connectivity!.bootstrapConnected);
});

test('refresh() returns the peer list and counts it', async () => {
  const refreshed = await stack.connectivity.refresh();
  assert.ok(Array.isArray(refreshed.peers));
  assert.equal(refreshed.count, refreshed.peers.length);
});

test('utilityStatus() reports disconnected with a null DID when no utility server is configured', async () => {
  const status = await stack.connectivity.utilityStatus();
  assert.equal(status.connected, false);
  assert.equal(status.did, null);
  assert.equal(status.vid, status.did, 'the deprecated alias carries the same value');
});

test('pushIdentity() reports the pending state rather than throwing when offline', async () => {
  const result = await stack.connectivity.pushIdentity();
  assert.equal(result.ok, false);
  assert.equal(result.pending, true);
  assert.equal(typeof result.error, 'string', 'a reason is always supplied');
});

test('connectUtility() rejects an empty OOBI', async () => {
  await assert.rejects(() => stack.connectivity.connectUtility(''), /utilityServerOobi is required/);
});

test('networkProfile() resolves (a profile or undefined) without throwing', async () => {
  const profile = await stack.connectivity.networkProfile();
  if (profile !== undefined) {
    assert.ok(Array.isArray(profile.lanIps));
    assert.equal(typeof profile.listenPort, 'number');
    assert.ok(Array.isArray(profile.libp2pAddrs));
    assert.equal(typeof profile.capturedAt, 'number');
  }
});

test('explainFailure() always words a reason, and is the ONE connectivity call that works with no agent', async () => {
  // Every other method in this file fails closed on a deactivated agent. This one must NOT, because "there is no
  // active agent" is one of the conditions it exists to explain — and it is called from the adapter's 503 path,
  // where throwing would replace the caller's own error with ours.
  const live = await stack.connectivity.explainFailure('send an invitation');
  assert.equal(typeof live, 'string');
  assert.match(live, /send an invitation/, 'the operation is quoted back so the sentence fits its call site');

  const other = await createAgentStack({
    home: mkdtempSync(join(tmpdir(), 'api-connectivity-3-')),
    agent: { name: 'quiet', passphrase: 'correct horse battery', port: 24013 },
  });
  try {
    await other.identity.deactivate();
    const dead = await other.connectivity.explainFailure('accept the invitation');
    assert.equal(typeof dead, 'string');
    assert.match(dead, /accept the invitation/);
    assert.doesNotMatch(dead, /No active VTA/, 'it explains connectivity, it does not report its own failure');
  } finally {
    await other.stop();
    rmSync(other.host.home, { recursive: true, force: true });
  }
});

test('every connectivity call fails closed once the agent is deactivated', async () => {
  const other = await createAgentStack({
    home: mkdtempSync(join(tmpdir(), 'api-connectivity-2-')),
    agent: { name: 'goner', passphrase: 'correct horse battery', port: 24012 },
  });
  try {
    await other.identity.deactivate();

    // health/ready answer "not active" instead of throwing — they are probes.
    assert.equal((await other.connectivity.health()).agent.active, false);
    assert.equal((await other.connectivity.ready()).ready, false);

    // Everything that needs the agent throws a typed error rather than returning a half-answer.
    await assert.rejects(() => other.connectivity.status(), /No active VTA/);
    await assert.rejects(() => other.connectivity.refresh(), /No active VTA/);
    await assert.rejects(() => other.connectivity.utilityStatus(), /No active VTA/);
    await assert.rejects(() => other.connectivity.networkProfile(), /No active VTA/);
  } finally {
    await other.stop();
    rmSync(other.host.home, { recursive: true, force: true });
  }
});
