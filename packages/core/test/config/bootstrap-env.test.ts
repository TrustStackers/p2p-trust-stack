// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * bootstrap-env tests — the typed, source-pluggable bootstrap config loader.
 *
 * These pin the contract that replaced the hardcoded `mediator.fpndtg.com`
 * address + peer ID and the `process.env.BOOTSTRAP_*` overrides: a `.env` (or any
 * `EnvSource`) is parsed into a validated `BootstrapEnv`, the peer ID is derived
 * deterministically from the seed, and a corrupt/missing config throws instead of
 * silently falling back to a wrong address.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/config/bootstrap-env.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  parseEnvText,
  loadBootstrapEnv,
  loadBootstrapClientEnv,
  derivePeerIdFromSeedHex,
  buildBootstrapUrls,
  verifyBootstrapEnv,
  hostToMultiaddrPrefix,
  isHex64,
  type EnvSource,
  type BootstrapEnv,
} from '../../src/config/bootstrap-env.js';

/** A known seed → peer ID pair (the value the production server used). */
const SEED = '152665e7af8722c4a32befd105c86467c57432e367416032b89fd8f018ccb1a6';
const PEER_ID = '12D3KooWKF2Tmh21NNSH5gWazfbmFEtTZS9XT1uXk8njFAy5jUda';

/** An in-memory EnvSource — the pluggable seam, used so tests never touch disk. */
function sourceOf(vars: Record<string, string>): EnvSource {
  return { name: 'test', read: () => vars };
}

function validVars(over: Record<string, string> = {}): Record<string, string> {
  return {
    BOOTSTRAP_SEED_HEX: SEED,
    BOOTSTRAP_PEER_ID: PEER_ID,
    BOOTSTRAP_HOST: 'mediator.example.com',
    BOOTSTRAP_TCP_PORT: '4001',
    BOOTSTRAP_WS_PORT: '4002',
    BOOTSTRAP_ENABLE_RELAY: 'true',
    ...over,
  };
}

// ---------------------------------------------------------------------------
// parseEnvText
// ---------------------------------------------------------------------------

test('parseEnvText skips comments/blanks and strips quotes', () => {
  const parsed = parseEnvText(
    [
      '# a comment',
      '',
      'BOOTSTRAP_HOST="quoted.example.com"',
      "BOOTSTRAP_PEER_ID='single.example'",
      'BOOTSTRAP_TCP_PORT=4001',
      'not-a-kv-line',
    ].join('\n'),
  );
  assert.equal(parsed.BOOTSTRAP_HOST, 'quoted.example.com');
  assert.equal(parsed.BOOTSTRAP_PEER_ID, 'single.example');
  assert.equal(parsed.BOOTSTRAP_TCP_PORT, '4001');
  assert.equal(parsed['not-a-kv-line'], undefined);
});

// ---------------------------------------------------------------------------
// loadBootstrapEnv
// ---------------------------------------------------------------------------

test('loadBootstrapEnv returns a typed env from a source', () => {
  const env = loadBootstrapEnv({ source: sourceOf(validVars()) });
  assert.equal(env.seedHex, SEED);
  assert.equal(env.peerId, PEER_ID);
  assert.equal(env.host, 'mediator.example.com');
  assert.equal(env.tcpPort, 4001);
  assert.equal(env.wsPort, 4002);
  assert.equal(env.enableRelay, true);
});

test('loadBootstrapEnv applies port/relay defaults', () => {
  const env = loadBootstrapEnv({
    source: sourceOf({ BOOTSTRAP_SEED_HEX: SEED, BOOTSTRAP_HOST: 'x.example' }),
  });
  assert.equal(env.tcpPort, 4001);
  assert.equal(env.wsPort, 4002);
  assert.equal(env.enableRelay, true);
  assert.equal(env.peerId, '', 'peer ID omitted is allowed (derived later)');
});

test('loadBootstrapEnv rejects a missing host', () => {
  assert.throws(
    () => loadBootstrapEnv({ source: sourceOf({ BOOTSTRAP_SEED_HEX: SEED }) }),
    /missing BOOTSTRAP_HOST/,
  );
});

test('loadBootstrapEnv rejects a malformed seed', () => {
  assert.throws(
    () => loadBootstrapEnv({ source: sourceOf(validVars({ BOOTSTRAP_SEED_HEX: 'abcd' })) }),
    /BOOTSTRAP_SEED_HEX must be 64 hex characters/,
  );
});

test('loadBootstrapEnv rejects an out-of-range port', () => {
  assert.throws(
    () => loadBootstrapEnv({ source: sourceOf(validVars({ BOOTSTRAP_TCP_PORT: '99999' })) }),
    /must be a TCP port/,
  );
});

test('loadBootstrapEnv from a missing file throws an actionable error', () => {
  assert.throws(
    () => loadBootstrapEnv({ path: '/nonexistent/definitely/not/here/.env' }),
    /Run `npm run init:bootstrap`/,
  );
});

// ---------------------------------------------------------------------------
// loadBootstrapClientEnv — the CLIENT shape (agent app / utility server)
// ---------------------------------------------------------------------------

test('loadBootstrapClientEnv reads host + peer ID and applies port defaults', () => {
  const env = loadBootstrapClientEnv({
    source: sourceOf({ BOOTSTRAP_PEER_ID: PEER_ID, BOOTSTRAP_HOST: 'mediator.example.com' }),
  });
  assert.equal(env.peerId, PEER_ID);
  assert.equal(env.host, 'mediator.example.com');
  assert.equal(env.tcpPort, 4001);
  assert.equal(env.wsPort, 4002);
  assert.equal(env.enableRelay, true);
});

test('loadBootstrapClientEnv requires the peer ID (there is no seed to derive it from)', () => {
  assert.throws(
    () => loadBootstrapClientEnv({ source: sourceOf({ BOOTSTRAP_HOST: 'x.example' }) }),
    /missing BOOTSTRAP_PEER_ID/,
  );
});

test('loadBootstrapClientEnv rejects a client .env that still carries the seed', () => {
  // A seed in a client file is a leaked private key, and the client has no use
  // for it — so it is a hard error, not something to quietly ignore.
  assert.throws(
    () => loadBootstrapClientEnv({
      source: sourceOf({ ...validVars(), BOOTSTRAP_SEED_HEX: SEED }),
    }),
    /BOOTSTRAP_SEED_HEX is present, but this component is a CLIENT/,
  );
});

test('loadBootstrapClientEnv rejects a missing host', () => {
  assert.throws(
    () => loadBootstrapClientEnv({ source: sourceOf({ BOOTSTRAP_PEER_ID: PEER_ID }) }),
    /missing BOOTSTRAP_HOST/,
  );
});

test('buildBootstrapUrls serves both env shapes', () => {
  const client = loadBootstrapClientEnv({
    source: sourceOf({ BOOTSTRAP_PEER_ID: PEER_ID, BOOTSTRAP_HOST: '203.0.113.5' }),
  });
  assert.equal(buildBootstrapUrls(client).tcpUrl, `/ip4/203.0.113.5/tcp/4001/p2p/${PEER_ID}`);

  const server = loadBootstrapEnv({ source: sourceOf(validVars()) });
  assert.equal(
    buildBootstrapUrls(server).relayAddr,
    `/dns/mediator.example.com/tcp/4001/p2p/${PEER_ID}/p2p-circuit`,
  );
});

// ---------------------------------------------------------------------------
// derivation + URL building
// ---------------------------------------------------------------------------

test('derivePeerIdFromSeedHex is deterministic and matches the known pair', async () => {
  assert.equal(await derivePeerIdFromSeedHex(SEED), PEER_ID);
});

test('verifyBootstrapEnv accepts a matching peer ID and fills in an omitted one', async () => {
  const env = loadBootstrapEnv({ source: sourceOf(validVars()) });
  assert.equal(await verifyBootstrapEnv(env), PEER_ID);

  const noPeerId = loadBootstrapEnv({
    source: sourceOf({ BOOTSTRAP_SEED_HEX: SEED, BOOTSTRAP_HOST: 'x.example' }),
  });
  assert.equal(await verifyBootstrapEnv(noPeerId), PEER_ID);
});

test('verifyBootstrapEnv rejects a peer ID that does not match the seed', async () => {
  const env: BootstrapEnv = {
    version: 1, seedHex: SEED, peerId: '12D3KooWNotTheRightPeerId',
    host: 'x.example', tcpPort: 4001, wsPort: 4002, enableRelay: true,
  };
  await assert.rejects(() => verifyBootstrapEnv(env), /does not match/);
});

test('buildBootstrapUrls emits /dns for a hostname and /ip4 for an IPv4', () => {
  const dns = buildBootstrapUrls({
    version: 1, seedHex: SEED, peerId: PEER_ID, host: 'mediator.example.com',
    tcpPort: 4001, wsPort: 4002, enableRelay: true,
  });
  assert.equal(dns.tcpUrl, `/dns/mediator.example.com/tcp/4001/p2p/${PEER_ID}`);
  assert.equal(dns.wsUrl, `/dns/mediator.example.com/tcp/4002/ws/p2p/${PEER_ID}`);
  assert.equal(dns.relayAddr, `/dns/mediator.example.com/tcp/4001/p2p/${PEER_ID}/p2p-circuit`);

  const ip = buildBootstrapUrls({
    version: 1, seedHex: SEED, peerId: PEER_ID, host: '203.0.113.5',
    tcpPort: 4001, wsPort: 4002, enableRelay: true,
  });
  assert.equal(ip.tcpUrl, `/ip4/203.0.113.5/tcp/4001/p2p/${PEER_ID}`);
});

test('hostToMultiaddrPrefix + isHex64 classify inputs', () => {
  assert.equal(hostToMultiaddrPrefix('203.0.113.5'), '/ip4/203.0.113.5');
  assert.equal(hostToMultiaddrPrefix('fe80::1'), '/ip6/fe80::1');
  assert.equal(hostToMultiaddrPrefix('bootstrap.example.com'), '/dns/bootstrap.example.com');
  assert.equal(isHex64(SEED), true);
  assert.equal(isHex64('xyz'), false);
});

