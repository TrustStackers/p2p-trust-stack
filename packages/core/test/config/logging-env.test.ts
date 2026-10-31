// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * logging-env tests — the config-file logging switch.
 *
 * These pin the contract that replaced the POSIX-only `P2PTS_LOG_LEVEL=info node …`
 * prefix in the reference apps' `package.json` scripts: a component's `.env` names the
 * level and the ceremony trace, the chain resolves as
 * `setLogLevel() > config file > P2PTS_LOG_LEVEL > warn`, and NOTHING about a missing,
 * unreadable or malformed config is fatal.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/config/logging-env.test.ts
 */
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import {
  loadLoggingEnv,
  applyLoggingEnv,
  getEffectiveLogging,
  LOG_LEVEL_KEY,
  CEREMONY_TRACE_KEY,
} from '../../src/config/logging-env.js';
import {
  DEFAULT_LOG_LEVEL,
  LOG_LEVEL_ENV,
  getLogLevel,
  setConfigLogLevel,
  setLogLevel,
} from '../../src/util/logger.js';
import {
  CEREMONY_TRACE_ENV,
  isCeremonyTraceEnabled,
  setCeremonyTrace,
} from '../../src/relationship/ceremony-trace.js';
import type { EnvSource } from '../../src/config/bootstrap-env.js';

/** An in-memory EnvSource — the pluggable seam, so tests never touch disk. */
function sourceOf(vars: Record<string, string>): EnvSource {
  return { name: 'test', read: () => vars };
}

/** An EnvSource that cannot read, standing in for an absent/unreadable config. */
const brokenSource: EnvSource = {
  name: 'broken',
  read() {
    throw new Error('no config here');
  },
};

/**
 * Return the process to a known state between tests.
 *
 * The logger's override slots and the ceremony flag are module state, and the two
 * environment variables are process state — all of which a test in this file may
 * have moved. Clearing them is what makes each assertion independent of the last.
 */
beforeEach(() => {
  setLogLevel(undefined);
  setConfigLogLevel(undefined);
  setCeremonyTrace(undefined);
  delete process.env[LOG_LEVEL_ENV];
  delete process.env[CEREMONY_TRACE_ENV];
});

// ---------------------------------------------------------------------------
// loadLoggingEnv
// ---------------------------------------------------------------------------

test('the exported keys are the documented ones', () => {
  assert.equal(LOG_LEVEL_KEY, 'P2PTS_LOG_LEVEL');
  assert.equal(CEREMONY_TRACE_KEY, 'CEREMONY_TRACE');
});

test('loadLoggingEnv reads a level and a trace flag from a source', () => {
  const env = loadLoggingEnv({
    source: sourceOf({ P2PTS_LOG_LEVEL: 'info', CEREMONY_TRACE: '1' }),
  });
  assert.deepEqual(env, { level: 'info', ceremonyTrace: true });
});

test('loadLoggingEnv reads only the keys it owns', () => {
  const env = loadLoggingEnv({
    source: sourceOf({ BOOTSTRAP_HOST: 'relay.example.com', P2PTS_LOG_LEVEL: 'debug' }),
  });
  assert.deepEqual(env, { level: 'debug' });
});

test('loadLoggingEnv trims and lowercases the level', () => {
  const env = loadLoggingEnv({ source: sourceOf({ P2PTS_LOG_LEVEL: '  INFO  ' }) });
  assert.equal(env.level, 'info');
});

test('loadLoggingEnv ignores an unknown level instead of guessing', () => {
  assert.deepEqual(loadLoggingEnv({ source: sourceOf({ P2PTS_LOG_LEVEL: 'chatty' }) }), {});
  assert.deepEqual(loadLoggingEnv({ source: sourceOf({ P2PTS_LOG_LEVEL: '' }) }), {});
});

test('loadLoggingEnv accepts the documented true/false words', () => {
  for (const word of ['1', 'true', 'yes', 'on', 'TRUE', 'On']) {
    assert.equal(
      loadLoggingEnv({ source: sourceOf({ CEREMONY_TRACE: word }) }).ceremonyTrace,
      true,
      `${word} should read as true`,
    );
  }
  for (const word of ['0', 'false', 'no', 'off', 'FALSE']) {
    assert.equal(
      loadLoggingEnv({ source: sourceOf({ CEREMONY_TRACE: word }) }).ceremonyTrace,
      false,
      `${word} should read as false`,
    );
  }
});

test('loadLoggingEnv ignores a nonsense trace value', () => {
  assert.deepEqual(loadLoggingEnv({ source: sourceOf({ CEREMONY_TRACE: 'maybe' }) }), {});
});

test('loadLoggingEnv returns no opinion for an unreadable source', () => {
  assert.deepEqual(loadLoggingEnv({ source: brokenSource }), {});
});

test('loadLoggingEnv returns no opinion for a missing file (never fatal)', () => {
  assert.deepEqual(loadLoggingEnv({ path: '/nonexistent/definitely/not/here/.env' }), {});
});

test('loadLoggingEnv reads a real file, tolerating comments and blanks', () => {
  const fixture = fileURLToPath(new URL('./fixtures/logging.env', import.meta.url));
  assert.deepEqual(loadLoggingEnv({ path: fixture }), { level: 'debug', ceremonyTrace: true });
});

// ---------------------------------------------------------------------------
// applyLoggingEnv — the precedence chain
// ---------------------------------------------------------------------------

test('applyLoggingEnv applies the level the file names', () => {
  applyLoggingEnv({ source: sourceOf({ P2PTS_LOG_LEVEL: 'info' }) });
  assert.equal(getLogLevel(), 'info');
  assert.deepEqual(getEffectiveLogging(), { level: 'info', ceremonyTrace: false });
});

test('applyLoggingEnv turns ceremony tracing on', () => {
  applyLoggingEnv({ source: sourceOf({ CEREMONY_TRACE: '1' }) });
  assert.equal(isCeremonyTraceEnabled(), true);
});

test('a config file beats the P2PTS_LOG_LEVEL environment variable', () => {
  process.env[LOG_LEVEL_ENV] = 'error';
  applyLoggingEnv({ source: sourceOf({ P2PTS_LOG_LEVEL: 'debug' }) });
  assert.equal(getLogLevel(), 'debug');
});

test('an explicit setLogLevel() still beats the config file', () => {
  applyLoggingEnv({ source: sourceOf({ P2PTS_LOG_LEVEL: 'debug' }) });
  setLogLevel('error');
  assert.equal(getLogLevel(), 'error');
});

test('an explicit setCeremonyTrace() still beats the config file', () => {
  applyLoggingEnv({ source: sourceOf({ CEREMONY_TRACE: '1' }) });
  setCeremonyTrace(false);
  assert.equal(isCeremonyTraceEnabled(), false);
});

test('a config file with no level leaves the environment variable in charge', () => {
  process.env[LOG_LEVEL_ENV] = 'info';
  applyLoggingEnv({ source: sourceOf({ BOOTSTRAP_HOST: 'relay.example.com' }) });
  assert.equal(getLogLevel(), 'info');
});

test('a config file with no level and no env var falls back to the default', () => {
  applyLoggingEnv({ source: sourceOf({}) });
  assert.equal(getLogLevel(), DEFAULT_LOG_LEVEL);
  assert.equal(DEFAULT_LOG_LEVEL, 'warn');
});

test('a missing config file is not fatal and falls back to the environment', () => {
  process.env[LOG_LEVEL_ENV] = 'error';
  assert.deepEqual(applyLoggingEnv({ path: '/nonexistent/definitely/not/here/.env' }), {});
  assert.equal(getLogLevel(), 'error');
});

test('re-applying clears a level the previous config had set', () => {
  applyLoggingEnv({ source: sourceOf({ P2PTS_LOG_LEVEL: 'debug' }) });
  assert.equal(getLogLevel(), 'debug');
  // A later apply with no level must NOT leave 'debug' pinned.
  applyLoggingEnv({ source: sourceOf({}) });
  assert.equal(getLogLevel(), DEFAULT_LOG_LEVEL);
});

test('the environment variable still works with no config applied at all', () => {
  process.env[LOG_LEVEL_ENV] = 'debug';
  assert.equal(getLogLevel(), 'debug');
  process.env[CEREMONY_TRACE_ENV] = '1';
  assert.equal(isCeremonyTraceEnabled(), true);
});
