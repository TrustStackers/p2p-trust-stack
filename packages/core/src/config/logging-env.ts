// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * logging-env — where a component's logging verbosity comes from.
 *
 * ## Why this exists
 *
 * `util/logger.ts` resolves its level from `P2PTS_LOG_LEVEL`, and the reference apps
 * used to set that variable **inline in their `package.json` scripts**:
 *
 *   "start": "P2PTS_LOG_LEVEL=info node index.ts"
 *
 * That syntax is POSIX-shell only. `cmd.exe` and PowerShell cannot parse it, so the
 * script fails on Windows — and an app launched by a native host rather than npm (the
 * Capacitor mobile build) has no `package.json` script to put it in at all. A variable
 * cannot be assigned from a `package.json` entry portably either: a script is ONE shell
 * string, so a "line" that sets a variable runs in its own subprocess and dies with it.
 *
 * A **config file** has neither problem, and this project already has one per component:
 * the same `.env` that carries the bootstrap block (see `bootstrap-env.ts`). This module
 * reads the logging keys out of it and applies them, so verbosity travels with the
 * component and every platform gets the same behaviour.
 *
 * ## The keys
 *
 *   P2PTS_LOG_LEVEL=silent | error | warn | info | debug    (default: warn)
 *   CEREMONY_TRACE=1                                        (default: off)
 *
 * ## Precedence
 *
 * Applied through {@link applyLoggingEnv}, highest first:
 *
 *   1. an explicit `setLogLevel()` / `setCeremonyTrace()` call by an embedder, else
 *   2. the component's config file (this module), else
 *   3. the `P2PTS_LOG_LEVEL` / `CEREMONY_TRACE` environment variable, else
 *   4. the defaults — `warn`, and tracing off.
 *
 * Rung 3 is kept so the contract published in the package READMEs still holds for an
 * embedder that sets the variable itself.
 *
 * ## Never fatal
 *
 * Every failure here is tolerated: a missing file, an unreadable file, an unknown key
 * or a nonsense value all resolve to "no opinion", and the level falls through to the
 * next rung. Logging must never be the thing that stops an app from starting — the same
 * rule `relationship/ceremony-trace.ts` and the mobile entry already follow.
 *
 * ## One source, every platform
 *
 * The file read is behind {@link EnvSource} (from `bootstrap-env.ts`), so the same API
 * serves a Node `.env`, a build-time injected map, or a test's in-memory map. A component
 * that is not a Node process supplies its own source instead of a path.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { parseEnvText, type EnvSource } from './bootstrap-env.js';
import {
  LOG_LEVEL_ENV,
  getLogLevel,
  isLogLevel,
  setConfigLogLevel,
  type LogLevel,
} from '../util/logger.js';
import {
  CEREMONY_TRACE_ENV,
  isCeremonyTraceEnabled,
  setCeremonyTrace,
} from '../relationship/ceremony-trace.js';

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/** The `.env` key naming the stack-wide log level. */
export const LOG_LEVEL_KEY = LOG_LEVEL_ENV;

/** The `.env` key turning `[CEREMONY]` tracing on. */
export const CEREMONY_TRACE_KEY = CEREMONY_TRACE_ENV;

/** The values that read as `true` for a boolean key. */
const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);
/** The values that read as `false` for a boolean key. */
const FALSE_VALUES = new Set(['0', 'false', 'no', 'off']);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** What a config file says about logging. Absent fields mean "no opinion". */
export interface LoggingEnv {
  /** The level the file named, when it named a valid one. */
  level?: LogLevel;
  /** Whether the file asked for `[CEREMONY]` tracing. */
  ceremonyTrace?: boolean;
}

export interface LoggingEnvOptions {
  /**
   * Explicit `.env` path. Defaults to `<cwd>/.env` — the same file
   * `bootstrap-env.ts` reads, so a component has ONE config file.
   */
  path?: string;
  /**
   * Override the source. Defaults to a file read. Supply this where there is no
   * `.env` on disk — a browser/Capacitor build, or a test.
   */
  source?: EnvSource;
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/** Parse a boolean key: a known true/false word, or `undefined` for anything else. */
function parseBoolKey(raw: Record<string, string>, key: string): boolean | undefined {
  const value = raw[key]?.trim().toLowerCase();
  if (!value) return undefined;
  if (TRUE_VALUES.has(value)) return true;
  if (FALSE_VALUES.has(value)) return false;
  return undefined;
}

/**
 * Read the logging block from a component's config.
 *
 * Never throws and never returns a partial guess: an unreadable source, a missing
 * key, or a value outside the documented set all come back as "no opinion" so the
 * caller falls through to the next precedence rung.
 */
export function loadLoggingEnv(opts: LoggingEnvOptions = {}): LoggingEnv {
  let raw: Record<string, string>;

  if (opts.source) {
    try {
      raw = opts.source.read(opts.path);
    } catch {
      // An injected source that cannot read is a deployment fact, not a crash:
      // logging falls back rather than taking the app down with it.
      return {};
    }
  } else {
    const file = opts.path ?? resolve(process.cwd(), '.env');
    let text: string;
    try {
      text = readFileSync(file, 'utf8');
    } catch {
      return {};
    }
    raw = parseEnvText(text);
  }

  const out: LoggingEnv = {};

  const level = raw[LOG_LEVEL_KEY]?.trim().toLowerCase();
  if (level && isLogLevel(level)) out.level = level;

  const trace = parseBoolKey(raw, CEREMONY_TRACE_KEY);
  if (trace !== undefined) out.ceremonyTrace = trace;

  return out;
}

/**
 * Read a component's logging block and apply it, then report what the file said.
 *
 * Applying `undefined` clears any previously applied config value rather than
 * pinning a default, which is what keeps the precedence chain honest across calls.
 */
export function applyLoggingEnv(opts: LoggingEnvOptions = {}): LoggingEnv {
  const env = loadLoggingEnv(opts);
  setConfigLogLevel(env.level);
  setCeremonyTrace(env.ceremonyTrace);
  return env;
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/** What logging is actually doing right now, after the whole chain is resolved. */
export interface EffectiveLogging {
  /** The level a line must reach to be emitted. */
  level: LogLevel;
  /** Whether `[CEREMONY]` tracing lines are being emitted. */
  ceremonyTrace: boolean;
}

/** The resolved state — useful for a startup line, or a UI status field. */
export function getEffectiveLogging(): EffectiveLogging {
  return { level: getLogLevel(), ceremonyTrace: isCeremonyTraceEnabled() };
}
