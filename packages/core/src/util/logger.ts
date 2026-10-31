// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * logger — the stack's single, dependency-free, leveled log gate.
 *
 * Every log line the published packages emit goes through here, so an embedder
 * has ONE switch for all of it. Verbosity is resolved **per call** (never frozen
 * at import) so a process that hosts a stack can change it at runtime — the same
 * rule `relationship/ceremony-trace.ts` already follows for its own opt-in trace.
 *
 * ## Precedence
 *
 *   1. an explicit {@link setLogLevel} override, else
 *   2. the level a host read from its own config file ({@link setConfigLogLevel},
 *      applied by `config/logging-env.ts` from a component's `.env`), else
 *   3. the `P2PTS_LOG_LEVEL` environment variable, else
 *   4. the default — `warn`.
 *
 * Rung 2 exists because an environment variable cannot be set portably: a
 * `package.json` script cannot assign one on Windows, and an app that launches
 * its own Node runtime (the Capacitor mobile build) has no npm script at all. A
 * config file can, so the level travels with the component — while rung 3 stays
 * for embedders who documented `P2PTS_LOG_LEVEL` and still set it that way.
 *
 * The default is deliberately quiet: a library that logs on import makes its host
 * noisy, so only warnings and errors are emitted unless the host asks for more.
 *
 *   P2PTS_LOG_LEVEL=silent | error | warn | info | debug
 *
 * ## Levels (quietest gate → loudest)
 *
 *   silent  nothing at all
 *   error   errors only
 *   warn    errors + warnings                 (DEFAULT)
 *   info    + lifecycle / state changes
 *   debug   + per-message wire traces
 *
 * ## Redirecting instead of suppressing
 *
 * A sink may be installed to route lines somewhere other than the console
 * (pino, a file, a test capture) — the level filter still applies, so a sink
 * changes WHERE lines go, not WHETHER they are emitted:
 *
 *   setLogSink((level, args) => myLogger[level](...args));
 *
 * Messages already carry their own `[prefix]` (e.g. `[Agent]`, `[tx-coordinator]`),
 * so call sites use the shared {@link logger} as-is. {@link createLogger} exists for
 * new code that wants the namespace added for it.
 */

export type LogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug';

export type LogSink = (level: Exclude<LogLevel, 'silent'>, args: unknown[]) => void;

const ORDER: Record<LogLevel, number> = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };

/** The environment variable read when no programmatic override is set. */
export const LOG_LEVEL_ENV = 'P2PTS_LOG_LEVEL';

/** The level used when neither an override nor a valid env value is present. */
export const DEFAULT_LOG_LEVEL: LogLevel = 'warn';

let overrideLevel: LogLevel | undefined;
let configLevel: LogLevel | undefined;
let sink: LogSink | undefined;

/**
 * The level in effect right now.
 *
 * `setLogLevel()` override > {@link setConfigLogLevel} (a component's config
 * file) > `P2PTS_LOG_LEVEL` > {@link DEFAULT_LOG_LEVEL}.
 */
export function getLogLevel(): LogLevel {
  if (overrideLevel) return overrideLevel;
  if (configLevel) return configLevel;
  const raw = process.env[LOG_LEVEL_ENV]?.trim().toLowerCase();
  return raw && isLogLevel(raw) ? raw : DEFAULT_LOG_LEVEL;
}

/**
 * Pin the level for this process, or pass `undefined` to fall back to the
 * environment. Returns the level now in effect.
 */
export function setLogLevel(level: LogLevel | undefined): LogLevel {
  overrideLevel = level;
  return getLogLevel();
}

/**
 * Record the level read from a component's config file.
 *
 * Deliberately a SEPARATE slot from {@link setLogLevel}, so the documented
 * precedence holds: an embedder that calls `setLogLevel()` explicitly still wins
 * over whatever the app's `.env` says, and a config file that names no level
 * leaves `P2PTS_LOG_LEVEL` and the default in charge. Applied for you by
 * `config/logging-env.ts`; call it directly only to drive the level from some
 * other config source. Pass `undefined` to clear it.
 */
export function setConfigLogLevel(level: LogLevel | undefined): LogLevel {
  configLevel = level;
  return getLogLevel();
}

/** True when `v` is one of the levels this module understands. */
export function isLogLevel(v: string): v is LogLevel {
  return v === 'silent' || v === 'error' || v === 'warn' || v === 'info' || v === 'debug';
}

/**
 * Redirect every line to `fn` instead of the console, or pass `undefined` to
 * restore console output.
 */
export function setLogSink(fn: LogSink | undefined): void {
  sink = fn;
}

function emit(level: Exclude<LogLevel, 'silent'>, args: unknown[]): void {
  if (ORDER[level] > ORDER[getLogLevel()]) return;
  if (sink) {
    sink(level, args);
    return;
  }
  const write = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
  write(...args);
}

/** A leveled logger. `debug` is the loudest gate; `error` the quietest. */
export interface Logger {
  debug(...args: unknown[]): void;
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
}

/**
 * Create a logger. `namespace`, when given, is prefixed to every line as
 * `[namespace]`.
 */
export function createLogger(namespace?: string): Logger {
  const prefix = namespace ? [`[${namespace}]`] : [];
  return {
    debug: (...args) => emit('debug', [...prefix, ...args]),
    info: (...args) => emit('info', [...prefix, ...args]),
    warn: (...args) => emit('warn', [...prefix, ...args]),
    error: (...args) => emit('error', [...prefix, ...args]),
  };
}

/** The shared logger used by every migrated call site in the stack. */
export const logger: Logger = createLogger();
