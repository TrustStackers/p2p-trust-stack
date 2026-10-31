// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `logging-config` domain — where a front end's log verbosity comes from.
 *
 * ## Why this is a domain and not app code
 *
 * The agent app has TWO composition roots (the TUI and the web server) and they must
 * report the same thing about logging: the level in effect, whether `[CEREMONY]`
 * tracing is on, and whether that came from the component's config or from a default.
 * Leaving it in `agent-app/` would duplicate the wiring in both, and re-implement it
 * for the next front end — the same argument `bootstrap-config.ts` makes for itself.
 *
 * ## What it wraps
 *
 * `@p2p-trust-stack/core/config/logging-env` owns the behaviour: it reads
 * `P2PTS_LOG_LEVEL` + `CEREMONY_TRACE` out of this component's `.env` and applies them,
 * so verbosity travels with the component instead of living in a `package.json` script
 * (which cannot assign a variable on Windows, and does not exist at all in the
 * Capacitor mobile build, where a native host launches Node). See that module for the
 * precedence chain: `setLogLevel() > .env > P2PTS_LOG_LEVEL > warn`.
 *
 * A `.env` is the SAME file the bootstrap block lives in — one config file per
 * component, not two.
 *
 * ## Never fatal
 *
 * `apply()` cannot throw. A missing, unreadable or malformed `.env` leaves logging at
 * whatever the environment and defaults say, because logging must never be the reason an
 * app fails to start.
 */

import {
  applyLoggingEnv,
  getEffectiveLogging,
} from '@p2p-trust-stack/core/config/logging-env.js';
import type { EnvSource } from '@p2p-trust-stack/core/config/bootstrap-env.js';
import type { LogLevel } from '@p2p-trust-stack/core/util/logger.js';

/** What logging is doing, and where the setting came from. */
export interface LoggingConfigView {
  /** The level a line must reach to be emitted. */
  level: LogLevel;
  /** Whether `[CEREMONY]` tracing lines are being emitted. */
  ceremonyTrace: boolean;
  /**
   * `'env'` when the component's config named a level, `'default'` when logging is
   * running on the environment variable or the built-in default.
   */
  source: 'env' | 'default';
}

export interface LoggingConfigApi {
  /**
   * Read this component's config and apply it, then report what is in effect.
   * Safe to call once at startup; calling it again re-reads the file.
   */
  apply(): LoggingConfigView;
  /** What is in effect now, without re-reading the file. */
  view(): LoggingConfigView;
}

export interface LoggingConfigDeps {
  /** Absolute path to this component's `.env` (the `init:bootstrap` block). */
  envPath: string;
  /**
   * Override the config source. Supply this where there is no `.env` on disk —
   * a Capacitor/browser build, or a test. Defaults to reading `envPath`.
   */
  source?: EnvSource;
  /** Notified when the config named a setting (for a startup log line). */
  onApply?: (message: string) => void;
}

/** Build the `logging-config` domain. */
export function createLoggingConfigApi(deps: LoggingConfigDeps): LoggingConfigApi {
  /** Where the level in effect came from, as of the last `apply()`. */
  let source: LoggingConfigView['source'] = 'default';

  function view(): LoggingConfigView {
    const effective = getEffectiveLogging();
    return { level: effective.level, ceremonyTrace: effective.ceremonyTrace, source };
  }

  return {
    apply(): LoggingConfigView {
      const env = applyLoggingEnv(
        deps.source ? { source: deps.source } : { path: deps.envPath },
      );
      source = env.level ? 'env' : 'default';

      const effective = view();
      deps.onApply?.(
        source === 'env'
          ? `logging level "${effective.level}" from .env` +
            (effective.ceremonyTrace ? ', ceremony trace on' : '')
          : `logging at the default level "${effective.level}" (no logging block in .env)`,
      );
      return effective;
    },

    view,
  };
}
