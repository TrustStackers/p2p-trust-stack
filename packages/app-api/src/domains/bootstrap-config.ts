// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `bootstrap-config` domain — where the bootstrap server address comes from.
 *
 * ## Why this is a domain and not app code
 *
 * The bootstrap address is the one piece of configuration BOTH front ends (TUI and
 * web UI) must read and write identically, and it has a real precedence chain plus
 * a persistence rule. Leaving it in `agent-app/` would duplicate that chain in two
 * composition roots and re-implement it for the next front end.
 *
 * ## The chain
 *
 *   `P2PTS_HOME/config.yaml` (a value the user typed)  →  the component's `.env`
 *   →  nothing (LAN-only mode)
 *
 * `.env` is the machine default; `config.yaml` records a deliberate override. The
 * override is NOT written back into `.env`: that file is the component's
 * configured shape, and rewriting it would silently retarget every agent on the
 * machine instead of the one the user was looking at.
 *
 * ## A client holds no seed
 *
 * The agent app and the utility server are CLIENTS. They need the address and the
 * peer ID to expect, and nothing else — only the bootstrap server derives its peer
 * ID from a word sequence. `loadBootstrapClientEnv()` enforces that: a `.env` that
 * still carries `BOOTSTRAP_SEED_HEX` is refused rather than ignored.
 */

import { loadBootstrapClientEnv, type BootstrapClientEnv } from '@p2p-trust-stack/core/config/bootstrap-env.js';
import {
  loadP2ptsConfig,
  saveP2ptsConfig,
  resolveP2ptsHome,
} from '@p2p-trust-stack/core/platform/p2pts-home.js';
import type { BootstrapConfigView } from '../dto/connectivity.js';

export interface BootstrapConfigApi {
  /**
   * Values for a startup screen's bootstrap boxes, plus WHERE they came from.
   *
   * Never throws: an unconfigured machine must still render its login screen with
   * empty, editable boxes rather than an error.
   */
  view(): BootstrapConfigView;
  /**
   * The bootstrap server this component should dial, or `null` for LAN-only mode.
   *
   * `null` is a legitimate state, not a failure — the agent still starts, it just
   * cannot discover peers.
   */
  resolve(): BootstrapClientEnv | null;
  /**
   * Record a bootstrap override the user typed, but ONLY when it differs from this
   * component's `.env`. Accepting the default records nothing.
   */
  recordOverride(bootstrapHost?: string, bootstrapPeerId?: string): void;
  /**
   * The VTN key this machine last joined, or `undefined`.
   *
   * Deliberately `undefined` rather than defaulted: an agent that has not chosen a
   * VTN sends no `net` at all, instead of claiming another network's key.
   */
  lastVtn(): string | undefined;
  /** Remember the VTN the user joined, so the next launch registers under it. */
  recordVtn(vtnKey: string): void;
}

export interface BootstrapConfigDeps {
  /** Absolute path to this component's `.env` (the `init:bootstrap` block). */
  envPath: string;
  /** P2PTS_HOME override. Defaults to `resolveP2ptsHome()`. */
  home?: string;
  /** Notified whenever the persisted config is rewritten (for logging). */
  onPersist?: (message: string) => void;
}

/** Build the `bootstrap-config` domain. */
export function createBootstrapConfigApi(deps: BootstrapConfigDeps): BootstrapConfigApi {
  const home = (): string => deps.home ?? resolveP2ptsHome();

  /** Read the component's `.env`, or `null` when it is absent/unusable. */
  function readEnv(): BootstrapClientEnv | null {
    try {
      return loadBootstrapClientEnv({ path: deps.envPath });
    } catch {
      // Absent, malformed, or still carrying a seed. None of these is fatal here:
      // the caller reports `source: 'none'` and the user can type the values.
      return null;
    }
  }

  /** The persisted override, or the `.env` value, or nothing. */
  function resolveTarget(): { host: string; peerId: string; env: BootstrapClientEnv | null } {
    const cfg = loadP2ptsConfig(home());
    const env = readEnv();
    return {
      host: cfg.bootstrap_host.trim() || env?.host || '',
      peerId: cfg.bootstrap_peer_id.trim() || env?.peerId || '',
      env,
    };
  }

  return {
    view(): BootstrapConfigView {
      const { host, peerId, env } = resolveTarget();
      const cfg = loadP2ptsConfig(home());
      const fromConfig = Boolean(cfg.bootstrap_host.trim() && cfg.bootstrap_peer_id.trim());
      return {
        host,
        peerId,
        tcpPort: env?.tcpPort ?? 4001,
        wsPort: env?.wsPort ?? 4002,
        source: fromConfig ? 'config' : host && peerId ? 'env' : 'none',
      };
    },

    resolve(): BootstrapClientEnv | null {
      const { host, peerId, env } = resolveTarget();
      if (!host || !peerId) return null;
      return {
        version: 1,
        host,
        peerId,
        tcpPort: env?.tcpPort ?? 4001,
        wsPort: env?.wsPort ?? 4002,
        enableRelay: env?.enableRelay ?? true,
      };
    },

    recordOverride(bootstrapHost?: string, bootstrapPeerId?: string): void {
      const host = bootstrapHost?.trim() ?? '';
      const peerId = bootstrapPeerId?.trim() ?? '';
      if (!host && !peerId) return; // nothing typed — keep whatever is recorded

      const env = readEnv();
      // Accepted the default: there is nothing to record, and recording it would
      // freeze today's `.env` against a future change to it.
      if (env && host === env.host && peerId === env.peerId) return;

      const cfg = loadP2ptsConfig(home());
      cfg.bootstrap_host = host;
      cfg.bootstrap_peer_id = peerId;
      saveP2ptsConfig(cfg, home());
      deps.onPersist?.(
        `bootstrap override ${host} (peer ${peerId.slice(0, 12)}...) recorded in config.yaml`,
      );
    },

    lastVtn(): string | undefined {
      return loadP2ptsConfig(home()).vtn.trim() || undefined;
    },

    recordVtn(vtnKey: string): void {
      const cfg = loadP2ptsConfig(home());
      if (cfg.vtn === vtnKey) return;
      cfg.vtn = vtnKey;
      saveP2ptsConfig(cfg, home());
      deps.onPersist?.(`VTN "${vtnKey}" recorded in config.yaml`);
    },
  };
}

