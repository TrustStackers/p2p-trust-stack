// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * bootstrap-env — typed, source-pluggable configuration for the bootstrap/relay
 * server's identity and address.
 *
 * ## Why this exists
 *
 * The bootstrap server's peer ID and address used to be **hardcoded** in two
 * source files (`bootstrap/server/bootstrap-protocol.ts` and
 * `packages/core/src/transport/bootstrap-client.ts`) with a `process.env.BOOTSTRAP_SERVER_URL`
 * escape hatch. That made swapping bootstrap servers a code change, and made the
 * config surface a mix of compiled-in constants and OS environment variables.
 *
 * This module replaces all of it with **one typed loader**:
 *
 *   - the value comes from a per-component **`.env` file** (gitignored, written
 *     by `scripts/init-bootstrap-env.ts` / `npm run init:bootstrap`);
 *   - the loader returns a **validated, typed `BootstrapEnv`** object — callers
 *     never read `process.env.BOOTSTRAP_*` themselves;
 *   - the SOURCE is pluggable (`EnvSource`), so the same public API works on
 *     Node (`.env` file) and, later, in a Capacitor/browser build
 *     (`import.meta.env` / an injected global).
 *
 * ## Two `.env` shapes — one per role
 *
 * There are exactly TWO kinds of component, and they need different things:
 *
 * **The bootstrap server** (`bootstrap/.env`) — the ONLY component whose identity
 * is derived from a word phrase. It holds the seed and derives the peer ID:
 *
 *   BOOTSTRAP_SEED_HEX=<64 hex chars>     # derived from the word sequence
 *   BOOTSTRAP_PEER_ID=12D3KooW...         # derived from the seed (optional)
 *   BOOTSTRAP_HOST=mediator.example.com   # DNS name OR fixed public IP
 *   BOOTSTRAP_TCP_PORT=4001
 *   BOOTSTRAP_WS_PORT=4002
 *   BOOTSTRAP_ENABLE_RELAY=true
 *
 * `BOOTSTRAP_PEER_ID` is optional there: when omitted it is derived from
 * `BOOTSTRAP_SEED_HEX` (see {@link derivePeerIdFromSeedHex}). When both are
 * present they must agree — a mismatch is a corrupt config, not a preference,
 * so {@link verifyBootstrapEnv} rejects it. Read with {@link loadBootstrapEnv}.
 *
 * **A client** (`agent-app/.env`, `utility-server/.env`) — every other component
 * only has to know WHERE the server is and WHICH peer ID to expect. It holds no
 * key material at all:
 *
 *   BOOTSTRAP_PEER_ID=12D3KooW...         # required — there is no seed to derive it from
 *   BOOTSTRAP_HOST=mediator.example.com
 *   BOOTSTRAP_TCP_PORT=4001
 *   BOOTSTRAP_WS_PORT=4002
 *   BOOTSTRAP_ENABLE_RELAY=true
 *
 * Read with {@link loadBootstrapClientEnv}, which REJECTS a client `.env` that
 * still carries `BOOTSTRAP_SEED_HEX` — a seed in a client file is a leaked
 * private key, not a preference, and a client has no use for it.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { keys } from '@libp2p/crypto';
import { peerIdFromPrivateKey } from '@libp2p/peer-id';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The validated bootstrap/relay identity + address every component needs. */
export interface BootstrapEnv {
  /** Schema version, so the shape can evolve. */
  version: 1;
  /** Hex-encoded 32-byte Ed25519 seed (the key the peer ID is derived from). */
  seedHex: string;
  /** The libp2p peer ID (base58btc `12D3Koo...`). */
  peerId: string;
  /** DNS hostname or fixed public IP the server is reachable at. */
  host: string;
  /** TCP listen/dial port (default 4001). */
  tcpPort: number;
  /** WebSocket listen/dial port (default 4002). */
  wsPort: number;
  /** Whether the circuit-relay service is enabled on the server. */
  enableRelay: boolean;
}

/** The multiaddrs derived from a {@link BootstrapEnv} or {@link BootstrapClientEnv}. */
export interface BootstrapUrls {
  /** TCP dial address, e.g. `/dns/host/tcp/4001/p2p/<peerId>`. */
  tcpUrl: string;
  /** WebSocket dial address, e.g. `/dns/host/tcp/4002/ws/p2p/<peerId>`. */
  wsUrl: string;
  /** Circuit-relay prefix, e.g. `/dns/host/tcp/4001/p2p/<peerId>/p2p-circuit`. */
  relayAddr: string;
}

/**
 * The bootstrap identity + address a **client** component needs — deliberately
 * WITHOUT the seed.
 *
 * Only the bootstrap server holds `BOOTSTRAP_SEED_HEX`: it is the one component
 * whose peer ID is derived from a word sequence. The agent app and the utility
 * server are clients — they only have to know where the server is and which peer
 * ID to expect — so their `.env` carries `BOOTSTRAP_PEER_ID` + `BOOTSTRAP_HOST`
 * and never any key material.
 */
export interface BootstrapClientEnv {
  /** Schema version, so the shape can evolve. */
  version: 1;
  /** The libp2p peer ID (base58btc `12D3Koo...`) to dial and to expect. */
  peerId: string;
  /** DNS hostname or fixed public IP the server is reachable at. */
  host: string;
  /** TCP dial port (default 4001). */
  tcpPort: number;
  /** WebSocket dial port (default 4002). */
  wsPort: number;
  /** Whether the server advertises a circuit-relay service. */
  enableRelay: boolean;
}

/**
 * The subset {@link buildBootstrapUrls} needs.
 *
 * Satisfied by BOTH {@link BootstrapEnv} (the server) and
 * {@link BootstrapClientEnv} (a client), so the one URL builder serves both roles
 * and neither has to convert into the other.
 */
export type BootstrapUrlsInput = Pick<BootstrapEnv, 'host' | 'tcpPort' | 'wsPort' | 'peerId'>;

/**
 * A pluggable source of raw `KEY=value` config.
 *
 * Node reads a `.env` file; a Capacitor/browser build reads `import.meta.env`
 * or an injected global. Everything downstream consumes the typed
 * {@link BootstrapEnv}, so the source is the only platform-specific piece.
 */
export interface EnvSource {
  /** Human-readable name, used in error messages. */
  readonly name: string;
  /** Read the raw key/value map. Throws when the source is unavailable. */
  read(path?: string): Record<string, string>;
}

// ---------------------------------------------------------------------------
// .env parsing (Node source)
// ---------------------------------------------------------------------------

/**
 * Parse dotenv-style `KEY=value` text.
 *
 * Deliberately minimal: blank lines and `# comments` are skipped, an optional
 * matching pair of single/double quotes is stripped, and the first `=` splits
 * the line. This is the subset every dotenv implementation agrees on.
 */
export function parseEnvText(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    if (!key) continue;
    let value = line.slice(eq + 1).trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

/** The default per-component env filename. */
export const BOOTSTRAP_ENV_FILENAME = '.env';

/** A source backed by a `.env` file on disk (the Node/default implementation). */
export function nodeEnvSource(): EnvSource {
  return {
    name: 'file',
    read(path?: string): Record<string, string> {
      const file = path ?? resolve(process.cwd(), BOOTSTRAP_ENV_FILENAME);
      let text: string;
      try {
        text = readFileSync(file, 'utf8');
      } catch {
        throw new Error(
          `bootstrap env: no config file at ${file}. ` +
          'Run `npm run init:bootstrap` to create one (it derives the peer ID ' +
          'from your word sequence and writes the address).',
        );
      }
      return parseEnvText(text);
    },
  };
}

/**
 * A source backed by build-time injected values (the Capacitor/browser seam).
 *
 * Capacitor has no Node runtime, so there is no `process.env` and no runtime
 * `.env` read. The expected mechanism there is Vite's `import.meta.env` at build
 * time (or a global injected before the bundle loads). This implementation
 * reads those, so the mobile port only has to populate them — no consumer code
 * changes. It throws a descriptive error when neither is present, rather than
 * silently returning an empty config.
 */
export function browserEnvSource(): EnvSource {
  return {
    name: 'browser',
    read(): Record<string, string> {
      // `import.meta.env` is a Vite construct; cast so this compiles under the
      // Node tsconfig too. Absent in plain Node ESM.
      const viteEnv = (import.meta as unknown as {
        env?: Record<string, string | undefined>;
      }).env;
      const injected = (globalThis as unknown as {
        __P2PTS_BOOTSTRAP_ENV__?: Record<string, string>;
      }).__P2PTS_BOOTSTRAP_ENV__;

      if (injected) return { ...injected };
      if (viteEnv) {
        return {
          BOOTSTRAP_PEER_ID: viteEnv.VITE_BOOTSTRAP_PEER_ID ?? '',
          BOOTSTRAP_HOST: viteEnv.VITE_BOOTSTRAP_HOST ?? '',
          BOOTSTRAP_TCP_PORT: viteEnv.VITE_BOOTSTRAP_TCP_PORT ?? '',
          BOOTSTRAP_WS_PORT: viteEnv.VITE_BOOTSTRAP_WS_PORT ?? '',
          BOOTSTRAP_ENABLE_RELAY: viteEnv.VITE_BOOTSTRAP_ENABLE_RELAY ?? '',
        };
      }
      throw new Error(
        'bootstrap env: no build-time source available. On Capacitor/browser, ' +
        'provide VITE_BOOTSTRAP_* (Vite) or inject globalThis.__P2PTS_BOOTSTRAP_ENV__.',
      );
    },
  };
}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** True for a 64-character hex string (a 32-byte seed). */
export function isHex64(value: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(value);
}

/** Decode a 64-char hex string into 32 bytes; throws on malformed input. */
export function hexToSeedBytes(seedHex: string): Uint8Array {
  if (!isHex64(seedHex)) {
    throw new Error(
      `bootstrap env: BOOTSTRAP_SEED_HEX must be 64 hex characters (32 bytes), got ${seedHex.length}`,
    );
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(seedHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Derive the libp2p peer ID from a hex seed.
 *
 * This is the SAME derivation the bootstrap server performs at startup
 * (`keys.generateKeyPairFromSeed('Ed25519', seed)`), which is what makes the
 * peer ID deterministic and shareable: the init tool computes it once, and
 * every component can trust the value in the `.env`.
 */
export async function derivePeerIdFromSeedHex(seedHex: string): Promise<string> {
  const privateKey = await keys.generateKeyPairFromSeed('Ed25519', hexToSeedBytes(seedHex));
  const peerId = await peerIdFromPrivateKey(privateKey);
  return peerId.toString();
}

/** `/ip4/…`, `/ip6/…`, or `/dns/…` for a host that may be an IP or a name. */
export function hostToMultiaddrPrefix(host: string): string {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return `/ip4/${host}`;
  if (host.includes(':')) return `/ip6/${host}`;
  return `/dns/${host}`;
}

/** Build the TCP/WS/relay multiaddrs from a validated env (server OR client). */
export function buildBootstrapUrls(env: BootstrapUrlsInput): BootstrapUrls {
  const hostPrefix = hostToMultiaddrPrefix(env.host);
  const peerSuffix = `/p2p/${env.peerId}`;
  return {
    tcpUrl: `${hostPrefix}/tcp/${env.tcpPort}${peerSuffix}`,
    wsUrl: `${hostPrefix}/tcp/${env.wsPort}/ws${peerSuffix}`,
    // The relay's own dialable address (with ITS peer ID) first, `/p2p-circuit`
    // last — a peer ID after /p2p-circuit would denote the destination instead.
    relayAddr: `${hostPrefix}/tcp/${env.tcpPort}${peerSuffix}/p2p-circuit`,
  };
}


// ---------------------------------------------------------------------------
// Loading + validation
// ---------------------------------------------------------------------------

export interface LoadBootstrapEnvOptions {
  /** Explicit `.env` path. Defaults to `<cwd>/.env` for the Node source. */
  path?: string;
  /** Override the source (tests / Capacitor). Defaults to {@link nodeEnvSource}. */
  source?: EnvSource;
}

function requireKey(raw: Record<string, string>, key: string, source: string): string {
  const value = raw[key]?.trim();
  if (!value) {
    throw new Error(
      `bootstrap env (${source}): missing ${key}. Run \`npm run init:bootstrap\` to generate the config.`,
    );
  }
  return value;
}

function parseIntKey(raw: Record<string, string>, key: string, fallback: number, source: string): number {
  const value = raw[key]?.trim();
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > 65535) {
    throw new Error(
      `bootstrap env (${source}): ${key} must be a TCP port (1-65535), got "${value}"`,
    );
  }
  return parsed;
}

function parseBoolKey(raw: Record<string, string>, key: string, fallback: boolean): boolean {
  const value = raw[key]?.trim().toLowerCase();
  if (!value) return fallback;
  return value === '1' || value === 'true' || value === 'yes' || value === 'on';
}

/**
 * Load and validate the bootstrap **server** env from the configured source.
 *
 * SERVER ONLY — this is the one loader that requires `BOOTSTRAP_SEED_HEX`,
 * because the bootstrap server is the one component whose peer ID is derived from
 * a word sequence. A client component (agent app, utility server) must use
 * {@link loadBootstrapClientEnv} instead, which never reads a seed.
 *
 * Throws with an actionable message on any missing/malformed field — never
 * returns a partially-populated config, and never falls back to a hardcoded
 * address (the whole point of this module).
 */
export function loadBootstrapEnv(opts: LoadBootstrapEnvOptions = {}): BootstrapEnv {
  const source = opts.source ?? nodeEnvSource();
  const raw = source.read(opts.path);

  const seedHex = requireKey(raw, 'BOOTSTRAP_SEED_HEX', source.name).toLowerCase();
  if (!isHex64(seedHex)) {
    throw new Error(
      `bootstrap env (${source.name}): BOOTSTRAP_SEED_HEX must be 64 hex characters (32 bytes), got ${seedHex.length}`,
    );
  }

  const host = requireKey(raw, 'BOOTSTRAP_HOST', source.name);
  const tcpPort = parseIntKey(raw, 'BOOTSTRAP_TCP_PORT', 4001, source.name);
  const wsPort = parseIntKey(raw, 'BOOTSTRAP_WS_PORT', 4002, source.name);
  const enableRelay = parseBoolKey(raw, 'BOOTSTRAP_ENABLE_RELAY', true);
  const peerId = raw.BOOTSTRAP_PEER_ID?.trim() || '';

  return {
    version: 1,
    seedHex,
    peerId,
    host,
    tcpPort,
    wsPort,
    enableRelay,
  };
}

/**
 * Load and validate a bootstrap **client** env from the configured source.
 *
 * This is the loader for the agent app and the utility server. Both are clients:
 * they only need to know where the bootstrap server is and which peer ID to
 * expect, so they read `BOOTSTRAP_HOST` + `BOOTSTRAP_PEER_ID` (both REQUIRED —
 * there is no seed to derive the peer ID from) plus the ports.
 *
 * A `BOOTSTRAP_SEED_HEX` in a client `.env` is REJECTED rather than ignored: a
 * seed in a client file is a leaked private key with no client use, and silently
 * tolerating it is how it stays there. Re-running
 * `npm run init:bootstrap -- --component <name>` removes it.
 */
export function loadBootstrapClientEnv(opts: LoadBootstrapEnvOptions = {}): BootstrapClientEnv {
  const source = opts.source ?? nodeEnvSource();
  const raw = source.read(opts.path);

  if (raw.BOOTSTRAP_SEED_HEX?.trim()) {
    throw new Error(
      `bootstrap env (${source.name}): BOOTSTRAP_SEED_HEX is present, but this component is a ` +
      'CLIENT. Only the bootstrap server holds the seed — remove the line and keep ' +
      'BOOTSTRAP_PEER_ID + BOOTSTRAP_HOST (re-run `npm run init:bootstrap -- --component ' +
      '<bootstrap|utility-server|agent>` to rewrite the file).',
    );
  }

  const host = requireKey(raw, 'BOOTSTRAP_HOST', source.name);
  const peerId = requireKey(raw, 'BOOTSTRAP_PEER_ID', source.name);
  const tcpPort = parseIntKey(raw, 'BOOTSTRAP_TCP_PORT', 4001, source.name);
  const wsPort = parseIntKey(raw, 'BOOTSTRAP_WS_PORT', 4002, source.name);
  const enableRelay = parseBoolKey(raw, 'BOOTSTRAP_ENABLE_RELAY', true);

  return {
    version: 1,
    peerId,
    host,
    tcpPort,
    wsPort,
    enableRelay,
  };
}

/**
 * Verify that `env.peerId` (when present) matches `env.seedHex`.
 *
 * SERVER ONLY — the seed is what the check is against, so there is nothing for a
 * client to verify here.
 *
 * Async because peer-ID derivation is async. Returns the resolved peer ID —
 * filling it in when the `.env` omitted `BOOTSTRAP_PEER_ID` — so a caller can
 * `env.peerId = await verifyBootstrapEnv(env)`.
 */
export async function verifyBootstrapEnv(env: BootstrapEnv): Promise<string> {
  const derived = await derivePeerIdFromSeedHex(env.seedHex);
  if (env.peerId && env.peerId !== derived) {
    throw new Error(
      `bootstrap env: BOOTSTRAP_PEER_ID (${env.peerId}) does not match ` +
      `BOOTSTRAP_SEED_HEX (derives ${derived}). The config is corrupt or hand-edited — ` +
      're-run `npm run init:bootstrap`.',
    );
  }
  return derived;
}

