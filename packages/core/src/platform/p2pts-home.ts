// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * P2PTS_HOME — platform-aware resolution of the user-level data directory
 * for the P2P Trust Stack.
 *
 * ## Embedding contract
 *
 * `P2PTS_HOME` is a **convenient default, not an assumption.** Every function here takes an
 * optional `p2ptsHome` argument, and nothing in this module — or in anything that imports it —
 * resolves the home at import time. The environment read therefore happens per call and can
 * always be overridden, which is what lets a host place a stack anywhere:
 *
 * ```ts
 * createAgentStack({ host: createNodeHost({ home: '/srv/tenant-42/p2pts' }), ... })
 * ```
 *
 * If you are embedding this library and want a location other than the default below, pass
 * `home` (app-api) / `p2ptsHome` (here) explicitly. Do not rely on setting the environment
 * process-wide: that works, but it makes two stacks in one process impossible to separate.
 *
 * ## Resolution Priority
 *
 * 1. Explicit `p2ptsHome` argument (overrides all)
 * 2. Environment variable `P2PTS_HOME` (overrides the platform default)
 * 3. Platform default:
 *
 *    | Platform | Default Path                                                      |
 *    |----------|-------------------------------------------------------------------|
 *    | macOS    | ~/Library/Application Support/P2PTS/                               |
 *    | Linux    | ~/.p2pts/ (respects $XDG_DATA_HOME if set: $XDG_DATA_HOME/p2pts/)   |
 *    | Windows  | %APPDATA%/P2PTS/                                                   |
 *    | iOS      | App Group container `group.com.p2pts.shared` (stub)                |
 *    | Android  | Context.getFilesDir() (stub)                                      |
 *
 * ## Directory Structure
 *
 * After `ensureP2ptsHome()` returns, the following structure exists:
 *
 * ```
 * P2PTS_HOME/
 * ├── vta/                    ← ONE per user per device (local cache of VTA identity)
 * │   ├── p2pts-keystore.db   ← Root keypairs (Argon2id + AES-256-GCM encrypted)
 * │   └── p2pts-database.db   ← Local cache of shared identity data
 * ├── contexts/              ← Per-app per-device derived context data
 * ├── names/                 ← Local alsoKnownAs → DID resolution cache
 * └── config.yaml            ← P2PTS configuration
 * ```
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  mkdirSync,
  existsSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

/** Platform identifiers derived from `process.platform` and extended context. */
export type P2ptsPlatform = 'macos' | 'linux' | 'windows' | 'ios' | 'android' | 'unknown';

/**
 * Detect the current platform.
 * Node.js provides `process.platform` for darwin/linux/win32;
 * mobile stubs return the platform name directly.
 */
export function detectPlatform(): P2ptsPlatform {
  const p = process.platform as string;
  if (p === 'darwin') return 'macos';
  if (p === 'linux') return 'linux';
  if (p === 'win32') return 'windows';
  if (p === 'ios') return 'ios';
  if (p === 'android') return 'android';
  return 'unknown';
}

// ---------------------------------------------------------------------------
// P2PTS_HOME resolution
// ---------------------------------------------------------------------------

/**
 * Resolve P2PTS_HOME from environment variable or platform default.
 * Does NOT create directories — call `ensureP2ptsHome()` for that.
 */
export function resolveP2ptsHome(): string {
  // 1. Environment variable override.
  const env = process.env.P2PTS_HOME;
  if (env && env.trim().length > 0) {
    return env.trim();
  }

  const platform = detectPlatform();

  // 2. Platform defaults.
  switch (platform) {
    case 'macos':
      return join(homedir(), 'Library', 'Application Support', 'P2PTS');

    case 'linux': {
      const xdg = process.env.XDG_DATA_HOME;
      if (xdg && xdg.trim().length > 0) {
        return join(xdg.trim(), 'p2pts');
      }
      return join(homedir(), '.p2pts');
    }

    case 'windows': {
      const appData = process.env.APPDATA;
      if (appData && appData.trim().length > 0) {
        return join(appData.trim(), 'P2PTS');
      }
      // Fallback: construct from homedir.
      return join(homedir(), 'AppData', 'Roaming', 'P2PTS');
    }

    case 'ios':
      // On iOS, databases and keystores live in distinct locations
      // (Keychain for secrets, App Group container for databases).
      // This stub returns a sensible default for development; real
      // iOS integration requires native bridge.
      return join(homedir(), '.p2pts');

    case 'android':
      // Android Keystore + EncryptedSharedPreferences handle secrets;
      // this stub returns a sensible default for development.
      return join(homedir(), '.p2pts');

    default:
      return join(homedir(), '.p2pts');
  }
}

// ---------------------------------------------------------------------------
// Subdirectory paths
// ---------------------------------------------------------------------------

/**
 * Well-known subdirectory paths within P2PTS_HOME.
 * Computed from `resolveP2ptsHome()` unless overridden.
 */
export interface P2ptsPaths {
  /** The root P2PTS_HOME directory (e.g., ~/Library/Application Support/P2PTS). */
  p2ptsHome: string;
  /**
   * VTA parent directory holding one subdirectory per agent: P2PTS_HOME/vta/.
   * Each agent's database + keystore + tx-coordinator DB live in
   * `P2PTS_HOME/vta/<agentKey>/` (see {@link getVtaPaths}).
   */
  vtaDir: string;
  /** Per-app context directory: P2PTS_HOME/contexts/ */
  contextsDir: string;
  /** Name resolution cache directory: P2PTS_HOME/names/ */
  namesDir: string;
  /** Name resolution cache database: P2PTS_HOME/names/name-cache.db */
  nameCachePath: string;
  /** P2PTS config file: P2PTS_HOME/config.yaml */
  configPath: string;
}

/**
 * Compute all well-known paths under P2PTS_HOME.
 *
 * @param p2ptsHome  Optional override for the root directory.
 *                  Passed through to `resolveP2ptsHome()` if not provided.
 */
export function getP2ptsPaths(p2ptsHome?: string): P2ptsPaths {
  const home = p2ptsHome ?? resolveP2ptsHome();
  const vtaDir = join(home, 'vta');
  return {
    p2ptsHome: home,
    vtaDir,
    contextsDir: join(home, 'contexts'),
    namesDir: join(home, 'names'),
    nameCachePath: join(home, 'names', 'name-cache.db'),
    configPath: join(home, 'config.yaml'),
  };
}

// ---------------------------------------------------------------------------
// Per-VTA (per-agent) paths
// ---------------------------------------------------------------------------

/**
 * Per-agent directory layout.
 *
 * Each local agent identity gets its OWN subdirectory under P2PTS_HOME/vta/,
 * holding that identity's database, keystore and transaction-coordinator
 * database — so agents are isolated from one another on disk (no shared
 * database, no shared keystore, no shared write lock):
 *
 *   P2PTS_HOME/vta/<agentKey>/
 *   ├── p2pts-database.db      ← identities, did_documents, keys, relationships, credentials
 *   ├── p2pts-keystore.db      ← that identity's encrypted private keys
 *   └── tx-coordinator.db      ← that identity's transaction log + outbox
 *
 * `<agentKey>` is a filesystem-safe form of the agent NAME (the registry key
 * selected by AGENT_NAME). The directory name is IMMUTABLE once created: a
 * later name change (e.g. an alsoKnownAs rotation) must NOT rename it — the
 * authoritative DID/UUID lives inside the per-agent database.
 */
export interface VtaPaths {
  /** The agent's own directory: P2PTS_HOME/vta/<agentKey>/ */
  agentDir: string;
  /** P2PTS_HOME/vta/<agentKey>/p2pts-database.db */
  dbPath: string;
  /** P2PTS_HOME/vta/<agentKey>/p2pts-keystore.db */
  keystorePath: string;
  /** P2PTS_HOME/vta/<agentKey>/tx-coordinator.db */
  txDbPath: string;
}

/** Filenames used inside a per-agent directory. */
export const VTA_DB_FILENAME = 'p2pts-database.db';
export const VTA_KEYSTORE_FILENAME = 'p2pts-keystore.db';
export const VTA_TX_DB_FILENAME = 'tx-coordinator.db';

/**
 * Filesystem-safe directory segment for an agent name.
 *
 * AGENT_NAME is operator-supplied and becomes a directory name, so strip
 * anything that could traverse (`..`), hide (leading `.`), or contain
 * whitespace. An empty/unsafe name falls back to `default`.
 */
export function sanitizeAgentName(agentName: string): string {
  return agentName.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '_') || 'default';
}

/**
 * Compute the per-agent directory + file paths under P2PTS_HOME/vta/<agentKey>/.
 *
 * @param agentName  The agent's registry name (AGENT_NAME).
 * @param p2ptsHome  Optional P2PTS_HOME override.
 */
export function getVtaPaths(agentName: string, p2ptsHome?: string): VtaPaths {
  const home = p2ptsHome ?? resolveP2ptsHome();
  const agentDir = join(home, 'vta', sanitizeAgentName(agentName));
  return {
    agentDir,
    dbPath: join(agentDir, VTA_DB_FILENAME),
    keystorePath: join(agentDir, VTA_KEYSTORE_FILENAME),
    txDbPath: join(agentDir, VTA_TX_DB_FILENAME),
  };
}

/**
 * Ensure the per-agent directory exists (idempotent). Returns its path.
 */
export function ensureVtaDir(agentName: string, p2ptsHome?: string): string {
  const { agentDir } = getVtaPaths(agentName, p2ptsHome);
  mkdirSync(agentDir, { recursive: true });
  return agentDir;
}

/**
 * List the on-disk agent directories under P2PTS_HOME/vta/ that actually hold a
 * VTA database. Returns the sanitized agent keys (directory names), sorted.
 *
 * This is how agents are enumerated now that each has its own database — there
 * is no single shared database to query.
 */
export function listVtaAgentDirs(p2ptsHome?: string): string[] {
  const vtaDir = join(p2ptsHome ?? resolveP2ptsHome(), 'vta');
  let entries: string[];
  try {
    entries = readdirSync(vtaDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name);
  } catch {
    return [];
  }
  return entries
    .filter((name) => existsSync(join(vtaDir, name, VTA_DB_FILENAME)))
    .sort();
}

// ---------------------------------------------------------------------------
// Directory creation
// ---------------------------------------------------------------------------

/**
 * Ensure the full P2PTS_HOME directory structure exists.
 *
 * Creates (if they don't already exist):
 * - P2PTS_HOME/
 * - P2PTS_HOME/vta/
 * - P2PTS_HOME/contexts/
 * - P2PTS_HOME/names/
 *
 * Idempotent — safe to call multiple times.
 *
 * @param p2ptsHome  Optional override for the root directory.
 * @returns The resolved P2PTS_HOME path.
 */
export function ensureP2ptsHome(p2ptsHome?: string): string {
  const home = p2ptsHome ?? resolveP2ptsHome();

  mkdirSync(home, { recursive: true });
  mkdirSync(join(home, 'vta'), { recursive: true });
  mkdirSync(join(home, 'contexts'), { recursive: true });
  mkdirSync(join(home, 'names'), { recursive: true });

  return home;
}

// ---------------------------------------------------------------------------
// Context-specific paths
// ---------------------------------------------------------------------------

/**
 * Compute paths for a specific app context.
 *
 * @param contextId  The context identifier (e.g., "agent-tui", "fiduciary-ai").
 * @param p2ptsHome   Optional P2PTS_HOME override.
 */
export function getContextPaths(
  contextId: string,
  p2ptsHome?: string,
): {
  contextDir: string;
  keystorePath: string;
  dbPath: string;
} {
  const paths = getP2ptsPaths(p2ptsHome);
  const contextDir = join(paths.contextsDir, contextId);
  return {
    contextDir,
    keystorePath: join(contextDir, 'context-keystore.db'),
    dbPath: join(contextDir, 'context-database.db'),
  };
}

/**
 * Ensure a specific context directory tree exists.
 *
 * Creates (if they don't already exist):
 * - P2PTS_HOME/contexts/<contextId>/
 *
 * Idempotent — safe to call multiple times.
 *
 * @param contextId  The context identifier.
 * @param p2ptsHome   Optional P2PTS_HOME override.
 * @returns The context directory path.
 */
export function ensureContextDir(
  contextId: string,
  p2ptsHome?: string,
): string {
  const { contextDir } = getContextPaths(contextId, p2ptsHome);
  mkdirSync(contextDir, { recursive: true });
  return contextDir;
}

// ---------------------------------------------------------------------------
// Config YAML (minimal)
// ---------------------------------------------------------------------------

/**
 * Shape of the P2PTS config.yaml file.
 * In the full implementation this will be a comprehensive config schema;
 * for Phase 1 we define the minimum set of fields.
 */
export interface P2ptsConfig {
  bootstrap_urls: string[];
  default_vta_name: string;
  utility_server_url: string;
  passphrase_session_timeout_sec: number;
}

const DEFAULT_CONFIG: P2ptsConfig = {
  bootstrap_urls: [],
  default_vta_name: '',
  utility_server_url: '',
  passphrase_session_timeout_sec: 900,
};

/**
 * Load P2PTS config from P2PTS_HOME/config.yaml.
 * Returns defaults for any missing fields.
 */
export function loadP2ptsConfig(p2ptsHome?: string): P2ptsConfig {
  const configPath = join(p2ptsHome ?? resolveP2ptsHome(), 'config.yaml');

  if (!existsSync(configPath)) {
    return { ...DEFAULT_CONFIG };
  }

  try {
    const raw = readFileSync(configPath, 'utf-8');
    // Minimal YAML parsing — for Phase 1 we support a flat key: value format.
    // A full YAML parser (e.g., `yaml` npm package) should replace this
    // when config complexity grows.
    const parsed = parseSimpleYaml(raw);
    return {
      bootstrap_urls: parseStringArray(parsed.bootstrap_urls) ?? DEFAULT_CONFIG.bootstrap_urls,
      default_vta_name: typeof parsed.default_vta_name === 'string'
        ? parsed.default_vta_name
        : DEFAULT_CONFIG.default_vta_name,
      utility_server_url: typeof parsed.utility_server_url === 'string'
        ? parsed.utility_server_url
        : DEFAULT_CONFIG.utility_server_url,
      passphrase_session_timeout_sec: typeof parsed.passphrase_session_timeout_sec === 'number'
        ? parsed.passphrase_session_timeout_sec
        : DEFAULT_CONFIG.passphrase_session_timeout_sec,
    };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

/**
 * Save P2PTS config to P2PTS_HOME/config.yaml.
 */
export function saveP2ptsConfig(config: P2ptsConfig, p2ptsHome?: string): void {
  const configPath = join(p2ptsHome ?? resolveP2ptsHome(), 'config.yaml');

  const lines: string[] = [
    '# P2PTS Configuration',
    '# See docs/one-scid-many-apps-architecture.md §1.3',
    '',
    `bootstrap_urls:`,
  ];
  for (const url of config.bootstrap_urls) {
    lines.push(`  - ${url}`);
  }
  lines.push(`default_vta_name: "${config.default_vta_name}"`);
  lines.push(`utility_server_url: "${config.utility_server_url}"`);
  lines.push(`passphrase_session_timeout_sec: ${config.passphrase_session_timeout_sec}`);
  lines.push('');

  writeFileSync(configPath, lines.join('\n'), 'utf-8');
}

// ---------------------------------------------------------------------------
// Minimal YAML parser (flat key: value only)
// ---------------------------------------------------------------------------

function parseSimpleYaml(raw: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  let currentKey = '';

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    // Array item: "- value"
    const arrayMatch = trimmed.match(/^-\s+(.+)$/);
    if (arrayMatch && currentKey) {
      // Lazily initialize array if this is the first array item for this key.
      if (!Array.isArray(result[currentKey])) {
        result[currentKey] = [];
      }
      const arr = result[currentKey] as string[];
      arr.push(arrayMatch[1].replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1'));
      continue;
    }

    // Key: value (value is optional for empty keys like `bootstrap_urls:`)
    const kvMatch = trimmed.match(/^(\w[\w_]*)\s*:\s*(.*)$/);
    if (kvMatch) {
      const key = kvMatch[1];
      const rawValue = kvMatch[2].trim();
      currentKey = key;

      // Remove surrounding quotes.
      const val = rawValue.replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');

      // Empty string value → prepare for array items.
      if (val === '') {
        result[key] = []; // Will be populated by array items on subsequent lines.
        continue;
      }

      // Try numeric parsing.
      const num = Number(val);
      if (!Number.isNaN(num)) {
        result[key] = num;
      } else if (val === 'true' || val === 'false') {
        result[key] = val === 'true';
      } else {
        result[key] = val;
      }
    }
  }

  return result;
}

function parseStringArray(value: unknown): string[] | undefined {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  return undefined;
}

// ---------------------------------------------------------------------------
// Existing data migration
// ---------------------------------------------------------------------------
//
// The previous shared-database layout (one P2PTS_HOME/vta/p2pts-database.db for
// every agent) is no longer supported: each agent now owns its own directory
// under P2PTS_HOME/vta/<agentKey>/ (see getVtaPaths). There is deliberately no
// automatic migration — the project is pre-release and databases are
// regenerated. Delete any old shared `p2pts-database.db` / `p2pts-keystore.db`
// left directly in P2PTS_HOME/vta/.
