/**
 * ContextManager — manages scoped, revocable app contexts provisioned from
 * the root VTA identity (Phase 3: Context Registry).
 *
 * Each app context receives an HKDF-derived keypair, scoped to a named
 * context. Apps NEVER touch the root keypair. Context keys are derived
 * deterministically (HKDF from root key + contextId) so any device with
 * the root key can re-derive them. Alternatively, context keys can be
 * generated randomly per-device for stronger isolation.
 *
 * Storage:
 *   P2PTS_HOME/contexts/<contextId>/
 *   ├── context-keystore.db   — HKDF-derived signing + agreement keys
 *   └── context-database.db   — App-scoped: relationships, messages, profiles
 */

import { createHmac, createHash } from 'node:crypto';
import { existsSync, unlinkSync, rmSync, readdirSync } from 'node:fs';
import { generateEd25519KeyPairFromSeed, type Ed25519KeyPair } from '@p2p-trust-stack/core/crypto/primitives.js';
import { cesrEncode } from '@p2p-trust-stack/core/crypto/cesr.js';
import { CESR_CODES } from '@p2p-trust-stack/core/crypto/codes.js';
import {
  getP2ptsPaths,
  getContextPaths,
  ensureContextDir,
} from '@p2p-trust-stack/core/platform/p2pts-home.js';
import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { openDatabase } from '@p2p-trust-stack/core/db/connection.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AppContext {
  contextId: string;
  allowedKeyIds: string[];
  expiresAt?: number;
  createdAt: number;
  deviceId?: string;
  deviceLocal: boolean;
}

/**
 * What a provisioned app context hands BACK to its caller.
 *
 * **Audit F-021 / ruling Y1 (2026-09-24): a private key never crosses this boundary.**
 *
 * This used to carry `contextSigningKey` and `contextAgreementKey` as raw
 * `Uint8Array` secret-key bytes, immediately after storing the same keys in the
 * context's own keystore — so the isolated copy was defeated by the one it was also
 * handed to. The caller receives **public** identifiers only:
 *
 *   - `contextSigningVid` / `contextAgreementVid` — CESR-encoded public keys, the
 *     context's own identity (what a peer or a roster refers to);
 *   - `keystorePath` — where the private half lives, for a process that owns the
 *     context and has its passphrase.
 *
 * If something genuinely needs a *signature*, the pattern is "use, don't export":
 * open the context keystore (the caller has the passphrase) or ask the context to
 * sign. Handing out the bytes would let a context's key be used after the context is
 * revoked — which is precisely what `revoke()` deletes the directory to prevent.
 */
export interface AppCredentialBundle {
  contextId: string;
  contextDid: string;
  /** CESR-encoded Ed25519 PUBLIC key of the context's signing key (its VID). */
  contextSigningVid: string;
  /** CESR-encoded X25519 PUBLIC key of the context's agreement key (its VID). */
  contextAgreementVid: string;
  /** Where the private halves live. They are NOT returned to the caller. */
  keystorePath: string;
  /** Always true — spelled out so the contract is visible at the type level. */
  keysStayInContext: true;
  vtaEndpoint?: string;
  allowedKeyIds: string[];
  expiresAt?: number;
}

export interface ProvisionAppOptions {
  allowedKeyIds?: string[];
  expiresAt?: number;
  deviceLocal?: boolean;
  deviceId?: string;
  passphrase: string;
}

// ---------------------------------------------------------------------------
// Migrations directory
// ---------------------------------------------------------------------------

const __migrationsDir = getMigrationsDir();

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// HKDF Key Derivation
// ---------------------------------------------------------------------------
//
// The `info` strings below are HKDF domain separators. They are deterministic on
// purpose: any device holding the same root key re-derives the SAME context key for
// a given contextId (see docs/one-scid-many-apps-architecture.md), which is what
// lets a context exist across devices without shipping private keys around.
//
// Consequence for changing them: because derivation is deterministic, editing these
// strings changes EVERY context key. All devices holding a root key must therefore be
// updated together — a device left on the old string derives a different key for the
// same context, and that context would present two different DIDs. That is a
// coordinated-release constraint, not a data-loss one: with no persistent data,
// re-provisioning rebuilds everything.
//
// Nothing else depends on the literal text: derived keys live only in the local
// per-context keystore, no verifier re-derives them (verification uses the published
// public key), and no golden test vector pins a derived value.

export function deriveContextSigningKey(
  rootSigningKey: Ed25519KeyPair,
  contextId: string,
): Ed25519KeyPair {
  return hkdfDeriveEd25519(
    rootSigningKey.secretKey,
    `p2pts-context:${contextId}:sign`,
  );
}

export function deriveContextAgreementKey(
  rootAgreementKey: Ed25519KeyPair,
  contextId: string,
): Ed25519KeyPair {
  return hkdfDeriveEd25519(
    rootAgreementKey.secretKey,
    `p2pts-context:${contextId}:agree`,
  );
}

function hkdfDeriveEd25519(
  rootSecretKey: Uint8Array,
  info: string,
): Ed25519KeyPair {
  const prk = createHash('sha256').update(rootSecretKey).digest();
  const infoBytes = Buffer.from(info, 'utf-8');
  const t1 = createHmac('sha256', prk)
    .update(Buffer.concat([infoBytes, Buffer.from([0x01])]))
    .digest();

  // FIX (2026-10-09): derive the public half with the codebase's own primitive.
  //
  // What was here before was broken twice over:
  //
  //   1. It called `createPrivateKey` with an OKP/Ed25519 JWK carrying only `d`. Node requires BOTH `x` and `d`
  //      for a JWK private key — it does not derive `x` from `d` — so this threw
  //      `ERR_INVALID_ARG_TYPE: The "key.x" property must be of type string` EVERY time. Context provisioning
  //      therefore failed for every caller that did not pass `deviceLocal: true` — and `deviceLocal` DEFAULTS TO
  //      FALSE, so the default path was the broken one. It went unnoticed because the only test
  //      (`test/agent/context-provisioning.test.ts`, F-021) opts into `deviceLocal: true`.
  //
  //   2. It assembled a 64-byte secret key (seed ‖ public). This codebase's Ed25519 secret key is the 32-byte
  //      RFC 8032 seed — `ED25519_SECRET_KEY_BYTES` is 32, `signMessage` REJECTS any other length
  //      (`src/tsp/v3/message.ts`), and the agent's own identity keys are 32 bytes. So even had the key been
  //      built, it could not have signed anything.
  //
  // `generateEd25519KeyPairFromSeed` is the primitive that already does exactly this correctly, and it is what
  // the rest of the codebase uses to seed deterministic identity keys.
  return generateEd25519KeyPairFromSeed(t1);
}

// ---------------------------------------------------------------------------
// ContextManager
// ---------------------------------------------------------------------------

export class ContextManager {
  readonly contextId: string;
  private readonly p2ptsHome?: string;
  readonly contextDir: string;
  readonly keystorePath: string;
  readonly dbPath: string;

  constructor(contextId: string, p2ptsHome?: string) {
    this.contextId = contextId;
    this.p2ptsHome = p2ptsHome;
    const paths = getContextPaths(contextId, p2ptsHome);
    this.contextDir = paths.contextDir;
    this.keystorePath = paths.keystorePath;
    this.dbPath = paths.dbPath;
  }

  async provision(
    rootSigningKey: Ed25519KeyPair,
    rootAgreementKey: Ed25519KeyPair,
    options: ProvisionAppOptions,
  ): Promise<AppCredentialBundle> {
    ensureContextDir(this.contextId, this.p2ptsHome);

    if (existsSync(this.keystorePath)) {
      const ks = new SqliteKeyStore(this.keystorePath);
      try {
        const existing = await ks.retrieveKeyPairAsync(
          this.contextId, 'ed25519', options.passphrase,
        ).catch(() => undefined);
        if (existing) {
          throw new Error(
            `ContextManager.provision: context "${this.contextId}" already exists.`,
          );
        }
      } finally {
        ks.close();
      }
    }

    let contextSigningKey: Ed25519KeyPair;
    let contextAgreementKey: Ed25519KeyPair;

    if (options.deviceLocal) {
      const { generateEd25519KeyPair } = await import(
        '@p2p-trust-stack/core/crypto/primitives.js'
      );
      contextSigningKey = generateEd25519KeyPair();
      contextAgreementKey = generateEd25519KeyPair();
    } else {
      contextSigningKey = deriveContextSigningKey(rootSigningKey, this.contextId);
      contextAgreementKey = deriveContextAgreementKey(rootAgreementKey, this.contextId);
    }

    const keystore = new SqliteKeyStore(this.keystorePath);
    try {
      await keystore.storeKeyPairAsync(
        this.contextId, 'ed25519', contextSigningKey, options.passphrase,
      );
      await keystore.storeKeyPairAsync(
        this.contextId, 'x25519', contextAgreementKey, options.passphrase,
      );
    } finally {
      keystore.close();
    }

    const contextDb = openDatabase(this.dbPath);
    try {
      const applied = runMigrations(contextDb, __migrationsDir);
      if (applied.length > 0) {
        console.log(
          `[ContextManager] Applied ${applied.length} migration(s) to context "${this.contextId}"`,
        );
      }

      const metadata = JSON.stringify({
        contextId: this.contextId,
        allowedKeyIds: options.allowedKeyIds ?? ['#key-1'],
        expiresAt: options.expiresAt ?? null,
        createdAt: Math.floor(Date.now() / 1000),
        deviceId: options.deviceId ?? null,
        deviceLocal: options.deviceLocal ?? false,
      });

      contextDb.prepare(`
        CREATE TABLE IF NOT EXISTS context_metadata (
          key   TEXT PRIMARY KEY,
          value TEXT NOT NULL
        )
      `).run();

      contextDb.prepare(
        'INSERT OR REPLACE INTO context_metadata (key, value) VALUES (?, ?)',
      ).run('context_metadata', metadata);
    } finally {
      contextDb.close();
    }

    return {
      contextId: this.contextId,
      contextDid: '',
      // F-021 / Y1: PUBLIC identifiers only. The private halves were just written to
      // this context's keystore and stay there — returning them defeated the isolation.
      contextSigningVid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, contextSigningKey.publicKey),
      contextAgreementVid: cesrEncode(CESR_CODES.X25519_PUBLIC_KEY, contextAgreementKey.publicKey),
      keystorePath: this.keystorePath,
      keysStayInContext: true,
      allowedKeyIds: options.allowedKeyIds ?? ['#key-1'],
      expiresAt: options.expiresAt,
    };
  }

  async revoke(): Promise<void> {
    if (existsSync(this.keystorePath)) unlinkSync(this.keystorePath);
    if (existsSync(this.dbPath)) unlinkSync(this.dbPath);
    try {
      rmSync(this.contextDir, { recursive: true, force: true });
    } catch {
      console.warn(`[ContextManager] Could not fully remove context directory: ${this.contextDir}`);
    }
  }

  getMetadata(): AppContext | undefined {
    if (!existsSync(this.dbPath)) return undefined;
    const db = openDatabase(this.dbPath);
    try {
      const row = db.prepare(
        "SELECT value FROM context_metadata WHERE key = 'context_metadata'",
      ).get() as { value: string } | undefined;
      if (!row) return undefined;
      return JSON.parse(row.value) as AppContext;
    } catch {
      return undefined;
    } finally {
      db.close();
    }
  }

  exists(): boolean {
    return existsSync(this.keystorePath);
  }

  isExpired(): boolean {
    const meta = this.getMetadata();
    if (!meta?.expiresAt) return false;
    return Math.floor(Date.now() / 1000) >= meta.expiresAt;
  }
}

// ---------------------------------------------------------------------------
// Utility: list all provisioned contexts
// ---------------------------------------------------------------------------

export function listProvisionedApps(p2ptsHome?: string): AppContext[] {
  const paths = getP2ptsPaths(p2ptsHome);
  const contextsDir = paths.contextsDir;

  let entries: string[];
  try {
    entries = readdirSync(contextsDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name);
  } catch {
    return [];
  }

  const contexts: AppContext[] = [];
  for (const contextId of entries) {
    const mgr = new ContextManager(contextId, p2ptsHome);
    const meta = mgr.getMetadata();
    if (meta) contexts.push(meta);
  }
  return contexts;
}