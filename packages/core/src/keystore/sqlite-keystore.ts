/**
 * SQLite-backed secure key store — Step 2.
 *
 * Stores Ed25519 and X25519 key pairs encrypted at rest using:
 *   - Argon2id KDF (@node-rs/argon2) to derive a 32-byte AES key from a passphrase
 *   - AES-256-GCM (node:crypto) for authenticated encryption of the secret key
 *   - node:sqlite (DatabaseSync) for storage — no native module required
 *
 * Schema:
 *   keys (id INTEGER PK, vid TEXT, key_type TEXT, public_key BLOB,
 *         encrypted_secret_key BLOB, salt BLOB, nonce BLOB, auth_tag BLOB,
 *         created_at INTEGER)
 *
 * Wrong passphrase → Argon2-derived key mismatch → AES-GCM auth tag
 * verification fails → throws an error (no silent data corruption).
 */

import { DatabaseSync } from 'node:sqlite';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { hashRaw, Algorithm } from '@node-rs/argon2';
import type { KeyStore, KeyType, RawKeyPair } from './types.js';

// ---------------------------------------------------------------------------
// Argon2id parameters
// ---------------------------------------------------------------------------

const ARGON2_OUTPUT_LEN = 32; // 256-bit AES key
const ARGON2_MEMORY_COST = 19456; // 19 MiB (OWASP recommended minimum)
const ARGON2_TIME_COST = 2;
const ARGON2_PARALLELISM = 1;
const SALT_BYTES = 16;
const NONCE_BYTES = 12; // 96-bit nonce for AES-256-GCM

// ---------------------------------------------------------------------------
// Encryption / decryption helpers
// ---------------------------------------------------------------------------

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<Uint8Array> {
  return hashRaw(passphrase, {
    salt,
    outputLen: ARGON2_OUTPUT_LEN,
    algorithm: Algorithm.Argon2id,
    memoryCost: ARGON2_MEMORY_COST,
    timeCost: ARGON2_TIME_COST,
    parallelism: ARGON2_PARALLELISM,
  });
}

interface EncryptedBlob {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  authTag: Uint8Array;
  salt: Uint8Array;
}

export async function encryptSecretKey(
  secretKey: Uint8Array,
  passphrase: string,
): Promise<EncryptedBlob> {
  const salt = new Uint8Array(randomBytes(SALT_BYTES));
  const nonce = new Uint8Array(randomBytes(NONCE_BYTES));
  const aesKey = await deriveKey(passphrase, salt);

  const cipher = createCipheriv('aes-256-gcm', aesKey, nonce);
  const ciphertext = Buffer.concat([cipher.update(secretKey), cipher.final()]);
  const authTag = new Uint8Array(cipher.getAuthTag());

  return { ciphertext: new Uint8Array(ciphertext), nonce, authTag, salt };
}

export async function decryptSecretKey(
  blob: EncryptedBlob,
  passphrase: string,
): Promise<Uint8Array> {
  const aesKey = await deriveKey(passphrase, blob.salt);

  const decipher = createDecipheriv('aes-256-gcm', aesKey, blob.nonce);
  decipher.setAuthTag(blob.authTag);

  try {
    const plaintext = Buffer.concat([decipher.update(blob.ciphertext), decipher.final()]);
    return new Uint8Array(plaintext);
  } catch {
    throw new Error('KeyStore: decryption failed — wrong passphrase or corrupted data');
  }
}

// ---------------------------------------------------------------------------
// SqliteKeyStore
// ---------------------------------------------------------------------------

/**
 * SQLite-backed implementation of KeyStore.
 *
 * @param dbPath  Path to the SQLite database file, or ':memory:' for an
 *                in-memory database (useful for tests).
 */
export class SqliteKeyStore implements KeyStore {
  private db: InstanceType<typeof DatabaseSync>;
  private readonly ownsDb: boolean;

  /**
   * @param dbPathOrHandle  Path to the SQLite database file, ':memory:' for an
   *                        in-memory database, or an existing DatabaseSync handle
   *                        to share a connection.
   */
  constructor(dbPathOrHandle: string | InstanceType<typeof DatabaseSync>) {
    if (typeof dbPathOrHandle === 'string') {
      this.db = new DatabaseSync(dbPathOrHandle);
      this.ownsDb = true;
    } else {
      this.db = dbPathOrHandle;
      this.ownsDb = false;
    }
    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS keystore_keys (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        vid                   TEXT    NOT NULL,
        key_type              TEXT    NOT NULL,
        public_key            BLOB    NOT NULL,
        encrypted_secret_key  BLOB    NOT NULL,
        salt                  BLOB    NOT NULL,
        nonce                 BLOB    NOT NULL,
        auth_tag              BLOB    NOT NULL,
        created_at            INTEGER NOT NULL DEFAULT (unixepoch()),
        UNIQUE(vid, key_type)
      )
    `);
  }

  /**
   * Encrypt and store a key pair for the given VID and key type.
   *
   * Argon2 KDF is async, so the KeyStore interface exposes only the async
   * variant. Use this in all application code.
   */
  async storeKeyPairAsync(
    vid: string,
    keyType: KeyType,
    keyPair: RawKeyPair,
    passphrase: string,
  ): Promise<void> {
    const { ciphertext, nonce, authTag, salt } = await encryptSecretKey(
      keyPair.secretKey,
      passphrase,
    );

    this.db
      .prepare(
        `INSERT INTO keystore_keys (vid, key_type, public_key, encrypted_secret_key, salt, nonce, auth_tag)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(vid, key_type) DO UPDATE SET
           public_key = excluded.public_key,
           encrypted_secret_key = excluded.encrypted_secret_key,
           salt = excluded.salt,
           nonce = excluded.nonce,
           auth_tag = excluded.auth_tag,
           created_at = unixepoch()`,
      )
      .run(
        vid,
        keyType,
        keyPair.publicKey,
        ciphertext,
        salt,
        nonce,
        authTag,
      );
  }

  /**
   * Retrieve and decrypt a key pair for the given VID and key type.
   *
   * Argon2 KDF is async, so the KeyStore interface exposes only the async
   * variant. Use this in all application code.
   */
  async retrieveKeyPairAsync(
    vid: string,
    keyType: KeyType,
    passphrase: string,
  ): Promise<RawKeyPair> {
    const row = this.db
      .prepare(
        `SELECT public_key, encrypted_secret_key, salt, nonce, auth_tag
         FROM keystore_keys WHERE vid = ? AND key_type = ?`,
      )
      .get(vid, keyType) as {
        public_key: Uint8Array;
        encrypted_secret_key: Uint8Array;
        salt: Uint8Array;
        nonce: Uint8Array;
        auth_tag: Uint8Array;
      } | undefined;

    if (!row) {
      throw new Error(`KeyStore: no key found for vid="${vid}" keyType="${keyType}"`);
    }

    const secretKey = await decryptSecretKey(
      {
        ciphertext: row.encrypted_secret_key,
        nonce: row.nonce,
        authTag: row.auth_tag,
        salt: row.salt,
      },
      passphrase,
    );

    return { secretKey, publicKey: row.public_key };
  }

  close(): void {
    if (this.ownsDb) {
      this.db.close();
    }
  }
}
