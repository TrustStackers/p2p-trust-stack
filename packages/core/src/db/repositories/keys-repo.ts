/**
 * Repository: keys table.
 *
 * Public key material for identities. encrypted_secret_key is NULL when
 * custody='remote' (keys pushed from agent-app without secret material).
 * identity_uuid and did_document_uuid are the distributed FK targets.
 * uuid is the table's PRIMARY KEY (uuid-first schema, migration 0018).
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export type KeyType = 'ed25519' | 'x25519' | 'ml_dsa_65' | 'mlkem768_x25519';

export interface KeyRow {
  uuid: string;
  identityUuid: string;
  didDocumentUuid: string | null;
  keyType: KeyType;
  publicKey: Buffer;
  encryptedSecretKey: Buffer | null;
  salt: Buffer | null;
  nonce: Buffer | null;
  authTag: Buffer | null;
  rotationVersion: number;
  recordedByNode: string | null;
  replicatedAt: number | null;
  createdAt: number | null;
}

export interface CreateKeyInput {
  identityUuid: string;
  didDocumentUuid?: string;
  keyType: KeyType;
  publicKey: Buffer;
  encryptedSecretKey?: Buffer;
  salt?: Buffer;
  nonce?: Buffer;
  authTag?: Buffer;
  rotationVersion?: number;
  recordedByNode?: string;
  replicatedAt?: number;
}

export interface CreateKeyWithSecretInput {
  identityUuid: string;
  didDocumentUuid?: string;
  keyType: KeyType;
  publicKey: Uint8Array;
  encryptedSecretKey: Uint8Array;
  salt: Uint8Array;
  nonce: Uint8Array;
  authTag: Uint8Array;
}

interface KeyDbRow {
  uuid: string;
  identity_uuid: string;
  did_document_uuid: string | null;
  key_type: string;
  public_key: Buffer;
  encrypted_secret_key: Buffer | null;
  salt: Buffer | null;
  nonce: Buffer | null;
  auth_tag: Buffer | null;
  rotation_version: number;
  recorded_by_node: string | null;
  replicated_at: number | null;
  created_at: number | null;
}

function rowToKey(row: KeyDbRow): KeyRow {
  return {
    uuid: row.uuid,
    identityUuid: row.identity_uuid,
    didDocumentUuid: row.did_document_uuid,
    keyType: row.key_type as KeyType,
    publicKey: row.public_key,
    encryptedSecretKey: row.encrypted_secret_key,
    salt: row.salt,
    nonce: row.nonce,
    authTag: row.auth_tag,
    rotationVersion: row.rotation_version,
    recordedByNode: row.recorded_by_node,
    replicatedAt: row.replicated_at,
    createdAt: row.created_at,
  };
}

/** Create a key row. Returns the new row's uuid (the PRIMARY KEY). */
export async function create(db: DataSource, input: CreateKeyInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const rowUuid = generateUuid();

  const result = await db.run(
    `INSERT INTO keys (identity_uuid, did_document_uuid, key_type, public_key, encrypted_secret_key, salt, nonce, auth_tag, rotation_version, uuid, recorded_by_node, replicated_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    input.identityUuid,
    input.didDocumentUuid ?? null,
    input.keyType,
    input.publicKey,
    input.encryptedSecretKey ?? null,
    input.salt ?? null,
    input.nonce ?? null,
    input.authTag ?? null,
    input.rotationVersion ?? 0,
    rowUuid,
    input.recordedByNode ?? null,
    input.replicatedAt ?? null,
    now,
  );

  void result;
  return rowUuid;
}

/**
 * Create key row with pre-encrypted secret material.
 * Encryption (Argon2id + AES-256-GCM) is handled by the caller using
 * the exported encryptSecretKey() from src/keystore/sqlite-keystore.ts.
 */
export function createWithSecret(
  db: DataSource,
  input: CreateKeyWithSecretInput,
): Promise<string> {
  return create(db, {
    identityUuid: input.identityUuid,
    didDocumentUuid: input.didDocumentUuid,
    keyType: input.keyType,
    publicKey: Buffer.from(input.publicKey),
    encryptedSecretKey: Buffer.from(input.encryptedSecretKey),
    salt: Buffer.from(input.salt),
    nonce: Buffer.from(input.nonce),
    authTag: Buffer.from(input.authTag),
  });
}

export async function findByUuid(db: DataSource, uuid: string): Promise<KeyRow | null> {
  const row = await db.get<KeyDbRow>('SELECT * FROM keys WHERE uuid = ?', uuid);
  return row ? rowToKey(row) : null;
}

export async function findByIdentityUuid(db: DataSource, identityUuid: string): Promise<KeyRow[]> {
  const rows = await db.all<KeyDbRow>('SELECT * FROM keys WHERE identity_uuid = ? ORDER BY key_type, rotation_version', identityUuid);
  return rows.map(rowToKey);
}

/**
 * Every Ed25519 public key registered for an identity.
 *
 * An identity can legitimately hold MORE THAN ONE (its authoritative did:scid:vh key plus
 * the did:peer:4 relationship-handshake stub's, both at `rotation_version` 0), and
 * `findByIdentityUuid` orders only by `(key_type, rotation_version)` — so "the first
 * Ed25519 key" is ARBITRARY. A verifier must try them all; taking the first silently
 * rejects valid signatures roughly half the time.
 */
export async function findEd25519KeysByIdentity(db: DataSource, identityUuid: string): Promise<Uint8Array[]> {
  const rows = await findByIdentityUuid(db, identityUuid);
  return rows
    .filter((k) => k.keyType === 'ed25519' && k.publicKey)
    .map((k) => new Uint8Array(k.publicKey as Uint8Array));
}

export async function findCurrentKeys(
  db: DataSource,
  identityUuid: string,
): Promise<KeyRow[]> {
  const rows = await db.all<KeyDbRow>(`
    SELECT k.* FROM keys k
    INNER JOIN (
      SELECT key_type, MAX(rotation_version) as max_version
      FROM keys WHERE identity_uuid = ?
      GROUP BY key_type
    ) latest ON k.key_type = latest.key_type AND k.rotation_version = latest.max_version
    WHERE k.identity_uuid = ?
  `, identityUuid, identityUuid);
  return rows.map(rowToKey);
}

/**
 * Upsert public-only key from replication (no secret material).
 * Returns the row uuid (the PRIMARY KEY).
 */
export async function upsertPublicKeyFromReplication(
  db: DataSource,
  input: CreateKeyInput & { recordedByNode: string; replicatedAt: number },
): Promise<string> {
  // Atomic upsert on the full unique tuple. The previous SELECT-then-create
  // raced under concurrent replication events (both sides see "absent"), so the
  // loser INSERT violated the unique constraint instead of merging — same bug
  // class as the identity_push race in syncRemotePublicKeys().
  const now = Math.floor(Date.now() / 1000);
  const rotationVersion = input.rotationVersion ?? 0;
  const rowUuid = generateUuid();

  // Replication: only store public_key, never encrypted_secret_key
  const row = await db.get<{ uuid: string }>(
    `INSERT INTO keys (identity_uuid, did_document_uuid, key_type, public_key, rotation_version, uuid, recorded_by_node, replicated_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (identity_uuid, did_document_uuid, key_type, rotation_version)
     DO UPDATE SET
       public_key        = excluded.public_key,
       did_document_uuid = COALESCE(excluded.did_document_uuid, keys.did_document_uuid),
       recorded_by_node  = excluded.recorded_by_node,
       replicated_at     = excluded.replicated_at
     RETURNING uuid`,
    input.identityUuid,
    input.didDocumentUuid ?? null,
    input.keyType,
    input.publicKey,
    rotationVersion,
    rowUuid,
    input.recordedByNode,
    input.replicatedAt,
    now,
  );
  return row?.uuid ?? rowUuid;
}

/**
 * Find the current (latest rotation version) key of a given type for a DID document.
 */
export async function findCurrentForDidDocument(
  db: DataSource,
  didDocumentUuid: string,
  keyType: KeyType,
): Promise<KeyRow | null> {
  const row = await db.get<KeyDbRow>(`
    SELECT * FROM keys
    WHERE did_document_uuid = ? AND key_type = ?
    ORDER BY rotation_version DESC
    LIMIT 1
  `, didDocumentUuid, keyType);
  return row ? rowToKey(row) : null;
}
