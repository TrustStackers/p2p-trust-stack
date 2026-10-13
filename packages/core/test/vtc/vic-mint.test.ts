/**
 * Tests for community signing-key persistence (Model A custody):
 * DidManager.resolveCommunitySigningKey round-trips the encrypted Ed25519 key
 * persisted at createVtc.
 *
 * The signed VIC itself is now minted by the `member-invitation` CEREMONY, so its
 * coverage lives beside the ceremony executor in the utility test tree
 * (utility-server/test/tx/ceremony-invitation.test.ts) rather than here.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/vtc/vic-mint.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

import { runMigrations } from '../../src/db/migrate.js';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import * as identitiesRepo from '../../src/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '../../src/db/repositories/did-documents-repo.js';
import * as keysRepo from '../../src/db/repositories/keys-repo.js';
import { DidManager, COMMUNITY_KEY_PASSPHRASE } from '../../src/services/did-manager.js';
import { generateEd25519KeyPair } from '../../src/crypto/primitives.js';
import { encryptSecretKey } from '../../src/keystore/sqlite-keystore.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = getMigrationsDir();

async function makeDb(): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

async function createIdentity(
  ds: SqliteDataSource,
  realDid: string,
  role: 'vtc' | 'vtn' | 'vta',
  name: string,
): Promise<{ identity: ReturnType<typeof identitiesRepo.findByUuid> extends Promise<infer T> ? T : never; docUuid: string }> {
  const uuid = await identitiesRepo.create(ds, { realDid, role, custody: 'local', name });
  const docUuid = await didDocumentsRepo.create(ds, {
    identityUuid: uuid,
    did: realDid,
    method: 'peer4',
    documentJson: '{}',
    isPrimary: true,
  });
  const identity = await identitiesRepo.findByUuid(ds, uuid);
  if (!identity) throw new Error('identity not found after create');
  return { identity, docUuid };
}

test('resolveCommunitySigningKey round-trips an encrypted community Ed25519 key', async () => {
  const ds = await makeDb();
  const did = 'did:peer:4:testCommunityKey';

  const { identity: community, docUuid } = await createIdentity(ds, did, 'vtc', 'Test VTC');

  const kp = generateEd25519KeyPair();
  const enc = await encryptSecretKey(kp.secretKey, COMMUNITY_KEY_PASSPHRASE);
  await keysRepo.createWithSecret(ds, {
    identityUuid: community.uuid,
    didDocumentUuid: docUuid,
    keyType: 'ed25519',
    publicKey: kp.publicKey,
    encryptedSecretKey: enc.ciphertext,
    salt: enc.salt,
    nonce: enc.nonce,
    authTag: enc.authTag,
  });

  const dm = new DidManager(ds);
  const key = await dm.resolveCommunitySigningKey(community.uuid);
  assert.ok(key, 'expected a resolvable community signing key');
  assert.equal(key!.did, did);
  assert.deepEqual(Array.from(key!.signerSecretKey), Array.from(kp.secretKey));
  assert.equal(key!.verificationMethod, `${did}#key-1`);
  assert.ok(key!.vid.startsWith('D'), 'vid should be a CESR Ed25519 public key');
});
