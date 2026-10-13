/**
 * The sender binding, made real (F-010 / R1 follow-up, 2026-09-25).
 *
 * The field log showed every cross-node prepare judged `invalid actor=DIdB25_WgIXu… but the
 * message came from did:scid:vh:…` — a CESR VID compared against a DID, which can never
 * match. The gate has the KEY for the sender, so the expected VID can be derived from it;
 * these tests pin the whole path: derive → sign → verify → refuse an impostor.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tx/operation-vid.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { generateUuid } from '../../src/db/uuid-helpers.js';
import * as identitiesRepo from '../../src/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '../../src/db/repositories/did-documents-repo.js';
import * as keysRepo from '../../src/db/repositories/keys-repo.js';
import { resolveOperationVid } from '../../src/services/vta.js';
import { cesrEncode } from '../../src/crypto/cesr.js';
import { CESR_CODES } from '../../src/crypto/codes.js';
import { generateEd25519KeyPair, signEd25519 } from '../../src/crypto/primitives.js';
import { signOperationProof, verifyOperationProof, gateOperationProof } from '../../src/tx/index.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

/** An identity with a primary document and a published ed25519 key — the sender's side. */
async function seedSender(db: SqliteDataSource, did: string): Promise<{ docUuid: string; secretKey: Uint8Array }> {
  const uuid = generateUuid();
  const kp = generateEd25519KeyPair();
  await identitiesRepo.create(db, {
    uuid, realDid: did, role: 'vta', subjectKind: 'human', custody: 'remote',
    name: 'sender', recordedByNode: 'test',
  });
  const docUuid = await didDocumentsRepo.create(db, {
    identityUuid: uuid, did, method: 'did:scid:vh', documentJson: '{}', isPrimary: true, recordedByNode: 'test',
  });
  await keysRepo.create(db, {
    identityUuid: uuid, didDocumentUuid: docUuid, keyType: 'ed25519',
    publicKey: Buffer.from(kp.publicKey), rotationVersion: 0, recordedByNode: 'test',
  });
  return { docUuid, secretKey: kp.secretKey };
}

test('resolveOperationVid: the expected VID is DERIVED from the sender key the node holds', async () => {
  const db = new SqliteDataSource(':memory:');
  runMigrations(db.getRawDb(), MIGRATIONS_DIR);
  try {
    const { docUuid } = await seedSender(db, 'did:scid:vh:1:zVidDerive');
    const key = await keysRepo.findCurrentForDidDocument(db, docUuid, 'ed25519');
    const expected = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, Buffer.from(key!.publicKey));

    assert.equal(await resolveOperationVid(db, docUuid), expected);
    // No document / unknown document → undefined, so the gate reports `indeterminate`
    // rather than inventing a verdict (F-031).
    assert.equal(await resolveOperationVid(db, null), undefined);
    assert.equal(await resolveOperationVid(db, generateUuid()), undefined);
  } finally {
    await db.close();
  }
});

test('the field path: a proof signed with the sender key now VERIFIES (was `invalid` on every message)', async () => {
  const db = new SqliteDataSource(':memory:');
  runMigrations(db.getRawDb(), MIGRATIONS_DIR);
  try {
    const { docUuid, secretKey } = await seedSender(db, 'did:scid:vh:1:zVidField');
    const senderVid = await resolveOperationVid(db, docUuid);

    const operations = [{ op: 'name_register', params: { name: 'alice' } }];
    const msg = {
      kind: 'tx_prepare', txId: 'tx-vid-1', messageId: 'msg-1', operations,
      proof: signOperationProof(
        { actorVid: senderVid!, txId: 'tx-vid-1', kind: 'tx_prepare', messageId: 'msg-1', operations },
        signEd25519, secretKey,
      ),
    };

    assert.equal(verifyOperationProof(msg, { senderVid }).verdict, 'verified');
    // …and `enforce` lets it through, which is the whole point: the gate is now usable.
    assert.equal(gateOperationProof(msg, { policy: 'enforce', senderVid }).allow, true);
  } finally {
    await db.close();
  }
});

test('the binding still BITES: another identity’s VID is refused as a substitution', async () => {
  const db = new SqliteDataSource(':memory:');
  runMigrations(db.getRawDb(), MIGRATIONS_DIR);
  try {
    const sender = await seedSender(db, 'did:scid:vh:1:zVidReal');
    const impostor = await seedSender(db, 'did:scid:vh:1:zVidImpostor');
    const impostorVid = await resolveOperationVid(db, impostor.docUuid);

    const operations = [{ op: 'name_register', params: { name: 'alice' } }];
    const msg = {
      kind: 'tx_prepare', txId: 'tx-vid-2', messageId: 'msg-1', operations,
      proof: signOperationProof(
        { actorVid: impostorVid!, txId: 'tx-vid-2', kind: 'tx_prepare', messageId: 'msg-1', operations },
        signEd25519, impostor.secretKey,
      ),
    };

    // The signature is valid, but it is not the key of the identity the transport says sent it.
    assert.equal(verifyOperationProof(msg, { senderVid: await resolveOperationVid(db, sender.docUuid) }).verdict, 'invalid');
    assert.equal(
      gateOperationProof(msg, {
        policy: 'enforce',
        senderVid: await resolveOperationVid(db, sender.docUuid),
      }).allow,
      false,
    );
  } finally {
    await db.close();
  }
});
