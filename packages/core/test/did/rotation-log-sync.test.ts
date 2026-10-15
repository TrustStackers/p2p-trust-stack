// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for the rotation-log PUSH path: agent log → wire JSON → server persist
 * → verified resolution.
 *
 * This is the regression guard for the gap where an agent's `identity_push`
 * carried the refreshed DID DOCUMENT but never the LOG, so the utility server
 * could only ever serve a cached snapshot (`source: 'cache'`) — even when the
 * document itself (e.g. `alsoKnownAs`) was current.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/did/rotation-log-sync.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { ScidVhMethod } from '../../src/did/scid-vh-method.js';
import { DidResolutionService } from '../../src/did/did-resolution-service.js';
import { packRotationEntry, rotationEntryToJson } from '../../src/did/rotation-entry-codec.js';
import { persistPushedRotationLog } from '../../src/services/rotation-log-sync.js';
import { payloadDigest } from '../../src/exchange/watermark.js';
import { generateEd25519KeyPair } from '../../src/crypto/primitives.js';
import type { RotationLogEntry } from '../../src/did/rotation-types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

function makeDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

/** Materialize the identity + primary DID document the way a push would. */
async function seedDoc(ds: SqliteDataSource, did: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  await ds.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES ('id-1', 'vta', 'human', 'remote', 'alice', ?, ?)`,
    now,
    now,
  );
  await ds.run(
    `INSERT INTO did_documents (uuid, identity_uuid, did, method, document_json, is_primary, status, created_at, updated_at)
     VALUES ('doc-1', 'id-1', ?, 'did:scid:vh', '{}', 1, 'active', ?, ?)`,
    did,
    now,
    now,
  );
  return 'doc-1';
}

/** One key rotation, so the log has two chained entries. */
async function rotatedLog(): Promise<{ did: string; log: RotationLogEntry[] }> {
  const method = new ScidVhMethod({});
  const created = await method.create();
  const v1 = await method.rotate({
    currentLog: created.log,
    outgoingSigningKeyPair: created.signingKeyPair,
    newSigningKeyPair: created.nextSigningKeyPairs[0],
    nextSigningPublicKey: generateEd25519KeyPair().publicKey,
    witnessAttestations: [],
    mlDsa65KeyPair: created.mlDsa65KeyPair,
  });
  return { did: created.did, log: [created.log[0], v1] };
}

test('a pushed rotation log turns a cached snapshot into a verified resolution', async () => {
  const ds = makeDb();
  const { did, log } = await rotatedLog();
  const docUuid = await seedDoc(ds, did);

  // BEFORE the push: the server holds a document but no log → cache, and it now
  // SAYS which cache case this is.
  const before = await new DidResolutionService(ds).resolve(did);
  assert.equal(before.source, 'cache');
  assert.equal(before.result.didResolutionMetadata.logHeld, false);
  assert.equal(before.result.didResolutionMetadata.cacheReason, 'no-log-held');

  // The agent serializes its log — exactly what goes on the wire.
  const synced = await persistPushedRotationLog(ds, docUuid, log.map(rotationEntryToJson));
  assert.equal(synced.inserted, 2, 'both versions are written');

  // AFTER the push: the chain replays → verified resolution.
  const after = await new DidResolutionService(ds).resolve(did);
  assert.equal(after.source, 'log');
  assert.equal(after.result.didResolutionMetadata.chainValid, true);
  assert.equal(after.result.didResolutionMetadata.logHeld, true);
  assert.equal(after.result.didDocument?.id, did);
  assert.equal(after.result.didDocumentMetadata.versionId, '1');

  await ds.close();
});

test('re-pushing the whole log is idempotent (insert-if-absent per version)', async () => {
  const ds = makeDb();
  const { did, log } = await rotatedLog();
  const docUuid = await seedDoc(ds, did);
  const wire = log.map(rotationEntryToJson);

  const first = await persistPushedRotationLog(ds, docUuid, wire);
  const second = await persistPushedRotationLog(ds, docUuid, wire);

  assert.equal(first.inserted, 2);
  assert.equal(second.inserted, 0, 'a re-sent log must not insert anything');
  assert.equal(second.skipped, 2);

  // And the resolution is unaffected by the re-send.
  assert.equal((await new DidResolutionService(ds).resolve(did)).source, 'log');

  await ds.close();
});

test('a roll changes the payload digest, so the ack-gate lets the push through', async () => {
  const method = new ScidVhMethod({});
  const created = await method.create();
  const v1 = await method.rotate({
    currentLog: created.log,
    outgoingSigningKeyPair: created.signingKeyPair,
    newSigningKeyPair: created.nextSigningKeyPairs[0],
    nextSigningPublicKey: generateEd25519KeyPair().publicKey,
    witnessAttestations: [],
    mlDsa65KeyPair: created.mlDsa65KeyPair,
  });

  // The recordset rows as the exchange engine sees them: the identity payload,
  // whose digest drives the "unchanged since last sync" ack-gate.
  const before = [{ rotationLog: created.log.map(rotationEntryToJson) }];
  const after = [{ rotationLog: [created.log[0], v1].map(rotationEntryToJson) }];

  assert.notEqual(
    payloadDigest(before),
    payloadDigest(after),
    'including the log in the payload is what stops a roll being gated as "unchanged"',
  );
});

test('a malformed entry is skipped without failing the push', async () => {
  const ds = makeDb();
  const { did, log } = await rotatedLog();
  const docUuid = await seedDoc(ds, did);

  const wire: unknown[] = [
    { version: 'not-a-number' },
    { didDocument: {} },
    null,
    ...log.map(rotationEntryToJson),
  ];

  const synced = await persistPushedRotationLog(ds, docUuid, wire);
  assert.equal(synced.total, 5);
  assert.equal(synced.inserted, 2, 'the valid entries still land');
  assert.equal(synced.skipped, 3, 'the malformed ones are skipped, not thrown');

  await ds.close();
});

test('a log that does not validate is reported as chain-invalid, not no-log-held', async () => {
  const ds = makeDb();
  const { did, log } = await rotatedLog();
  const docUuid = await seedDoc(ds, did);
  await persistPushedRotationLog(ds, docUuid, log.map(rotationEntryToJson));

  // Tamper with the stored version-0 document: validateChain recomputes the
  // digest from the entry fields, so the chain no longer validates.
  const tampered = { ...log[0].didDocument, alsoKnownAs: ['vta:evil:impostor'] };
  await ds.run(
    `UPDATE rotation_log SET signed_entry = ? WHERE did_document_uuid = 'doc-1' AND version = 0`,
    Buffer.from(
      packRotationEntry({
        didDocument: tampered,
        parameters: log[0].parameters,
        digest: log[0].digest,
        signature: log[0].signature,
        mlDsa65Signature: log[0].mlDsa65Signature,
      }),
    ),
  );

  const report = await new DidResolutionService(ds).resolve(did);
  assert.equal(report.source, 'cache');
  assert.equal(report.result.didResolutionMetadata.logHeld, true, 'a log IS held…');
  assert.equal(
    report.result.didResolutionMetadata.cacheReason,
    'chain-invalid',
    '…but it does not validate — a different problem from never being sent one',
  );

  await ds.close();
});
