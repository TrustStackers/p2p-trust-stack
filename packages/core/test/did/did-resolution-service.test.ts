// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for DidResolutionService — the shared core behind the public
 * did:scid:vh resolver.
 *
 * Pins the behaviours that matter:
 *   - a did:scid:vh with a full log resolves by REPLAYING and validating the
 *     chain (`source: 'log'`), not by trusting a cached document;
 *   - a rotated identity reports the latest version;
 *   - `versionId` pins resolution to an earlier version;
 *   - a DID with no log falls back to the cached snapshot (`source: 'cache'`)
 *     and says so, rather than pretending it resolved;
 *   - the emitted JSON is consumable by `HttpRotationLogSource` — the shape
 *     contract that makes remote resolution actually work.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/did/did-resolution-service.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { ScidVhMethod } from '../../src/did/scid-vh-method.js';
import { DidResolutionService } from '../../src/did/did-resolution-service.js';
import { DidResolver } from '../../src/did/did-resolver.js';
import { HttpRotationLogSource } from '../../src/did/rotation-log-source.js';
import { packRotationEntry, rotationLogToJsonl } from '../../src/did/rotation-entry-codec.js';
import { createDidPeer4 } from '../../src/did/create.js';
import { generateEd25519KeyPair } from '../../src/crypto/primitives.js';
import type { RotationLogEntry } from '../../src/did/rotation-types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

function makeDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

/** Persist a DID document row plus its rotation log, the way a writer would. */
async function seed(
  ds: SqliteDataSource,
  did: string,
  log: RotationLogEntry[],
  opts: { documentJson?: string; status?: string } = {},
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await ds.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES ('id-1', 'vta', 'human', 'local', 'alice', ?, ?)`,
    now,
    now,
  );
  await ds.run(
    `INSERT INTO did_documents (uuid, identity_uuid, did, method, document_json, is_primary, status, created_at, updated_at)
     VALUES ('doc-1', 'id-1', ?, 'did:scid:vh', ?, 1, ?, ?, ?)`,
    did,
    opts.documentJson ?? null,
    opts.status ?? 'active',
    now,
    now,
  );
  for (const entry of log) {
    await ds.run(
      `INSERT INTO rotation_log (uuid, did_document_uuid, version, previous_hash, new_public_key, signed_entry, created_at)
       VALUES (?, 'doc-1', ?, ?, ?, ?, ?)`,
      `rl-${entry.version}`,
      entry.version,
      entry.prevHash ?? null,
      Buffer.from(JSON.stringify(entry.nextKeyCommitments.map((k) => Buffer.from(k).toString('base64')))),
      Buffer.from(
        packRotationEntry({
          didDocument: entry.didDocument,
          parameters: entry.parameters,
          digest: entry.digest,
          signature: entry.signature,
          mlDsa65Signature: entry.mlDsa65Signature,
        }),
      ),
      entry.createdAt,
    );
  }
}

test('resolve: did:scid:vh replays the rotation log (source: log)', async () => {
  const ds = makeDb();
  const created = await new ScidVhMethod({}).create();
  await seed(ds, created.did, created.log);

  const report = await new DidResolutionService(ds).resolve(created.did);

  assert.equal(report.source, 'log');
  assert.equal(report.result.didResolutionMetadata.source, 'log');
  assert.equal(report.result.didResolutionMetadata.chainValid, true);
  assert.equal(report.result.didDocument?.id, created.did, 'the resolved document carries its DID as id');
  assert.equal(report.result.didDocumentMetadata.versionId, '0');
  assert.ok((report.result.didDocument?.verificationMethod ?? []).length >= 2);
  assert.equal(report.log?.length, 1);

  await ds.close();
});

test('resolve: a rotated did:scid:vh reports the latest version', async () => {
  const ds = makeDb();
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
  await seed(ds, created.did, [created.log[0], v1]);

  const report = await new DidResolutionService(ds).resolve(created.did);

  assert.equal(report.source, 'log');
  assert.equal(report.result.didDocumentMetadata.versionId, '1');
  assert.equal(report.result.didResolutionMetadata.rotated, true);
  assert.equal(report.log?.length, 2);

  // The pinned view must still expose version 0's document.
  const pinned = await new DidResolutionService(ds).resolve(created.did, { versionId: '0' });
  assert.equal(pinned.result.didDocumentMetadata.versionId, '0');

  await ds.close();
});

test('resolve: cached snapshot when no rotation log is held (source: cache)', async () => {
  const ds = makeDb();
  const did = 'did:scid:vh:1:CachedOnly';
  await seed(ds, did, [], {
    documentJson: JSON.stringify({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [],
      authentication: [],
      keyAgreement: [],
    }),
  });

  const report = await new DidResolutionService(ds).resolve(did);

  assert.equal(report.source, 'cache', 'a cached document must not be labelled a verified resolution');
  assert.equal(report.result.didResolutionMetadata.source, 'cache');
  assert.equal(report.result.didDocument?.id, did);
  assert.equal(report.log, null);

  await ds.close();
});

test('resolve: unknown DID is notFound; unsupported method is methodNotSupported', async () => {
  const ds = makeDb();
  const svc = new DidResolutionService(ds);

  assert.equal((await svc.resolve('did:scid:vh:1:Nope')).result.didResolutionMetadata.error, 'notFound');
  assert.equal((await svc.resolve('did:web:example.com')).result.didResolutionMetadata.error, 'methodNotSupported');

  await ds.close();
});

test('resolve: did:peer:4 resolves offline from the DID string', async () => {
  const ds = makeDb();
  const peer = await createDidPeer4();
  const report = await new DidResolutionService(ds).resolve(peer.did);

  assert.equal(report.source, 'offline');
  assert.equal(report.result.didDocument?.id, peer.did);

  await ds.close();
});

test('resolveLog: emitted JSON is consumable by HttpRotationLogSource', async () => {
  const ds = makeDb();
  const created = await new ScidVhMethod({}).create();
  await seed(ds, created.did, created.log);

  const log = await new DidResolutionService(ds).resolveLog(created.did);
  assert.ok(log, 'resolveLog must return the log');
  const entries = (log as { entries: RotationLogEntry[] }).entries;

  // Serve the emitted JSONL through the HTTP source the agent uses, then replay
  // it through DidResolver. If the wire shape were wrong (field names or byte
  // encoding), this would fail — which is exactly the contract being pinned.
  const lines = rotationLogToJsonl(entries)
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line));

  const source = new HttpRotationLogSource({
    endpoint: 'https://resolver.test',
    fetchFn: (async () =>
      new Response(JSON.stringify({ entries: lines }), { status: 200 })) as unknown as typeof fetch,
  });
  const result = await new DidResolver({ logSource: source }).resolve(created.did);

  assert.equal(result.didDocument?.id, created.did);

  await ds.close();
});
