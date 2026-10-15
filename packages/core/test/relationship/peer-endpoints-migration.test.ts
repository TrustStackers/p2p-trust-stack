// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for the peer_endpoints design (base schema) and the guarded
 * endpoint write semantics:
 *   - setActiveEndpoint retires the identity's other active endpoints
 *   - setActiveEndpoint refuses to reassign a peer claimed by another identity
 *   - hasAnyEndpoint discriminates "real VTA" vs TSP-bridge fake
 *   - findByRoleAndSubjectKind only returns VTAs with an endpoint
 *   - identities table does NOT define a peer_id column (peer binding lives in
 *     peer_endpoints, keyed by identity_uuid)
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/relationship/peer-endpoints-migration.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

import { runMigrations } from '../../src/db/migrate.js';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import type { DataSource } from '../../src/db/data-source.js';
import {
  setActiveEndpoint,
  ownsActiveEndpoint,
  findActive,
} from '../../src/db/repositories/peer-endpoints-repo.js';
import * as identitiesRepo from '../../src/db/repositories/identities-repo.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function makeHarness(): { db: DataSource; raw: DatabaseSync } {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), getMigrationsDir());
  return { db: ds, raw: ds.getRawDb() };
}

// ---------------------------------------------------------------------------
// Base schema: identities has no peer_id column; peer_endpoints is keyed by uuid
// ---------------------------------------------------------------------------

test('base schema: identities has no peer_id column and peer_endpoints keeps peer_id + identity_uuid', () => {
  const { raw } = makeHarness();
  const identityCols = raw.prepare(`SELECT name FROM pragma_table_info('identities')`).all()
    .map((r: { name: string }) => r.name);
  assert.ok(!identityCols.includes('peer_id'), 'identities.peer_id must not exist');

  const epCols = raw.prepare(`SELECT name FROM pragma_table_info('peer_endpoints')`).all()
    .map((r: { name: string }) => r.name);
  assert.ok(epCols.includes('peer_id'), 'peer_endpoints.peer_id retained');
  assert.ok(epCols.includes('identity_uuid'), 'peer_endpoints.identity_uuid retained');
});

// ---------------------------------------------------------------------------
// setActiveEndpoint
// ---------------------------------------------------------------------------

test('setActiveEndpoint: activating a new peer retires the identity\'s other active endpoints', async () => {
  const { db, raw } = makeHarness();
  // uuid-first schema: create() RETURNS the identity uuid (there is no integer id
  // and no findById — that API went away with the uuid-first refactor).
  const uuid = await identitiesRepo.create(db, {
    realDid: 'did:peer:4:ztestactive1',
    role: 'vta',
    subjectKind: 'human',
    custody: 'local',
    name: 'active-test',
  });

  await setActiveEndpoint(db, { identityUuid: uuid, peerId: 'peer-A' });
  await setActiveEndpoint(db, { identityUuid: uuid, peerId: 'peer-B' });

  const active = await findActive(db, uuid);
  assert.equal(active?.peerId, 'peer-B', 'active endpoint must be the latest');
  const rows = raw.prepare('SELECT peer_id, is_active FROM peer_endpoints').all() as {
    peer_id: string; is_active: number;
  }[];
  assert.equal(rows.length, 2);
  assert.equal(rows.find(r => r.peer_id === 'peer-A')?.is_active, 0, 'peer-A retired');
  assert.equal(rows.find(r => r.peer_id === 'peer-B')?.is_active, 1, 'peer-B active');
});

test('setActiveEndpoint: refuses to reassign a peer active on another identity', async () => {
  const { db, raw } = makeHarness();
  const uuidA = await identitiesRepo.create(db, {
    realDid: 'did:peer:4:ztestA', role: 'vta', subjectKind: 'human', custody: 'local', name: 'A',
  });
  const uuidB = await identitiesRepo.create(db, {
    realDid: 'did:peer:4:ztestB', role: 'vta', subjectKind: 'human', custody: 'local', name: 'B',
  });

  await setActiveEndpoint(db, { identityUuid: uuidA, peerId: 'shared-peer' });
  const result = await setActiveEndpoint(db, { identityUuid: uuidB, peerId: 'shared-peer' });

  assert.deepEqual(result, { applied: false, reason: 'peer-claimed', ownerUuid: uuidA });
  // The peer must still belong to A.
  assert.equal(await ownsActiveEndpoint(db, 'shared-peer', uuidB), true);
  const owner = raw.prepare('SELECT identity_uuid FROM peer_endpoints WHERE peer_id = ? AND is_active = 1')
    .get('shared-peer') as { identity_uuid: string };
  assert.equal(owner.identity_uuid, uuidA);
});

// ---------------------------------------------------------------------------
// hasAnyEndpoint / findByRoleAndSubjectKind (real VTA discrimination)
// ---------------------------------------------------------------------------

test('hasAnyEndpoint and findByRoleAndSubjectKind treat endpoint-less identities as fakes', async () => {
  const { db } = makeHarness();

  // A TSP-bridge fake: identity created WITHOUT an endpoint.
  const fakeUuid = await identitiesRepo.create(db, {
    realDid: 'did:peer:4:zfake', role: 'vta', subjectKind: 'human', custody: 'remote', name: 'fake',
  });
  assert.equal(await identitiesRepo.hasAnyEndpoint(db, fakeUuid), false);

  // A real VTA with an endpoint.
  const realUuid = await identitiesRepo.create(db, {
    realDid: 'did:peer:4:zreal', role: 'vta', subjectKind: 'human', custody: 'local', name: 'real',
    peerId: 'real-peer',
  });
  assert.equal(await identitiesRepo.hasAnyEndpoint(db, realUuid), true);

  const realVtas = await identitiesRepo.findByRoleAndSubjectKind(db, 'vta', 'human');
  assert.ok(realVtas.some(v => v.name === 'real'), 'real VTA must be listed');
  assert.ok(!realVtas.some(v => v.name === 'fake'), 'endpoint-less fake must be excluded');
});

test('hasAnyEndpoint treats a VTA with a retired endpoint as real (any endpoint counts)', async () => {
  const { db, raw } = makeHarness();
  const uuid = await identitiesRepo.create(db, {
    realDid: 'did:peer:4:zrekey', role: 'vta', subjectKind: 'human', custody: 'local', name: 'rekeyed',
    peerId: 'old-peer',
  });
  // Simulate re-key / deactivation: the endpoint is retired, none left active.
  raw.prepare('UPDATE peer_endpoints SET is_active = 0 WHERE peer_id = ?').run('old-peer');
  assert.equal(await identitiesRepo.hasAnyEndpoint(db, uuid), true, 'a retired endpoint still makes this a real VTA');
});

// ---------------------------------------------------------------------------
// identities-repo.create records the endpoint beside the identity
// ---------------------------------------------------------------------------

test('identities-repo.create records an active peer_endpoint when peerId is provided', async () => {
  const { db } = makeHarness();
  const uuid = await identitiesRepo.create(db, {
    realDid: 'did:peer:4:zcreatepeer', role: 'vta', subjectKind: 'human',
    custody: 'local', name: 'with-peer', peerId: 'created-peer',
  });
  const active = await findActive(db, uuid);
  assert.equal(active?.peerId, 'created-peer');
  const ident = await identitiesRepo.findByPeerId(db, 'created-peer');
  assert.ok(ident, 'findByPeerId resolves via peer_endpoints');
  assert.equal(ident!.uuid, uuid);
});
