import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import * as trustTasksRepo from '../../src/db/repositories/trust-tasks-repo.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

test('record persists a task document; listByThread returns the thread in order', async () => {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);

  const threadId = 'thread-1';
  await trustTasksRepo.record(ds, {
    uuid: 'doc-request',
    threadId,
    type: 'task:p2pts:vtc:establish:0.1',
    direction: 'request',
    issuerDid: 'did:example:admin',
    recipientDid: 'did:example:club',
    payload: { name: 'Chess Club', threshold: 2, allowedClaimTypes: ['membership'] },
  });
  await trustTasksRepo.record(ds, {
    uuid: 'doc-response',
    threadId,
    type: 'task:p2pts:vtc:establish:0.1',
    direction: 'response',
    issuerDid: 'did:example:club',
    recipientDid: 'did:example:admin',
    payload: { governanceDocDigest: 'abc123' },
    status: 'completed',
  });

  const thread = await trustTasksRepo.listByThread(ds, threadId);
  assert.equal(thread.length, 2);
  assert.equal(thread[0]!.direction, 'request');
  assert.equal(thread[1]!.direction, 'response');

  // payload/proof are stored as JSON TEXT; round-trip back to values.
  const req = await trustTasksRepo.findByUuid(ds, 'doc-request');
  assert.equal(JSON.parse(req!.payload!).name, 'Chess Club');
  assert.equal(req!.status, 'recorded');
  const res = await trustTasksRepo.findByUuid(ds, 'doc-response');
  assert.equal(res!.proof, null);
});

test('an unknown thread returns an empty list, not null', async () => {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  assert.deepEqual(await trustTasksRepo.listByThread(ds, 'nope'), []);
});
