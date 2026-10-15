// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { driveCeremony } from '../../src/services/trust-tasks/driver.js';
import { registerExecutor } from '../../src/services/trust-tasks/catalog.js';
import * as trustTasksRepo from '../../src/db/repositories/trust-tasks-repo.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

// Effect handlers the driver resolves from the CODE registry. The establish step
// produces `foundingAdmins`; the membership-vmc step fans out over that output.
registerExecutor('task:p2pts:vtc:establish:0.1', async () => ({
  identity: { name: 'Root VTC' },
  foundingAdmins: [
    { uuid: 'm1', admin: 'alice' },
    { uuid: 'm2', admin: 'bob' },
  ],
  recipientDid: 'did:root-vtc',
}));
registerExecutor('task:p2pts:credential:membership-vmc:0.1', async (ctx) => {
  const admin = ctx.item as { uuid: string; admin: string };
  return { membershipUuid: admin.uuid, admin: admin.admin, recipientDid: `did:${admin.admin}` };
});
registerExecutor('task:p2pts:credential:onboarding-vmc:0.1', async () => ({
  credentialUuid: 'onboarding-cred-1',
  recipientDid: 'did:example:member',
}));

const allowAll = { authorize: async () => ({ allowed: true }) };
const denyAll = { authorize: async () => ({ allowed: false }) };

function open() {
  const db = new SqliteDataSource(':memory:');
  runMigrations(db.getRawDb(), MIGRATIONS_DIR);
  return db;
}

async function seedPolicyGatedCeremony(db: SqliteDataSource): Promise<void> {
  // A tiny policy-gated ceremony (gate → effect) to exercise the authorizer path;
  // the founding 'vtc-establish' ceremony is effect-only (its gate is createVtc's
  // validation), so the policy path is tested against this synthetic ceremony.
  await db.run(
    `INSERT INTO ceremony_templates (uuid, name, version, template, recorded_by_node, created_at, updated_at)
     VALUES ('00000000-0000-4000-8000-00000000ffff','test-policy-gate','0.1',
       '{"steps":[{"step":"task:p2pts:policy:membership-vmc-authorized:0.1"},{"step":"task:p2pts:vtc:establish:0.1"}]}',
       'test',0,0)`,
  );
}

test('driving vtc-establish fans out the membership-vmc step over the establish output', async () => {
  const db = open();
  const res = await driveCeremony(db, 'vtc-establish', 'thread-1', {});
  assert.equal(res.completed, true);
  assert.equal(res.stepsRun, 3); // establish + 2× membership-vmc (output-fed repeat)
  assert.ok(res.outputs['task:p2pts:vtc:establish:0.1']);

  const rows = await trustTasksRepo.listByThread(db, 'thread-1');
  assert.equal(rows.length, 6); // request + response per step execution
  assert.equal(
    rows.filter((r) => r.type === 'task:p2pts:credential:membership-vmc:0.1').length,
    4,
  );

  const mintRequests = rows.filter(
    (r) => r.type === 'task:p2pts:credential:membership-vmc:0.1' && r.direction === 'request',
  );
  assert.equal(mintRequests.length, 2);
  const admins = mintRequests.map((r) => JSON.parse(r.payload!).item.admin).sort();
  assert.deepEqual(admins, ['alice', 'bob']);

  // recipient_did is surfaced on the RESPONSE record from the executor's result.
  const establishResponse = rows.find(
    (r) => r.type === 'task:p2pts:vtc:establish:0.1' && r.direction === 'response',
  )!;
  assert.equal(establishResponse.recipientDid, 'did:root-vtc');
  const mintResponses = rows.filter(
    (r) => r.type === 'task:p2pts:credential:membership-vmc:0.1' && r.direction === 'response',
  );
  assert.equal(mintResponses.length, 2);
  assert.deepEqual(
    mintResponses.map((r) => r.recipientDid).sort(),
    ['did:alice', 'did:bob'],
  );
});

test('a policy deny halts the ceremony at the gate', async () => {
  const db = open();
  await seedPolicyGatedCeremony(db);
  const res = await driveCeremony(db, 'test-policy-gate', 'thread-2', { authorizer: denyAll });
  assert.equal(res.completed, false);
  assert.equal(res.haltedAt, 'task:p2pts:policy:membership-vmc-authorized:0.1');
  assert.equal(res.stepsRun, 1);

  const rows = await trustTasksRepo.listByThread(db, 'thread-2');
  assert.equal(rows.length, 2); // one request + one deny response
  const response = rows.find((r) => r.direction === 'response')!;
  assert.equal(JSON.parse(response.payload!).decision, 'deny');
  const request = rows.find((r) => r.direction === 'request')!;
  assert.equal(request.type, 'task:p2pts:policy:membership-vmc-authorized:0.1');
});

test('a policy allow lets the ceremony continue to the effect step', async () => {
  const db = open();
  await seedPolicyGatedCeremony(db);
  const res = await driveCeremony(db, 'test-policy-gate', 'thread-3', { authorizer: allowAll });
  assert.equal(res.completed, true);
  assert.equal(res.stepsRun, 2); // gate allow + establish effect
  assert.ok(res.outputs['task:p2pts:vtc:establish:0.1']);
});

test('the real member-onboarding ceremony gates on the policy step, then mints', async () => {
  const db = open();

  const allowed = await driveCeremony(db, 'member-onboarding', 'thread-onb-allow', { authorizer: allowAll });
  assert.equal(allowed.completed, true);
  assert.equal(allowed.stepsRun, 2); // gate allow + onboarding-vmc effect
  const out = allowed.outputs['task:p2pts:credential:onboarding-vmc:0.1'] as { credentialUuid?: string };
  assert.equal(out.credentialUuid, 'onboarding-cred-1');

  const allowedRows = await trustTasksRepo.listByThread(db, 'thread-onb-allow');
  assert.equal(allowedRows.length, 4); // request+response for each of 2 steps
  const allowResponse = allowedRows.find(
    (r) => r.type === 'task:p2pts:credential:onboarding-vmc:0.1' && r.direction === 'response',
  )!;
  assert.equal(allowResponse.recipientDid, 'did:example:member');

  const denied = await driveCeremony(db, 'member-onboarding', 'thread-onb-deny', { authorizer: denyAll });
  assert.equal(denied.completed, false);
  assert.equal(denied.haltedAt, 'task:p2pts:policy:membership-vmc-authorized:0.1');

  const deniedRows = await trustTasksRepo.listByThread(db, 'thread-onb-deny');
  assert.equal(deniedRows.length, 2); // only the gate's request + deny response
  assert.equal(
    deniedRows.filter((r) => r.type === 'task:p2pts:credential:onboarding-vmc:0.1').length,
    0,
    'a denied gate must not run the mint effect',
  );
});
