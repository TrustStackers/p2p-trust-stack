// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `delegations` domain — the standing accountability/custody links between identities.
 *
 * This domain is unusual in the layer: it is built on `delegations-repo` rather than on the runtime, because
 * the runtime has no delegation methods at all. `AgentHandle` declares `createDelegation?`/`listDelegations?`
 * as optional and nothing implements them, so the TUI screen that programmed to those two had a permanently
 * empty list, a create that never ran, and a Revoke key that printed "Delegation revoked." while doing nothing.
 *
 * Two consequences are pinned here:
 *
 *  - **It works without a started agent.** Every other domain that reads the database needs `start()` to wire
 *    the runtime; this one goes straight to the repository through the `Host`'s `DataSource`. The tests below
 *    use an unstarted stack deliberately — that is a property, not an accident.
 *  - **Revoke actually revokes.** The old screen's no-op is the defect this file exists to prevent, so the
 *    revoke test asserts the PERSISTED `revokedAt` via a fresh read, not the returned value.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/trust_app_api/delegations.test.ts
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createAgentStack, type TrustStack } from '../../src/index.js';

const HOMES: string[] = [];
const STACKS: TrustStack[] = [];

after(async () => {
  for (const s of STACKS) {
    try { await s.stop(); } catch { /* not started */ }
  }
  for (const h of HOMES) rmSync(h, { recursive: true, force: true });
});

async function makeStack(agentName = 'delegator'): Promise<TrustStack> {
  const home = mkdtempSync(join(tmpdir(), 'api-deleg-'));
  HOMES.push(home);
  const stack = await createAgentStack({ home, agent: { name: agentName, passphrase: 'correct horse battery', port: 24017 } });
  STACKS.push(stack);
  return stack;
}

/**
 * Seed a second identity and return its uuid, so a delegation has two real sides.
 *
 * `create()` refuses a side this node does not know (that guard is tested below), so the fixture has to make
 * one exist rather than passing an invented uuid.
 */
async function seedIdentity(stack: TrustStack, name = 'counterparty'): Promise<string> {
  const { SqliteDataSource } = await import('@p2p-trust-stack/core/db/sqlite-data-source.js');
  const { generateUuid } = await import('@p2p-trust-stack/core/db/uuid-helpers.js');

  const me = (await stack.identity.current()).name;
  assert.ok(me, 'seedIdentity needs an active agent');
  const ds = stack.host.storageFor(me) as InstanceType<typeof SqliteDataSource>;
  const uuid = generateUuid();
  const now = Math.floor(Date.now() / 1000);
  try {
    await ds.run(
      `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
       VALUES (?, 'vta', 'ai_agent', 'remote', ?, ?, ?)`,
      uuid, name, now, now,
    );
    return uuid;
  } finally {
    await ds.close();
  }
}

/** The active agent's own identity uuid — the principal in most of these tests. */
async function myUuid(stack: TrustStack): Promise<string> {
  const { SqliteDataSource } = await import('@p2p-trust-stack/core/db/sqlite-data-source.js');
  const me = (await stack.identity.current()).name;
  const ds = stack.host.storageFor(me!) as InstanceType<typeof SqliteDataSource>;
  try {
    const row = await ds.get<{ uuid: string }>('SELECT uuid FROM identities WHERE name = ?', me);
    assert.ok(row, 'the active agent must have an identities row');
    return row.uuid;
  } finally {
    await ds.close();
  }
}

/** Assert a rejection carries a specific `code`. */
async function rejectsWithCode(fn: () => Promise<unknown>, code: string): Promise<Error> {
  let caught: unknown;
  try {
    await fn();
  } catch (err) {
    caught = err;
  }
  assert.ok(caught, `expected a rejection with code '${code}', but the call resolved`);
  assert.equal(
    (caught as { code?: string }).code,
    code,
    `expected code '${code}', got '${(caught as { code?: string }).code}': ${(caught as Error).message}`,
  );
  return caught as Error;
}

// ── reads ────────────────────────────────────────────────────────────────────

test('delegations: list() is empty on a fresh agent, without the agent being started', async () => {
  // The unstarted stack is the point: this domain never touches the runtime.
  const stack = await makeStack();
  assert.deepEqual(await stack.delegations.list(), []);
});

// ── create(): the typed refusals ─────────────────────────────────────────────

test('delegations: create() requires both sides and a known relationship type', async () => {
  const stack = await makeStack();
  const other = await seedIdentity(stack);
  const me = await myUuid(stack);

  await rejectsWithCode(
    () => stack.delegations.create({ principalIdentityUuid: '', dependentIdentityUuid: other, relationshipType: 'operates' }),
    'invalid_input',
  );
  await rejectsWithCode(
    () => stack.delegations.create({ principalIdentityUuid: me, dependentIdentityUuid: '', relationshipType: 'operates' }),
    'invalid_input',
  );
  // The table has a CHECK constraint on this column; catching it here names the allowed set instead of
  // surfacing a SQLite constraint error.
  await rejectsWithCode(
    () => stack.delegations.create({ principalIdentityUuid: me, dependentIdentityUuid: other, relationshipType: 'nonsense' as never }),
    'invalid_input',
  );
});

test('delegations: an identity cannot delegate to itself', async () => {
  const stack = await makeStack();
  const me = await myUuid(stack);
  const err = await rejectsWithCode(
    () => stack.delegations.create({ principalIdentityUuid: me, dependentIdentityUuid: me, relationshipType: 'owns' }),
    'self_delegation',
  );
  assert.match(err.message, /cannot delegate to itself/);
});

test('delegations: a side this node does not know is `not_found`, not a link to nobody', async () => {
  const stack = await makeStack();
  const me = await myUuid(stack);
  const err = await rejectsWithCode(
    () => stack.delegations.create({
      principalIdentityUuid: me,
      dependentIdentityUuid: '00000000-0000-0000-0000-000000000000',
      relationshipType: 'employs',
    }),
    'not_found',
  );
  assert.match(err.message, /No identity known locally for the dependent/);
});


// ── create() + list() ────────────────────────────────────────────────────────

test('delegations: create() returns the new link, and list() reports it', async () => {
  const stack = await makeStack();
  const other = await seedIdentity(stack);
  const me = await myUuid(stack);

  const created = await stack.delegations.create({
    principalIdentityUuid: me,
    dependentIdentityUuid: other,
    relationshipType: 'operates',
    scope: JSON.stringify({ resource: 'sensor-7' }),
  });
  assert.equal(created.relationshipType, 'operates');
  assert.equal(created.revokedAt, null, 'a new delegation is not revoked');
  assert.ok(created.grantedAt, 'grantedAt is stamped on create');
  assert.equal(created.scope, JSON.stringify({ resource: 'sensor-7' }));

  // `list()` is the caller's OWN view, and the caller is the principal here.
  const mine = await stack.delegations.list();
  assert.equal(mine.length, 1);
  assert.equal(mine[0].uuid, created.uuid);
});

test('delegations: list() includes links where the caller is the DEPENDENT', async () => {
  // A delegation is one link seen from two ends; a screen showing only the principal's view would hide
  // "who acts for me". The second identity is seeded as the principal so the active agent is the dependent.
  const stack = await makeStack();
  const other = await seedIdentity(stack, 'my-principal');
  const me = await myUuid(stack);

  await stack.delegations.create({
    principalIdentityUuid: other,
    dependentIdentityUuid: me,
    relationshipType: 'represents',
  });

  const mine = await stack.delegations.list();
  assert.equal(mine.length, 1, 'the link is visible from the dependent side');
  assert.equal(mine[0].dependentIdentityUuid, me);
});

// ── revoke() — the defect this domain replaces ───────────────────────────────

test('delegations: revoke() actually persists, and is idempotent', async () => {
  // The screen this replaces printed "Delegation revoked." and wrote nothing. So this asserts the PERSISTED
  // state via a fresh read, not the returned value.
  const stack = await makeStack();
  const other = await seedIdentity(stack);
  const me = await myUuid(stack);

  const created = await stack.delegations.create({
    principalIdentityUuid: me,
    dependentIdentityUuid: other,
    relationshipType: 'employs',
  });

  const revoked = await stack.delegations.revoke(created.uuid);
  assert.ok(revoked.revokedAt, 'the returned link carries revokedAt');
  const firstStamp = revoked.revokedAt;

  // Re-read through list(), which goes back to the database.
  const listed = await stack.delegations.list();
  assert.equal(listed[0].revokedAt, firstStamp, 'revocation is persisted, not just reported');

  // Idempotent: a repeat click must not rewrite when the link lapsed.
  const again = await stack.delegations.revoke(created.uuid);
  assert.equal(again.revokedAt, firstStamp, 'the FIRST revocation timestamp is kept');
});

test('delegations: revoke() refuses an unknown uuid and an empty one', async () => {
  const stack = await makeStack();
  await rejectsWithCode(() => stack.delegations.revoke('no-such-uuid'), 'not_found');
  await rejectsWithCode(() => stack.delegations.revoke(''), 'invalid_input');
});

// ── the capability surface ───────────────────────────────────────────────────

test('delegations: the domain is scopable — `list` is a read, `create`/`revoke` are writes', async () => {
  const { METHOD_CLASSIFICATION } = await import('../../src/index.js');
  assert.deepEqual([...METHOD_CLASSIFICATION.read.delegations], ['list']);
  assert.deepEqual([...METHOD_CLASSIFICATION.write.delegations].sort(), ['create', 'revoke']);
  assert.deepEqual([...METHOD_CLASSIFICATION.denied.delegations], [], 'nothing is denied — the whole domain is classified');
});

