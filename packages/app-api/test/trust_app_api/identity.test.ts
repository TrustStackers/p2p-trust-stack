/**
 * `identity` domain tests — the first real domain, driven through the public barrel only.
 *
 * These import **`trust-app-api/index.js`** and nothing else from the layer (see the layering rule in the plan's
 * §4.1): a test that needs a `runtime/` internal to pass is a finding that the API surface is missing
 * something, not a reason to reach around it.
 *
 * Real agents, real crypto, a throwaway P2PTS_HOME. `activate()` boots a real libp2p node, so this file is
 * the slower of the P2 domain tests by design — it exercises the path an application actually takes.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/trust_app_api/identity.test.ts
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createAgentStack, NoActiveAgentError, UtilityServerUnavailableError, type TrustStack } from '../../src/index.js';

const HOMES: string[] = [];
const STACKS: TrustStack[] = [];

/** Filenames inside an agent's own directory (P2PTS_HOME/vta/<name>/). */
const DB_FILE = 'p2pts-database.db';
const KEYSTORE_FILE = 'p2pts-keystore.db';

/**
 * Distinct listen port per stack in this file.
 *
 * Several tests here start an agent, and stacks are only stopped in `after()` — so more than one agent can be
 * listening at once. A fixed port would collide (`EADDRINUSE`); the runtime honours an explicit port, so each
 * stack takes the next one.
 */
let nextPort = 24010;

/** A fresh, isolated stack. The named agent is created (not started). */
async function makeStack(agentName: string) {
  const home = mkdtempSync(join(tmpdir(), 'api-identity-'));
  HOMES.push(home);
  // No registry is passed: the stack builds its own from `home`, which is exactly what an application does.
  const stack = await createAgentStack({
    home,
    agent: { name: agentName, passphrase: 'correct horse battery', port: nextPort++ },
  });
  // Guard first, before anything can write: an isolated home is a precondition for every assertion below.
  // Without this, a regression in home resolution writes agents into the developer's real P2PTS_HOME and the
  // damage is only visible much later (this actually happened — see `AgentRegistry`'s third-parameter note).
  assert.equal(
    stack.host.home,
    home,
    'the stack must be bound to the isolated home, not the real P2PTS_HOME',
  );
  STACKS.push(stack);
  return { stack, home };
}

after(async () => {
  for (const s of STACKS) {
    try { await s.stop(); } catch { /* not started */ }
  }
  for (const h of HOMES) rmSync(h, { recursive: true, force: true });
});

test('identity.current() reports the active identity, including its own row', async () => {
  const { stack, home } = await makeStack('alice');

  const current = await stack.identity.current();
  assert.equal(current.active, true);
  assert.equal(current.name, 'alice');
  assert.match(current.did!, /^did:/, 'a real DID');
  assert.ok(current.vid, 'a CESR VID');
  assert.ok(current.meta, 'meta is present');
  assert.equal(current.meta!.name, 'alice');
  assert.equal(current.meta!.dataDir, join(home, 'vta', 'alice'));

  // The identity row comes from the agent's OWN database via identities-repo — not raw SQL.
  assert.ok(current.identity, 'identity row resolved');
  assert.equal(current.identity!.role, 'vta');
  assert.equal(current.identity!.custody, 'local');
  assert.ok(current.identity!.uuid);
});

test('identity.sign() returns a 64-byte Ed25519 signature', async () => {
  const { stack } = await makeStack('signer');
  const { signature } = await stack.identity.sign('hello');
  assert.equal(typeof signature, 'string');
  assert.equal(Buffer.from(signature, 'base64').length, 64);
});

test('identity.create() makes its own directory, database and keystore, and emits identity.created', async () => {
  const { stack, home } = await makeStack('primary');

  const events: Array<{ name: string; did: string }> = [];
  stack.on('identity.created', (p) => events.push({ name: p.name, did: p.did }));

  const created = await stack.identity.create({ name: 'bob', passphrase: 'correct horse battery' });

  assert.equal(created.name, 'bob');
  assert.match(created.did, /^did:/);
  assert.ok(created.uuid);
  assert.equal(typeof created.publicKeys.ed25519, 'string');
  assert.equal(typeof created.publicKeys.x25519, 'string');

  // Own directory + database + keystore (the schema was migrated before the identity was written).
  const dir = join(home, 'vta', 'bob');
  assert.ok(existsSync(dir), 'own directory exists');
  assert.ok(existsSync(join(dir, DB_FILE)), 'own database exists');
  assert.ok(existsSync(join(dir, KEYSTORE_FILE)), 'own keystore exists');

  assert.deepEqual(events, [{ name: 'bob', did: created.did }]);
});

test('identity.create() rejects a duplicate name and a short passphrase', async () => {
  const { stack } = await makeStack('dup');

  await assert.rejects(
    () => stack.identity.create({ name: 'dup', passphrase: 'correct horse battery' }),
    /already exists/,
  );
  await assert.rejects(
    () => stack.identity.create({ name: 'shorty', passphrase: 'tiny' }),
    /at least 8 characters/,
  );
});

test('identity.list() resolves each agent from its OWN database', async () => {
  const { stack } = await makeStack('lister');
  await stack.identity.create({ name: 'carol', passphrase: 'correct horse battery' });

  const list = await stack.identity.list();
  const names = list.map((a) => a.name).sort();
  assert.deepEqual(names, ['carol', 'lister']);

  // Each summary carries its own id/subjectKind/custody — the point of the fix over the adapter, which
  // resolved these against the *active* agent's database and so could only be right for the active agent.
  for (const a of list) {
    assert.ok(a.id, `${a.name} resolved its own identity uuid`);
    assert.equal(a.custody, 'local');
  }
  const carol = list.find((a) => a.name === 'carol')!;
  const lister = list.find((a) => a.name === 'lister')!;
  assert.notEqual(carol.id, lister.id, 'each agent has its own identity row');
});

test('identity.activate() switches the active agent and emits identity.activated', async () => {
  const { stack } = await makeStack('first');
  await stack.identity.create({ name: 'second', passphrase: 'correct horse battery' });

  const activated: string[] = [];
  stack.on('identity.activated', (p) => activated.push(p.name));

  const result = await stack.identity.activate({ name: 'second', passphrase: 'correct horse battery' });

  assert.equal(result.ok, true);
  assert.equal(result.agent.name, 'second');
  assert.deepEqual(activated, ['second']);

  const current = await stack.identity.current();
  assert.equal(current.name, 'second', 'the active agent was swapped');
});

test('identity.deactivate() clears the active agent, and the surface then fails closed', async () => {
  const { stack } = await makeStack('leaver');

  // Activate (this starts a real libp2p node) so deactivate has something to stop.
  await stack.identity.activate({ name: 'leaver', passphrase: 'correct horse battery' });
  assert.equal((await stack.identity.current()).active, true);

  const deactivated: Array<string | null> = [];
  stack.on('identity.deactivated', (p) => deactivated.push(p.name));

  const result = await stack.identity.deactivate();
  assert.deepEqual(result, { ok: true });
  assert.deepEqual(deactivated, ['leaver']);

  const after = await stack.identity.current();
  assert.deepEqual(after, { active: false }, 'current() reports inactive, it does not throw');

  await assert.rejects(() => stack.identity.sign('x'), NoActiveAgentError);
  await assert.rejects(() => stack.identity.sign('x'), /No active VTA/);
});

test('identity.deactivate() with no active agent is a no-op', async () => {
  const { stack } = await makeStack('idle');
  await stack.identity.deactivate();
  assert.deepEqual(await stack.identity.deactivate(), { ok: true });
  assert.equal((await stack.identity.current()).active, false);
});

test('identity.recoveryState() refuses when the utility server is not connected', async () => {
  const { stack } = await makeStack('recoverer');
  // Unlocked but never started: there is no utility-server link, so this must fail closed rather than
  // hanging on a TSP request that can never be answered.
  await assert.rejects(
    () => stack.identity.recoveryState(),
    (err: unknown) =>
      err instanceof UtilityServerUnavailableError || err instanceof NoActiveAgentError,
  );
});

test('createAgentStack() does not start the agent — the caller subscribes first, then starts', async () => {
  const { stack } = await makeStack('subscriber');

  // Subscribing before start() is what makes it impossible to miss the activation event.
  const opened: string[] = [];
  const closed: string[] = [];
  stack.on('connection.open', (p) => opened.push(p.peerId));
  stack.on('connection.close', (p) => closed.push(p.peerId));

  // Not started yet: the node is not listening, so there are no multiaddrs.
  assert.equal((await stack.identity.current()).multiaddrs?.length ?? 0, 0);

  await stack.start();
  const started = await stack.identity.current();
  assert.ok((started.multiaddrs?.length ?? 0) > 0, 'the node is listening after start()');

  // Every connection event the bus retained must have reached the subscriber. Whether any occurred at all
  // depends on the environment (a reachable bootstrap server yields one), so this asserts the *wiring*
  // rather than a count — a subscriber that missed events would show up as a length mismatch here.
  const retainedOpen = stack.replay('connection.open', { since: 0 }).events.length;
  const retainedClose = stack.replay('connection.close', { since: 0 }).events.length;
  assert.equal(opened.length, retainedOpen, 'every retained connection.open reached the subscriber');
  assert.equal(closed.length, retainedClose, 'every retained connection.close reached the subscriber');
});

test('the barrel exposes the API version as semver', async () => {
  const { stack } = await makeStack('versioned');
  assert.match(stack.version, /^\d+\.\d+\.\d+$/);
});

