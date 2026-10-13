/**
 * The `Host` seam — and specifically the **agent lifecycle** that moved onto it.
 *
 * `Host` used to supply only `name`, `home`, `transport`, `keystore` and `storageFor`. Everything else about
 * *which agents exist* lived in `agent-app/api/agent-api.ts` — a 270-line `AgentApi` facade that every caller
 * imported, which made the runtime's own `AgentHandle` look like an application API. When that facade was
 * deleted (2026-10-09), the lifecycle it had been delegating landed where it belongs: on the object that already
 * owns `home` and the per-agent layout.
 *
 * These tests pin the operations that moved, because they are the ones the TUI picker and both composition roots
 * now call:
 *
 *   - `listAgents()` — the picker's listing, and deliberately **no database opened**;
 *   - `agentExists(name)` / `createAgent(config)` / `unlockAgent(config)` — create-or-unlock;
 *   - `deleteAgent(name)` — irreversible, and the picker confirms before calling it.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/trust_app_api/host.test.ts
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createNodeHost, createAgentStack, type TrustStack } from '../../src/index.js';

const HOMES: string[] = [];
const STACKS: TrustStack[] = [];

const PASS = 'correct horse battery';

after(async () => {
  for (const s of STACKS) { try { await s.stop(); } catch { /* never started */ } }
  for (const h of HOMES) rmSync(h, { recursive: true, force: true });
});

/** A host over a fresh, isolated home. Nothing here starts an agent, so no port is bound. */
function makeHost(): { host: ReturnType<typeof createNodeHost>; home: string } {
  const home = mkdtempSync(join(tmpdir(), 'api-host-'));
  HOMES.push(home);
  const host = createNodeHost({ home });
  assert.equal(host.home, home, 'the host must be bound to the isolated home, not the real P2PTS_HOME');
  return { host, home };
}

test('a fresh home lists no agents, and nothing exists yet', () => {
  const { host } = makeHost();
  assert.deepEqual(host.listAgents(), []);
  assert.equal(host.agentExists('nobody'), false);
});

test('createAgent() puts an agent in THIS host home, and listAgents() reports it', async () => {
  const { host, home } = makeHost();

  const agent = await host.createAgent({ name: 'alice', passphrase: PASS });
  assert.equal(agent.getName(), 'alice');

  assert.equal(host.agentExists('alice'), true);
  const listed = host.listAgents();
  assert.equal(listed.length, 1);
  assert.equal(listed[0].name, 'alice');

  // The listing is scoped to the host's home — that is the whole point of putting the lifecycle here.
  assert.ok(
    existsSync(join(home, 'vta', 'alice')),
    'the agent directory must be under the host home, not the real P2PTS_HOME',
  );
  assert.equal(listed[0].dataDir.startsWith(home), true, 'dataDir is inside the host home');
});

test('listAgents() carries the fields a picker renders, without opening a database', async () => {
  const { host } = makeHost();
  await host.createAgent({ name: 'bob', passphrase: PASS });

  const [meta] = host.listAgents();
  // The picker reads name/vid/createdAt/did. Asserting the whole key set keeps a future field addition honest.
  for (const key of ['name', 'vid', 'did', 'createdAt', 'method', 'dataDir']) {
    assert.equal(key in meta, true, `listAgents() must provide '${key}'`);
  }
  assert.match(meta.did, /^did:/);
  assert.equal(typeof meta.createdAt, 'number');
  // `id`/`subjectKind`/`custody` are deliberately ABSENT: those come from opening each agent's database, which
  // is `identity.list()`'s job, not this one.
  assert.equal('subjectKind' in meta, false, 'the cheap listing must not pretend to know the identity row');
});

test('createAgent() twice with the same name is refused rather than silently replacing', async () => {
  const { host } = makeHost();
  await host.createAgent({ name: 'carol', passphrase: PASS });
  await assert.rejects(() => host.createAgent({ name: 'carol', passphrase: PASS }));
});

test('unlockAgent() loads an agent this host created', async () => {
  const { host } = makeHost();
  await host.createAgent({ name: 'dave', passphrase: PASS });

  const unlocked = await host.unlockAgent({ name: 'dave', passphrase: PASS });
  assert.equal(unlocked.getName(), 'dave');
  assert.equal(unlocked.getDid().startsWith('did:'), true);
});

test('deleteAgent() removes the agent and everything in it', async () => {
  const { host, home } = makeHost();
  await host.createAgent({ name: 'eve', passphrase: PASS });
  const dir = join(home, 'vta', 'eve');
  assert.ok(existsSync(dir), 'precondition: the agent directory exists');

  host.deleteAgent('eve');

  assert.equal(host.agentExists('eve'), false);
  assert.deepEqual(host.listAgents(), []);
  assert.equal(existsSync(dir), false, 'deletion is a directory removal — keys, database and all');
});


test('the host is what createAgentStack() uses, so a stack and a host agree on the home', async () => {
  // The consolidation: `createAgentStack` used to branch on a registry it built itself and call the runtime
  // factories directly. It now goes through the host, so there is one implementation of create-or-unlock.
  const { host, home } = makeHost();

  const stack = await createAgentStack({ host, agent: { name: 'frank', passphrase: PASS, port: 24080 } });
  STACKS.push(stack);

  assert.equal(stack.host, host, 'the stack must use the host it was given');
  assert.equal(stack.host.home, home);
  // …and the agent the stack created is visible to the host that owns it.
  assert.equal(host.agentExists('frank'), true);
  assert.deepEqual(host.listAgents().map((a) => a.name), ['frank']);
});

test('a second stack over the same home unlocks rather than recreating', async () => {
  const { host } = makeHost();
  const first = await createAgentStack({ host, agent: { name: 'gina', passphrase: PASS, port: 24081 } });
  STACKS.push(first);
  try { await first.stop(); } catch { /* never started */ }

  // The agent already exists, so this must unlock — not throw "already exists". That branch is the one the
  // consolidation moved onto the host, so it is worth pinning.
  const second = await createAgentStack({ host, agent: { name: 'gina', passphrase: PASS, port: 24082 } });
  STACKS.push(second);
  assert.equal((await second.identity.current()).name, 'gina');
});
