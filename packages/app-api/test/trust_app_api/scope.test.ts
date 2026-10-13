/**
 * `asContext()` — the capability scope's acceptance test.
 *
 * The API-level twin of `test/agent/context-provisioning.test.ts`, which pins the F-021 / Y1 ruling: *a private
 * key never crosses the provisioning boundary*. That test proves the context's keys stay put; this one proves the
 * context's AUTHORITY stays put.
 *
 * Four properties, each a security defect if it silently stopped holding:
 *
 *   1. **Deny by default.** An empty `allow` grants nothing, and a capability that was not granted is refused.
 *   2. **Deny by omission.** Every method of every exposed domain is classified read/write. A method in NEITHER
 *      list is refused — so a domain gaining a method makes it denied until someone classifies it, rather than
 *      reachable by accident. Asserted BOTH ways: structurally against the domain sources, and at runtime.
 *   3. **Expiry is enforced**, and re-checked per call rather than captured at construction.
 *   4. **Revocation stops calls AND events.** `revoke()` deletes the context directory, and the scope must notice
 *      on the NEXT call — an object that cached liveness would keep working after revocation.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/trust_app_api/scope.test.ts
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createAgentStack,
  METHOD_CLASSIFICATION,
  type ContextCapability,
  type ScopedDomain,
  type ScopedTrustStack,
  type TrustStack,
} from '../../src/index.js';

const HOMES: string[] = [];
const STACKS: TrustStack[] = [];

/**
 * Distinct listen port per stack — the runtime honours an explicit port and several stacks coexist in this file.
 *
 * The agent is created but deliberately NOT started: provisioning needs the identity, not the libp2p node, and
 * the events these tests drive are local. Not starting means this suite binds no ports and cannot fail with the
 * `EADDRINUSE` a shared fixed port produces.
 */
let nextPort = 24040;

async function makeScoped(
  contextId: string,
  opts: { allow: readonly ContextCapability[]; provision?: { expiresAt?: number } },
): Promise<{ stack: TrustStack; scoped: ScopedTrustStack }> {
  const home = mkdtempSync(join(tmpdir(), 'api-scope-'));
  HOMES.push(home);
  const stack = await createAgentStack({
    home,
    agent: { name: `scope-${contextId}`, passphrase: 'correct horse battery', port: nextPort++ },
  });
  // Guard FIRST, before anything can write. A regression in home resolution would otherwise create the agent in
  // the developer's real P2PTS_HOME and stay invisible until much later — that has actually happened here.
  assert.equal(stack.host.home, home, 'the stack must be bound to the isolated home, not the real P2PTS_HOME');
  STACKS.push(stack);

  await stack.contexts.provision(contextId, opts.provision ?? {});
  return { stack, scoped: stack.asContext(contextId, { allow: opts.allow }) };
}

after(async () => {
  for (const stack of STACKS) { try { await stack.stop(); } catch { /* never started */ } }
  for (const home of HOMES) rmSync(home, { recursive: true, force: true });
});

/** Assert a call is refused with `capability_denied` and a message matching `pattern`. */
async function refuses(fn: () => Promise<unknown>, pattern: RegExp): Promise<void> {
  await assert.rejects(fn, (err: unknown) => {
    assert.equal((err as { code?: string }).code, 'capability_denied');
    assert.match((err as Error).message, pattern);
    return true;
  });
}


// ---------------------------------------------------------------------------
// 1. Deny by default
// ---------------------------------------------------------------------------

test('an empty `allow` grants NOTHING — even a read', async () => {
  const { scoped } = await makeScoped('empty', { allow: [] });
  await refuses(() => scoped.relationships.list(), /was not granted 'relationships\.read'/);
  // …and the refusal is not domain-specific: nothing at all is reachable.
  await refuses(() => scoped.messaging.unread(), /was not granted/);
  await refuses(() => scoped.communities.list(), /was not granted/);
  await refuses(() => scoped.identity.current(), /was not granted/);
});

test('a granted read works; the matching WRITE in the same domain is still refused', async () => {
  const { scoped } = await makeScoped('readonly', { allow: ['relationships.read'] });

  // The granted capability reaches the REAL domain — this is a scope, not a stub that answers everything.
  assert.deepEqual(await scoped.relationships.list(), []);

  // A read grant must not carry the write half of the same domain.
  await refuses(() => scoped.relationships.connect('not-an-oobi'), /was not granted 'relationships\.write'/);
});

test('a granted write implies nothing about reads, and neither implies another domain', async () => {
  const { scoped } = await makeScoped('writeonly', { allow: ['messaging.write'] });
  // The write half is reachable — `clear` takes a peer DID and the scope does not alter arguments.
  await scoped.messaging.clear('did:scid:vh:peer-not-present');
  // …while a read in the same domain is not, and no other domain is.
  await refuses(() => scoped.messaging.unread(), /was not granted 'messaging\.read'/);
  await refuses(() => scoped.profiles.list(), /was not granted 'profiles\.read'/);
});

test('the scoped object does not expose host authority at all', async () => {
  const { scoped } = await makeScoped('nohost', { allow: ['identity.read', 'relationships.read'] });
  const asRecord = scoped as unknown as Record<string, unknown>;
  // Absent, not merely gated: a context is an application, not an operator. `contexts` is absent too — a context
  // must not be able to provision or revoke other contexts.
  for (const forbidden of ['start', 'stop', 'host', 'version', 'adopt', 'contexts', 'replay', 'cursor']) {
    assert.equal(forbidden in asRecord, false, `'${forbidden}' must not be reachable from a scoped stack`);
  }
});

test('identity.sign is refused even with identity.read — a context must not sign with the ROOT key', async () => {
  // The sharpest case: precisely what F-021's isolation exists to protect. The root keypair is the host's.
  const { scoped } = await makeScoped('nosign', { allow: ['identity.read'] });
  await refuses(() => scoped.identity.sign(new Uint8Array([1, 2, 3])), /not part of the context surface/);
});


// ---------------------------------------------------------------------------
// 2. Deny by omission
// ---------------------------------------------------------------------------

test('every method of every exposed domain is classified — an unclassified one would be denied silently', () => {
  // Structural, against the domain SOURCES. This is what makes the scope robust to a domain gaining a method: a
  // new method is not reachable by accident, it is refused until someone classifies it — and this test fails so
  // the omission is noticed rather than shipped as an accidental grant.
  const domainsDir = new URL('../../src/domains/', import.meta.url).pathname;
  const unclassified: string[] = [];

  for (const domain of Object.keys(METHOD_CLASSIFICATION.read) as ScopedDomain[]) {
    const src = readFileSync(join(domainsDir, `${domain}.ts`), 'utf8');
    const iface = /export interface \w*Api\s*\{([\s\S]*?)\n\}/.exec(src);
    assert.ok(iface, `${domain}.ts must declare an API interface`);

    // Method declarations at interface-member indentation (`  name(`). Nested option-object fields are indented
    // further, so they are excluded.
    const methods = [...iface![1].matchAll(/^ {2}([a-zA-Z_$][\w$]*)\s*\(/gm)].map((m) => m[1]);
    assert.ok(methods.length > 0, `${domain}.ts declares methods`);

    // Every declared method must be classified read/write OR listed as deliberately denied. A method in none of
    // those is the case this guard exists to catch: it would be refused at runtime by omission, which is safe
    // but silent — someone has to decide, and this test is what makes them.
    const classified = new Set<string>([
      ...METHOD_CLASSIFICATION.read[domain],
      ...METHOD_CLASSIFICATION.write[domain],
      ...METHOD_CLASSIFICATION.denied[domain],
    ]);
    for (const method of methods) {
      if (!classified.has(method)) unclassified.push(`${domain}.${method}`);
    }
    // Drift in the other direction: a classification naming a method that no longer exists.
    for (const name of classified) {
      assert.ok(methods.includes(name), `${domain}.${name} is classified but not declared — stale entry`);
    }
  }

  assert.deepEqual(
    unclassified, [],
    'these methods are on a domain but neither classified nor deliberately denied — decide which they are',
  );
});

test('an unclassified method is refused at runtime, not granted', async () => {
  // The structural guard above proves the classification is COMPLETE today; this proves what incompleteness
  // would DO. `identity.sign` is deliberately unclassified, and granting its domain's read does not unlock it.
  const { scoped } = await makeScoped('omission', { allow: ['identity.read'] });
  await refuses(() => scoped.identity.sign(new Uint8Array([9])), /not part of the context surface/);
});

// ---------------------------------------------------------------------------
// 3. Expiry
// ---------------------------------------------------------------------------

test('an expired context is refused, and expiry is re-evaluated per call rather than captured', async () => {
  // `expiresAt` in the PAST — already expired when the scoped object is built.
  const { scoped } = await makeScoped('expired', {
    allow: ['relationships.read'],
    provision: { expiresAt: Math.floor(Date.now() / 1000) - 60 },
  });

  await refuses(() => scoped.relationships.list(), /is expired/);
  assert.equal(scoped.state().live, false);
  assert.equal(scoped.state().reason, 'expired');
});

test('a context with no expiresAt never expires', async () => {
  const { scoped } = await makeScoped('never', { allow: ['relationships.read'] });
  assert.equal(scoped.state().live, true);
  assert.equal(scoped.state().reason, 'active');
  assert.deepEqual(await scoped.relationships.list(), []);
});

// ---------------------------------------------------------------------------
// 4. Revocation stops calls AND events
// ---------------------------------------------------------------------------

test('revocation stops calls on the NEXT call — liveness is not cached at construction', async () => {
  const { stack, scoped } = await makeScoped('revoked', { allow: ['relationships.read'] });

  // Works while live…
  assert.deepEqual(await scoped.relationships.list(), []);
  assert.equal(scoped.state().live, true);

  // …then revoke, which DELETES the context directory.
  await stack.contexts.revoke('revoked');

  // The SAME scoped object must now refuse. An implementation that captured liveness once would keep serving.
  await refuses(() => scoped.relationships.list(), /is revoked/);
  assert.equal(scoped.state().live, false);
  assert.equal(scoped.state().reason, 'revoked');
});

test('a revoked context receives no further events', async () => {
  // A REAL event on the real bus, not a test seam: `identity.created` is local and needs no peer, so the
  // delivery path exercised here is the one an application uses.
  const { stack, scoped } = await makeScoped('revoked-events', { allow: ['identity.read'] });

  const names: string[] = [];
  scoped.on('identity.created', (p) => { names.push(p.name); });

  // While live the event IS delivered — otherwise the assertion below would pass vacuously.
  await stack.identity.create({ name: 'while-live', passphrase: 'correct horse battery' });

  await stack.contexts.revoke('revoked-events');
  await stack.identity.create({ name: 'after-revocation', passphrase: 'correct horse battery' });

  assert.deepEqual(names, ['while-live'], 'a revoked context must receive no further events');
});

test('the scope still reports what it WAS granted after revocation — the grant is not erased, the context is', async () => {
  const { stack, scoped } = await makeScoped('revoked-grant', { allow: ['messaging.read'] });
  await stack.contexts.revoke('revoked-grant');
  const state = scoped.state();
  assert.equal(state.live, false);
  assert.deepEqual(state.capabilities, ['messaging.read']);
});

// ---------------------------------------------------------------------------
// 5. The domain itself
// ---------------------------------------------------------------------------

test('contexts.list() sees a provisioned context, and revoke() removes it', async () => {
  const { stack } = await makeScoped('lifecycle', { allow: [] });

  const before = await stack.contexts.list();
  assert.deepEqual(before.map((c) => c.contextId), ['lifecycle']);
  assert.equal(before[0].deviceLocal, false, 'deviceLocal defaults to false');
  assert.deepEqual(before[0].allowedKeyIds, ['#key-1'], 'the key scope defaults to #key-1');

  assert.equal(await stack.contexts.isExpired('lifecycle'), false);

  await stack.contexts.revoke('lifecycle');
  assert.deepEqual(await stack.contexts.list(), [], 'a revoked context is gone from the registry');
  assert.equal(await stack.contexts.get('lifecycle'), null);
});

test('contexts.provision() returns PUBLIC identifiers only — no secret-key field crosses the boundary', async () => {
  // The API-level restatement of F-021 / Y1. `test/agent/context-provisioning.test.ts` pins the runtime bundle;
  // this pins what the DOMAIN hands a caller, which is the surface a third-party app actually sees.
  const home = mkdtempSync(join(tmpdir(), 'api-scope-'));
  HOMES.push(home);
  const stack = await createAgentStack({
    home,
    agent: { name: 'scope-f021', passphrase: 'correct horse battery', port: nextPort++ },
  });
  STACKS.push(stack);

  const bundle = await stack.contexts.provision('app-under-test');
  assert.deepEqual(
    Object.keys(bundle).sort(),
    [
      'allowedKeyIds', 'contextAgreementVid', 'contextDid', 'contextId',
      'contextSigningVid', 'expiresAt', 'keysStayInContext', 'keystorePath',
    ].sort(),
    'the provision result must expose public identifiers and the keystore path — and nothing else',
  );
  for (const [key, value] of Object.entries(bundle)) {
    assert.notEqual(value instanceof Uint8Array, true, `${key} must not carry raw key bytes`);
  }
  assert.equal(bundle.keysStayInContext, true);
});

test('contexts.provision() rejects an empty contextId rather than creating an unnamed context', async () => {
  const { stack } = await makeScoped('valid', { allow: [] });
  await assert.rejects(
    () => stack.contexts.provision('   '),
    (err: unknown) => {
      assert.equal((err as { code?: string }).code, 'invalid_context_id');
      return true;
    },
  );
});

test('asContext() rejects an empty contextId', async () => {
  const { stack } = await makeScoped('valid2', { allow: [] });
  assert.throws(
    () => stack.asContext('', { allow: [] }),
    (err: unknown) => {
      assert.equal((err as { code?: string }).code, 'invalid_context_id');
      return true;
    },
  );
});
