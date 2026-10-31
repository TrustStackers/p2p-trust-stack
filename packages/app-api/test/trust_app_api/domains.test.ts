// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `relationships`, `names`, `profiles`, and `credentials` domain tests — driven through the public barrel only.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/trust_app_api/domains.test.ts
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createAgentStack, type TrustStack } from '../../src/index.js';

const HOMES: string[] = [];
const STACKS: TrustStack[] = [];
const PASS = 'correct horse battery';

after(async () => {
  for (const s of STACKS) {
    try { await s.stop(); } catch { /* not started */ }
  }
  for (const h of HOMES) rmSync(h, { recursive: true, force: true });
});

async function makeStack(agentName = 'domainer'): Promise<TrustStack> {
  const home = mkdtempSync(join(tmpdir(), 'api-domains-'));
  HOMES.push(home);
  const stack = await createAgentStack({ home, agent: { name: agentName, passphrase: PASS, port: 24013 } });
  assert.equal(stack.host.home, home, 'isolated home — must never touch the real P2PTS_HOME');
  STACKS.push(stack);
  return stack;
}

/**
 * A stack whose agent is **started**.
 *
 * Several runtime operations need the live node or an open data source — `generateOobi`, `resolveName`, and
 * the profile store among them — and throw "Agent not started" without it. That requirement is part of the
 * surface as it stands, so the tests that exercise those calls start the agent rather than pretending
 * otherwise.
 *
 * **One shared instance, not one per test.** A started agent binds a libp2p listen port from a small fixed
 * range, and `node --test` runs test *files* concurrently — so several started agents across files exhaust
 * that range and fail with `EADDRINUSE`. Sharing one per file keeps the suite honest about the API without
 * making it flaky about ports.
 */
let started: Promise<TrustStack> | null = null;
function makeStartedStack(agentName = 'domainer'): Promise<TrustStack> {
  if (!started) {
    started = (async () => {
      const stack = await makeStack(agentName);
      await stack.start();
      return stack;
    })();
  }
  return started;
}

// ── relationships ────────────────────────────────────────────────────────────

test('relationships: oobi() returns a non-empty OOBI once the agent is started', async () => {
  // generateOobi needs the live libp2p node, so the agent must be started.
  const stack = await makeStartedStack();
  const { oobi } = await stack.relationships.oobi();
  assert.equal(typeof oobi, 'string');
  assert.ok(oobi.length > 0, 'a started agent can always produce its OOBI');
});

test('relationships: list() is empty on a fresh agent and get() returns null', async () => {
  const stack = await makeStack();
  assert.deepEqual(await stack.relationships.list(), []);
  assert.equal(await stack.relationships.get('did:scid:vh:1:znobody'), null);
});
test('relationships: ceremonyStatus() reports the peer with no ceremony, not an error', async () => {
  const stack = await makeStack();
  const status = await stack.relationships.ceremonyStatus('did:scid:vh:1:znobody');
  assert.equal(status.remoteDid, 'did:scid:vh:1:znobody');
  assert.equal(status.personhoodStatus, null);
  assert.equal(status.status, null);
  assert.equal(status.ceremony, null);
});

test('relationships: vrc() reports unverified with no credentials', async () => {
  const stack = await makeStack();
  assert.deepEqual(await stack.relationships.vrc('did:scid:vh:1:znobody'), { verified: false, vrcs: [] });
});

test('relationships: dtgVrc() reports unverified for an unknown peer', async () => {
  const stack = await makeStack();
  assert.deepEqual(await stack.relationships.dtgVrc('did:scid:vh:1:znobody'), { verified: false, dtgVrcs: [] });
});

test('relationships: connect() rejects an empty OOBI', async () => {
  const stack = await makeStack();
  await assert.rejects(() => stack.relationships.connect('   '), /oobi is required/);
});

test('relationships: every call fails closed once deactivated', async () => {
  const stack = await makeStack('leaver');
  await stack.identity.deactivate();
  await assert.rejects(() => stack.relationships.list(), /No active VTA/);
  await assert.rejects(() => stack.relationships.oobi(), /No active VTA/);
  await assert.rejects(() => stack.relationships.ceremonyStatus('did:x'), /No active VTA/);
});

// ── names ────────────────────────────────────────────────────────────────────

test('names: list() is empty on a fresh agent', async () => {
  const stack = await makeStack();
  assert.deepEqual(await stack.names.list(), []);
});

test('names: register() requires a name and a namespace', async () => {
  const stack = await makeStack();
  await assert.rejects(() => stack.names.register({ name: '', namespace: 'ns' }), /name and namespace/);
  await assert.rejects(() => stack.names.register({ name: 'n', namespace: '' }), /name and namespace/);
});

test('names: resolve() requires a name URI and rejects a malformed one with a helpful message', async () => {
  // resolveName needs the live node, so the agent must be started.
  const stack = await makeStartedStack();
  await assert.rejects(() => stack.names.resolve(''), /nameUri is required/);
  // A name URI is `vta:<namespace>:<name>`; anything else is refused before any lookup is attempted, so this
  // assertion needs no network. (A well-formed URI that is merely unbound would require a live resolver.)
  await assert.rejects(
    () => stack.names.resolve('did:scid:vh:1:znobody/names/nope'),
    /expected format vta:<namespace>:<name>/,
  );
});

test('names: every call fails closed once deactivated', async () => {
  const stack = await makeStack('leaver');
  await stack.identity.deactivate();
  await assert.rejects(() => stack.names.list(), /No active VTA/);
  await assert.rejects(() => stack.names.resolve('x'), /No active VTA/);
});

// ── profiles ─────────────────────────────────────────────────────────────────

test('profiles: create → list → claims → card → remove, emitting profile.changed', async () => {
  // The profile store needs the agent's open data source, so the agent must be started.
  const stack = await makeStartedStack();

  const changed: string[] = [];
  stack.on('profile.changed', (p) => changed.push(p.profileUuid));

  const profile = await stack.profiles.create({ label: 'Primary', purpose: 'personal' });
  assert.ok(profile.uuid, 'a uuid comes back');
  assert.equal(profile.label, 'Primary');
  assert.equal(profile.purpose, 'personal');
  assert.deepEqual(changed, [profile.uuid], 'create announced itself');

  const list = await stack.profiles.list();
  assert.equal(list.length, 1);
  assert.equal(list[0].uuid, profile.uuid);

  const claim = await stack.profiles.addClaim({
    profileUuid: profile.uuid,
    claimKey: 'email',
    claimValue: 'a@example.com',
    // The schema CHECK allows exactly: always | discretionary | never | zkp_only.
    disclosure: 'always',
  });
  assert.equal(claim.claimKey, 'email');
  assert.equal(changed.length, 2, 'addClaim announced itself');

  const claims = await stack.profiles.claims(profile.uuid);
  assert.equal(claims.length, 1);
  // A claim row carries a commitment `salt`; it must never cross the API boundary.
  assert.equal('salt' in (claims[0] as object), false, 'the commitment salt is NOT exposed');

  const card = await stack.profiles.card(profile.uuid);
  assert.equal(card.profileUuid, profile.uuid);
  assert.equal(card.label, 'Primary');
  assert.ok(Array.isArray(card.claims));

  // A second profile is required before the first can go: the runtime refuses to remove the LAST profile for
  // an identity. That rule is a real invariant, so it is pinned rather than worked around.
  await assert.rejects(() => stack.profiles.remove(profile.uuid), /last profile/);

  const second = await stack.profiles.create({ label: 'Secondary' });
  const removed = await stack.profiles.remove(profile.uuid);
  assert.deepEqual(removed, { ok: true });
  assert.deepEqual((await stack.profiles.list()).map((p) => p.uuid), [second.uuid]);
});

test('profiles: syncStatus() reports a well-formed status without a utility server', async () => {
  const stack = await makeStack();
  const status = await stack.profiles.syncStatus();
  assert.equal(typeof status.pending, 'boolean');
  assert.ok(status.lastError === null || typeof status.lastError === 'string');
});

test('the bus is wired to every runtime callback the catalogue promises', () => {
  // The wiring is a source-level property — a dropped registration line is the failure mode, and it would not
  // show up in behaviour until a ceremony actually ran. Asserted at the source, in the same spirit as the
  // delegation guards.
  const src = readFileSync(
    fileURLToPath(new URL('../../src/client/trust-stack.ts', import.meta.url)),
    'utf8',
  );
  const REQUIRED = [
    'onMessage',
    'onRelationshipChange',
    'onCeremonyPrompt',
    'onCeremonyAckChange',
    'onCeremonyComplete',
    'onCeremonyExpired',
    'onCeremonyFailed',
    'onConnectionEvent',
    'onNetworkChange',
    // The arrival signals added for the last two polling pages. A dropped registration here is invisible in
    // behaviour until a push actually lands, which is precisely why it is asserted at the source.
    'onCredentialReceived',
    'onCommunityChanged',
    'onGovernanceProposal',
  ];
  const missing = REQUIRED.filter((cb) => !src.includes(`agent.${cb}`));
  assert.deepEqual(missing, [], 'these runtime callbacks must be bridged onto the bus');
});

/**
 * Events the catalogue declares with a payload that **nothing emits yet**.
 *
 * A catalogue entry nothing emits is a lie about the contract: it promises a push that never arrives, and any
 * page that subscribes waits forever — which is why the pages that needed these kept polling instead. Two were
 * fixed in the credential-signal slice (`credential.issued`, `invitation.received`) and two more here
 * (`community.changed`, `governance.proposal`).
 *
 * This list is a **ratchet, like the boundary guard's ceilings**: it may only SHRINK. The test fails if a new
 * unemitted event appears (a fresh lie) *and* if one of these is fixed without being removed here (a stale
 * entry hides the next gap). Each entry names what would emit it.
 */
const KNOWN_UNEMITTED: ReadonlyArray<[string, string]> = [
  ['identity.rotated', 'the CAPABILITY exists (`AgentHandle.rotate()`, called by scid-vh-agent) but the identity domain does not expose it — exposing key rotation through the API is a security decision, not a mechanical emit'],
];

test('every catalogue event that has a declared payload is emitted by SOMETHING', async () => {
  const catalogue = readFileSync(
    fileURLToPath(new URL('../../src/events/catalog.ts', import.meta.url)),
    'utf8',
  );
  // Every `'name': { payload }` line is an event with a declared payload, i.e. one a caller can subscribe to.
  const declared = [...catalogue.matchAll(/^ {2}'([a-z][a-z.]*)': \{[^}]*\}/gm)].map((m) => m[1]);
  assert.ok(declared.length > 10, `expected the catalogue to declare events, found ${declared.length}`);

  // An event is emitted if ANY file in the layer calls `emit('<name>'` — a domain, a runtime callback, or the
  // client root all count.
  const emitted = new Set<string>();
  for (const dir of ['client', 'domains', 'events']) {
    const base = fileURLToPath(new URL(`../../src/${dir}/`, import.meta.url));
    for (const entry of readdirSync(base)) {
      if (!entry.endsWith('.ts')) continue;
      const src = readFileSync(base + entry, 'utf8');
      for (const m of src.matchAll(/emit\('([a-z][a-z.]*)'/g)) emitted.add(m[1]);
    }
  }

  const allowlisted = new Set(KNOWN_UNEMITTED.map(([name]) => name));
  const newlyUnemitted = declared.filter((name) => !emitted.has(name) && !allowlisted.has(name));
  assert.deepEqual(
    newlyUnemitted,
    [],
    'these events are declared with a payload but nothing emits them — a subscriber would wait forever. '
      + 'Emit them, or add them to KNOWN_UNEMITTED with what would emit them.',
  );

  const nowEmitted = KNOWN_UNEMITTED.filter(([name]) => emitted.has(name)).map(([name]) => name);
  assert.deepEqual(
    nowEmitted,
    [],
    'these are now emitted — remove them from KNOWN_UNEMITTED so the list keeps showing the real gaps',
  );
});

test('relationships: acknowledge() emits relationship.ceremony so a UI needs no poll', async () => {
  const stack = await makeStack();
  const steps: string[] = [];
  stack.on('relationship.ceremony', (p) => steps.push(p.step));

  await stack.relationships.acknowledge('did:scid:vh:1:zpeer');
  assert.deepEqual(steps, ['acknowledged']);
});

test('profiles: every call fails closed once deactivated', async () => {
  const stack = await makeStack('leaver');
  await stack.identity.deactivate();
  await assert.rejects(() => stack.profiles.list(), /No active VTA/);
  await assert.rejects(() => stack.profiles.create({ label: 'x' }), /No active VTA/);
  await assert.rejects(() => stack.profiles.card('1'), /No active VTA/);
});

// ── credentials ──────────────────────────────────────────────────────────────

test('credentials: list() is empty on a fresh agent, from BOTH stores', async () => {
  const stack = await makeStack();
  assert.deepEqual(await stack.credentials.list(), []);
});

test('credentials: signatures() returns null for an unknown uuid and rejects an empty one', async () => {
  const stack = await makeStack();
  // null rather than a throw: the adapter turns it into a 404, and "no such credential" is not a caller error.
  assert.equal(await stack.credentials.signatures('00000000-0000-0000-0000-000000000000'), null);
  // Addressed by uuid, not a numeric rowid. An empty address is a caller error; a uuid that simply does not
  // exist is a 404.
  await assert.rejects(() => stack.credentials.signatures(''), /uuid is required/);
});

test('credentials: revoke() returns null for an unknown uuid and rejects an empty one', async () => {
  const stack = await makeStack();
  assert.equal(await stack.credentials.revoke('00000000-0000-0000-0000-000000000000'), null);
  await assert.rejects(() => stack.credentials.revoke(''), /uuid is required/);
});

test('credentials: invitations() is empty on a fresh agent', async () => {
  const stack = await makeStack();
  assert.deepEqual(await stack.credentials.invitations(), []);
});

test('credentials: declineInvitation() is idempotent — declining something unknown is not an error', async () => {
  const stack = await makeStack();
  assert.deepEqual(await stack.credentials.declineInvitation('no-such-uuid'), { ok: true });
  // ...but an empty uuid is a caller error, not a silent no-op.
  await assert.rejects(() => stack.credentials.declineInvitation(''), /uuid is required/);
});

// ── acceptInvitation — the last route whose SQL left the adapter ─────────────

/**
 * Seed a VIC addressed to the active identity.
 *
 * `acceptInvitation` reads the row itself, so the fixture has to put one there. `credentials-repo` is the same
 * repository the domain uses, which is what makes this a real end-to-end read rather than a stub.
 *
 * The uuid is NOT settable — `create()` generates it — so callers find the row through `invitations()`, which is
 * also how a real caller gets it.
 */
async function seedInvitation(
  stack: TrustStack,
  opts: { claim?: string | null; w3cVcJson?: string | null },
): Promise<void> {
  const { SqliteDataSource } = await import('@p2p-trust-stack/core/db/sqlite-data-source.js');
  const credentialsRepo = await import('@p2p-trust-stack/core/db/repositories/credentials-repo.js');
  const name = (await stack.identity.current()).name;
  assert.ok(name, 'seedInvitation needs an active agent');

  const ds = stack.host.storageFor(name) as InstanceType<typeof SqliteDataSource>;
  try {
    const me = await ds.get<{ uuid: string }>('SELECT uuid FROM identities WHERE name = ?', name);
    const issuer = await ds.get<{ uuid: string }>('SELECT uuid FROM identities WHERE uuid != ? LIMIT 1', me!.uuid);
    await credentialsRepo.create(ds, {
      vcType: 'vic',
      issuerIdentityUuid: issuer?.uuid ?? 'community-uuid',
      subjectIdentityUuid: me!.uuid,
      claim: opts.claim ?? undefined,
      w3cVcJson: opts.w3cVcJson ?? undefined,
      validFrom: Math.floor(Date.now() / 1000),
    });
  } finally {
    await ds.close();
  }
}

test('credentials: acceptInvitation() refuses an unknown invitation with `not_found`, and an empty uuid', async () => {
  const stack = await makeStack();
  await assert.rejects(
    () => stack.credentials.acceptInvitation('no-such-uuid'),
    (err: unknown) => {
      assert.equal((err as { code?: string }).code, 'not_found');
      assert.match((err as Error).message, /invitation not found/);
      return true;
    },
  );
  await assert.rejects(() => stack.credentials.acceptInvitation(''), /uuid is required/);
});

test('credentials: acceptInvitation() refuses when the community cannot be determined from the VIC', async () => {
  const stack = await makeStack();
  // A VIC whose claim has no OOBI and whose W3C document has no issuer: there is nothing to accept INTO.
  await seedInvitation(stack, { claim: '{}', w3cVcJson: '{}' });

  const pending = await stack.credentials.invitations();
  assert.equal(pending.length, 1, 'the seeded invitation is pending');
  await assert.rejects(
    () => stack.credentials.acceptInvitation(pending[0].uuid),
    (err: unknown) => {
      assert.equal((err as { code?: string }).code, 'invalid_invitation');
      assert.match((err as Error).message, /cannot determine community/);
      return true;
    },
  );
});

test('credentials: a FAILED accept does not consume the invitation — it stays retryable', async () => {
  // The ordering guarantee. The VIC is marked spent only AFTER the server confirms, so a transient failure must
  // leave the invitation in the pending list rather than burning it against a membership that was never created.
  const stack = await makeStack();
  await seedInvitation(stack, {

    claim: JSON.stringify({ communityName: 'Springfield', oobi: { did: 'did:scid:vh:1:zspringfield' } }),
  });

  const before = await stack.credentials.invitations();
  assert.equal(before.length, 1);

  // No utility server is reachable in this test, so the accept fails at the seam.
  await assert.rejects(
    () => stack.credentials.acceptInvitation(before[0].uuid),
    (err: unknown) => {
      assert.equal((err as { code?: string }).code, 'utility_server_unavailable');
      return true;
    },
  );

  const after = await stack.credentials.invitations();
  assert.equal(after.length, 1, 'a failed accept must leave the invitation pending, not consume it');
  assert.equal(after[0].uuid, before[0].uuid);
});

test('credentials: viewModels() returns the page read model — view models, groups, stats, scenarios', async () => {
  // The credential factory is only available once the node is up, so this one needs a started agent.
  const stack = await makeStartedStack();
  const model = await stack.credentials.viewModels();
  assert.ok(Array.isArray(model.viewModels), 'viewModels is a list');
  assert.equal(typeof model.groups, 'object');
  assert.equal(typeof model.stats, 'object');
  assert.ok(Array.isArray(model.scenarios), 'scenarios is a list — the issue form iterates it');
  // The groups/stats maps are keyed by scenario; a fresh agent simply has no entries.
  assert.deepEqual(Object.keys(model.stats), Object.keys(model.groups));
});

test('credentials: every call fails closed once deactivated', async () => {
  const stack = await makeStack('credleaver');
  await stack.identity.deactivate();
  await assert.rejects(() => stack.credentials.list(), /No active VTA/);
  await assert.rejects(() => stack.credentials.invitations(), /No active VTA/);
  await assert.rejects(() => stack.credentials.viewModels(), /No active VTA/);
  await assert.rejects(() => stack.credentials.signatures('any-uuid'), /No active VTA/);
});

// ── communities ─────────────────────────────────────────────────────────────

test('communities: list() is empty on a fresh agent', async () => {
  const stack = await makeStack();
  assert.deepEqual(await stack.communities.list(), []);
});

test('communities: detail() throws a typed community_not_found, not a bare Error', async () => {
  const stack = await makeStack();
  // The route maps this code to a 404, so the code is the contract — a generic throw would become a 500.
  await assert.rejects(
    () => stack.communities.detail('did:peer:4:not-a-community'),
    (err: unknown) => {
      assert.equal((err as { code?: string }).code, 'community_not_found');
      return true;
    },
  );
});

test('communities: adminCandidates() lists this agent as its own first founding admin', async () => {
  const stack = await makeStack();
  const candidates = await stack.communities.adminCandidates();
  assert.equal(candidates.length, 1, 'a fresh agent has no VRC peers');
  assert.equal(candidates[0].isCreator, true);
  assert.ok(candidates[0].uuid, 'the creator uuid must be resolved from the local store');
});

test('communities: parents() degrades to the local list with no utility server', async () => {
  const stack = await makeStack();
  // The server leg is skipped rather than throwing — the picker must still render.
  assert.deepEqual(await stack.communities.parents(), []);
});

test('communities: checkName() rejects an empty name before touching the server', async () => {
  const stack = await makeStack();
  assert.deepEqual(await stack.communities.checkName('   '), { available: false, message: 'name is required' });
});

test('communities: the ceremony READS degrade to empty lists, and the log carries no mutation', async () => {
  // A STARTED agent: `pendingCeremonies()` resolves this identity's uuid before it can query, so an unstarted
  // agent is not a state this read is defined for (the routes are all guarded by `hasAgent`).
  const stack = await makeStartedStack();
  // These go through the bare query seam (`queryUtilityServer`), which returns null when there is no link.
  // A read that threw here would break the Communities page whenever the server was down.
  assert.deepEqual(await stack.communities.ceremonyLog(), []);
  assert.deepEqual(await stack.communities.ceremonyLogThread('any-thread'), []);
  assert.deepEqual(await stack.communities.pendingCeremonies(), []);
});

test('communities: ceremony() reports the connectivity failure in-band rather than returning null', async () => {
  const stack = await makeStartedStack();
  const status = await stack.communities.ceremony('00000000-0000-4000-8000-000000000000');
  // `{ error }` and not `null`: the caller must be able to tell "no such ceremony" from "server unreachable".
  assert.match(String(status.error), /cannot check the ceremony status/i);
});

test('communities: every call fails closed once deactivated', async () => {
  const stack = await makeStack('commleaver');
  await stack.identity.deactivate();
  await assert.rejects(() => stack.communities.list(), /No active VTA/);
  await assert.rejects(() => stack.communities.detail('did:peer:4:x'), /No active VTA/);
  await assert.rejects(() => stack.communities.adminCandidates(), /No active VTA/);
  await assert.rejects(() => stack.communities.parents(), /No active VTA/);
  await assert.rejects(() => stack.communities.checkName('anything'), /No active VTA/);
  await assert.rejects(() => stack.communities.governanceProposals(), /No active VTA/);
  await assert.rejects(() => stack.communities.ceremonyLog(), /No active VTA/);
});

