// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `credentials.issue()` and `credentials.verify()` — Group A of the API-layer refactor.
 *
 * Both methods were absent from the layer, and both were **contract decisions**, not ports: the deleted
 * `POST /api/vrcs` took caller-supplied `signers: [{ vid, signingKeyPair }]`, which would have required the
 * credentials page to hold admin private keys, and the deleted `POST /api/vrcs/:id/verify` addressed a VRC by a
 * numeric `id` that `listVrcsForSelf()` never returned.
 *
 * What is pinned here:
 *
 *  - the five typed refusals (`not_found` · `not_admin` · `claim_not_allowed` · `threshold_not_met` ·
 *    `unknown_subject`) each fire for their OWN reason and not by accident;
 *  - the round trip `issue()` → `verify()` returns `valid: true` for a community whose threshold the caller can
 *    satisfy — which is only possible if the runtime signed with the real identity key AND the store preserved
 *    the signer's CESR key (see `src/vtc/store.ts`);
 *  - `verify()` distinguishes "could not be checked" (404) from "did not check out" (`valid: false`).
 *
 * The fixture seeds a real governance row rather than mocking the store: `governanceRowToDoc` derives the admin
 * list by JOINing `memberships → identities → did_documents → keys`, so the only way to prove `issue()` sees the
 * caller as an admin is to give it rows to derive from.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/trust_app_api/credentials-issue-verify.test.ts
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createAgentStack, type TrustStack } from '../../src/index.js';

const HOMES: string[] = [];
const STACKS: TrustStack[] = [];
const PASS = 'correct horse battery';
const CLAIM = 'witness-member';

after(async () => {
  for (const s of STACKS) {
    try { await s.stop(); } catch { /* not started */ }
  }
  for (const h of HOMES) rmSync(h, { recursive: true, force: true });
});

/**
 * ONE **started** stack, shared by every test in this file.
 *
 * Both properties are load-bearing:
 *
 *  - **Started.** `VtcApiModule.init(this.db.vtcStore)` happens inside `BaseAgent.start()`, so on an unstarted
 *    stack `getCommunityByDid()` short-circuits to `undefined` and every issue reports `not_found` — the
 *    community is seeded correctly and still "not known locally". The runtime genuinely requires a live agent
 *    for this path, so the tests start one rather than pretending otherwise.
 *  - **Shared.** A started agent binds a libp2p listen port from a small fixed range, and `node --test` runs
 *    test *files* concurrently — so one started agent per test exhausts that range and fails with
 *    `EADDRINUSE`. One per file keeps the suite honest without making it flaky.
 *
 * Sharing means the tests share a DATABASE, so each seeds its own community and assertions are scoped to that
 * community rather than to the whole credential list.
 */
let started: Promise<TrustStack> | null = null;
function makeStartedStack(agentName = 'credentialer'): Promise<TrustStack> {
  if (!started) {
    started = (async () => {
      const home = mkdtempSync(join(tmpdir(), 'api-cred-'));
      HOMES.push(home);
      const stack = await createAgentStack({ home, agent: { name: agentName, passphrase: PASS, port: 24014 } });
      STACKS.push(stack);
      await stack.start();
      return stack;
    })();
  }
  return started;
}

/** Assert a rejection carries a specific `code`, and return the error for further inspection. */
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

/**
 * Seed a VTC into the active agent's database, with the agent itself as an admin.
 *
 * The agent is made an admin by a `memberships` row rather than by writing `adminVids` directly: `adminVids` is
 * DERIVED (from the admin's primary `did_documents` + its Ed25519 `keys` row), so seeding the derivation inputs
 * is what makes `issue()`'s admin check exercise the real path — including the `keys.public_key` resolution that
 * the `governanceRowToDoc` fix restored.
 *
 * `threshold` defaults to 1 so the caller can actually satisfy it; passing 2 is how the `threshold_not_met`
 * refusal is reached.
 */
async function seedCommunity(
  stack: TrustStack,
  opts: { threshold?: number; claimTypes?: string[]; adminIsAgent?: boolean } = {},
): Promise<{ vtcDid: string }> {
  const { SqliteDataSource } = await import('@p2p-trust-stack/core/db/sqlite-data-source.js');
  const { generateUuid } = await import('@p2p-trust-stack/core/db/uuid-helpers.js');

  const name = (await stack.identity.current()).name;
  assert.ok(name, 'seedCommunity needs an active agent');
  const ds = stack.host.storageFor(name) as InstanceType<typeof SqliteDataSource>;

  const communityUuid = generateUuid();
  const vtcDid = `did:scid:vh:1:z${communityUuid.replace(/-/g, '').slice(0, 20)}`;
  const now = Math.floor(Date.now() / 1000);

  try {
    await ds.run(
      `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
       VALUES (?, 'vta', 'ai_agent', 'local', ?, ?, ?)`,
      communityUuid, 'Springfield', now, now,
    );
    // The primary DID document is what `IdentityResolver.lookupByDid` resolves, and therefore what
    // `getGovernanceDoc(vtcDid)` needs before it can return anything at all.
    await ds.run(
      `INSERT INTO did_documents (uuid, identity_uuid, did, method, is_primary, status, created_at, updated_at)
       VALUES (?, ?, ?, 'peer4', 1, 'active', ?, ?)`,
      generateUuid(), communityUuid, vtcDid, now, now,
    );
    await ds.run(
      `INSERT INTO governance (uuid, community_identity_uuid, admin_threshold_m, admin_threshold_n, updated_at)
       VALUES (?, ?, ?, 1, ?)`,
      generateUuid(), communityUuid, opts.threshold ?? 1, now,
    );

    if (opts.adminIsAgent !== false) {
      const me = await ds.get<{ uuid: string }>('SELECT uuid FROM identities WHERE name = ?', name);
      assert.ok(me, 'the active agent must have an identities row');
      await ds.run(
        `INSERT INTO memberships (uuid, member_identity_uuid, community_identity_uuid, role, status, issued_at)
         VALUES (?, ?, ?, 'admin', 'active', ?)`,
        generateUuid(), me.uuid, communityUuid, now,
      );

      // The agent's Ed25519 public key, planted under its PRIMARY did_document.
      //
      // Not a convenience: `resolveAdmins` derives `adminVids` by JOINing
      // `memberships → identities → did_documents (is_primary=1) → keys`, so without a `keys` row the admin
      // resolves in `adminDids` but contributes NOTHING to `adminVids` — and `adminVids` is the list `issueVrc`
      // checks the signer against. The agent's own key normally lives in the separate keystore FILE, not this
      // table, so the fixture plants it, decoding its CESR vid for the public bytes.
      const { cesrDecode } = await import('@p2p-trust-stack/core/crypto/cesr.js');
      const agentVid = (await stack.identity.current()).vid;
      assert.ok(agentVid, 'the active agent must expose its CESR vid');
      const doc = await ds.get<{ uuid: string }>(
        'SELECT uuid FROM did_documents WHERE identity_uuid = ? AND is_primary = 1',
        me.uuid,
      );
      assert.ok(doc, 'the active agent must have a primary did_document');
      // Idempotent: the key belongs to the AGENT, not the community, and the started stack is shared — so this
      // must not re-insert on every call (`keys` is UNIQUE on identity_uuid + did_document_uuid + key_type +
      // rotation_version).
      const already = await ds.get(
        `SELECT uuid FROM keys WHERE identity_uuid = ? AND did_document_uuid = ? AND key_type = 'ed25519'`,
        me.uuid, doc.uuid,
      );
      if (!already) {
        await ds.run(
          `INSERT INTO keys (uuid, identity_uuid, did_document_uuid, key_type, public_key, rotation_version, created_at)
           VALUES (?, ?, ?, 'ed25519', ?, 0, ?)`,
          generateUuid(), me.uuid, doc.uuid, cesrDecode(agentVid).bytes, now,
        );
      }
    }

    for (const ct of opts.claimTypes ?? [CLAIM]) {
      // `governanceRowToDoc` reads claim types from these bindings, matching on the rule_type PREFIX.
      await ds.run(
        `INSERT INTO community_policy_bindings (uuid, community_identity_uuid, rule_type, enabled, params, updated_at)
         VALUES (?, ?, ?, 1, ?, ?)`,
        generateUuid(),
        communityUuid,
        `task:p2pts:rule:claim-type-allow:0.1#${ct}`,
        JSON.stringify({ claim_type: ct }),
        now,
      );
    }

    return { vtcDid };
  } finally {
    await ds.close();
  }
}


// ── issue(): the typed refusals ──────────────────────────────────────────────

test('issue(): a missing vtcDid or claim.type is `invalid_input`, not a store lookup', async () => {
  const stack = await makeStartedStack();
  await rejectsWithCode(() => stack.credentials.issue({ vtcDid: '', claim: { type: CLAIM } }), 'invalid_input');
  await rejectsWithCode(() => stack.credentials.issue({ vtcDid: 'did:scid:vh:1:zx', claim: { type: '' } }), 'invalid_input');
});

test('issue(): an unknown community is `not_found` — distinct from not being an admin of one', async () => {
  const stack = await makeStartedStack();
  const err = await rejectsWithCode(
    () => stack.credentials.issue({ vtcDid: 'did:scid:vh:1:znosuchcommunity', claim: { type: CLAIM } }),
    'not_found',
  );
  assert.match(err.message, /No community known locally/);
});

test('issue(): a known community the caller does not administer is `not_admin`', async () => {
  const stack = await makeStartedStack();
  // A real governance row, but NO membership row for the agent — so `adminVids` resolves to nothing.
  const { vtcDid } = await seedCommunity(stack, { adminIsAgent: false });
  const err = await rejectsWithCode(
    () => stack.credentials.issue({ vtcDid, claim: { type: CLAIM } }),
    'not_admin',
  );
  assert.match(err.message, /admin of the issuing community/);
});

test('issue(): a claim type the community does not allow is `claim_not_allowed`', async () => {
  const stack = await makeStartedStack();
  const { vtcDid } = await seedCommunity(stack, { claimTypes: ['some-other-claim'] });
  const err = await rejectsWithCode(
    () => stack.credentials.issue({ vtcDid, claim: { type: CLAIM } }),
    'claim_not_allowed',
  );
  // The message names the allowed set, so the page can tell the user what WOULD work.
  assert.match(err.message, /some-other-claim/);
});

test('issue(): a community needing more than one signature is `threshold_not_met`', async () => {
  // The decision this pins: REFUSE rather than record a `pending_signatures` credential. `graph()` filters only
  // revoked/expired, so a below-threshold row would render as a LIVE trust edge — recording one means teaching
  // the graph and every verifier to treat it as unproven first, which is a second design.
  const stack = await makeStartedStack();
  const { vtcDid } = await seedCommunity(stack, { threshold: 2 });
  const err = await rejectsWithCode(
    () => stack.credentials.issue({ vtcDid, claim: { type: CLAIM } }),
    'threshold_not_met',
  );
  assert.match(err.message, /requires 2 admin signatures/);
  // ...and nothing was written FOR THIS COMMUNITY: a refused issue must not leave a credential behind. Scoped by
  // issuer because the started stack is shared, so other tests' credentials are legitimately present.
  const mine = (await stack.credentials.list()).filter((c) => c.source === 'vtc' && c.issuerVid === vtcDid);
  assert.deepEqual(mine, []);
});


test('issue(): a subject this node does not know is `unknown_subject`, not a fabricated identity', async () => {
  // `VtcStore.saveVrc` calls `resolveRemoteIdentity`, which FABRICATES a placeholder row for an unknown VID.
  // Without this guard a typo would mint a phantom identity AND a credential no later read can match.
  const stack = await makeStartedStack();
  const { vtcDid } = await seedCommunity(stack);
  // A VALID CESR key that belongs to nobody here: `asCesrVid` accepts it (so this is not `invalid_input`), but
  // no `identities` row carries it — which is the condition `unknown_subject` exists to catch. A malformed
  // string would exercise the wrong branch and pass for the wrong reason.
  const { cesrEncode, CESR_CODES } = await import('@p2p-trust-stack/core/crypto/cesr.js');
  const { randomBytes } = await import('node:crypto');
  const strangerVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, new Uint8Array(randomBytes(32)));
  const err = await rejectsWithCode(
    () => stack.credentials.issue({ vtcDid, subjectVid: strangerVid, claim: { type: CLAIM } }),
    'unknown_subject',
  );
  assert.match(err.message, /No identity known locally for subject/);
});

test('issue(): a DID where a CESR VID belongs is `invalid_input`, and the codec names the field', async () => {
  const stack = await makeStartedStack();
  const { vtcDid } = await seedCommunity(stack);
  const err = await rejectsWithCode(
    () => stack.credentials.issue({ vtcDid, subjectVid: 'did:scid:vh:1:znotacesrkey', claim: { type: CLAIM } }),
    'invalid_input',
  );
  assert.match(err.message, /subjectVid/);
});

// ── issue(): the success path and the round trip ─────────────────────────────

test('issue(): self-issue succeeds, signs once, and persists the credential', async () => {
  const stack = await makeStartedStack();
  const { vtcDid } = await seedCommunity(stack);

  const issued = await stack.credentials.issue({ vtcDid, claim: { type: CLAIM } });
  assert.equal(issued.claimType, CLAIM);
  assert.equal(issued.signatureCount, 1, 'a self-signed credential carries exactly one signature');

  // Read back through the OTHER accessor, so the assertion is about what was stored rather than what was returned.
  const listed = await stack.credentials.list();
  const found = listed.find((c) => c.source === 'vtc' && c.issuerVid === vtcDid && c.claimType === CLAIM);
  assert.ok(found, 'the issued credential is listed from the VTC store');
  assert.equal(found.subjectVid, issued.subjectVid, 'self-issue names the caller as the subject');
});

test('issue() → verify() round trip: a self-signed credential verifies against its community', async () => {
  // The end-to-end claim of this slice, and the test that caught two real store defects. It can only pass if:
  //  (1) the runtime signed with the ACTIVE IDENTITY's key, and
  //  (2) the store round-tripped the signer as a CESR key rather than its identity uuid.
  // (2) failed before this slice: `saveVrc` resolved `sig.signerVid` (a CESR key) as a DID, fabricating a
  // phantom identity, and `deserializeSignatures` then reported the uuid — so `countValidAdminSignatures`, which
  // requires `adminVids.includes(signerVid)` AND `decodeVidToPublicKey(signerVid)`, always counted 0.
  const stack = await makeStartedStack();
  const { vtcDid } = await seedCommunity(stack);

  const issued = await stack.credentials.issue({ vtcDid, claim: { type: CLAIM } });
  const result = await stack.credentials.verify({
    subjectVid: issued.subjectVid,
    issuerVid: issued.issuerVid,
    claimType: issued.claimType,
  });

  assert.equal(result.valid, true, `expected a valid credential, got: ${result.reason ?? '(no reason)'}`);
  assert.equal(result.validSignatureCount, 1);
  assert.equal(result.reason, undefined, 'a valid result carries no reason');
});


test('issue(): emits `credential.issued`, recovered through the digest the store persisted', async () => {
  // P5 retired the polls, so the bus is the only thing that refreshes another client's credential list. The
  // store assigns the row's uuid inside `saveVrc` and the returned `Vrc` does not carry it, so the domain
  // recovers it by digest — this test is what proves that recovery actually finds the row.
  const stack = await makeStartedStack();
  const { vtcDid } = await seedCommunity(stack);

  const seen: Array<{ uuid: string; vcType: string }> = [];
  const sub = stack.on('credential.issued', (payload) => {
    seen.push(payload as { uuid: string; vcType: string });
  });
  try {
    await stack.credentials.issue({ vtcDid, claim: { type: CLAIM } });
  } finally {
    sub.unsubscribe();
  }

  assert.equal(seen.length, 1, 'exactly one credential.issued event');
  assert.equal(seen[0].vcType, 'vrc');
  assert.ok(seen[0].uuid.length > 0, 'the uuid was recovered — an empty one would mean the digest lookup missed');
});

// ── verify(): could-not-check vs did-not-check-out ───────────────────────────

test('verify(): an unknown credential is `not_found` — not a `valid: false` verdict', async () => {
  const stack = await makeStartedStack();
  await seedCommunity(stack);
  // "I cannot check this" and "this did not check out" are different answers, and only the second is evidence
  // against a credential.
  const err = await rejectsWithCode(
    () => stack.credentials.verify({ subjectVid: 'znobody', issuerVid: 'znobody', claimType: CLAIM }),
    'not_found',
  );
  assert.match(err.message, /No such credential/);
});

test('verify(): an empty field is `invalid_input` — all three parts are required', async () => {
  const stack = await makeStartedStack();
  await rejectsWithCode(() => stack.credentials.verify({ subjectVid: '', issuerVid: 'a', claimType: 'c' }), 'invalid_input');
  await rejectsWithCode(() => stack.credentials.verify({ subjectVid: 'a', issuerVid: '', claimType: 'c' }), 'invalid_input');
  await rejectsWithCode(() => stack.credentials.verify({ subjectVid: 'a', issuerVid: 'b', claimType: '' }), 'invalid_input');
});

// ── revoke(): addressed by UUID ──────────────────────────────────────────────

test('revoke() round-trips by UUID — the addressing no consumer could supply before', async () => {
  // `revoke()` took a node-local SQLite rowid until 2026-10-10. **No DTO published one**, so the method was
  // unreachable from any consumer and the web UI's Revoke button was disabled outright, with a title saying
  // exactly that. This is the round trip that was impossible then: seed a DTG credential, revoke it by the uuid
  // `list()` reports, and confirm the change through a SEPARATE read.
  const stack = await makeStartedStack();

  const name = (await stack.identity.current()).name;
  assert.ok(name, 'revoke() needs an active agent');
  const { SqliteDataSource } = await import('@p2p-trust-stack/core/db/sqlite-data-source.js');
  const credentialsRepo = await import('@p2p-trust-stack/core/db/repositories/credentials-repo.js');
  const identitiesRepo = await import('@p2p-trust-stack/core/db/repositories/identities-repo.js');
  const ds = stack.host.storageFor(name) as InstanceType<typeof SqliteDataSource>;

  const me = await identitiesRepo.findByRealDid(ds, (await stack.identity.current()).did!);
  assert.ok(me, 'the active identity has a row');

  const uuid = await credentialsRepo.create(ds, {
    vcType: 'vrc',
    issuerIdentityUuid: me.uuid,
    subjectIdentityUuid: me.uuid,
    validFrom: Math.floor(Date.now() / 1000),
  });

  // The uuid IS the address, and it is published: `StoredCredentialDto.uuid`.
  const listed = (await stack.credentials.list()).find((c) => c.source === 'dtg' && c.uuid === uuid);
  assert.ok(listed, 'the seeded credential is listed, addressed by the uuid a consumer can see');

  // Both events fire, in order: `changed` is the generic repaint signal every credential mutation emits;
  // `revoked` says WHY and carries the vcType a subscriber needs to react without re-reading the row.
  const seen: Array<{ name: string; payload: any }> = [];
  stack.on('credential.changed', (p) => seen.push({ name: 'changed', payload: p }));
  stack.on('credential.revoked', (p) => seen.push({ name: 'revoked', payload: p }));

  const revoked = await stack.credentials.revoke(uuid);
  assert.ok(revoked, 'revoke() returns the updated row rather than null');
  assert.equal(revoked.uuid, uuid, 'addressed by uuid, so the returned row is the one asked for');
  assert.equal(revoked.status, 'revoked');

  assert.deepEqual(seen.map((e) => e.name), ['changed', 'revoked']);
  assert.equal(seen[1].payload.vcType, 'vrc', '`credential.revoked` carries the vcType');
  assert.equal(seen[1].payload.uuid, uuid);

  // Read back through a DIFFERENT accessor, so the assertion is about what was PERSISTED. `list()` reports
  // ISSUED credentials, so a revoked row drops out of it — which is itself the observable effect.
  const after = (await stack.credentials.list()).find((c) => c.source === 'dtg' && c.uuid === uuid);
  assert.equal(after, undefined, 'a revoked credential is no longer reported as issued');

  // And it is still addressable afterwards — a second revoke finds the row and reports it revoked, rather than
  // 404ing as if the credential had vanished.
  const again = await stack.credentials.revoke(uuid);
  assert.equal(again?.status, 'revoked');
});

