/**
 * F-012 stage 3 — does the policy engine actually decide, and can a party be in
 * several communities?
 *
 * Two questions, both prompted by reading the guard rather than its summary:
 *
 *  1. **The engine's facts are assembled by `GovernanceGuard`.** `actor_is_admin`
 *     is evaluated as `data.governance.adminDids.includes(query.actorDid)` — a
 *     DID comparison — but the guard pushes each admin member's
 *     `memberIdentityUuid` into that array, and `identities.uuid` is a UUIDv5,
 *     *not* a DID (`did_documents.did` is the DID). If that mismatch is real,
 *     every `actor_is_admin: true` rule in the default policy denies the very
 *     admins it was written for, and the only issuance that passes is the
 *     community issuing to itself — because `adminDids[0]` is the governance DID.
 *     These tests assert the CORRECT behaviour, so a failure is the evidence.
 *
 *  2. **F-025** claims *"a community has exactly one `parent_community_id`, so a
 *     party cannot be listed by several communities."* The second half looks
 *     false: `memberships` carries `UNIQUE(member_identity_uuid,
 *     community_identity_uuid)`, which is a many-to-many join table, and
 *     `GET /vtcs/for-member/:uuid` fans out over every membership row. Pinned
 *     here so the claim is settled by execution, not by reading.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/services/governance-guard.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import * as identitiesRepo from '../../src/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '../../src/db/repositories/did-documents-repo.js';
import * as membershipsRepo from '../../src/db/repositories/memberships-repo.js';
import * as governanceRepo from '../../src/db/repositories/governance-repo.js';
import { GovernanceGuard } from '../../src/services/governance-guard.js';
import { defaultPolicy } from '../../src/services/policy-engine.js';
import { seedDefaultBindings } from '../../src/services/policy-bindings.js';
import type {
  PolicyEngine, PolicyQuery, PolicyData, PolicyResult, JsonPolicy, JsonPolicyV2,
} from '../../src/services/policy-engine.js';
import { LocalPolicyEngine } from '../../src/services/local-policy-engine.js';
import * as keysRepo from '../../src/db/repositories/keys-repo.js';
import { generateEd25519KeyPair, signEd25519 } from '../../src/crypto/primitives.js';
import type { Ed25519KeyPair } from '../../src/crypto/primitives.js';
import type { CeremonyProposal, CeremonyApproval } from '../../src/tx/ceremony-store.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();
const CLUB_DID = 'did:scid:vh:club';
const ADMIN_DID = 'did:scid:vh:admin';
const NEWBIE_DID = 'did:scid:vh:newbie';

async function makeAppDb(): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

/**
 * Create an identity **and its primary DID document**.
 *
 * `identitiesRepo.create()` does not write `did_documents` (the DID string lives
 * there, not on the identity row), and every guard lookup joins on `d.did` — so a
 * fixture that skips this makes the guard report "issuer DID … not found" and
 * never reach the policy decision being tested.
 */
async function seedIdentity(
  db: SqliteDataSource,
  opts: { did: string; role: 'vta' | 'vtc' | 'vtn'; name: string },
): Promise<string> {
  const uuid = await identitiesRepo.create(db, {
    realDid: opts.did, role: opts.role, name: opts.name,
  });
  await didDocumentsRepo.create(db, {
    identityUuid: uuid,
    did: opts.did,
    method: opts.did.split(':')[1] ?? 'scid',
    isPrimary: true,
  });
  return uuid;
}

/** A VTC with one active `founding_admin` and the default baseline policy. */
async function seedClub(db: SqliteDataSource): Promise<{ vtcUuid: string; adminUuid: string }> {
  const vtcUuid = await seedIdentity(db, { did: CLUB_DID, role: 'vtc', name: 'Chess Club' });
  const adminUuid = await seedIdentity(db, { did: ADMIN_DID, role: 'vta', name: 'Club Admin' });
  await membershipsRepo.create(db, {
    memberIdentityUuid: adminUuid,
    communityIdentityUuid: vtcUuid,
    role: 'founding_admin',
    status: 'active',
  });
  await governanceRepo.create(db, {
    communityIdentityUuid: vtcUuid,
    adminThresholdM: 1,
    adminThresholdN: 1,
  });
  await seedDefaultBindings(db, vtcUuid, 'vtc');
  return { vtcUuid, adminUuid };
}

// ── 1. The policy engine's `actor_is_admin` fact ────────────────────────────

test('F-012: a founding_admin may issue a VMC under the default policy', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  const { adminUuid } = await seedClub(db);
  await seedIdentity(db, { did: NEWBIE_DID, role: 'vta', name: 'Newbie' });

  const result = await guard.validateCredentialIssuance({
    kind: 'MembershipCredential',
    issuerDid: ADMIN_DID,
    subjectDid: NEWBIE_DID,
    governanceDid: CLUB_DID,
  });

  assert.equal(
    result.allowed,
    true,
    `the club's own admin must be allowed to issue a VMC (uuid=${adminUuid}), got: ${result.reason}`,
  );
});

test('F-012: the community DID may issue to itself (control — isolates the mapping)', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  await seedClub(db);
  await seedIdentity(db, { did: NEWBIE_DID, role: 'vta', name: 'Newbie' });

  const result = await guard.validateCredentialIssuance({
    kind: 'MembershipCredential',
    issuerDid: CLUB_DID,
    subjectDid: NEWBIE_DID,
    governanceDid: CLUB_DID,
  });

  assert.equal(result.allowed, true, `self-issuance must pass, got: ${result.reason}`);
});

test('F-012: an issuer with no governance role is still denied (the rule must bite)', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  await seedClub(db);
  await seedIdentity(db, { did: 'did:scid:vh:outsider', role: 'vta', name: 'Outsider' });
  await seedIdentity(db, { did: NEWBIE_DID, role: 'vta', name: 'Newbie' });

  const result = await guard.validateCredentialIssuance({
    kind: 'MembershipCredential',
    issuerDid: 'did:scid:vh:outsider',
    subjectDid: NEWBIE_DID,
    governanceDid: CLUB_DID,
  });

  assert.equal(result.allowed, false, 'a non-admin must not issue a VMC');
  // The DECISION is the security property and is asserted above. The reason string
  // changed with the v2 document: v2 returns the policy author's own
  // `default.explanation` ('no rule matched') in preference to the engine's generated
  // text, which is the point of having an explanation field at all. Both v1's wording
  // and v2's are accepted here so this pins "denied, with a reason" rather than the
  // exact sentence a future document might reword.
  assert.match(String(result.reason), /no matching allow rule|no rule matched|not found/);
});

// ── 2. F-025: is a party listable by several communities? ───────────────────

test('F-025: one party holds memberships in two communities and is listed for each', async () => {
  const db = await makeAppDb();
  const clubA = await seedIdentity(db, { did: 'did:scid:vh:clubA', role: 'vtc', name: 'Club A' });
  const clubB = await seedIdentity(db, { did: 'did:scid:vh:clubB', role: 'vtc', name: 'Club B' });
  const agent = await seedIdentity(db, { did: 'did:scid:vh:agent', role: 'vta', name: 'Agent' });

  await membershipsRepo.create(db, {
    memberIdentityUuid: agent, communityIdentityUuid: clubA, role: 'member', status: 'active',
  });
  await membershipsRepo.create(db, {
    memberIdentityUuid: agent, communityIdentityUuid: clubB, role: 'member', status: 'active',
  });

  const rows = await membershipsRepo.findForMemberByUuid(db, agent);
  assert.deepEqual(
    rows.map((r) => r.communityIdentityUuid).sort(),
    [clubA, clubB].sort(),
    'a per-member listing must see both memberships',
  );

  // …and each community lists the same party.
  assert.equal((await membershipsRepo.findForCommunity(db, clubA)).length, 1);
  assert.equal((await membershipsRepo.findForCommunity(db, clubB)).length, 1);
});

test('F-025: the memberships uniqueness is per (member, community) pair', async () => {
  const db = await makeAppDb();
  const clubA = await seedIdentity(db, { did: 'did:scid:vh:clubA', role: 'vtc', name: 'Club A' });
  const agent = await seedIdentity(db, { did: 'did:scid:vh:agent', role: 'vta', name: 'Agent' });

  await membershipsRepo.create(db, {
    memberIdentityUuid: agent, communityIdentityUuid: clubA, role: 'member', status: 'active',
  });
  // A duplicate pair is refused (it is a join table, not a one-row-per-member table)…
  await assert.rejects(() =>
    membershipsRepo.create(db, {
      memberIdentityUuid: agent, communityIdentityUuid: clubA, role: 'member', status: 'active',
    }),
  );
});

// ── 3. P2: the baseline document follows the COMMUNITY's role ───────────────

/**
 * A `PolicyEngine` that records the document the guard handed it.
 *
 * The guard assembles `PolicyData` itself, so substituting the engine is how you
 * observe *which* policy the guard chose — without reaching into a private method
 * or asserting on real decisions that both baselines would answer the same way.
 */
class CapturingEngine implements PolicyEngine {
  public seen: JsonPolicy | undefined;
  evaluate(_query: PolicyQuery, data: PolicyData): PolicyResult {
    this.seen = data.policy;
    return { allowed: true };
  }
  validatePolicy(): PolicyResult {
    return { allowed: true };
  }
  defaultPolicy(kind: 'vtc' | 'vtn'): JsonPolicyV2 {
    return defaultPolicy(kind);
  }
}

test('P2: a VTN with no stored policy falls back to the VTN baseline, not the VTC one', async () => {
  const db = await makeAppDb();
  const engine = new CapturingEngine();
  const guard = new GovernanceGuard(db, engine);

  // A VTN with an admin and NO governance row, so the guard must supply a baseline.
  const vtnUuid = await seedIdentity(db, { did: 'did:scid:vh:net', role: 'vtn', name: 'Network' });
  const adminUuid = await seedIdentity(db, { did: ADMIN_DID, role: 'vta', name: 'Net Admin' });
  await membershipsRepo.create(db, {
    memberIdentityUuid: adminUuid, communityIdentityUuid: vtnUuid,
    role: 'founding_admin', status: 'active',
  });
  await seedIdentity(db, { did: NEWBIE_DID, role: 'vta', name: 'Newbie' });
  await seedDefaultBindings(db, vtnUuid, 'vtn');

  await guard.validateCredentialIssuance({
    kind: 'MembershipCredential',
    issuerDid: ADMIN_DID,
    subjectDid: NEWBIE_DID,
    governanceDid: 'did:scid:vh:net',
  });

  assert.ok(engine.seen, 'the guard must have consulted the engine');
  assert.deepEqual(engine.seen.appliesTo, ['vtn'], 'a VTN must be governed by the VTN baseline');
  assert.equal(
    engine.seen.rules.some((r) => r.id === 'affiliate-vtc'),
    true,
    'the VTN baseline is the one that can accept and remove children',
  );
});

test('P2: a VTC with no stored policy falls back to the VTC baseline (control)', async () => {
  const db = await makeAppDb();
  const engine = new CapturingEngine();
  const guard = new GovernanceGuard(db, engine);

  // Seeded by hand rather than via `seedClub`, because `seedClub` writes a governance
  // row — and this test needs the guard to have NOTHING to read, so it must fall back.
  const vtcUuid = await seedIdentity(db, { did: CLUB_DID, role: 'vtc', name: 'Chess Club' });
  const adminUuid = await seedIdentity(db, { did: ADMIN_DID, role: 'vta', name: 'Club Admin' });
  await membershipsRepo.create(db, {
    memberIdentityUuid: adminUuid, communityIdentityUuid: vtcUuid,
    role: 'founding_admin', status: 'active',
  });
  await seedIdentity(db, { did: NEWBIE_DID, role: 'vta', name: 'Newbie' });
  await seedDefaultBindings(db, vtcUuid, 'vtc');

  await guard.validateCredentialIssuance({
    kind: 'MembershipCredential',
    issuerDid: ADMIN_DID,
    subjectDid: NEWBIE_DID,
    governanceDid: CLUB_DID,
  });

  assert.ok(engine.seen);
  assert.deepEqual(engine.seen.appliesTo, ['vtc']);
  assert.equal(
    engine.seen.rules.some((r) => r.id === 'affiliate-vtc'),
    false,
    'a VTC cannot affiliate itself into a network — its parent decides',
  );
});

// ── 4. P3: crystallization and the parent-child check are now POLICY ────────

/**
 * An identity with a primary DID document AND an Ed25519 key.
 *
 * `resolvePublicKey()` reads `keys` (joined via `did_documents`), so a fixture without
 * a key makes the guard report "cannot resolve key for …" and never reach the policy
 * decision under test.
 */
async function seedAdmin(
  db: SqliteDataSource,
  did: string,
): Promise<{ uuid: string; keyPair: Ed25519KeyPair }> {
  const uuid = await seedIdentity(db, { did, role: 'vta', name: did });
  const keyPair = generateEd25519KeyPair();
  await keysRepo.create(db, {
    identityUuid: uuid,
    keyType: 'ed25519',
    publicKey: Buffer.from(keyPair.publicKey),
  });
  return { uuid, keyPair };
}

const PROPOSAL_HASH = 'ceremony-proposal-hash';

function proposal(over: Partial<CeremonyProposal> = {}): CeremonyProposal {
  return {
    proposalId: 'prop-1',
    proposerDid: ADMIN_DID,
    proposerUuid: null,
    vtcDid: CLUB_DID,
    name: 'Chess Club',
    kind: 'vtc',
    adminDids: [],
    adminUuids: [],
    threshold: 2,
    expiresAt: 0,
    status: 'pending',
    proposalHash: PROPOSAL_HASH,
    parentCommunityDid: null,
    errorReason: null,
    createdAt: 0,
    crystallizedAt: null,
    ...over,
  };
}

/** A valid approval from `did`, signed over the proposal hash with that admin's key. */
function approval(did: string, keyPair: Ed25519KeyPair, hash = PROPOSAL_HASH): CeremonyApproval {
  const sig = signEd25519(new TextEncoder().encode(hash), keyPair.secretKey);
  return {
    approvalId: `appr-${did}`,
    proposalId: 'prop-1',
    approverDid: did,
    signature: Buffer.from(sig).toString('base64'),
    receivedAt: 0,
  };
}


test('P3: a VTC proposal with a met quorum is allowed', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  const a1 = await seedAdmin(db, 'did:scid:vh:admin1');
  const a2 = await seedAdmin(db, 'did:scid:vh:admin2');

  const result = await guard.validateCrystallization(
    proposal({ adminDids: ['did:scid:vh:admin1', 'did:scid:vh:admin2'], threshold: 2 }),
    [approval('did:scid:vh:admin1', a1.keyPair), approval('did:scid:vh:admin2', a2.keyPair)],
  );

  assert.equal(result.allowed, true, result.reason);
});

test('P3: a short quorum returns requireConsent naming the approver set and the minimum', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  const a1 = await seedAdmin(db, 'did:scid:vh:admin1');
  await seedAdmin(db, 'did:scid:vh:admin2');
  await seedAdmin(db, 'did:scid:vh:admin3');

  const result = await guard.validateCrystallization(
    proposal({
      adminDids: ['did:scid:vh:admin1', 'did:scid:vh:admin2', 'did:scid:vh:admin3'],
      threshold: 3,
    }),
    [approval('did:scid:vh:admin1', a1.keyPair)],
  );

  assert.equal(result.allowed, false);
  assert.ok(result.requireConsent, 'the caller must learn what it needs, not only "no"');
  assert.equal(result.requireConsent.approverSet, 'community-admins');
  // The FOUNDING quorum is the declared ADMIN COUNT (`threshold_n`): every named
  // admin must co-sign. `threshold_m` is the community's change-approval quorum —
  // a different decision (see update_governance).
  assert.equal(result.requireConsent.minApprovalsFromFact, 'threshold_n');
  assert.match(String(result.reason), /community-admins/, 'and the reason must say so too');
});

test('P3: duplicate approvals from one admin count ONCE (the signature-counting defect)', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  const a1 = await seedAdmin(db, 'did:scid:vh:admin1');
  await seedAdmin(db, 'did:scid:vh:admin2');

  // The threshold used to be compared against `approvals.length` BEFORE any signature
  // was verified, and duplicates were never deduplicated — so N copies of one admin's
  // signature satisfied an N-of-N threshold.
  const result = await guard.validateCrystallization(
    proposal({ adminDids: ['did:scid:vh:admin1', 'did:scid:vh:admin2'], threshold: 2 }),
    [approval('did:scid:vh:admin1', a1.keyPair), approval('did:scid:vh:admin1', a1.keyPair)],
  );

  assert.equal(result.allowed, false, 'one admin must not satisfy a 2-of-2 quorum alone');
  assert.ok(result.requireConsent);
});

test('a single-admin VTC is allowed — the founding floor is 1, not 2', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  const a1 = await seedAdmin(db, 'did:scid:vh:admin1');

  // The founding minimum was relaxed from 2 admins to 1: a lone founding admin may
  // crystallize with their single verified approval (threshold 1).
  const result = await guard.validateCrystallization(
    proposal({ adminDids: ['did:scid:vh:admin1'], threshold: 1 }),
    [approval('did:scid:vh:admin1', a1.keyPair)],
  );

  assert.equal(result.allowed, true);
});

test('P3: a VTC threshold below 1 is denied — by POLICY', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  const a1 = await seedAdmin(db, 'did:scid:vh:admin1');
  const a2 = await seedAdmin(db, 'did:scid:vh:admin2');

  // A threshold of 0 is nonsense and only the `vtc-min-threshold` rule refuses it
  // (the quorum rule is otherwise satisfied — both admins approved).
  const denied = await guard.validateCrystallization(
    proposal({ adminDids: ['did:scid:vh:admin1', 'did:scid:vh:admin2'], threshold: 0 }),
    [approval('did:scid:vh:admin1', a1.keyPair), approval('did:scid:vh:admin2', a2.keyPair)],
  );
  assert.equal(denied.allowed, false);
  assert.match(String(denied.reason), /threshold must be >= 1/);
});

test('P3: a VTC with M=1 still needs EVERY declared admin to co-sign the founding', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  const a1 = await seedAdmin(db, 'did:scid:vh:admin1');
  const a2 = await seedAdmin(db, 'did:scid:vh:admin2');

  const admins = ['did:scid:vh:admin1', 'did:scid:vh:admin2'];

  // `threshold_m` is the community's CHANGE-approval quorum (how many signatures a
  // later governance change needs) — NOT how many signatures found the community.
  // Founding requires the declared ADMIN COUNT: naming someone an admin is a
  // REQUEST and their own signature over the proposal hash is the ACCEPTANCE, so
  // the creator cannot found a two-admin community on the co-admin's behalf.
  const creatorOnly = await guard.validateCrystallization(
    proposal({ adminDids: admins, threshold: 1 }),
    [approval('did:scid:vh:admin1', a1.keyPair)],
  );
  assert.equal(creatorOnly.allowed, false, "the creator cannot found it on the co-admin's behalf");
  assert.ok(creatorOnly.requireConsent);

  const bothCoSigned = await guard.validateCrystallization(
    proposal({ adminDids: admins, threshold: 1 }),
    [approval('did:scid:vh:admin1', a1.keyPair), approval('did:scid:vh:admin2', a2.keyPair)],
  );
  assert.equal(bothCoSigned.allowed, true, bothCoSigned.reason);
});

test('P3: an invalid signature is refused by the GUARD, and is NOT reported as requireConsent', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  const a1 = await seedAdmin(db, 'did:scid:vh:admin1');
  const a2 = await seedAdmin(db, 'did:scid:vh:admin2');

  // Signed over a different hash — a real signature, for the wrong message.
  const wrong = approval('did:scid:vh:admin2', a2.keyPair, 'a different hash');

  const result = await guard.validateCrystallization(
    proposal({ adminDids: ['did:scid:vh:admin1', 'did:scid:vh:admin2'], threshold: 2 }),
    [approval('did:scid:vh:admin1', a1.keyPair), wrong],
  );

  assert.equal(result.allowed, false);
  assert.match(String(result.reason), /invalid signature/);
  assert.equal(
    result.requireConsent,
    undefined,
    'a crypto failure must not masquerade as a request for more approvals',
  );
});
// ── 5. P3: the parent-VTN child-kind check is now POLICY ────────────────────

/** A VTN with a governance row and bindings carrying an optional child-kind restriction. */
async function seedVtn(db: SqliteDataSource, doc: Record<string, unknown>): Promise<string> {
  const uuid = await seedIdentity(db, { did: 'did:scid:vh:net', role: 'vtn', name: 'Network' });
  await governanceRepo.create(db, {
    communityIdentityUuid: uuid,
    adminThresholdM: 2,
    adminThresholdN: 3,
  });
  await seedDefaultBindings(db, uuid, 'vtn', {
    allowedChildKinds: Array.isArray(doc.allowedChildKinds) ? (doc.allowedChildKinds as string[]) : undefined,
  });
  return uuid;
}

test('P3: a parent VTN that declares NO allowedChildKinds accepts any child kind', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  await seedVtn(db, {});

  const result = await guard.validateParentVtnPolicy('did:scid:vh:net', 'vtc');
  assert.equal(result.allowed, true, 'silence is not a restriction');
});

test('P3: a parent VTN that permits the kind accepts it', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  await seedVtn(db, { allowedChildKinds: ['vtc'] });

  const result = await guard.validateParentVtnPolicy('did:scid:vh:net', 'vtc');
  assert.equal(result.allowed, true, result.reason);
});

test('P3: a parent VTN that omits the kind REFUSES it', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  await seedVtn(db, { allowedChildKinds: ['something-else'] });

  const result = await guard.validateParentVtnPolicy('did:scid:vh:net', 'vtc');
  assert.equal(result.allowed, false, 'the declared restriction must bite');
});

test('P3: no parent at all is allowed (the question does not apply)', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());

  for (const parent of [null, undefined]) {
    const result = await guard.validateParentVtnPolicy(parent, 'vtc');
    assert.equal(result.allowed, true, 'an orphan community is not a governance violation');
  }
});

test('P3: a parent DID that is not a VTN is allowed (there is no VTN policy to apply)', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  // A VTC used as a parent: the lookup filters on role='vtn', so it does not resolve.
  await seedIdentity(db, { did: 'did:scid:vh:notanet', role: 'vtc', name: 'Not A Network' });

  const result = await guard.validateParentVtnPolicy('did:scid:vh:notanet', 'vtc');
  assert.equal(result.allowed, true);
});

test('P3: a parent VTN with default bindings accepts any child kind (from POLICY)', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  const uuid = await seedIdentity(db, { did: 'did:scid:vh:net', role: 'vtn', name: 'Network' });
  await seedDefaultBindings(db, uuid, 'vtn');

  const result = await guard.validateParentVtnPolicy('did:scid:vh:net', 'vtc');
  assert.equal(result.allowed, true, 'the default binding declares no child-kind restriction, so it accepts');
  assert.equal(result.decision?.decision, 'allow', 'and the decision came from POLICY, not a hard-coded allow');
});

test('P3: a parent VTN with default bindings accepts (the restriction is a binding param)', async () => {
  const db = await makeAppDb();
  const guard = new GovernanceGuard(db, new LocalPolicyEngine());
  const uuid = await seedIdentity(db, { did: 'did:scid:vh:net', role: 'vtn', name: 'Network' });
  await seedDefaultBindings(db, uuid, 'vtn');

  const result = await guard.validateParentVtnPolicy('did:scid:vh:net', 'vtc');
  assert.equal(result.allowed, true);
  assert.equal(result.decision?.decision, 'allow');
});
