// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Membership admission presentation — audit F-026, decision F-001b.
 *
 * The finding: admission required **no presentation of any kind**, so nothing proved
 * the party being admitted is the party who asked — the guard proved only the
 * community's half of a two-party membership fact.
 *
 * These tests pin the four outcomes apart, because the whole value of the change is
 * that "I cannot check" never reads as "this is forged":
 *
 *   verified / invalid / indeterminate / absent
 *
 * and that ONLY a definite `invalid` (or nothing at all) is refused, and only under
 * `enforce`.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/services/membership-presentation.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { generateUuid } from '../../src/db/uuid-helpers.js';
import * as identitiesRepo from '../../src/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '../../src/db/repositories/did-documents-repo.js';
import * as keysRepo from '../../src/db/repositories/keys-repo.js';
import * as noncesRepo from '../../src/db/repositories/nonces-repo.js';
import { generateEd25519KeyPair, signEd25519 } from '../../src/crypto/primitives.js';
import {
  admissionChallenge,
  classifyMembershipPresentation,
  refusesAdmission,
  resolveMembershipPresentationPolicy,
  MEMBERSHIP_PRESENTATION_PURPOSE,
} from '../../src/services/membership-presentation.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

async function makeDb(): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

/** An identity with a DID document, optionally holding a real Ed25519 key pair. */
async function seedMember(
  ds: SqliteDataSource,
  did: string,
  withKey: boolean,
): Promise<{ uuid: string; keyPair: ReturnType<typeof generateEd25519KeyPair> | null }> {
  const uuid = generateUuid();
  await identitiesRepo.create(ds, {
    uuid, realDid: did, role: 'vta', subjectKind: 'human', custody: 'local',
    name: did.slice(-8), recordedByNode: 'test',
  });
  const docUuid = await didDocumentsRepo.create(ds, {
    identityUuid: uuid, did, method: 'did:scid:vh',
    documentJson: JSON.stringify({ id: did }), isPrimary: true, recordedByNode: 'test',
  });
  if (!withKey) return { uuid, keyPair: null };

  const kp = generateEd25519KeyPair();
  await keysRepo.createWithSecret(ds, {
    identityUuid: uuid, didDocumentUuid: docUuid, keyType: 'ed25519',
    publicKey: kp.publicKey,
    encryptedSecretKey: new Uint8Array(32).fill(1), salt: new Uint8Array(16).fill(2),
    nonce: new Uint8Array(12).fill(3), authTag: new Uint8Array(16).fill(4),
  });
  return { uuid, keyPair: kp };
}

/** Issue a live nonce for `memberUuid` and return it. */
async function issueNonce(ds: SqliteDataSource, memberUuid: string): Promise<string> {
  const nonce = `nonce-${generateUuid()}`;
  await noncesRepo.create(ds, {
    identityUuid: memberUuid,
    nonce,
    purpose: MEMBERSHIP_PRESENTATION_PURPOSE,
    expiresAt: Math.floor(Date.now() / 1000) + 300,
  });
  return nonce;
}

function presentationFor(
  kp: { secretKey: Uint8Array },
  communityUuid: string,
  memberUuid: string,
  nonce: string,
  role?: string,
) {
  const challenge = admissionChallenge({ communityUuid, memberIdentityUuid: memberUuid, role, nonce });
  const signature = signEd25519(new TextEncoder().encode(challenge), kp.secretKey);
  return { nonce, signature: Buffer.from(signature).toString('base64url') };
}

test('admissionChallenge: canonical, and BINDS the role being granted', () => {
  const base = { communityUuid: 'c1', memberIdentityUuid: 'm1', nonce: 'n1' };
  assert.equal(admissionChallenge(base), admissionChallenge(base), 'deterministic');

  // A presentation collected for one role must not authorise another.
  assert.notEqual(
    admissionChallenge({ ...base, role: 'member' }),
    admissionChallenge({ ...base, role: 'admin' }),
    'role is part of the signed challenge',
  );
  assert.notEqual(
    admissionChallenge(base),
    admissionChallenge({ ...base, nonce: 'n2' }),
    'the nonce is part of the signed challenge',
  );
  assert.notEqual(
    admissionChallenge(base),
    admissionChallenge({ ...base, communityUuid: 'c2' }),
    'the community is part of the signed challenge',
  );
});

test('policy resolution: warn by default, unknown values fall back to warn', () => {
  assert.equal(resolveMembershipPresentationPolicy(undefined), 'warn');
  assert.equal(resolveMembershipPresentationPolicy(''), 'warn');
  assert.equal(resolveMembershipPresentationPolicy(' ENFORCE '), 'enforce');
  assert.equal(resolveMembershipPresentationPolicy('off'), 'off');
  // A typo must never start refusing memberships.
  assert.equal(resolveMembershipPresentationPolicy('enforced'), 'warn');
});

test('a member that PROVES possession is verified, and its nonce is spent', async () => {
  const ds = await makeDb();
  const member = await seedMember(ds, 'did:scid:vh:1:zPresenter', true);
  const nonce = await issueNonce(ds, member.uuid);
  const presentation = presentationFor(member.keyPair!, 'community-1', member.uuid, nonce, 'member');

  const outcome = await classifyMembershipPresentation(ds, {
    communityUuid: 'community-1', memberIdentityUuid: member.uuid, role: 'member', presentation,
  });
  assert.equal(outcome.verdict, 'verified', outcome.reason);
  assert.equal(outcome.admissible, true);

  // Replay of the very same presentation is now INVALID, not verified again.
  const replay = await classifyMembershipPresentation(ds, {
    communityUuid: 'community-1', memberIdentityUuid: member.uuid, role: 'member', presentation,
  });
  assert.equal(replay.verdict, 'invalid', 'a spent nonce makes the replay fail');
  assert.match(replay.reason, /already been used|unknown/);

  await ds.close();
});

test('a signature by the WRONG key is invalid (checked and failed)', async () => {
  const ds = await makeDb();
  const member = await seedMember(ds, 'did:scid:vh:1:zWrongKey', true);
  const impostor = generateEd25519KeyPair();
  const nonce = await issueNonce(ds, member.uuid);
  // Correct challenge, signature from a key the member does not hold.
  const forged = presentationFor(impostor, 'community-1', member.uuid, nonce, 'member');

  const outcome = await classifyMembershipPresentation(ds, {
    communityUuid: 'community-1', memberIdentityUuid: member.uuid, role: 'member', presentation: forged,
  });
  assert.equal(outcome.verdict, 'invalid');
  assert.equal(outcome.admissible, false);

  await ds.close();
});

test('a challenge signed for a DIFFERENT role does not authorise this one', async () => {
  const ds = await makeDb();
  const member = await seedMember(ds, 'did:scid:vh:1:zRoleBind', true);
  const nonce = await issueNonce(ds, member.uuid);
  const asMember = presentationFor(member.keyPair!, 'community-1', member.uuid, nonce, 'member');

  const outcome = await classifyMembershipPresentation(ds, {
    communityUuid: 'community-1', memberIdentityUuid: member.uuid, role: 'admin', presentation: asMember,
  });
  assert.equal(outcome.verdict, 'invalid', 'the role is bound into the signed bytes');

  await ds.close();
});

test('NO local key means INDETERMINATE — never treated as forgery', async () => {
  const ds = await makeDb();
  // The member exists and presents a well-formed signature, but this node holds no
  // key for it (a peer whose DID document has not replicated here yet).
  const member = await seedMember(ds, 'did:scid:vh:1:zNoKeyHere', false);
  const kp = generateEd25519KeyPair();
  const nonce = await issueNonce(ds, member.uuid);
  const presentation = presentationFor(kp, 'community-1', member.uuid, nonce, 'member');

  const outcome = await classifyMembershipPresentation(ds, {
    communityUuid: 'community-1', memberIdentityUuid: member.uuid, role: 'member', presentation,
  });
  assert.equal(outcome.verdict, 'indeterminate');
  assert.equal(outcome.admissible, true, 'an unchecked presentation is not an invalid one');
  assert.match(outcome.reason, /could not be checked/);

  // And enforce does not block it — the F-031/F-003 discipline.
  assert.equal(refusesAdmission('enforce', outcome), false, 'enforce must not refuse the uncheckable');

  await ds.close();
});

test('absent / expired / unknown-nonce presentations, and what enforce does with each', async () => {
  const ds = await makeDb();
  const member = await seedMember(ds, 'did:scid:vh:1:zAbsent', true);
  const ctx = { communityUuid: 'community-1', memberIdentityUuid: member.uuid, role: 'member' };

  // 1. No presentation at all — pre-F-001b behaviour.
  const absent = await classifyMembershipPresentation(ds, ctx);
  assert.equal(absent.verdict, 'absent');
  assert.equal(refusesAdmission('enforce', absent), true, 'enforce requires a presentation');
  assert.equal(refusesAdmission('warn', absent), false, 'warn admits it');
  assert.equal(refusesAdmission('off', absent), false, 'off admits it');

  // 2. A nonce this node never issued.
  const unknown = await classifyMembershipPresentation(ds, {
    ...ctx,
    presentation: presentationFor(member.keyPair!, 'community-1', member.uuid, 'never-issued', 'member'),
  });
  assert.equal(unknown.verdict, 'invalid');
  assert.equal(refusesAdmission('enforce', unknown), true);

  // 3. An expired nonce.
  const expired = `nonce-expired-${generateUuid()}`;
  await noncesRepo.create(ds, {
    identityUuid: member.uuid, nonce: expired, purpose: MEMBERSHIP_PRESENTATION_PURPOSE,
    expiresAt: Math.floor(Date.now() / 1000) - 10,
  });
  const stale = await classifyMembershipPresentation(ds, {
    ...ctx,
    presentation: presentationFor(member.keyPair!, 'community-1', member.uuid, expired, 'member'),
  });
  assert.equal(stale.verdict, 'invalid');
  assert.match(stale.reason, /expired/);

  // 4. A malformed signature is invalid, and does not throw out of the classifier.
  const malformed = await classifyMembershipPresentation(ds, {
    ...ctx,
    presentation: { nonce: await issueNonce(ds, member.uuid), signature: 'not-base64!!' },
  });
  assert.equal(malformed.verdict, 'invalid');

  await ds.close();
});


