// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * F-003 — the credential verifier now runs on the receive path.
 *
 * The audit finding this covers: `CredentialFactoryImpl.verify()` was fully
 * implemented and had **no caller anywhere in the tree**, so every credential the
 * stack received was persisted unverified. These tests pin:
 *
 *   1. the verdict classifier (pure): "could not verify" stays distinct from
 *      "invalid" (audit F-031), and only a *judged* proof failure is invalid;
 *   2. the policy resolver: explicit → env → `warn`, and a typo never escalates
 *      to `enforce`;
 *   3. the participant: `warn` (default) stores an invalid credential and votes
 *      yes; `enforce` refuses it with a clean `no` vote and stores nothing;
 *      neither path can throw into the 2PC prepare loop.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/agent/credential-receive.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { TX_SCHEMA_SQL, applyTxSchemaAdditions } from '@p2p-trust-stack/core/tx/schema.js';
import {
  classifyCredentialVerdict,
  classifyCredentialBinding,
  resolveCredentialVerifyPolicy,
  resolveCredentialBindingPolicy,
  CREDENTIAL_VERIFY_POLICY_ENV,
  CREDENTIAL_BINDING_POLICY_ENV,
} from '@p2p-trust-stack/core/services/credential-factory/verify-policy.js';
import { CredentialReceiveParticipant } from '../../src/runtime/tx/credential-receive-participant.js';
import type { Operation } from '@p2p-trust-stack/core/tx/types.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

async function makeAppDb(): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

/**
 * The participant's second DataSource is the tx coordinator, which has its OWN
 * schema (`TX_SCHEMA_SQL` + additive columns) — not the application migrations.
 * Getting this wrong fails at `tx_participant_state`, after the credential write
 * has already happened.
 */
async function makeTxDb(): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(':memory:');
  await ds.exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(ds);
  return ds;
}

/** A delivery whose payload the verifier will judge: parsed, but proof invalid. */
/**
 * A delivery as the server actually produces it: `vcType` is read from the
 * server's own `credentials.vc_type` column, which the CHECK constrains to
 * lowercase. `vcTypeOverride` lets a test inject the non-canonical form.
 */
function credentialOp(uuid: string, w3cVcJson: string | null, vcTypeOverride?: string): Operation {
  return {
    op: 'exchange:credential',
    params: {
      credentialUuid: uuid,
      vcType: vcTypeOverride ?? 'vmc',
      issuerIdentityUuid: 'issuer-uuid',
      subjectIdentityUuid: 'subject-uuid',
      w3cVcJson,
      claim: null,
      status: 'issued',
      validFrom: 1,
      validUntil: null,
      credentialDigest: null,
      createdAt: 1,
      issuerDid: null,
      subjectDid: null,
    },
  } as unknown as Operation;
}

async function credentialRows(ds: SqliteDataSource, uuid: string): Promise<number> {
  const rows = await ds.all('SELECT uuid FROM credentials WHERE uuid = ?', uuid);
  return rows.length;
}

async function storedVcType(ds: SqliteDataSource, uuid: string): Promise<string | undefined> {
  const row = await ds.get<{ vc_type: string }>('SELECT vc_type FROM credentials WHERE uuid = ?', uuid);
  return row?.vc_type;
}

// ---------------------------------------------------------------------------
// 1. The classifier — invalid vs indeterminate (audit F-031)
// ---------------------------------------------------------------------------

test('classifyCredentialVerdict: no payload, a throwing verifier, and unparseable input are all INDETERMINATE', () => {
  for (const policy of ['warn', 'enforce'] as const) {
    assert.equal(
      classifyCredentialVerdict({ hasPayload: false }, policy).verdict,
      'indeterminate',
      'no VC payload is indeterminate — not a failed verification',
    );
    assert.equal(
      classifyCredentialVerdict({ hasPayload: true, error: new Error('boom') }, policy).verdict,
      'indeterminate',
      'a verifier that could not run has not judged the credential',
    );
    assert.equal(
      classifyCredentialVerdict({ hasPayload: true, result: { valid: false, reason: 'not recognised' } }, policy).verdict,
      'indeterminate',
      'no detectedKind ⇒ the verifier never judged a proof',
    );
  }
  // …and none of them is ever refused, under either policy.
  assert.equal(classifyCredentialVerdict({ hasPayload: false }, 'enforce').store, true);
  assert.equal(classifyCredentialVerdict({ hasPayload: true, error: new Error('x') }, 'enforce').store, true);
});

test('classifyCredentialVerdict: a JUDGED proof failure is invalid, and only `enforce` refuses it', () => {
  const judged = {
    hasPayload: true,
    result: { valid: false, reason: 'signature verification failed', detectedKind: 'VMC' },
  };

  const warned = classifyCredentialVerdict(judged, 'warn');
  assert.equal(warned.verdict, 'invalid');
  assert.equal(warned.store, true, 'warn persists an invalid credential (default: no behaviour change)');
  assert.match(warned.message, /persisted anyway \(policy=warn\)/);

  const enforced = classifyCredentialVerdict(judged, 'enforce');
  assert.equal(enforced.verdict, 'invalid');
  assert.equal(enforced.store, false, 'enforce refuses it');
  assert.equal(enforced.level, 'error');
  assert.match(enforced.message, /signature verification failed/, 'the verifier reason is carried verbatim');
});

test('classifyCredentialVerdict: a verified credential is never refused', () => {
  const ok = { hasPayload: true, result: { valid: true, detectedKind: 'VMC' } };
  for (const policy of ['warn', 'enforce'] as const) {
    const decision = classifyCredentialVerdict(ok, policy);
    assert.equal(decision.verdict, 'verified');
    assert.equal(decision.store, true);
    assert.equal(decision.level, 'info');
  }
});

// ---------------------------------------------------------------------------
// 2. The receive path — the verifier is actually consulted now
// ---------------------------------------------------------------------------

/** A VC the verifier parses but whose proof it judges invalid. */
const UUID = '11111111-1111-4111-8111-111111111111';
const UUID2 = '22222222-2222-4222-8222-222222222222';

/** A payload the REAL verifier will parse but cannot judge: its key is unresolvable. */
const UNRESOLVABLE_KEY_VC = JSON.stringify({
  type: ['MembershipCredential', 'VerifiableCredential'],
  proof: {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: 'did:scid:vh:1:zNope#key-1',
  },
});

/** A verifier that reports a DEFINITE verdict: the key was found and rejected the proof. */
const judgedInvalid = async () => ({
  valid: false, reason: 'signature verification failed', detectedKind: 'MembershipCredential',
});

test('receive path, policy=warn (DEFAULT): the verifier RUNS; the credential is still stored; vote is yes', async () => {
  const appDb = await makeAppDb();
  const txDb = await makeTxDb();
  const participant = new CredentialReceiveParticipant('peer:did:x', appDb, txDb);

  const vote = await participant.prepare('tx-warn', [credentialOp(UUID, UNRESOLVABLE_KEY_VC)]);

  assert.equal(vote, 'yes', 'warn must not change the outcome');
  assert.equal(await credentialRows(appDb, UUID), 1, 'the credential is persisted (warn)');

  await appDb.close();
  await txDb.close();
});

test('receive path, policy=enforce: a JUDGED-invalid credential is REFUSED with a clean `no`, and stored nowhere', async () => {
  const appDb = await makeAppDb();
  const txDb = await makeTxDb();
  const participant = new CredentialReceiveParticipant('peer:did:x', appDb, txDb, 'enforce', judgedInvalid);

  const vote = await participant.prepare('tx-refuse', [credentialOp(UUID2, UNRESOLVABLE_KEY_VC)]);

  assert.equal(vote, 'no', 'enforce refuses a judged-invalid credential');
  assert.equal(await credentialRows(appDb, UUID2), 0, 'and does not persist it');

  await appDb.close();
  await txDb.close();
});

test('receive path, policy=enforce: an UNRESOLVABLE key is INDETERMINATE — stored, never refused (audit F-031)', async () => {
  // The guarantee that matters operationally: `enforce` must not reject a
  // legitimate credential from a peer whose DID document this node has not seen
  // yet. "Could not verify" is not "invalid".
  const appDb = await makeAppDb();
  const txDb = await makeTxDb();
  const participant = new CredentialReceiveParticipant('peer:did:x', appDb, txDb, 'enforce');

  const uuid = '7'.repeat(8) + '-7777-4777-8777-777777777777';
  const vote = await participant.prepare('tx-indeterminate', [credentialOp(uuid, UNRESOLVABLE_KEY_VC)]);

  assert.equal(vote, 'yes', 'an unresolvable key must not be treated as forgery');
  assert.equal(await credentialRows(appDb, uuid), 1, 'the credential is stored');

  await appDb.close();
  await txDb.close();
});

test('receive path: a delivery with NO payload is indeterminate — stored under BOTH policies', async () => {
  for (const policy of ['warn', 'enforce'] as const) {
    const appDb = await makeAppDb();
    const txDb = await makeTxDb();
    const participant = new CredentialReceiveParticipant('peer:did:x', appDb, txDb, policy);

    const uuid = policy === 'warn' ? '3'.repeat(8) + '-3333-4333-8333-333333333333'
      : '4'.repeat(8) + '-4444-4444-8444-444444444444';
    const vote = await participant.prepare(`tx-${policy}`, [credentialOp(uuid, null)]);

    assert.equal(vote, 'yes', `${policy}: "could not verify" must not refuse`);
    assert.equal(await credentialRows(appDb, uuid), 1, `${policy}: indeterminate credentials are stored`);

    await appDb.close();
    await txDb.close();
  }
});

test('receive path, policy=off: the verifier is not consulted at all and behaviour is unchanged', async () => {
  const appDb = await makeAppDb();
  const txDb = await makeTxDb();
  const participant = new CredentialReceiveParticipant('peer:did:x', appDb, txDb, 'off');

  const uuid = '5'.repeat(8) + '-5555-4555-8555-555555555555';
  const vote = await participant.prepare('tx-off', [credentialOp(uuid, UNRESOLVABLE_KEY_VC)]);

  assert.equal(vote, 'yes');
  assert.equal(await credentialRows(appDb, uuid), 1, 'off = pre-F-003 behaviour, byte for byte');

  await appDb.close();
  await txDb.close();
});

test('receive path: a non-canonical vcType is normalised, not lost to a 2PC abort', async () => {
  // Surfaced while wiring F-003: the credential is written with `vcType` verbatim
  // against a lowercase CHECK, so an uppercase payload failed the INSERT — and
  // because `prepare()` votes 'no' on a throw, the credential vanished in an abort
  // with only a generic "prepare failed" line. Every producer today reads the value
  // from the server's own column (lowercase), so this is hardening rather than a
  // live defect — but the failure mode is silent loss, so it is pinned.
  const appDb = await makeAppDb();
  const txDb = await makeTxDb();
  const participant = new CredentialReceiveParticipant('peer:did:x', appDb, txDb, 'off');

  const uuid = '6'.repeat(8) + '-6666-4666-8666-666666666666';
  const vote = await participant.prepare('tx-case', [credentialOp(uuid, null, 'VMC')]);

  assert.equal(vote, 'yes', 'a case mismatch must not abort the delivery');
  assert.equal(await credentialRows(appDb, uuid), 1, 'the credential is persisted');
  assert.equal(await storedVcType(appDb, uuid), 'vmc', 'and stored in the canonical lowercase form');

  await appDb.close();
  await txDb.close();
});


// ---------------------------------------------------------------------------
// 3. Binding — is this credential FOR me, and FROM whom it claims? (F-001/F-026)
//
// The audit found the membership fact asserted by the community alone, and that
// the member's own acceptance was context-free: `verify()` sees only bytes, so a
// valid VMC minted for another identity verified exactly as well as one addressed
// to the recipient. These tests pin the context check.
// ---------------------------------------------------------------------------

const SELF = 'did:scid:vh:1:zSelfAgentForBinding';
const COMMUNITY = 'did:scid:vh:1:zCommunityForBinding';
const OTHER = 'did:scid:vh:1:zSomeOtherAgent';

/** A VMC in the shape dtg-vmc.ts builds: issuer + credentialSubject{id, memberOf}. */
function vmc(opts: { subjectId?: string; issuer?: string; memberOf?: string }): string {
  return JSON.stringify({
    type: ['MembershipCredential', 'VerifiableCredential'],
    ...(opts.issuer ? { issuer: opts.issuer } : {}),
    credentialSubject: {
      ...(opts.subjectId ? { id: opts.subjectId } : {}),
      ...(opts.memberOf ? { memberOf: opts.memberOf } : {}),
    },
    proof: {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod: 'did:scid:vh:1:zNope#key-1',
    },
  });
}

test('classifyCredentialBinding: subject / issuer / memberOf mismatches are all definite', () => {
  const base = { hasPayload: true, selfDid: SELF } as const;

  const subjectMismatch = classifyCredentialBinding(
    { ...base, vcIssuer: COMMUNITY, vcSubjectId: OTHER }, 'enforce');
  assert.equal(subjectMismatch.verdict, 'mismatch');
  assert.equal(subjectMismatch.store, false, 'enforce refuses a credential minted for someone else');
  assert.match(subjectMismatch.message, /is not this agent/);

  const issuerMismatch = classifyCredentialBinding(
    { ...base, payloadIssuerDid: COMMUNITY, vcIssuer: OTHER, vcSubjectId: SELF }, 'enforce');
  assert.equal(issuerMismatch.verdict, 'mismatch');
  assert.match(issuerMismatch.message, /disagrees with the delivery's issuerDid/);

  const memberOfMismatch = classifyCredentialBinding(
    { ...base, vcIssuer: COMMUNITY, vcSubjectId: SELF, vcMemberOf: OTHER }, 'enforce');
  assert.equal(memberOfMismatch.verdict, 'mismatch');
  assert.match(memberOfMismatch.message, /is not the signing issuer/);
});

test('classifyCredentialBinding: warn persists a mismatch; enforce refuses it', () => {
  const input = { hasPayload: true, selfDid: SELF, vcIssuer: COMMUNITY, vcSubjectId: OTHER };
  assert.equal(classifyCredentialBinding(input, 'warn').store, true, 'default keeps behaviour');
  assert.equal(classifyCredentialBinding(input, 'warn').verdict, 'mismatch', 'but it is reported as a mismatch');
  assert.equal(classifyCredentialBinding(input, 'enforce').store, false);
});

test('classifyCredentialBinding: agreement is BOUND; incomplete data is indeterminate and stored', () => {
  const bound = classifyCredentialBinding({
    hasPayload: true, selfDid: SELF, payloadIssuerDid: COMMUNITY,
    vcIssuer: COMMUNITY, vcSubjectId: SELF, vcMemberOf: COMMUNITY,
  }, 'enforce');
  assert.equal(bound.verdict, 'bound');
  assert.equal(bound.store, true);

  // Nothing established ⇒ nothing refused (the F-031 principle, reused).
  const noPayload = classifyCredentialBinding({ hasPayload: false }, 'enforce');
  assert.equal(noPayload.verdict, 'indeterminate');
  assert.equal(noPayload.store, true);

  const noSelf = classifyCredentialBinding(
    { hasPayload: true, vcIssuer: COMMUNITY, vcSubjectId: SELF }, 'enforce');
  assert.equal(noSelf.verdict, 'indeterminate');
  assert.equal(noSelf.store, true);
  assert.match(noSelf.message, /no self DID to bind against/);
});

test('receive path: a VMC addressed to ANOTHER agent is refused under enforce, stored under warn', async () => {
  const foreign = vmc({ subjectId: OTHER, issuer: COMMUNITY, memberOf: COMMUNITY });

  // enforce: refused, nothing stored
  const appDb1 = await makeAppDb();
  const txDb1 = await makeTxDb();
  const strict = new CredentialReceiveParticipant(`peer:${SELF}`, appDb1, txDb1, 'off', undefined, 'enforce');
  const refused = await strict.prepare('tx-bind-1', [credentialOp(UUID, foreign)]);
  assert.equal(refused, 'no', 'a credential for someone else must not be accepted');
  assert.equal(await credentialRows(appDb1, UUID), 0);
  await appDb1.close(); await txDb1.close();

  // warn (the default): reported, still stored
  const appDb2 = await makeAppDb();
  const txDb2 = await makeTxDb();
  const lenient = new CredentialReceiveParticipant(`peer:${SELF}`, appDb2, txDb2);
  const stored = await lenient.prepare('tx-bind-2', [credentialOp(UUID2, foreign)]);
  assert.equal(stored, 'yes', 'warn must not change behaviour');
  assert.equal(await credentialRows(appDb2, UUID2), 1);
  await appDb2.close(); await txDb2.close();
});

test('receive path: a VMC addressed to THIS agent passes under enforce', async () => {
  const appDb = await makeAppDb();
  const txDb = await makeTxDb();
  const participant = new CredentialReceiveParticipant(`peer:${SELF}`, appDb, txDb, 'off', undefined, 'enforce');

  const uuid = '8'.repeat(8) + '-8888-4888-8888-888888888888';
  const vote = await participant.prepare('tx-bind-3', [credentialOp(uuid, vmc({
    subjectId: SELF, issuer: COMMUNITY, memberOf: COMMUNITY,
  }))]);

  assert.equal(vote, 'yes', 'a correctly addressed credential must be accepted');
  assert.equal(await credentialRows(appDb, uuid), 1);

  await appDb.close();
  await txDb.close();
});


// ---------------------------------------------------------------------------
// 4. Policy resolution (unit)
// ---------------------------------------------------------------------------

test('resolveCredentialVerifyPolicy: explicit → env → warn, and a typo never escalates', () => {
  const saved = process.env[CREDENTIAL_VERIFY_POLICY_ENV];
  try {
    delete process.env[CREDENTIAL_VERIFY_POLICY_ENV];
    assert.equal(resolveCredentialVerifyPolicy(), 'warn', 'default is warn');

    process.env[CREDENTIAL_VERIFY_POLICY_ENV] = 'enforce';
    assert.equal(resolveCredentialVerifyPolicy(), 'enforce');
    assert.equal(resolveCredentialVerifyPolicy('off'), 'off', 'an explicit option wins over the env');

    process.env[CREDENTIAL_VERIFY_POLICY_ENV] = 'ENFORCE '; // trimmed + lowercased
    assert.equal(resolveCredentialVerifyPolicy(), 'enforce');

    process.env[CREDENTIAL_VERIFY_POLICY_ENV] = 'yes-please';
    assert.equal(resolveCredentialVerifyPolicy(), 'warn', 'an unrecognised value falls back to warn, never enforce');
  } finally {
    if (saved === undefined) delete process.env[CREDENTIAL_VERIFY_POLICY_ENV];
    else process.env[CREDENTIAL_VERIFY_POLICY_ENV] = saved;
  }
});

// ---------------------------------------------------------------------------
// The arrival signal (`onPersisted`)
//
// The participant is the ONLY component that observes a credential delivery, so this callback is the only way
// an observer can learn of an arrival without polling the local table. It is what let `nav.js` stop polling
// `/api/invitations` every 5 s and `credentials.html` stop polling every 3 s.
// ---------------------------------------------------------------------------

test('onPersisted fires once, with the credential identity, after a real write', async () => {
  const appDb = await makeAppDb();
  const txDb = await makeTxDb();
  const seen: Array<{ uuid: string; vcType: string; status: string }> = [];
  const participant = new CredentialReceiveParticipant(
    'peer:did:x', appDb, txDb, 'off', undefined, undefined,
    (c) => seen.push({ uuid: c.uuid, vcType: c.vcType, status: c.status }),
  );

  await participant.prepare('tx-arrival', [credentialOp(UUID, UNRESOLVABLE_KEY_VC)]);

  assert.equal(seen.length, 1, 'exactly one announcement for one write');
  assert.equal(seen[0].uuid, UUID);
  assert.equal(seen[0].vcType, 'vmc');
  assert.equal(seen[0].status, 'issued');

  await appDb.close();
  await txDb.close();
});

test('onPersisted announces a VIC as a VIC — the type is what makes it an invitation', async () => {
  // `trust-stack` keys `invitation.received` off this field, so a normalised or defaulted type here would
  // silently stop the invitation badge from updating.
  const appDb = await makeAppDb();
  const txDb = await makeTxDb();
  const seen: string[] = [];
  const participant = new CredentialReceiveParticipant(
    'peer:did:x', appDb, txDb, 'off', undefined, undefined,
    (c) => seen.push(c.vcType),
  );

  await participant.prepare('tx-vic', [credentialOp(UUID2, UNRESOLVABLE_KEY_VC, 'vic')]);

  assert.deepEqual(seen, ['vic']);

  await appDb.close();
  await txDb.close();
});

test('onPersisted does NOT fire for an idempotent re-delivery', async () => {
  // A re-delivery of a credential we already hold is not a new arrival. Announcing it would make every open UI
  // re-read for nothing, and the badge would look like it had gone up again.
  const appDb = await makeAppDb();
  const txDb = await makeTxDb();
  const seen: string[] = [];
  const participant = new CredentialReceiveParticipant(
    'peer:did:x', appDb, txDb, 'off', undefined, undefined,
    (c) => seen.push(c.uuid),
  );

  await participant.prepare('tx-first', [credentialOp(UUID, UNRESOLVABLE_KEY_VC)]);
  await participant.prepare('tx-again', [credentialOp(UUID, UNRESOLVABLE_KEY_VC)]);

  assert.deepEqual(seen, [UUID], 'the second delivery announced nothing');
  assert.equal(await credentialRows(appDb, UUID), 1, 'and did not double-write');

  await appDb.close();
  await txDb.close();
});

test('onPersisted does NOT fire for a refused credential', async () => {
  // `enforce` + a judged-invalid proof stores nothing, so there is nothing to announce. A signal here would
  // make a UI re-read for a credential it will never see.
  const appDb = await makeAppDb();
  const txDb = await makeTxDb();
  const seen: string[] = [];
  const participant = new CredentialReceiveParticipant(
    'peer:did:x', appDb, txDb, 'enforce', judgedInvalid, undefined,
    (c) => seen.push(c.uuid),
  );

  const vote = await participant.prepare('tx-refused', [credentialOp(UUID2, UNRESOLVABLE_KEY_VC)]);

  assert.equal(vote, 'no');
  assert.deepEqual(seen, [], 'a refused credential announces nothing');

  await appDb.close();
  await txDb.close();
});

test('a throwing observer cannot fail the delivery leg', async () => {
  // The callback runs inside the 2PC prepare path, so an observer that throws must not turn a successful
  // delivery into an abort. It is invoked AFTER the write, so the write survives regardless.
  const appDb = await makeAppDb();
  const txDb = await makeTxDb();
  const participant = new CredentialReceiveParticipant(
    'peer:did:x', appDb, txDb, 'off', undefined, undefined,
    () => { throw new Error('observer exploded'); },
  );

  let vote: string | undefined;
  try {
    vote = await participant.prepare('tx-throwing', [credentialOp(UUID, UNRESOLVABLE_KEY_VC)]);
  } catch {
    assert.fail('the participant must not propagate an observer failure into the 2PC loop');
  }

  assert.equal(vote, 'yes');
  assert.equal(await credentialRows(appDb, UUID), 1);

  await appDb.close();
  await txDb.close();
});
