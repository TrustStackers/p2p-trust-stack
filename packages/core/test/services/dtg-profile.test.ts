/**
 * F-002 — a VEC and a VWC are v1.0 statement-credential *profiles*, not types.
 *
 * The audit said the two are "emitted as concrete subtypes" and the pinned spec
 * "folds them into one statement type". Research against the DTG Credentials
 * Core Specification v1.0 settled both halves, and they point in opposite
 * directions:
 *
 *   - the taxonomy reading is RIGHT — "The endorsement and witness credentials
 *     of Working Draft 02 are predicate profiles of the VSC, not types";
 *   - the prescribed fix as written is WRONG — the migration keeps the names as
 *     profile names, and CONTEXT.md states for both: "Name retained for the
 *     profile; no longer a W3C type string". So the conformant array is the
 *     three-element statement form, with the distinction carried by
 *     `credentialSubject.predicate` (`dtg:endorses` / `dtg:witnessed`).
 *
 * Because the type string stops carrying meaning, the verifier half
 * (`detectKindFromType`) has to read the predicate — covered here through the
 * exported policy surface, and in `credential-factory` by predicate dispatch.
 *
 * The change alters canonical bytes (hence a credential's digest), so it sits
 * behind `TSP_DTG_PROFILE_POLICY`: `off`/`warn` reproduce the WD02 bytes exactly,
 * `enforce` emits the profile. Every case below pins one of those.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/services/dtg-profile.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateEd25519KeyPair, sha256 } from '../../src/crypto/primitives.js';
import { sha256 as mfSha256 } from 'multiformats/hashes/sha2';
import { create as mfMultihash } from 'multiformats/hashes/digest';
import { base58btc } from 'multiformats/bases/base58';
import { buildDtgCredential, verifyDtgProof } from '../../src/services/dtg-credential.js';
import { toDtgVec } from '../../src/services/dtg/dtg-vec.js';
import { toDtgVwc } from '../../src/services/dtg/dtg-vwc.js';
import type { Vrc } from '../../src/vtc/types.js';
import {
  DTG_PREDICATE_ENDORSES,
  DTG_PREDICATE_WITNESSED,
  DTG_PROFILE_POLICY_ENV,
  STATEMENT_CREDENTIAL_TYPE,
  fromSha256MultibaseMultihash,
  resolveDtgProfilePolicy,
  toDigestMultibase,
  toSha256MultibaseMultihash,
} from '../../src/services/dtg/index.js';

const keyPair = generateEd25519KeyPair();
const utf8 = (s: string) => new TextEncoder().encode(s);

/** Run `fn` with the policy env var set, restoring the previous value after. */
async function withPolicy<T>(value: string | undefined, fn: () => T | Promise<T>): Promise<T> {
  const previous = process.env[DTG_PROFILE_POLICY_ENV];
  if (value === undefined) delete process.env[DTG_PROFILE_POLICY_ENV];
  else process.env[DTG_PROFILE_POLICY_ENV] = value;
  try {
    return await fn();
  } finally {
    if (previous === undefined) delete process.env[DTG_PROFILE_POLICY_ENV];
    else process.env[DTG_PROFILE_POLICY_ENV] = previous;
  }
}

// ── Policy resolution ──────────────────────────────────────────────────────

test('F-002 policy: defaults to enforce, parses off|warn|enforce, falls back to the default', () => {
  assert.equal(
    resolveDtgProfilePolicy(undefined),
    'enforce',
    'unset ⇒ the v1.0 profile, by the owner’s Y6-yes ruling',
  );
  assert.equal(resolveDtgProfilePolicy(''), 'enforce');
  assert.equal(resolveDtgProfilePolicy('off'), 'off');
  assert.equal(resolveDtgProfilePolicy('warn'), 'warn');
  assert.equal(resolveDtgProfilePolicy('enforce'), 'enforce');
  assert.equal(resolveDtgProfilePolicy('  OFF '), 'off', 'case- and space-insensitive');
  assert.equal(
    resolveDtgProfilePolicy('yes'),
    'enforce',
    'a typo lands on the default, not on an unrequested third behaviour',
  );
});

// ── Digest encoding (the VWC's object member) ──────────────────────────────

test('F-002 digest: multibase(multihash(sha2-256)) matches the multiformats oracle', () => {
  const bytes = utf8('hello world');
  const ours = toSha256MultibaseMultihash(sha256(bytes));
  // NOTE: multiformats v14 wraps a multihash via `create(code, digest)` —
  // `hasher.encode()` returns the bare digest bytes, and `Multihash.toString()`
  // does not apply a base — so the oracle is the prefixed `.bytes`.
  const oracle = base58btc.encode(mfMultihash(0x12, mfSha256.encode(bytes)).bytes);
  assert.equal(ours, oracle, 'hand-rolled encoder must agree with an independent implementation');
  assert.ok(ours.startsWith('zQm'), `sha2-256 multihash must read zQm…, got ${ours.slice(0, 4)}`);
  assert.deepEqual(fromSha256MultibaseMultihash(ours), sha256(bytes), 'round trip');
});

test('F-002 digest: rejects values that only look like a multihash', () => {
  assert.throws(() => toSha256MultibaseMultihash(new Uint8Array(31)), /expected a 32-byte digest/);
  assert.throws(() => fromSha256MultibaseMultihash('Qmd'), /Expected multibase "z" prefix/);

  // Right shape, wrong algorithm code: 0x13 (sha2-512's neighbour) instead of 0x12.
  const wrongCode = base58btc.encode(
    new Uint8Array([0x13, 0x20, ...Array.from(sha256(utf8('x')))]),
  );
  assert.throws(() => fromSha256MultibaseMultihash(wrongCode), /not a sha2-256 multihash/);

  // Right header, wrong length.
  const truncated = base58btc.encode(new Uint8Array([0x12, 0x1f, ...Array.from(sha256(utf8('x'))).slice(0, 31)]));
  assert.throws(() => fromSha256MultibaseMultihash(truncated), /expected 34 bytes/);
});

test('F-002 digest: toDigestMultibase normalises the shapes a caller may pass', () => {
  const digest = sha256(utf8('endorsed'));
  const expected = toSha256MultibaseMultihash(digest);
  const hex = Array.from(digest).map(b => b.toString(16).padStart(2, '0')).join('');

  assert.equal(toDigestMultibase(`sha256:${hex}`), expected);
  assert.equal(toDigestMultibase(hex), expected);
  assert.equal(toDigestMultibase(expected), expected, 'already multibase ⇒ unchanged');
  assert.equal(toDigestMultibase('not-a-digest'), 'not-a-digest', 'unknown ⇒ pass through, never throw');
});

// ── VEC emission ───────────────────────────────────────────────────────────

const VEC_DIGEST_HEX = 'ab'.repeat(32);

function buildVec() {
  return toDtgVec({
    issuerDid: 'did:key:z6MkIssuer',
    subjectDid: 'did:key:z6MkSubject',
    endorsedCredentialDigest: `sha256:${VEC_DIGEST_HEX}`,
    endorsementType: 'skill',
    verificationMethod: 'did:key:z6MkIssuer#key-1',
    signerSecretKey: keyPair.secretKey,
    validFrom: 1_700_000_000,
  });
}

test('F-002 VEC: off/warn reproduce the WD02 concrete subtype', async () => {
  for (const policy of ['off', 'warn'] as const) {
    await withPolicy(policy, () => {
      const vc = buildVec();
      assert.deepEqual(vc.type, ['VerifiableCredential', 'DTGCredential', 'EndorsementCredential']);
      const subject = vc.credentialSubject as Record<string, unknown>;
      assert.equal(subject.endorsedCredentialDigest, `sha256:${VEC_DIGEST_HEX}`);
      assert.equal(subject.endorsementType, 'skill');
      assert.equal(subject.predicate, undefined, 'no predicate in the WD02 form');
      assert.equal(subject.object, undefined);
    });
  }
});

test('F-002 VEC: enforce emits a StatementCredential under dtg:endorses, with no alias', async () => {
  await withPolicy('enforce', () => {
    const vc = buildVec();
    assert.deepEqual(vc.type, ['VerifiableCredential', 'DTGCredential', STATEMENT_CREDENTIAL_TYPE]);
    assert.equal(vc.type.includes('EndorsementCredential'), false, 'the name is not a type string');
    const subject = vc.credentialSubject as Record<string, unknown>;
    assert.equal(subject.predicate, DTG_PREDICATE_ENDORSES);
    assert.deepEqual(subject.object, { digestMultibase: toDigestMultibase(VEC_DIGEST_HEX) });
    assert.equal(subject.endorsementType, 'skill', 'the assertion stays a subject member');
    assert.equal(subject.endorsedCredentialDigest, undefined, 'it moved into object');
  });
});

test('F-002: the UNSET default emits the v1.0 profile (the flip, pinned)', async () => {
  await withPolicy(undefined, () => {
    const vc = buildVec();
    assert.deepEqual(vc.type, ['VerifiableCredential', 'DTGCredential', STATEMENT_CREDENTIAL_TYPE]);
    const subject = vc.credentialSubject as Record<string, unknown>;
    assert.equal(subject.predicate, DTG_PREDICATE_ENDORSES);
    assert.deepEqual(subject.object, { digestMultibase: toDigestMultibase(VEC_DIGEST_HEX) });
  });
});

test('F-002: a credential carrying no statement is identical under every policy', async () => {
  const build = () =>
    buildDtgCredential({
      subtype: 'RelationshipCredential',
      id: 'urn:uuid:test',
      issuerDid: 'did:key:z6MkIssuer',
      subjectDid: 'did:key:z6MkSubject',
      claim: { edge: 'x' },
      validFrom: 1_700_000_000,
      verificationMethod: 'did:key:z6MkIssuer#key-1',
      signerSecretKey: keyPair.secretKey,
    });
  // `proof.created` is a build-time timestamp, so compare the signed content only.
  const strip = (vc: { proof?: unknown }) => {
    const { proof: _proof, ...rest } = vc as Record<string, unknown>;
    return rest;
  };

  const off = strip(await withPolicy('off', build));
  const warn = strip(await withPolicy('warn', build));
  const enforce = strip(await withPolicy('enforce', build));

  assert.deepEqual(off.type, ['VerifiableCredential', 'DTGCredential', 'RelationshipCredential']);
  assert.deepEqual(off, warn);
  assert.deepEqual(warn, enforce, 'only statement-bearing credentials are affected');
});

// ── VWC emission ───────────────────────────────────────────────────────────

const vrc = {
  claim: { type: 'rotation-witness', note: 'witnessed' },
  issuedAt: 1_700_000_000,
  expiresAt: 1_800_000_000,
} as unknown as Vrc;

const vwcParams = {
  vrc,
  issuerDid: 'did:key:z6MkWitness',
  subjectDid: 'did:key:z6MkParty',
  taskContext: 'thread-abc-123',
  verificationMethod: 'did:key:z6MkWitness#key-1',
  signerSecretKey: keyPair.secretKey,
};

test('F-002 VWC: enforce emits the dtg:witnessed profile with object.digestMultibase', async () => {
  await withPolicy('enforce', () => {
    const vc = toDtgVwc(vwcParams);
    assert.deepEqual(vc.type, ['VerifiableCredential', 'DTGCredential', STATEMENT_CREDENTIAL_TYPE]);
    assert.equal(vc.type.includes('WitnessCredential'), false, 'the name is not a type string');

    const subject = vc.credentialSubject as Record<string, unknown>;
    assert.equal(subject.predicate, DTG_PREDICATE_WITNESSED);
    assert.equal(subject.taskContext, 'thread-abc-123', 'REQUIRED by the profile');
    assert.equal(subject.digest, undefined, 'the flat digest moves into object');

    // The digest is of the originating edge claim, in the spec's encoding.
    const expected = toSha256MultibaseMultihash(sha256(utf8(JSON.stringify(vrc.claim))));
    assert.deepEqual(subject.object, { digestMultibase: expected });
    assert.ok(expected.startsWith('zQm'));
  });
});

test('F-002 VWC: the dtg:witnessed profile refuses to issue without taskContext', async () => {
  await withPolicy('enforce', () => {
    assert.throws(
      () => toDtgVwc({ ...vwcParams, taskContext: undefined }),
      /taskContext is REQUIRED by the 'dtg:witnessed' profile/,
    );
  });
  // …while the WD02 form still tolerates its absence.
  await withPolicy('off', () => {
    assert.ok(toDtgVwc({ ...vwcParams, taskContext: undefined }));
  });
});

test('F-002 VWC: off keeps the WD02 array and the sha256: hex digest', async () => {
  await withPolicy('off', () => {
    const vc = toDtgVwc(vwcParams);
    assert.deepEqual(vc.type, ['VerifiableCredential', 'DTGCredential', 'WitnessCredential']);
    const subject = vc.credentialSubject as Record<string, unknown>;
    assert.match(String(subject.digest), /^sha256:[0-9a-f]{64}$/);
    assert.equal(subject.predicate, undefined);
  });
});

test('F-002 VWC: an absent taskContext is omitted, not signed as null', async () => {
  // jcsCanonicalize() renders undefined as `null` while JSON.stringify() drops the
  // key, so `taskContext: undefined` was SIGNED over `"taskContext":null` but
  // STORED without the member — and verifyDtgProof() re-canonicalises the parsed
  // document, so such a credential could never verify. Issue without a
  // taskContext and check the document that gets persisted verifies.
  await withPolicy('off', () => {
    const vc = toDtgVwc({ ...vwcParams, taskContext: undefined });
    const stored = JSON.parse(JSON.stringify(vc)) as typeof vc; // what is persisted
    assert.equal('taskContext' in (stored.credentialSubject as Record<string, unknown>), false);
    assert.equal(verifyDtgProof(stored, keyPair.publicKey), true);
  });
});
