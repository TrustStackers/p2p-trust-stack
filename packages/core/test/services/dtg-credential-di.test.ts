/**
 * F-01 — the complete credential signing contract (`eddsa-jcs-2022`).
 *
 * SYN-006: `buildDtgCredential()` signed `SHA-256(JCS(document))` alone and then
 * attached a proof. Everything inside `proof` — `verificationMethod`, `created`,
 * `proofPurpose`, `cryptosuite` — was outside the signed input, and the
 * `eddsa-jcs-2022` label was asserted without implementing the suite. These tests
 * pin the corrected contract:
 *
 *   1. the signed bytes match an INDEPENDENT implementation (node:crypto/OpenSSL
 *      for Ed25519 + the vetted `canonicalize` lib for JCS), not just our own
 *      sign/verify pair agreeing with itself;
 *   2. a known-answer vector pins the byte-level algorithm so it cannot drift;
 *   3. changes to top-level fields, NESTED claims, or any suite-required proof
 *      configuration are rejected;
 *   4. the verification method's controller is bound to the credential's issuer,
 *      so `issuer: did:victim` signed by an attacker's key is rejected.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/services/dtg-credential-di.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import canonicalize from 'canonicalize';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';
import { base58btc } from 'multiformats/bases/base58';

import {
  buildDtgCredential,
  buildDiHashData,
  verifyDtgProof,
  serializeDtgCredential,
  deserializeDtgCredential,
  toBase58btc,
  fromBase58btc,
} from '../../src/services/dtg-credential.js';
import {
  generateEd25519KeyPair,
  generateEd25519KeyPairFromSeed,
} from '../../src/crypto/primitives.js';
import { toDtgVmc } from '../../src/services/dtg/dtg-vmc.js';
import { DidResolver } from '../../src/did/did-resolver.js';
import { createDidPeer4 } from '../../src/did/index.js';
import { CredentialFactoryImpl } from '../../src/services/credential-factory/credential-factory-impl.js';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import type { GovernanceGuard } from '../../src/services/governance-guard.js';
import type { Vrc } from '../../src/vtc/types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

// ── Independent oracles (deliberately NOT the repo's own sign/verify path) ───

const enc = new TextEncoder();

/** SHA-256 of an already-canonical string, via OpenSSL. */
function nodeSha256(canonical: string): Buffer {
  return createHash('sha256').update(Buffer.from(enc.encode(canonical))).digest();
}

/**
 * Independent eddsa-jcs-2022 hashData:
 *   SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(unsignedDocument))
 * using `canonicalize` (RFC 8785) + node:crypto, with no reference to
 * `buildDiHashData`.
 */
function independentHashData(proofConfig: object, document: object): Buffer {
  const proofHash = nodeSha256(canonicalize(proofConfig) as string);
  const docHash = nodeSha256(canonicalize(document) as string);
  return Buffer.concat([proofHash, docHash]);
}

/** Reconstruct an Ed25519 key pair from a raw 32-byte seed using OpenSSL only. */
function nodeEd25519KeyPair(seed: Uint8Array) {
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(seed),
  ]);
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return { privateKey, publicKey: new Uint8Array(spki.slice(-32)) };
}

/** The credential without its `proof` (the unsigned document). */
function withoutProof(vc: Record<string, unknown>): Record<string, unknown> {
  const { proof: _proof, ...rest } = vc;
  void _proof;
  return rest;
}

// ── 1. The signed bytes match an independent implementation ──────────────────

test('F-01: a built credential verifies, and its signed bytes match an independent implementation', () => {
  const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
  const kp = generateEd25519KeyPairFromSeed(seed);
  const { privateKey, publicKey } = nodeEd25519KeyPair(seed);

  // OpenSSL and @noble derive the same public key from the same seed.
  assert.equal(
    Buffer.from(kp.publicKey).toString('hex'),
    Buffer.from(publicKey).toString('hex'),
    'the independent key agrees with the signer',
  );

  const vc = buildDtgCredential({
    subtype: 'RelationshipCredential',
    id: 'urn:uuid:11111111-1111-4111-8111-111111111111',
    issuerDid: 'did:key:z6MkIssuer',
    subjectDid: 'did:key:z6MkSubject',
    claim: { edge: 'x' },
    validFrom: 1_700_000_000,
    verificationMethod: 'did:key:z6MkIssuer#key-1',
    signerSecretKey: kp.secretKey,
  });

  assert.equal(verifyDtgProof(vc, kp.publicKey), true, 'our verifier accepts it');
  assert.equal(vc.id, 'urn:uuid:11111111-1111-4111-8111-111111111111', 'the id is emitted');
  assert.equal((vc.proof as unknown as Record<string, unknown>).cryptosuite, 'eddsa-jcs-2022');

  const proof = vc.proof as unknown as Record<string, unknown>;
  const { proofValue, ...proofConfig } = proof;
  const document = withoutProof(vc as unknown as Record<string, unknown>);
  const expected = independentHashData(proofConfig, document);

  // (a) our hashData is byte-identical to the independent one.
  assert.equal(
    Buffer.from(buildDiHashData(proofConfig, document)).toString('hex'),
    expected.toString('hex'),
    'hashData must match an independent implementation',
  );

  // (b) the emitted proofValue equals an independent OpenSSL signature over that hashData.
  const independentSig = nodeSign(null, expected, privateKey);
  assert.equal(
    proofValue,
    base58btc.encode(independentSig),
    'proofValue must equal an independent Ed25519 signature',
  );
  assert.equal(nodeVerify(null, expected, createPublicKey(privateKey), independentSig), true);

  // (c) our base58btc codec agrees with multiformats, and round-trips.
  assert.equal(toBase58btc(new Uint8Array(independentSig)), base58btc.encode(independentSig));
  assert.deepEqual(fromBase58btc(proofValue as string), new Uint8Array(independentSig));

  // (d) the serialized form is stable: parse→verify still succeeds.
  const reparsed = deserializeDtgCredential(serializeDtgCredential(vc));
  assert.equal(verifyDtgProof(reparsed, kp.publicKey), true);
});

// ── 2. Known-answer vector (pins the algorithm against silent drift) ─────────

test('F-01 KAT: hashData and the Ed25519 signature are pinned to the eddsa-jcs-2022 algorithm', () => {
  const ctx = [
    'https://www.w3.org/ns/credentials/v2',
    'https://trustoverip.org/dtg/credentials/v1',
    'https://w3id.org/security/data-integrity/v1',
  ];
  const document = {
    '@context': ctx,
    id: 'urn:uuid:11111111-1111-4111-8111-111111111111',
    type: ['VerifiableCredential', 'DTGCredential', 'RelationshipCredential'],
    issuer: 'did:key:z6MkKATIssuer',
    validFrom: '2023-11-14T22:13:20.000Z',
    credentialSubject: { id: 'did:key:z6MkKATSubject', edge: 'x' },
  };
  const proofConfig = {
    '@context': ctx,
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: '2024-01-01T00:00:00.000Z',
    verificationMethod: 'did:key:z6MkKATIssuer#key-1',
    proofPurpose: 'assertionMethod',
  };

  const hashData = buildDiHashData(proofConfig, document);
  assert.equal(
    Buffer.from(hashData).toString('hex'),
    'ed0891408fefdc06fa83891498c574b24d4b2ecb20dd3e9c47ad3324ee2bef5f' +
      '6428c33893ae97a540d28fe5762c37e61c9626c13c1d02e356e1d689e0c18473',
    'hashData is pinned',
  );

  const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
  const { privateKey } = nodeEd25519KeyPair(seed);
  const signature = nodeSign(null, hashData, privateKey);
  assert.equal(
    Buffer.from(signature).toString('hex'),
    '137d1f24c6d7e73d46f9cda6809e40c640850ee5e248762ea1ac2b8c692d01e7' +
      '6d19c06f6e57d461ca5b3071ca783a786f5ab2bf6d46e3f1bf4affaefefcca01',
    'the Ed25519 signature over hashData is pinned',
  );
});

// ── 3. Tamper rejection ─────────────────────────────────────────────────────

test('F-01: changes to signed credential fields or suite proof configuration are rejected', () => {
  const kp = generateEd25519KeyPair();
  const base = buildDtgCredential({
    subtype: 'RelationshipCredential',
    id: 'urn:uuid:55555555-5555-4555-8555-555555555555',
    issuerDid: 'did:key:z6MkIssuer',
    subjectDid: 'did:key:z6MkSubject',
    claim: { edge: 'x', nested: { object: { digestMultibase: 'zQmAAA' } } },
    validFrom: 1_700_000_000,
    verificationMethod: 'did:key:z6MkIssuer#key-1',
    signerSecretKey: kp.secretKey,
  });
  const clone = () => JSON.parse(JSON.stringify(base)) as Record<string, unknown>;
  const ok = (vc: Record<string, unknown>) => verifyDtgProof(vc as never, kp.publicKey);

  assert.equal(ok(clone()), true, 'the untouched credential verifies');

  // Top-level document fields.
  let v = clone();
  v.issuer = 'did:key:z6MkAttacker';
  assert.equal(ok(v), false, 'a changed issuer is rejected');

  v = clone();
  v.id = 'urn:uuid:66666666-6666-4666-8666-666666666666';
  assert.equal(ok(v), false, 'a changed id is rejected (it is signed)');

  v = clone();
  v.type = ['VerifiableCredential', 'DTGCredential'];
  assert.equal(ok(v), false, 'a changed type is rejected');

  v = clone();
  v['@context'] = ['https://www.w3.org/ns/credentials/v2'];
  assert.equal(ok(v), false, 'a changed document @context is rejected');

  // NESTED value inside credentialSubject.
  v = clone();
  ((v.credentialSubject as Record<string, unknown>).nested as { object: { digestMultibase: string } })
    .object.digestMultibase = 'zQmBBB';
  assert.equal(ok(v), false, 'a changed nested claim is rejected');

  // Suite-required proof configuration.
  v = clone();
  (v.proof as Record<string, unknown>).verificationMethod = 'did:key:z6MkAttacker#key-1';
  assert.equal(ok(v), false, 'a re-pointed verificationMethod is rejected (F-01 core)');

  v = clone();
  (v.proof as Record<string, unknown>).created = '2020-01-01T00:00:00.000Z';
  assert.equal(ok(v), false, 'a backdated created is rejected');

  v = clone();
  (v.proof as Record<string, unknown>).proofPurpose = 'authentication';
  assert.equal(ok(v), false, 'a changed proofPurpose is rejected');

  v = clone();
  (v.proof as Record<string, unknown>).cryptosuite = 'eddsa-rdfc-2022';
  assert.equal(ok(v), false, 'a substituted cryptosuite label is rejected');

  v = clone();
  delete (v.proof as Record<string, unknown>)['@context'];
  assert.equal(ok(v), false, 'dropping the proof @context changes the signed bytes');

  // proofValue encoding / length.
  v = clone();
  (v.proof as Record<string, unknown>).proofValue =
    'u' + String((v.proof as Record<string, unknown>).proofValue).slice(1);
  assert.equal(ok(v), false, 'a non-base58btc proofValue is rejected');

  v = clone();
  (v.proof as Record<string, unknown>).proofValue = 'z1';
  assert.equal(ok(v), false, 'a truncated proofValue is rejected');
});

// ── 4. Personhood VMC verifies (regression: was mutated after signing) ───────

test('F-01: a personhood VMC verifies — the type array is signed, not mutated afterwards', () => {
  const kp = generateEd25519KeyPair();
  const vrc = {
    claim: { type: 'witness-member' },
    issuedAt: 1_700_000_000,
    expiresAt: 1_800_000_000,
  } as unknown as Vrc;

  const vmc = toDtgVmc({
    vrc,
    issuerDid: 'did:key:z6MkCommunity',
    subjectDid: 'did:key:z6MkMember',
    membershipRole: 'member',
    verificationMethod: 'did:key:z6MkCommunity#key-1',
    signerSecretKey: kp.secretKey,
    assertPersonhood: true,
  });

  assert.ok(vmc.type.includes('PersonhoodCredential'), 'the PHC type is present');
  assert.equal(verifyDtgProof(vmc, kp.publicKey), true, 'a PHC must verify');
});

// ── 5. Controller ↔ issuer binding, end to end through the factory ───────────

test('F-01: verification binds the verificationMethod controller to the credential issuer', async () => {
  const issuer = await createDidPeer4();
  const attacker = await createDidPeer4();
  const issuerVm = `${issuer.did}#key-1`;
  const attackerVm = `${attacker.did}#key-1`;

  // The resolver exposes the controller and the authorized relationship.
  const resolver = new DidResolver();
  const deref = await resolver.dereferenceVerificationMethod(issuerVm);
  assert.ok(deref, 'the issuer verification method resolves');
  assert.equal(deref!.controller, issuer.did, 'controller falls back to the DID portion');
  assert.ok(deref!.proofPurposes.includes('assertionMethod'), '#key-1 asserts');

  const factory = new CredentialFactoryImpl(new SqliteDataSource(':memory:'));

  // Legitimate: the issuer's own key under the issuer's own DID.
  const good = buildDtgCredential({
    subtype: 'RelationshipCredential',
    id: 'urn:uuid:77777777-7777-4777-8777-777777777777',
    issuerDid: issuer.did,
    subjectDid: 'did:key:z6MkSubject',
    claim: { edge: 'x' },
    validFrom: 1_700_000_000,
    verificationMethod: issuerVm,
    signerSecretKey: issuer.signingKeyPair.secretKey,
  });
  const goodResult = await factory.verify(good as unknown as Record<string, unknown>);
  assert.equal(goodResult.valid, true, String(goodResult.reason ?? ''));

  // Forgery: `issuer` names the victim, but the key belongs to the attacker.
  const forged = buildDtgCredential({
    subtype: 'RelationshipCredential',
    id: 'urn:uuid:88888888-8888-4888-8888-888888888888',
    issuerDid: issuer.did,
    subjectDid: 'did:key:z6MkSubject',
    claim: { edge: 'x' },
    validFrom: 1_700_000_000,
    verificationMethod: attackerVm,
    signerSecretKey: attacker.signingKeyPair.secretKey,
  });
  const forgedResult = await factory.verify(forged as unknown as Record<string, unknown>);
  assert.equal(forgedResult.valid, false, 'a mismatched controller must be refused');
  assert.match(String(forgedResult.reason), /controller .* is not the credential issuer/);
});

// ── 6. F-02 — the membership factory finalises content BEFORE signing ───────
//
// SYN-007 / F-02: the `MembershipCredential` branch used to append
// `PersonhoodCredential` to `vc.type` AFTER `buildDtgCredential()` returned, so
// the verifier re-canonicalised a proofless document the signer never saw and
// the PHC could never verify. These tests exercise the CITED factory branch end
// to end (`mint()` → `verify()`) with personhood ENABLED and DISABLED, prove a
// deliberate post-sign change fails verification, and prove the built document
// can no longer be mutated at all.

const MIGRATIONS_DIR = getMigrationsDir();

/** A migrated in-memory app DB — `mint()` writes a `credentials` row. */
async function makeAppDb(): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

/** Governance is out of scope here — the guard always admits. */
const allowAllGuard = {
  validateCredentialIssuance: async () => ({ allowed: true }),
} as unknown as GovernanceGuard;

/** Mint a VMC through the cited factory branch, optionally as a PHC. */
async function mintMembershipVmcViaFactory(
  db: SqliteDataSource,
  issuer: Awaited<ReturnType<typeof createDidPeer4>>,
  assertPersonhood?: boolean,
) {
  const factory = new CredentialFactoryImpl(db, allowAllGuard);
  const result = await factory.mint({
    kind: 'MembershipCredential',
    scenario: 'community-join',
    issuerDid: issuer.did,
    subjectDid: 'did:key:z6MkMemberSubject',
    governanceDid: issuer.did,
    claim: { membershipRole: 'member', communityName: 'Test Club' },
    verificationMethod: `${issuer.did}#key-1`,
    signerSecretKey: issuer.signingKeyPair.secretKey,
    ...(assertPersonhood ? { assertPersonhood: true } : {}),
  });
  return { factory, result };
}

test('F-02: a factory-minted VMC verifies with personhood enabled AND disabled', async () => {
  const db = await makeAppDb();
  const issuer = await createDidPeer4();

  // assertPersonhood: true → the PHC type is INSIDE the signed bytes.
  const phc = await mintMembershipVmcViaFactory(db, issuer, true);
  const phcType = (JSON.parse(phc.result.w3cVcJson!) as { type: string[] }).type;
  assert.ok(phcType.includes('PersonhoodCredential'), 'the PHC type is present');
  const phcVerdict = await phc.factory.verify(phc.result.w3cVcJson!);
  assert.equal(phcVerdict.valid, true, `a PHC must verify: ${phcVerdict.reason ?? ''}`);

  // assertPersonhood omitted → a plain VMC, no PHC type, still verifies.
  const vmc = await mintMembershipVmcViaFactory(db, issuer, false);
  const vmcType = (JSON.parse(vmc.result.w3cVcJson!) as { type: string[] }).type;
  assert.ok(!vmcType.includes('PersonhoodCredential'), 'a plain VMC carries no PHC type');
  const vmcVerdict = await vmc.factory.verify(vmc.result.w3cVcJson!);
  assert.equal(vmcVerdict.valid, true, `a VMC must verify: ${vmcVerdict.reason ?? ''}`);

  await db.close();
});

test('F-02: appending PersonhoodCredential AFTER signing fails verification', async () => {
  const db = await makeAppDb();
  const issuer = await createDidPeer4();
  const { factory, result } = await mintMembershipVmcViaFactory(db, issuer, false);

  // Exactly the F-02 mutation: append the PHC type to the already-signed,
  // proofless document.
  const tampered = JSON.parse(result.w3cVcJson!) as Record<string, unknown>;
  (tampered.type as string[]).push('PersonhoodCredential');

  const verdict = await factory.verify(JSON.stringify(tampered));
  assert.equal(verdict.valid, false, 'a post-sign type change must not verify');

  await db.close();
});

test('F-02: a built credential is deeply frozen — post-sign mutation throws', () => {
  const kp = generateEd25519KeyPair();
  const vc = buildDtgCredential({
    subtype: 'MembershipCredential',
    id: 'urn:uuid:99999999-9999-4999-8999-999999999999',
    issuerDid: 'did:key:z6MkIssuer',
    subjectDid: 'did:key:z6MkSubject',
    claim: { memberOf: 'did:key:z6MkIssuer', membershipRole: 'member' },
    validFrom: 1_700_000_000,
    verificationMethod: 'did:key:z6MkIssuer#key-1',
    signerSecretKey: kp.secretKey,
  });

  // The exact F-02 shapes, plus nested writes — each must throw in strict mode.
  assert.throws(() => { (vc as unknown as { type: string[] }).type = ['x']; }, TypeError);
  assert.throws(() => { (vc.type as string[]).push('PersonhoodCredential'); }, TypeError);
  assert.throws(() => { (vc.proof as { proofValue: string }).proofValue = 'z1'; }, TypeError);
  assert.throws(() => { (vc.credentialSubject as Record<string, unknown>).id = 'x'; }, TypeError);

  // The document is unchanged and still verifies.
  assert.equal(verifyDtgProof(vc, kp.publicKey), true);
});