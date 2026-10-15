// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `governanceRowToDoc` admin resolution — the §3.5.1c fix.
 *
 * `adminVids` is consumed as **CESR Ed25519 public keys**: `asEncodedGovernanceDoc`
 * validates every entry with `asCesrVid` (which throws on anything else), and `issueVrc`
 * tests membership with `adminVids.includes(signer.vid)` where `signer.vid` is a CESR key.
 * It used to be filled with display labels (`name ?? uuid`), which made the `issueVrc`
 * admin check **unsatisfiable for every store-loaded doc**.
 *
 * The central test below inverts what was previously an impossible assertion: `issueVrc`
 * now SUCCEEDS for a governance doc read back out of the store.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/vtc/store-admin-resolution.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runMigrations } from '../../src/db/migrate.js';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import * as keysRepo from '../../src/db/repositories/keys-repo.js';
import { encryptSecretKey } from '../../src/keystore/sqlite-keystore.js';
import { COMMUNITY_KEY_PASSPHRASE } from '../../src/services/did-manager.js';
import { IdentityResolver } from '../../src/services/identity-resolver.js';
import { generateEd25519KeyPair, signEd25519 } from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { VtcStore } from '../../src/vtc/store.js';
import { didToUuid, generateUuid } from '../../src/db/uuid-helpers.js';
import { asCesrVid, computeGovernanceDocDigest } from '../../src/vtc/codec.js';
import { issueVrc, verifyVrc } from '../../src/vtc/vtc.js';
import type { VrcSignature, VtcGovernanceDoc } from '../../src/vtc/types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLAIM = 'witness-member';

interface Vid { vid: string; secretKey: Uint8Array; publicKey: Uint8Array }

function makeVid(): Vid {
  const kp = generateEd25519KeyPair();
  return { vid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, kp.publicKey), ...kp };
}

function makeStore(): { db: DatabaseSync; store: VtcStore } {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  return { db, store: new VtcStore(db, new IdentityResolver(db)) };
}

/** A governance doc whose adminVids are the real CESR keys (what createVtc produces). */
function makeGovernanceDoc(vtc: Vid, admins: Vid[], threshold: number, name = 'Test VTC'): VtcGovernanceDoc {
  const unsigned = {
    vtcVid: vtc.vid,
    vtcDid: `did:peer:4:z${vtc.vid.slice(1, 12)}`,
    name,
    adminVids: admins.map(a => a.vid),
    threshold,
    allowedClaimTypes: [CLAIM],
    createdAt: 1700000000,
  };
  const digest = computeGovernanceDocDigest(unsigned);
  const signatures: VrcSignature[] = admins.map(a => ({
    signerVid: a.vid,
    signature: signEd25519(digest, a.secretKey),
  }));
  return { ...unsigned, digest, signatures };
}


/**
 * Seed one admin identity: the `identities` row, a PRIMARY `did_documents` row, its
 * Ed25519 key(s), and the `memberships` row that makes it an admin of `communityUuid`.
 *
 * `primaryKeys` carries rotation versions so a test can plant a rotated pair; `stubKey`
 * plants the non-primary `did:peer:4` key an identity legitimately also holds.
 */
function seedAdmin(db: DatabaseSync, opts: {
  communityUuid: string;
  name: string;
  identityUuid?: string;
  /** Ed25519 keys on the PRIMARY did_document, by rotation_version. Omit for none. */
  primaryKeys?: Array<{ publicKey: Uint8Array; rotationVersion: number }>;
  /** Ed25519 key on a NON-primary document (the relationship-handshake stub shape). */
  stubKey?: { publicKey: Uint8Array; did: string };
  role?: string;
}): string {
  const identityUuid = opts.identityUuid ?? generateUuid();
  const did = `did:peer:4:zadmin-${identityUuid}`;
  const now = 1700000000;

  db.prepare(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES (?, 'vta', 'ai_agent', 'local', ?, ?, ?)`,
  ).run(identityUuid, opts.name, now, now);

  const primaryDocUuid = generateUuid();
  db.prepare(
    `INSERT INTO did_documents (uuid, identity_uuid, did, method, is_primary, status, created_at, updated_at)
     VALUES (?, ?, ?, 'peer4', 1, 'active', ?, ?)`,
  ).run(primaryDocUuid, identityUuid, did, now, now);

  for (const k of opts.primaryKeys ?? []) {
    db.prepare(
      `INSERT INTO keys (uuid, identity_uuid, did_document_uuid, key_type, public_key, rotation_version, created_at)
       VALUES (?, ?, ?, 'ed25519', ?, ?, ?)`,
    ).run(generateUuid(), identityUuid, primaryDocUuid, k.publicKey, k.rotationVersion, now);
  }

  if (opts.stubKey) {
    const stubDocUuid = generateUuid();
    db.prepare(
      `INSERT INTO did_documents (uuid, identity_uuid, did, method, is_primary, status, created_at, updated_at)
       VALUES (?, ?, ?, 'peer4', 0, 'active', ?, ?)`,
    ).run(stubDocUuid, identityUuid, opts.stubKey.did, now, now);
    db.prepare(
      `INSERT INTO keys (uuid, identity_uuid, did_document_uuid, key_type, public_key, rotation_version, created_at)
       VALUES (?, ?, ?, 'ed25519', ?, 0, ?)`,
    ).run(generateUuid(), identityUuid, stubDocUuid, opts.stubKey.publicKey, now);
  }

  db.prepare(
    `INSERT INTO memberships (uuid, member_identity_uuid, community_identity_uuid, role, status, issued_at)
     VALUES (?, ?, ?, ?, 'active', ?)`,
  ).run(generateUuid(), identityUuid, opts.communityUuid, opts.role ?? 'admin', now);

  return identityUuid;
}

/** Seed the claim-type-allow binding that makes `allowedClaimTypes` non-empty. */
function seedClaimTypeAllow(db: DatabaseSync, communityUuid: string, claimType = CLAIM): void {
  db.prepare(
    `INSERT INTO community_policy_bindings (uuid, community_identity_uuid, rule_type, enabled, params, updated_at)
     VALUES (?, ?, ?, 1, ?, unixepoch())`,
  ).run(generateUuid(), communityUuid, `task:p2pts:rule:claim-type-allow:0.1#${claimType}`, JSON.stringify({ claim_type: claimType }));
}
/**
 * Give the COMMUNITY itself an Ed25519 key against its primary did_document — the shape
 * `services/vtc.ts` writes (`keysRepo.createWithSecret({ didDocumentUuid: docUuid,
 * keyType: 'ed25519' })`). `saveGovernanceDoc`'s resolver call already created the
 * identity and its primary document, so this only adds the key.
 */
function seedCommunityKey(db: DatabaseSync, communityUuid: string, publicKey: Uint8Array, rotationVersion = 0): void {
  const doc = db.prepare(
    'SELECT uuid FROM did_documents WHERE identity_uuid = ? AND is_primary = 1',
  ).get(communityUuid) as { uuid: string } | undefined;
  assert.ok(doc, 'saveGovernanceDoc must have created the community primary did_document');

  db.prepare(
    `INSERT INTO keys (uuid, identity_uuid, did_document_uuid, key_type, public_key, rotation_version, created_at)
     VALUES (?, ?, ?, 'ed25519', ?, ?, 1700000000)`,
  ).run(generateUuid(), communityUuid, doc.uuid, publicKey, rotationVersion);
}



// ---------------------------------------------------------------------------
// The fix
// ---------------------------------------------------------------------------

test('adminVids holds CESR public keys, not display labels', () => {
  const { db, store } = makeStore();
  const vtc = makeVid();
  const alice = makeVid();
  const bob = makeVid();
  const doc = makeGovernanceDoc(vtc, [alice, bob], 2);
  store.saveGovernanceDoc(doc);

  const communityUuid = didToUuid(doc.vtcDid);
  seedAdmin(db, { communityUuid, name: 'Alice', primaryKeys: [{ publicKey: alice.publicKey, rotationVersion: 0 }] });
  seedAdmin(db, { communityUuid, name: 'Bob', primaryKeys: [{ publicKey: bob.publicKey, rotationVersion: 0 }] });
  seedCommunityKey(db, communityUuid, vtc.publicKey);

  const fetched = store.getGovernanceDoc(doc.vtcDid)!;

  assert.deepEqual(
    [...fetched.adminVids].sort(),
    [alice.vid, bob.vid].sort(),
    'adminVids must be the admins\' CESR keys',
  );
  // The old behaviour: display labels. Pin that they are NOT present.
  assert.ok(!fetched.adminVids.includes('Alice'), 'adminVids must not contain a display label');
  assert.ok(!fetched.adminVids.includes('Bob'), 'adminVids must not contain a display label');
  // Each entry is genuinely CESR-encodable — the per-entry contract that
  // `asEncodedGovernanceDoc` enforces and `countValidAdminSignatures` relies on.
  // (The doc as a whole is NOT CESR-encodable from the store, because `vtcVid` is a DID
  // by design — see the `vtcVid` tests below.)
  for (const [i, vid] of fetched.adminVids.entries()) {
    assert.doesNotThrow(() => asCesrVid(vid, `adminVids[${i}]`, 'test'), `adminVids[${i}] must be a CESR key`);
  }
});

test('issueVrc SUCCEEDS for a doc read back from the store (previously impossible)', () => {
  const { db, store } = makeStore();
  const vtc = makeVid();
  const admin = makeVid();
  const doc = makeGovernanceDoc(vtc, [admin], 1);
  store.saveGovernanceDoc(doc);

  const communityUuid = didToUuid(doc.vtcDid);
  seedAdmin(db, { communityUuid, name: 'Admin', primaryKeys: [{ publicKey: admin.publicKey, rotationVersion: 0 }] });
  seedClaimTypeAllow(db, communityUuid);
  seedCommunityKey(db, communityUuid, vtc.publicKey);

  const fetched = store.getGovernanceDoc(doc.vtcDid)!;
  const subject = makeVid();

  // This threw `issueVrc: signer ... is not on the VTC's admin list` before the fix,
  // for a VTC the signer demonstrably administered.
  const vrc = issueVrc({
    governanceDoc: fetched,
    subjectVid: subject.vid,
    claim: { type: CLAIM },
    signers: [{ vid: admin.vid, signingKeyPair: admin }],
  });

  // issuerVid is the VTC's DID — by design, not an oversight. The pre-refactor code
  // documented this (see the `⚠️ Boundary note` on `VtcApiModule.issueVrc`): storage and
  // verification are DID/DID-keyed, and only the binary codec needs a CESR key. A CESR
  // key here breaks `verifyVrc`'s `getGovernanceDoc(vrc.issuerVid)` lookup.
  assert.equal(vrc.issuerVid, doc.vtcDid);
  assert.equal(vrc.signatures.length, 1);
  assert.equal(vrc.signatures[0].signerVid, admin.vid);
});

test('adminDids is populated, parallel to adminVids', () => {
  const { db, store } = makeStore();
  const vtc = makeVid();
  const alice = makeVid();
  const doc = makeGovernanceDoc(vtc, [alice], 1);
  store.saveGovernanceDoc(doc);

  const communityUuid = didToUuid(doc.vtcDid);
  const aliceUuid = seedAdmin(db, {
    communityUuid, name: 'Alice', primaryKeys: [{ publicKey: alice.publicKey, rotationVersion: 0 }],
  });

  const fetched = store.getGovernanceDoc(doc.vtcDid)!;

  assert.ok(Array.isArray(fetched.adminDids), 'adminDids must be populated');
  assert.equal(fetched.adminDids!.length, fetched.adminVids.length, 'adminDids must be parallel to adminVids');
  assert.equal(fetched.adminDids![0], `did:peer:4:zadmin-${aliceUuid}`);
});


// ---------------------------------------------------------------------------
// Which key
// ---------------------------------------------------------------------------

test('picks the PRIMARY did_document key, not a did:peer:4 stub at the same rotation_version', () => {
  const { db, store } = makeStore();
  const vtc = makeVid();
  const admin = makeVid();
  const stub = makeVid(); // the relationship-handshake key an identity also holds
  const doc = makeGovernanceDoc(vtc, [admin], 1);
  store.saveGovernanceDoc(doc);

  const communityUuid = didToUuid(doc.vtcDid);
  seedAdmin(db, {
    communityUuid,
    name: 'Admin',
    primaryKeys: [{ publicKey: admin.publicKey, rotationVersion: 0 }],
    stubKey: { publicKey: stub.publicKey, did: 'did:peer:4:zrelationship-stub' },
  });

  const fetched = store.getGovernanceDoc(doc.vtcDid)!;

  assert.deepEqual(fetched.adminVids, [admin.vid], 'must resolve the root identity key');
  assert.ok(!fetched.adminVids.includes(stub.vid), 'the non-primary stub key must not be chosen');
});

test('picks MAX(rotation_version) on the primary document', () => {
  const { db, store } = makeStore();
  const vtc = makeVid();
  const v1 = makeVid();
  const v2 = makeVid();
  const doc = makeGovernanceDoc(vtc, [v1], 1);
  store.saveGovernanceDoc(doc);

  const communityUuid = didToUuid(doc.vtcDid);
  seedAdmin(db, {
    communityUuid,
    name: 'Rotated',
    primaryKeys: [
      { publicKey: v1.publicKey, rotationVersion: 0 },
      { publicKey: v2.publicKey, rotationVersion: 1 },
    ],
  });

  const fetched = store.getGovernanceDoc(doc.vtcDid)!;

  assert.deepEqual(fetched.adminVids, [v2.vid], 'the current key is the highest rotation_version');
});

// ---------------------------------------------------------------------------
// Degenerate cases
// ---------------------------------------------------------------------------

test('an admin with no resolvable key is omitted from adminVids but kept in adminDids', () => {
  const { db, store } = makeStore();
  const vtc = makeVid();
  const withKey = makeVid();
  const doc = makeGovernanceDoc(vtc, [withKey], 1);
  store.saveGovernanceDoc(doc);

  const communityUuid = didToUuid(doc.vtcDid);
  seedAdmin(db, { communityUuid, name: 'Has Key', primaryKeys: [{ publicKey: withKey.publicKey, rotationVersion: 0 }] });
  const keylessUuid = seedAdmin(db, { communityUuid, name: 'No Key' }); // no primaryKeys

  const fetched = store.getGovernanceDoc(doc.vtcDid)!;

  assert.deepEqual(fetched.adminVids, [withKey.vid], 'the keyless admin cannot be represented as a VID');
  assert.equal(fetched.adminDids!.length, 2, 'but both admins remain addressable by DID');
  assert.ok(fetched.adminDids!.includes(`did:peer:4:zadmin-${keylessUuid}`));
});

test('a community with no admins yields empty adminVids and no adminDids', () => {
  const { store } = makeStore();
  const vtc = makeVid();
  const doc = makeGovernanceDoc(vtc, [makeVid()], 1);
  store.saveGovernanceDoc(doc);

  const fetched = store.getGovernanceDoc(doc.vtcDid)!;

  assert.deepEqual(fetched.adminVids, []);
  assert.equal(fetched.adminDids, undefined, 'the optional field is absent when there is nothing to carry');
});

test('a non-admin member is not on the admin list', () => {
  const { db, store } = makeStore();
  const vtc = makeVid();
  const admin = makeVid();
  const member = makeVid();
  const doc = makeGovernanceDoc(vtc, [admin], 1);
  store.saveGovernanceDoc(doc);

  const communityUuid = didToUuid(doc.vtcDid);
  seedAdmin(db, { communityUuid, name: 'Admin', primaryKeys: [{ publicKey: admin.publicKey, rotationVersion: 0 }] });
  seedAdmin(db, {
    communityUuid, name: 'Member', role: 'member',
    primaryKeys: [{ publicKey: member.publicKey, rotationVersion: 0 }],
  });

  const fetched = store.getGovernanceDoc(doc.vtcDid)!;

  assert.deepEqual(fetched.adminVids, [admin.vid]);
});


// ---------------------------------------------------------------------------
// The community's own VID (vtcVid) — a DID, deliberately
// ---------------------------------------------------------------------------

/**
 * `vtcVid` holds the VTC's **DID**, not a CESR key — see the note on `governanceRowToDoc`.
 * It reads like a naming artifact, and it is one, but the behaviour is load-bearing:
 * `verifyVrc` resolves the governance doc from a VRC's `issuerVid` (which `issueVrc` sets
 * to this field) via `getGovernanceDoc` → `IdentityResolver.lookupByDid`.
 *
 * This test exists because a CESR key here is *plausible-looking* and was in fact tried —
 * it makes `adminVids` and `vtcVid` look consistent while silently breaking verification.
 */
test('vtcVid is the DID, so a store-loaded doc is resolvable by its own vtcVid', () => {
  const { db, store } = makeStore();
  const vtc = makeVid();
  const doc = makeGovernanceDoc(vtc, [makeVid()], 1);
  store.saveGovernanceDoc(doc);

  const communityUuid = didToUuid(doc.vtcDid);
  seedCommunityKey(db, communityUuid, vtc.publicKey);

  const fetched = store.getGovernanceDoc(doc.vtcDid)!;

  assert.equal(fetched.vtcVid, fetched.vtcDid, 'vtcVid is the VTC DID');
  assert.equal(fetched.vtcDid, doc.vtcDid);
  // The property that actually matters: the doc is resolvable BY ITS OWN vtcVid.
  // This is the lookup `VtcApiModule.verifyVrc` performs on `vrc.issuerVid`.
  assert.ok(
    store.getGovernanceDoc(fetched.vtcVid),
    'a doc must be resolvable by its own vtcVid — verifyVrc depends on it',
  );
});

test('vtcVid is the DID even when the community has local key material', () => {
  const { db, store } = makeStore();
  const vtc = makeVid();
  const doc = makeGovernanceDoc(vtc, [makeVid()], 1);
  store.saveGovernanceDoc(doc);

  // A locally-created VTC DOES have an Ed25519 key (services/vtc.ts stores one) — and
  // vtcVid must still be the DID, because the resolver is DID-keyed.
  const communityUuid = didToUuid(doc.vtcDid);
  seedCommunityKey(db, communityUuid, vtc.publicKey);
  assert.ok(store.getGovernanceDoc(doc.vtcDid)!.vtcVid.startsWith('did:'), 'DID form');

  assert.equal(store.listGovernanceDocs().length, 1, 'the list stays total');
});


// ---------------------------------------------------------------------------
// End-to-end: the REAL repo writers, not hand-written SQL
// ---------------------------------------------------------------------------

/**
 * The tests above seed the tables with SQL. This one closes the gap by writing the
 * community's key through `keysRepo.createWithSecret` — the very call
 * `services/vtc.ts` makes at createVtc — and asserting the store reads back a doc that
 * CESR-encodes. If my query's assumptions (primary document, ed25519, rotation_version)
 * disagreed with what the production writers emit, this is what would catch it.
 */
test('round-trip through the real repo writers: createVtc-shape community key reads back encodable', async () => {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), getMigrationsDir());
  const db = ds.getRawDb();
  const store = new VtcStore(db, new IdentityResolver(db));

  // A community, exactly as services/vtc.ts builds one.
  const vtc = makeVid();
  const doc = makeGovernanceDoc(vtc, [makeVid()], 1);
  store.saveGovernanceDoc(doc);

  const communityUuid = didToUuid(doc.vtcDid);
  const docRow = db.prepare(
    'SELECT uuid FROM did_documents WHERE identity_uuid = ? AND is_primary = 1',
  ).get(communityUuid) as { uuid: string };

  // The real writer — same call, same arguments as services/vtc.ts:439.
  const enc = await encryptSecretKey(vtc.secretKey, COMMUNITY_KEY_PASSPHRASE);
  await keysRepo.createWithSecret(ds, {
    identityUuid: communityUuid,
    didDocumentUuid: docRow.uuid,
    keyType: 'ed25519',
    publicKey: vtc.publicKey,
    encryptedSecretKey: enc.ciphertext,
    salt: enc.salt,
    nonce: enc.nonce,
    authTag: enc.authTag,
  });

  // An admin, seeded the same way as the tests above (seedAdmin already creates its
  // primary did_document, so no second document is inserted).
  const admin = makeVid();
  seedAdmin(db, {
    communityUuid, name: 'Repo Admin', primaryKeys: [{ publicKey: admin.publicKey, rotationVersion: 0 }],
  });

  const fetched = store.getGovernanceDoc(doc.vtcDid)!;

  assert.equal(fetched.vtcVid, fetched.vtcDid, 'vtcVid stays the DID even with a real community key');
  assert.deepEqual(fetched.adminVids, [admin.vid]);
  for (const [i, vid] of fetched.adminVids.entries()) {
    assert.doesNotThrow(() => asCesrVid(vid, `adminVids[${i}]`, 'test'));
  }
});


// ---------------------------------------------------------------------------
// The round trip the two encodings have to satisfy — issue THEN verify
// ---------------------------------------------------------------------------

/**
 * `adminVids` and `vtcVid` have DIFFERENT jobs and therefore different encodings, and
 * this test is what pins the difference:
 *
 *   - `adminVids` is a **signature-verification list**: `countValidAdminSignatures` does
 *     `adminVids.includes(sig.signerVid)` and `decodeVidToPublicKey(sig.signerVid)`, so it
 *     must hold **CESR keys**.
 *   - `vtcVid` is an **identity reference**: `VtcApiModule.verifyVrc` does
 *     `getGovernanceDoc(vrc.issuerVid)`, which resolves through `IdentityResolver.lookupByDid`,
 *     so it must hold a **DID**.
 *
 * The pre-refactor code documented this split explicitly (see the `⚠️ Boundary note` on
 * `VtcApiModule.issueVrc` at 6af60f1): a store-loaded doc's `vtcVid` is the VTC's DID, the
 * resulting VRC's `issuerVid` is therefore DID-form, and that is "fine for storage/verification
 * (both are DID/DID-keyed)" — it only must not be fed to the binary codec.
 *
 * Issue alone passes with either encoding. Only this round trip catches a wrong one.
 */
test('round trip: a VRC issued from a store-loaded doc verifies against it', () => {
  const { db, store } = makeStore();
  const vtc = makeVid();
  const admin = makeVid();
  const doc = makeGovernanceDoc(vtc, [admin], 1);
  store.saveGovernanceDoc(doc);

  const communityUuid = didToUuid(doc.vtcDid);
  seedAdmin(db, { communityUuid, name: 'Admin', primaryKeys: [{ publicKey: admin.publicKey, rotationVersion: 0 }] });
  seedClaimTypeAllow(db, communityUuid);
  seedCommunityKey(db, communityUuid, vtc.publicKey);

  const fetched = store.getGovernanceDoc(doc.vtcDid)!;
  const subject = makeVid();

  const vrc = issueVrc({
    governanceDoc: fetched,
    subjectVid: subject.vid,
    claim: { type: CLAIM },
    signers: [{ vid: admin.vid, signingKeyPair: admin }],
  });

  // What VtcApiModule.verifyVrc does: resolve the issuer's governance doc from issuerVid.
  const issuerDoc = store.getGovernanceDoc(vrc.issuerVid);
  assert.ok(
    issuerDoc,
    `verifyVrc resolves the doc via getGovernanceDoc(vrc.issuerVid) → lookupByDid, so ` +
    `issuerVid must be the VTC's DID; got ${vrc.issuerVid.slice(0, 20)}...`,
  );

  // And the admin signature must validate against adminVids.
  const result = verifyVrc(vrc, issuerDoc!);
  assert.equal(result.valid, true, `expected a valid VRC, got: ${result.reason}`);
  assert.equal(result.validSignatureCount, 1);
});

