/**
 * Tests for VtcStore — Step 10, Task 10.7.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/vtc/store.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

import { runMigrations } from '../../src/db/migrate.js';
import { IdentityResolver } from '../../src/services/identity-resolver.js';
import { generateEd25519KeyPair, signEd25519 } from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { VtcStore } from '../../src/vtc/store.js';
import { didToUuid } from '../../src/db/uuid-helpers.js';
import { computeGovernanceDocDigest, computeVrcDigest } from '../../src/vtc/codec.js';
import type { Vrc, VrcSignature, VtcGovernanceDoc } from '../../src/vtc/types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeVid(): { vid: string; secretKey: Uint8Array; publicKey: Uint8Array } {
  const kp = generateEd25519KeyPair();
  return { vid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, kp.publicKey), ...kp };
}

function makeStore(): { db: DatabaseSync; resolver: IdentityResolver; store: VtcStore } {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  const resolver = new IdentityResolver(db);
  const store = new VtcStore(db, resolver);
  return { db, resolver, store };
}

function makeGovernanceDoc(
  vtc: { vid: string },
  admins: Array<{ vid: string; secretKey: Uint8Array }>,
  threshold: number,
  name = 'Test VTC',
): VtcGovernanceDoc {
  const unsigned = {
    vtcVid: vtc.vid,
    vtcDid: `did:peer:4:z${vtc.vid.slice(1, 12)}`,
    name,
    adminVids: admins.map(a => a.vid),
    threshold,
    allowedClaimTypes: ['witness-member'],
    createdAt: 1700000000,
  };
  const digest = computeGovernanceDocDigest(unsigned);
  const signatures: VrcSignature[] = admins.map(a => ({
    signerVid: a.vid,
    signature: signEd25519(digest, a.secretKey),
  }));
  return { ...unsigned, digest, signatures };
}

function makeVrc(
  subjectVid: string,
  issuerVid: string,
  admin: { vid: string; secretKey: Uint8Array },
  claimType = 'witness-member',
): Vrc {
  const unsigned = {
    subjectVid,
    issuerVid,
    claim: { type: claimType },
    issuedAt: 1700000001,
    expiresAt: undefined,
  };
  const digest = computeVrcDigest(unsigned);
  return {
    ...unsigned,
    digest,
    signatures: [{ signerVid: admin.vid, signature: signEd25519(digest, admin.secretKey) }],
  };
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

test('VtcStore: constructor initialises without error', () => {
  const { store } = makeStore();
  assert.ok(store, 'store must be created');
});

test('VtcStore: schema migrations applied and tables exist', () => {
  const { db } = makeStore();
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all() as { name: string }[];
  const names = tables.map(t => t.name);
  assert.ok(names.includes('governance'), 'governance table must exist');
  assert.ok(names.includes('credentials'), 'credentials table must exist');
  assert.ok(names.includes('credential_signatures'), 'credential_signatures table must exist');
});

// ---------------------------------------------------------------------------
// Governance docs
// ---------------------------------------------------------------------------

test('VtcStore.saveGovernanceDoc / getGovernanceDoc: round-trips', () => {
  const { store, db } = makeStore();
  const vtc = makeVid();
  const admin1 = makeVid();
  const admin2 = makeVid();
  const doc = makeGovernanceDoc(vtc, [admin1, admin2], 2, 'Witness VTC');

  store.saveGovernanceDoc(doc);
  const fetched = store.getGovernanceDoc(doc.vtcDid);

  assert.ok(fetched, 'governance doc must be fetched');
  // name/threshold are DERIVED from the tables...
  assert.equal(fetched!.name, doc.name);
  assert.equal(fetched!.threshold, doc.threshold);
  // ...the digest is the STORED commitment and round-trips verbatim...
  assert.deepEqual(Array.from(fetched!.digest), Array.from(doc.digest));
  // ...and adminVids / claim types are derived (nothing seeded → empty).
  assert.deepEqual(fetched!.adminVids, []);
  assert.deepEqual(fetched!.allowedClaimTypes, []);

  // Governance must reflect BOTH founding admins: admin_threshold_m must be the
  // doc.threshold (2), not a hardcoded 1 (which would restrict governance to a
  // single required founder). community_identity_uuid is the deterministic
  // UUIDv5 of the VTC DID.
  const govRow = db.prepare(
    'SELECT admin_threshold_m, admin_threshold_n FROM governance WHERE community_identity_uuid = ?',
  ).get(didToUuid(doc.vtcDid)) as { admin_threshold_m: number; admin_threshold_n: number } | undefined;
  assert.ok(govRow, 'governance row must exist');
  assert.equal(govRow.admin_threshold_m, doc.threshold);
  assert.equal(govRow.admin_threshold_n, doc.adminVids.length);
});

test('VtcStore.getGovernanceDoc: returns undefined for unknown vtcDid', () => {
  const { store } = makeStore();
  assert.equal(store.getGovernanceDoc('did:peer:4:znonexistent'), undefined);
});

test('VtcStore.saveGovernanceDoc: upsert — same vtcDid updates row', () => {
  const { store } = makeStore();
  const vtc = makeVid();
  const admin1 = makeVid();
  const doc1 = makeGovernanceDoc(vtc, [admin1], 1, 'Original Name');

  store.saveGovernanceDoc(doc1);

  const admin2 = makeVid();
  const doc2 = makeGovernanceDoc(vtc, [admin1, admin2], 2, 'Renamed VTC');
  store.saveGovernanceDoc(doc2);

  const fetched = store.getGovernanceDoc(doc1.vtcDid);
  assert.ok(fetched);
  assert.equal(fetched!.name, 'Renamed VTC');
  assert.equal(fetched!.threshold, 2);
  assert.equal(store.listGovernanceDocs().length, 1);
});

// ---------------------------------------------------------------------------
// VRCs
// ---------------------------------------------------------------------------

test('VtcStore.saveVrc / getVrc: round-trips', () => {
  const { store } = makeStore();
  const vtc = makeVid();
  const admin = makeVid();
  const subject = makeVid();

  const vrc = makeVrc(subject.vid, vtc.vid, admin);
  store.saveVrc(vrc);

  const fetched = store.getVrc(subject.vid, vtc.vid, 'witness-member');
  assert.ok(fetched, 'VRC must be fetched');
  assert.deepEqual(fetched!.claim, vrc.claim);
  assert.equal(fetched!.issuedAt, vrc.issuedAt);
  assert.equal(fetched!.signatures.length, 1);
});

test('VtcStore.getVrc: returns undefined for unknown VRC', () => {
  const { store } = makeStore();
  assert.equal(store.getVrc(makeVid().vid, makeVid().vid, 'witness-member'), undefined);
});

test('VtcStore.saveVrc: stores a retrievable VRC', () => {
  const { store } = makeStore();
  const vtc = makeVid();
  const admin = makeVid();
  const subject = makeVid();

  store.saveVrc(makeVrc(subject.vid, vtc.vid, admin));
  const vrc = store.getVrc(subject.vid, vtc.vid, 'witness-member');
  assert.ok(vrc, 'VRC must be retrievable after saveVrc');
});

test('VtcStore.listVrcsForSubject: returns VRCs for subject', () => {
  const { store } = makeStore();
  const vtc1 = makeVid();
  const vtc2 = makeVid();
  const admin = makeVid();
  const subject = makeVid();

  store.saveVrc(makeVrc(subject.vid, vtc1.vid, admin));
  store.saveVrc(makeVrc(subject.vid, vtc2.vid, admin));

  const vrcs = store.listVrcsForSubject(subject.vid);
  assert.equal(vrcs.length, 2);
});

test('VtcStore.listVrcsForIssuer: returns VRCs for issuer', () => {
  const { store } = makeStore();
  const vtc = makeVid();
  const admin = makeVid();
  const subject1 = makeVid();
  const subject2 = makeVid();

  store.saveVrc(makeVrc(subject1.vid, vtc.vid, admin));
  store.saveVrc(makeVrc(subject2.vid, vtc.vid, admin));

  const vrcs = store.listVrcsForIssuer(vtc.vid);
  assert.equal(vrcs.length, 2);
});

test('VtcStore.listVrcsForSubject: returns empty array for no VRCs', () => {
  const { store } = makeStore();
  assert.deepEqual(store.listVrcsForSubject(makeVid().vid), []);
});
// ---------------------------------------------------------------------------
// Received VRCs — identity record + custody
// ---------------------------------------------------------------------------

test('VtcStore.storeReceivedDtgVrc: persists issuer identity record with custody=remote and stable UUID', () => {
  const { db, store } = makeStore();
  const issuerDid = 'did:peer:4:zissuerremote1';
  const subjectDid = 'did:peer:4:zsubjectlocal1';

  store.storeReceivedDtgVrc(
    JSON.stringify({ id: 'vrc-identity-1', type: 'RelationshipCredential' }),
    issuerDid,
    subjectDid,
    {
      uuid: didToUuid(issuerDid),
      realDid: issuerDid,
      did: issuerDid,
      method: 'peer4',
      name: 'alice_login',
      role: 'vta',
      subjectKind: 'human',
      custody: 'local', // informational — receiver must override
      peerId: '12D3KooWpeerid',
      didDocument: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: issuerDid,
        verificationMethod: [],
      },
    },
  );

  // The issuer row exists, keyed by the deterministic UUIDv5 of the real DID
  // (unchanged — other code selects on this key), with login name populated
  // and custody forced to 'remote' because this node is not the creator.
  const expectedUuid = didToUuid(issuerDid);
  const issuerRow = db.prepare(
    'SELECT uuid, name, role, subject_kind, custody FROM identities WHERE uuid = ?',
  ).get(expectedUuid) as {
    uuid: string; name: string | null; role: string;
    subject_kind: string; custody: string;
  };
  assert.ok(issuerRow, 'issuer identity row must exist');
  assert.equal(issuerRow.uuid, expectedUuid, 'UUID must be the deterministic key, unchanged');
  assert.equal(issuerRow.name, 'alice_login');
  assert.equal(issuerRow.role, 'vta');
  assert.equal(issuerRow.subject_kind, 'human');
  assert.equal(issuerRow.custody, 'remote', 'receiver is not the creator → custody=remote');
  // The peer binding lives in peer_endpoints now (identities.peer_id does not
  // exist in the base schema).
  const endpointRow = db.prepare(
    'SELECT peer_id FROM peer_endpoints WHERE identity_uuid = ? AND is_active = 1',
  ).get(expectedUuid) as { peer_id: string } | undefined;
  assert.ok(endpointRow, 'issuer must have an active peer_endpoint');
  assert.equal(endpointRow.peer_id, '12D3KooWpeerid');

  // The subject (local agent) is resolved as its own row.
  const subjectRow = db.prepare(
    'SELECT uuid FROM identities WHERE uuid = ?',
  ).get(didToUuid(subjectDid));
  assert.ok(subjectRow, 'subject identity row must exist');

  // The VRC itself landed in the credentials table.
  const cred = db.prepare(
    "SELECT vc_type, status FROM credentials WHERE vc_type = 'vrc'",
  ).get() as { vc_type: string; status: string };
  assert.ok(cred, 'received VRC must be stored');
  assert.equal(cred.status, 'issued');
});

test('VtcStore.storeReceivedDtgVrc: corrects a stale local custody to remote and updates name', () => {
  const { db, resolver, store } = makeStore();
  const issuerDid = 'did:peer:4:zissuer2';
  const subjectDid = 'did:peer:4:zsubject2';

  // Simulate an earlier handshake that left this identity row with local
  // custody and an old name.
  resolver.resolveLocalIdentity({
    did: issuerDid,
    name: 'old_name',
    method: 'peer4',
    peerId: 'peer-local',
  });

  store.storeReceivedDtgVrc(
    JSON.stringify({ id: 'vrc-identity-2' }),
    issuerDid,
    subjectDid,
    { uuid: didToUuid(issuerDid), did: issuerDid, name: 'new_login', role: 'vta', subjectKind: 'human' },
  );

  const row = db.prepare(
    'SELECT name, custody FROM identities WHERE uuid = ?',
  ).get(didToUuid(issuerDid)) as { name: string | null; custody: string };
  assert.ok(row, 'issuer identity row must exist');
  assert.equal(row.custody, 'remote', 'stale local custody must be corrected to remote');
  assert.equal(row.name, 'new_login', 'non-empty sender name must overwrite the stale name');
});
