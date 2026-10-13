/**
 * VRC ceremony saga + DTG mint tests.
 *
 * Verifies:
 *   1. The VrcCeremonyStore drives a ceremony through personhood → mint →
 *      sharing → complete, and marks it failed(step) when a leg exhausts its
 *      retries.
 *   2. mintPeerVrc persists the VRC in the credentials table WITH a DTG
 *      w3c_vc_json (the regression this suite guards against) and is idempotent
 *      on re-mint.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tx/vrc-ceremony.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { TX_SCHEMA_SQL } from '../../src/tx/schema.js';
import { VrcCeremonyStore } from '../../src/tx/vrc-ceremony-store.js';
import { runMigrations } from '../../src/db/migrate.js';
import { didToUuid } from '../../src/db/uuid-helpers.js';
import { IdentityResolver } from '../../src/services/identity-resolver.js';
import { generateEd25519KeyPair } from '../../src/crypto/primitives.js';
import { mintPeerVrc } from '../../src/relationship/vrc-mint.js';
import { VtcStore } from '../../src/vtc/store.js';
import type { LocalIdentity } from '../../src/relationship/types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = getMigrationsDir();

// ---------------------------------------------------------------------------
// 1. VrcCeremonyStore saga transitions
// ---------------------------------------------------------------------------

test('VrcCeremonyStore drives a ceremony through its phases and marks failed(step)', async () => {
  const ds = new SqliteDataSource(':memory:');
  await ds.exec(TX_SCHEMA_SQL);
  const store = new VrcCeremonyStore(ds);

  const localDid = 'did:peer:4:zAlice';
  const remoteDid = 'did:peer:4:zBob';

  const session = await store.ensureSession(localDid, remoteDid);
  assert.equal(session.phase, 'personhood');
  assert.equal(session.localMinted, false);

  // Same pair → same session (idempotent).
  const again = await store.ensureSession(localDid, remoteDid);
  assert.equal(again.sessionId, session.sessionId);

  // Local + remote ack.
  await store.setLocalAcked(session.sessionId);
  await store.setRemoteAcked(session.sessionId);

  // Ack delivery leg: my ack reached the peer's coordinator. Completion now
  // requires this — the ack is a real coordinator leg, not a hopeful send.
  const delivered = await store.setLeg(session.sessionId, { ackSentToPeer: true });
  assert.equal(delivered.ackSentToPeer, true);

  // Mint leg.
  let s = await store.setLeg(session.sessionId, { localMinted: true });
  assert.equal(s.localMinted, true);
  assert.equal(s.phase, 'sharing'); // mint done, peer/server still pending

  // Peer + server legs done; but peer_vrc not yet received → still sharing.
  s = await store.setLeg(session.sessionId, { sentToPeer: true, sentToServer: true });
  assert.equal(s.phase, 'sharing');

  // Peer VRC arrives → complete.
  s = await store.setLeg(session.sessionId, { peerVrcReceived: true });
  assert.equal(s.phase, 'complete');

  // A separate session that exhausts its retries → failed with the step.
  const fail = await store.ensureSession(localDid, 'did:peer:4:zCarol');
  let f = fail;
  for (let i = 0; i < 6; i++) {
    f = await store.recordFailure(f.sessionId, 'peer_delivery', 'peer unreachable', 2_000, 6);
  }
  assert.equal(f.phase, 'failed');
  assert.equal(f.failedStep, 'peer_delivery');
  assert.equal(f.lastError, 'peer unreachable');

  await ds.close();
});

// ---------------------------------------------------------------------------
// 1b. Completion is PEER-TO-PEER only; the utility archive is deferred
// ---------------------------------------------------------------------------

test('VrcCeremonyStore: the ack-delivery leg never advances the phase past personhood', async () => {
  const ds = new SqliteDataSource(':memory:');
  await ds.exec(TX_SCHEMA_SQL);
  const store = new VrcCeremonyStore(ds);
  const s = await store.ensureSession('did:peer:4:zAlice', 'did:peer:4:zBob');

  // Only the LOCAL side has pressed. Delivering that ack must NOT make the saga
  // look like it left the button gate: the stale-sweep and the UI countdown both
  // read `phase`, and the peer still has to press.
  await store.setLocalAcked(s.sessionId);
  const delivered = await store.setLeg(s.sessionId, { ackSentToPeer: true });
  assert.equal(delivered.ackSentToPeer, true);
  assert.equal(delivered.phase, 'personhood', 'a one-sided press stays at the gate');

  // The peer presses: the gate is cleared and minting may begin.
  await store.setRemoteAcked(s.sessionId);
  const mutual = await store.setLeg(s.sessionId, {});
  assert.equal(mutual.phase, 'minting', 'mutual ack leaves the gate');

  await ds.close();
});

test('VrcCeremonyStore: a ceremony completes with the two agents alone (no utility archive)', async () => {
  const ds = new SqliteDataSource(':memory:');
  await ds.exec(TX_SCHEMA_SQL);
  const store = new VrcCeremonyStore(ds);
  const s = await store.ensureSession('did:peer:4:zAlice', 'did:peer:4:zBob');

  await store.setLocalAcked(s.sessionId);
  await store.setRemoteAcked(s.sessionId);
  await store.setLeg(s.sessionId, { ackSentToPeer: true });
  await store.setLeg(s.sessionId, { localMinted: true });
  await store.setLeg(s.sessionId, { sentToPeer: true });

  // Every PEER-TO-PEER leg is done and the archive never ran. Requiring
  // `sent_to_server` here is what used to fail an otherwise-successful ceremony
  // (after VRC_CEREMONY_MAX_ATTEMPTS) whenever the utility server was
  // unreachable — this is the pure peer-to-peer guarantee.
  const done = await store.setLeg(s.sessionId, { peerVrcReceived: true });
  assert.equal(done.sentToServer, false, 'the archive genuinely did not happen');
  assert.equal(done.phase, 'complete', 'two agents alone must be able to complete');

  await ds.close();
});

test('VrcCeremonyStore: deferring the utility archive is recorded, non-fatal and never a false success', async () => {
  const ds = new SqliteDataSource(':memory:');
  await ds.exec(TX_SCHEMA_SQL);
  const store = new VrcCeremonyStore(ds);
  const s = await store.ensureSession('did:peer:4:zAlice', 'did:peer:4:zBob');

  await store.markArchiveDeferred(s.sessionId, 'no utility server configured');
  const after = await store.getById(s.sessionId);

  assert.equal(after.archiveDeferred, true, 'the deferral is durable');
  // `sent_to_server` means "actually archived". It must never be set without a
  // durable ack, otherwise the deferred push pipeline thinks the work is done.
  assert.equal(after.sentToServer, false);
  // And a missing utility server must not fail, advance or starve the ceremony.
  assert.equal(after.phase, 'personhood');
  assert.equal(after.attempt, 0, 'the archive must not consume the failure budget');

  await ds.close();
});

// ---------------------------------------------------------------------------
// 2. mintPeerVrc persists a DTG VRC and is idempotent
// ---------------------------------------------------------------------------

function makeIdentityDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  ds.getRawDb().exec('PRAGMA foreign_keys = OFF');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

async function makeResolvableIdentity(
  db: DatabaseSync,
  realDid: string,
  role: 'vta',
  custody: 'local' | 'remote',
): Promise<void> {
  const keyDid = didToUuid(realDid);
  const now = Math.floor(Date.now() / 1000);
  // Deterministic per-identity (not per-custody) so two local agents on one
  // table don't collide on did_documents.uuid.
  const docUuid = 'aaaaaaaa-bbbb-cccc-dddd-' + keyDid.slice(0, 12);
  // identities/did_documents are uuid-first (migration 0019): `uuid` is the
  // row key and there is no integer `id` / `identity_id` column anymore.
  db.prepare(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES (?, ?, 'human', ?, ?, ?, ?)`,
  ).run(keyDid, role, custody, custody === 'local' ? 'Alice' : 'Bob', now, now);
  db.prepare(
    `INSERT INTO did_documents (uuid, identity_uuid, did, method, document_json, is_primary, status, created_at)
     VALUES (?, ?, ?, 'peer4', ?, 1, 'active', ?)`,
  ).run(docUuid, keyDid, realDid, JSON.stringify({ id: realDid }), now);
}

test('mintPeerVrc stores VRC with DTG w3c_vc_json and is idempotent', async () => {
  const ds = makeIdentityDb();
  const db = ds.getRawDb();
  const localDid = 'did:peer:4:zAlice';
  const remoteDid = 'did:peer:4:zBob';
  await makeResolvableIdentity(db, localDid, 'vta', 'local');
  await makeResolvableIdentity(db, remoteDid, 'vta', 'remote');

  const resolver = new IdentityResolver(db);
  const keys = generateEd25519KeyPair();
  const identity: LocalIdentity = {
    vid: 'zFakeVid',
    did: localDid,
    didDocument: {
      id: localDid,
      verificationMethod: [{ id: `${localDid}#key-1` }],
    } as any,
    signingKeyPair: keys,
    agreementKeyPair: generateEd25519KeyPair(),
  };

  const record = {
    localDid: localDid,
    remoteDid: remoteDid,
    direction: 'bidirectional',
    status: 'established',
    rfiDigest: new Uint8Array([1, 2, 3]),
    rfaReplyDigest: new Uint8Array([4, 5, 6]),
    createdAt: Date.now() / 1000,
    updatedAt: Date.now() / 1000,
  } as any;

  const first = await mintPeerVrc({ dataSource: ds, resolver, identity, record });
  assert.equal(first.success, true, 'first mint should succeed');
  assert.ok(first.w3cVcJson, 'mint should produce a DTG w3c_vc_json');
  assert.ok(first.w3cVcJson!.includes('RelationshipCredential'), 'DTG should be a RelationshipCredential');

  const row = db.prepare(
    "SELECT credential_digest FROM credentials WHERE vc_type = 'vrc' AND w3c_vc_json IS NOT NULL",
  ).get() as { credential_digest: string } | undefined;
  assert.ok(row, 'VRC must be persisted in the credentials table with DTG JSON');

  // Idempotent re-mint (same digest → hit the early-return path): the
  // function's idempotent branch returns { success: true } WITHOUT a fresh
  // w3cVcJson — it does not re-mint. The contract we assert is idempotency:
  // success + the persisted row count stays 1 (no duplicate credential row).
  // This is the DTG-output-preservation guarantee: the first mint's JSON
  // remains on the single persisted row, matched by `SELECT ... LIMIT 1`
  // inside mintPeerVrc.
  const second = await mintPeerVrc({ dataSource: ds, resolver, identity, record });
  assert.equal(second.success, true, 're-mint should be an idempotent success');

  const count = db.prepare("SELECT COUNT(*) AS c FROM credentials WHERE vc_type = 'vrc'")
    .get() as { c: number };
  assert.equal(count.c, 1, 're-mint must not duplicate the credential row');

  ds.close(); // closes the underlying DatabaseSync (raw `db` handle shares it)
});

// ---------------------------------------------------------------------------
// 3. Shared-credentials-table dedup — two agents, one device
// ---------------------------------------------------------------------------
// Regression: when BOTH agents of a VRC ceremony write to the SAME
// credentials table (one device / P2PTS_HOME, or the utility-server aggregate),
// each logical VRC was previously inserted TWICE — once by mintPeerVrc (digest
// = claim digest) and once by storeReceivedDtgVrc (digest = VC digest). The two
// digests never collided, so both rows survived their respective dedup checks
// and the table ended up with 4 VRC rows instead of 2.

test('shared credentials table keeps exactly 2 VRC rows after both agents mint AND receive', async () => {
  const ds = makeIdentityDb();
  const db = ds.getRawDb();
  const aliceDid = 'did:peer:4:zAliceShared';
  const bobDid = 'did:peer:4:zBobShared';
  await makeResolvableIdentity(db, aliceDid, 'vta', 'local');
  await makeResolvableIdentity(db, bobDid, 'vta', 'local');
  const resolver = new IdentityResolver(db);
  const vtcStore = new VtcStore(db, resolver);
  const keys = generateEd25519KeyPair();

  const identityFor = (did: string): LocalIdentity => ({
    vid: 'zFakeVid',
    did,
    didDocument: { id: did, verificationMethod: [{ id: `${did}#key-1` }] } as any,
    signingKeyPair: keys,
    agreementKeyPair: generateEd25519KeyPair(),
  });

  const recordFor = (local: string, remote: string) => ({
    localDid: local,
    remoteDid: remote,
    direction: 'bidirectional',
    status: 'established',
    rfiDigest: new Uint8Array([1, 2, 3]),
    rfaReplyDigest: new Uint8Array([4, 5, 6]),
    createdAt: Date.now() / 1000,
    updatedAt: Date.now() / 1000,
  } as any);

  // Agent A: mints A→B; Agent B's mirror of the SAME pair is stored via the
  // receive path on the same table. First-wins dedup must keep only one row.
  const mintAB = await mintPeerVrc({ dataSource: ds, resolver, identity: identityFor(aliceDid), record: recordFor(aliceDid, bobDid) });
  assert.equal(mintAB.success, true, 'first mint A→B should succeed');
  assert.ok(mintAB.w3cVcJson, 'first mint A→B must produce a DTG envelope');
  vtcStore.storeReceivedDtgVrc(mintAB.w3cVcJson!, aliceDid, bobDid);

  // Agent B: mints B→A; Agent A's mirror of the SAME pair is then stored.
  const mintBA = await mintPeerVrc({ dataSource: ds, resolver, identity: identityFor(bobDid), record: recordFor(bobDid, aliceDid) });
  assert.equal(mintBA.success, true, 'mint B→A should succeed');
  assert.ok(mintBA.w3cVcJson, 'mint B→A must produce a DTG envelope');
  vtcStore.storeReceivedDtgVrc(mintBA.w3cVcJson!, bobDid, aliceDid);

  const rows = db.prepare(
    `SELECT c.uuid, c.credential_digest, i.did AS issuer, s.did AS subject
     FROM credentials c
     LEFT JOIN did_documents i ON i.identity_uuid = c.issuer_identity_uuid AND i.is_primary = 1
     LEFT JOIN did_documents s ON s.identity_uuid = c.subject_identity_uuid AND s.is_primary = 1
     WHERE c.vc_type = 'vrc'`,
  ).all() as Array<{ uuid: string; credential_digest: string | null; issuer: string; subject: string }>;

  // Exactly 2 rows — one per direction — and no (issuer, subject) pair twice.
  assert.equal(rows.length, 2, 'shared credentials table must hold exactly 2 VRC rows, got ' + rows.length);
  const pairs = rows.map((r) => `${r.issuer}->${r.subject}`);
  assert.equal(new Set(pairs).size, pairs.length, `no duplicate (issuer, subject) pairs allowed, got ${pairs.join(', ')}`);
  assert.ok(pairs.includes(`${aliceDid}->${bobDid}`), 'expected A→B VRC row');
  assert.ok(pairs.includes(`${bobDid}->${aliceDid}`), 'expected B→A VRC row');

  ds.close();
});
