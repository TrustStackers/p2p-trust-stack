/**
 * Regression — a DOCUMENT-LESS `identities` row must not break the OOBI / VRC
 * handshake (the "community fan-out then connect" failure).
 *
 * ## The reported scenario (fewest steps, from manual testing)
 *
 *   1. `erika` accepts a community invitation. The utility server fans the
 *      community package out to the member agents, and the agent-side receiver
 *      (`src/tx/vtc-receive-participant.ts` → `upsertCommunity`) writes ONE
 *      `identities` row per member with
 *          `INSERT OR IGNORE INTO identities (uuid, name, role, custody, …)`
 *      keyed by the member's deterministic uuid (`didToUuid(memberDid)`), and
 *      NO `did_documents` row (the package carries no per-member document).
 *      The credential receiver (`trust-app-api/runtime/tx/credential-receive-participant.ts`)
 *      does the same for a credential's issuer/subject.
 *   2. `G7WIN11` shares an OOBI and `erika` pastes it and connects. That runs
 *      `RelationshipStore.insertOutbound` → `IdentityResolver.resolveRemoteIdentity`.
 *
 * ## Why it failed
 *
 * `resolveRemoteIdentity`'s existence probe JOINs `did_documents`:
 *
 *     SELECT i.uuid FROM identities i
 *       JOIN did_documents d ON d.identity_uuid = i.uuid WHERE d.did = ?
 *
 * A document-less identity row therefore MISSES the probe, `existing` is
 * `undefined`, and the `else` branch INSERTs a NEW row at the SAME deterministic
 * uuid (`didToUuid(did)`) — a PRIMARY KEY collision:
 *
 *     UNIQUE constraint failed: identities.uuid
 *
 * thrown out of `sendRfi`, so the RFI is never sent and the ceremony dies before
 * it starts. The server-side counterpart (`utility-server/src/node/relationship-store-ds.ts`)
 * already guards for exactly this ("The deterministic uuid may already exist
 * WITHOUT a document row … Treat that as existing rather than colliding on the
 * primary key."); the agent-side synchronous resolver did not.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/relationship/identity-resolver-documentless.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

import { runMigrations } from '../../src/db/migrate.js';
import { IdentityResolver } from '../../src/services/identity-resolver.js';
import { RelationshipStore } from '../../src/relationship/store.js';
import { generateEd25519KeyPair, generateX25519KeyPair } from '../../src/crypto/primitives.js';
import { buildDidPeer4Document } from '../../src/did/create.js';
import { didToUuid } from '../../src/db/uuid-helpers.js';
import type { DidDocument } from '../../src/did/types.js';
import type { TransportAddress } from '../../src/transport/types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

let didCounter = 0;
function makeDid(tag: string): string {
  return `did:peer:4:z${tag}${didCounter++}`;
}

function makeDidDocument(): DidDocument {
  const ed = generateEd25519KeyPair();
  const x = generateX25519KeyPair();
  return buildDidPeer4Document(ed.publicKey, x.publicKey);
}

function makeTransport(): TransportAddress {
  return { peerId: '12D3KooWTestPeer', multiaddrs: ['/ip4/127.0.0.1/tcp/4001'] };
}

function makeHarness(): { db: DatabaseSync; resolver: IdentityResolver; store: RelationshipStore } {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  const resolver = new IdentityResolver(db);
  const store = new RelationshipStore(db, resolver);
  return { db, resolver, store };
}

function resolveLocal(resolver: IdentityResolver, did: string): void {
  resolver.resolveLocalIdentity({
    did,
    name: 'local',
    method: 'did:peer:4',
    peerId: '12D3KooWLocalPeer',
    didDocumentJson: JSON.stringify(makeDidDocument()),
  });
}

/**
 * Replay EXACTLY what the community / credential fan-out writes: a document-less
 * identity row keyed by the member's deterministic uuid.
 */
function writeDocumentlessMemberRow(db: DatabaseSync, did: string, name: string): string {
  const uuid = didToUuid(did);
  db.prepare(
    `INSERT OR IGNORE INTO identities (uuid, name, role, custody, created_at)
     VALUES (?, ?, 'vta', 'remote', unixepoch())`,
  ).run(uuid, name);
  return uuid;
}


// ---------------------------------------------------------------------------
// 1. resolveRemoteIdentity must tolerate a document-less identity row
// ---------------------------------------------------------------------------

test('resolveRemoteIdentity: a pre-existing document-less identity row is REUSED, not re-inserted', () => {
  const { db, resolver } = makeHarness();
  const peerDid = makeDid('peer');
  const seededUuid = writeDocumentlessMemberRow(db, peerDid, 'G7WIN11');

  // Must not throw `UNIQUE constraint failed: identities.uuid`.
  const resolved = resolver.resolveRemoteIdentity({ did: peerDid, method: 'did:peer:4' });

  assert.equal(resolved.identityUuid, seededUuid, 'must reuse the fan-out row keyed by didToUuid(did)');
  assert.ok(resolved.didDocumentUuid, 'the DID document must be materialized onto the reused row');

  const identities = db.prepare('SELECT COUNT(*) AS n FROM identities WHERE uuid = ?').get(seededUuid) as { n: number };
  assert.equal(identities.n, 1, 'exactly one identity row for the peer');
  const docs = db.prepare('SELECT COUNT(*) AS n FROM did_documents WHERE identity_uuid = ?').get(seededUuid) as { n: number };
  assert.equal(docs.n, 1, 'exactly one DID document row for the peer');
});

test('resolveRemoteIdentity: name/subjectKind from the handshake heal the document-less row', () => {
  const { db, resolver } = makeHarness();
  const peerDid = makeDid('peer');
  const uuid = writeDocumentlessMemberRow(db, peerDid, null as unknown as string);

  resolver.resolveRemoteIdentity({ did: peerDid, method: 'did:peer:4', name: 'G7WIN11', subjectKind: 'human' });

  const row = db.prepare('SELECT name, subject_kind FROM identities WHERE uuid = ?').get(uuid) as
    { name: string | null; subject_kind: string | null };
  assert.equal(row.name, 'G7WIN11');
  assert.equal(row.subject_kind, 'human');
});

// ---------------------------------------------------------------------------
// 2. The actual failing path — insertOutbound (sendRfi) after the fan-out
// ---------------------------------------------------------------------------

test('insertOutbound: the OOBI/RFI handshake survives a prior community fan-out row', () => {
  const { db, resolver, store } = makeHarness();
  const localDid = makeDid('local');
  const remoteDid = makeDid('remote');
  resolveLocal(resolver, localDid);

  // Step 1 — erika accepted the community invitation: the fan-out wrote a
  // document-less identity row for G7WIN11.
  writeDocumentlessMemberRow(db, remoteDid, 'G7WIN11');

  // Step 2 — erika pastes G7WIN11's OOBI and connects. Must not throw.
  store.insertOutbound({
    localDid,
    localMethod: 'did:peer:4',
    remoteDid,
    remoteMethod: 'did:peer:4',
    didDocument: makeDidDocument(),
    rfiDigest: new Uint8Array(32).fill(0x01),
    remoteTransport: makeTransport(),
  });

  const record = store.get(localDid, remoteDid);
  assert.ok(record, 'the outbound relationship record must exist after insertOutbound');
  assert.equal(record!.direction, 'outbound');
  assert.equal(record!.status, 'pending');

  // The fan-out row was REUSED, not duplicated: one identity row, one document,
  // and the document is bound to the fan-out uuid.
  const fanoutUuid = didToUuid(remoteDid);
  const identityCount = db.prepare('SELECT COUNT(*) AS n FROM identities WHERE uuid = ?').get(fanoutUuid) as { n: number };
  assert.equal(identityCount.n, 1, 'the fan-out identity row must be reused');
  const docs = db.prepare('SELECT identity_uuid FROM did_documents WHERE did = ?').all(remoteDid) as { identity_uuid: string }[];
  assert.equal(docs.length, 1, 'exactly one DID document row for the peer');
  assert.equal(docs[0].identity_uuid, fanoutUuid, 'the document must attach to the fan-out identity row');
});

test('upsertInbound: the responder side survives a prior community fan-out row', () => {
  const { db, resolver, store } = makeHarness();
  const localDid = makeDid('local');
  const remoteDid = makeDid('remote');
  resolveLocal(resolver, localDid);
  writeDocumentlessMemberRow(db, remoteDid, 'erika');

  const result = store.upsertInbound({
    localDid,
    localMethod: 'did:peer:4',
    remoteDid,
    remoteMethod: 'did:peer:4',
    didDocument: makeDidDocument(),
    remoteTransport: makeTransport(),
    rfiDigest: new Uint8Array(32).fill(0x02),
  });

  assert.equal(result, 'accepted');
  assert.ok(store.get(localDid, remoteDid));
});

// ---------------------------------------------------------------------------
// 3. resolveLocalIdentity — same JOIN-only probe, same guard
// ---------------------------------------------------------------------------

test('resolveLocalIdentity: a pre-existing document-less local row is reused', () => {
  const { db, resolver } = makeHarness();
  const did = makeDid('local');
  const uuid = didToUuid(did);
  db.prepare(
    `INSERT OR IGNORE INTO identities (uuid, name, role, custody, created_at)
     VALUES (?, 'recovered', 'vta', 'local', unixepoch())`,
  ).run(uuid);

  const resolved = resolver.resolveLocalIdentity({
    did,
    name: 'local',
    method: 'did:peer:4',
    peerId: '12D3KooWLocalPeer',
    didDocumentJson: JSON.stringify(makeDidDocument()),
  });

  assert.equal(resolved.identityUuid, uuid);
  const n = db.prepare('SELECT COUNT(*) AS n FROM identities WHERE uuid = ?').get(uuid) as { n: number };
  assert.equal(n.n, 1);
});
