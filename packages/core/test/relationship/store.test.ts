/**
 * Tests for RelationshipStore — the resolver-based (DID/FK) store API.
 *
 * Covers:
 *   - insertOutbound: creates outbound-pending record
 *   - upsertInbound: creates inbound-pending record (no conflict)
 *   - confirmBidirectional: updates record to bidirectional/established
 *   - get: returns undefined for unknown DID pair
 *   - list: returns all records for a local DID
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/relationship/store.test.ts
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
import type { TransportAddress } from '../../src/transport/types.js';
import type { DidDocument } from '../../src/did/types.js';
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

function newDigest(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

// ---------------------------------------------------------------------------
// insertOutbound
// ---------------------------------------------------------------------------

test('insertOutbound: creates outbound-pending record', () => {
  const { resolver, store } = makeHarness();
  const localDid = makeDid('local');
  const remoteDid = makeDid('remote');
  resolveLocal(resolver, localDid);

  store.insertOutbound({
    localDid, localMethod: 'did:peer:4',
    remoteDid, remoteMethod: 'did:peer:4',
    didDocument: makeDidDocument(),
    rfiDigest: newDigest(0x01),
    remoteTransport: makeTransport(),
  });

  const record = store.get(localDid, remoteDid);
  assert.ok(record, 'record must exist after insertOutbound');
  assert.equal(record!.direction, 'outbound', 'direction must be outbound');
  assert.equal(record!.status, 'pending', 'status must be pending');
  assert.deepEqual(record!.rfiDigest, newDigest(0x01), 'rfiDigest must match');
});

test('insertOutbound: throws on duplicate relationship', () => {
  const { resolver, store } = makeHarness();
  const localDid = makeDid('local');
  const remoteDid = makeDid('remote');
  resolveLocal(resolver, localDid);

  const params = {
    localDid, localMethod: 'did:peer:4',
    remoteDid, remoteMethod: 'did:peer:4',
    didDocument: makeDidDocument(),
    remoteTransport: makeTransport(),
  };
  store.insertOutbound(params);
  assert.throws(() => store.insertOutbound(params), /already exists/);
});

// ---------------------------------------------------------------------------
// upsertInbound
// ---------------------------------------------------------------------------

test('upsertInbound: creates inbound-pending record (no conflict)', () => {
  const { resolver, store } = makeHarness();
  const localDid = makeDid('local');
  const remoteDid = makeDid('remote');
  resolveLocal(resolver, localDid);

  const result = store.upsertInbound({
    localDid, localMethod: 'did:peer:4',
    remoteDid, remoteMethod: 'did:peer:4',
    didDocument: makeDidDocument(),
    remoteTransport: makeTransport(),
    rfiDigest: newDigest(0x02),
  });

  assert.equal(result, 'accepted', 'upsertInbound must accept when no conflict');
  const record = store.get(localDid, remoteDid);
  assert.ok(record);
  assert.equal(record!.direction, 'inbound', 'direction must be inbound');
  assert.equal(record!.status, 'pending', 'status must be pending');
});

// ---------------------------------------------------------------------------
// confirmBidirectional
// ---------------------------------------------------------------------------

test('confirmBidirectional: updates record to bidirectional/established', () => {
  const { resolver, store } = makeHarness();
  const localDid = makeDid('local');
  const remoteDid = makeDid('remote');
  resolveLocal(resolver, localDid);

  store.insertOutbound({
    localDid, localMethod: 'did:peer:4',
    remoteDid, remoteMethod: 'did:peer:4',
    didDocument: makeDidDocument(),
    rfiDigest: newDigest(0x03),
    remoteTransport: makeTransport(),
  });

  const rfaReplyDigest = newDigest(0x04);
  store.confirmBidirectional({ localDid, remoteDid, remoteTransport: makeTransport(), rfaReplyDigest });

  const record = store.get(localDid, remoteDid);
  assert.ok(record);
  assert.equal(record!.direction, 'bidirectional', 'direction must be bidirectional');
  assert.equal(record!.status, 'established', 'status must be established');
  assert.deepEqual(record!.rfaReplyDigest, rfaReplyDigest, 'rfaReplyDigest must match');
});

test('confirmBidirectional: throws if no record exists', () => {
  const { resolver, store } = makeHarness();
  const localDid = makeDid('local');
  const remoteDid = makeDid('remote');
  resolveLocal(resolver, localDid);

  assert.throws(
    () => store.confirmBidirectional({ localDid, remoteDid, remoteTransport: makeTransport() }),
    /no record found|identity not resolved/,
    'confirmBidirectional must throw if no record exists',
  );
});

// ---------------------------------------------------------------------------
// get / list
// ---------------------------------------------------------------------------

test('get: returns undefined for unknown DID pair', () => {
  const { resolver, store } = makeHarness();
  resolveLocal(resolver, makeDid('local'));
  assert.equal(store.get(makeDid('x'), makeDid('y')), undefined, 'get must return undefined for unknown pair');
});

test('list: returns all records for a local DID', () => {
  const { resolver, store } = makeHarness();
  const localDid = makeDid('local');
  const remoteDid1 = makeDid('remote1');
  const remoteDid2 = makeDid('remote2');
  resolveLocal(resolver, localDid);

  store.insertOutbound({
    localDid, localMethod: 'did:peer:4',
    remoteDid: remoteDid1, remoteMethod: 'did:peer:4',
    didDocument: makeDidDocument(), rfiDigest: newDigest(0x01), remoteTransport: makeTransport(),
  });
  store.insertOutbound({
    localDid, localMethod: 'did:peer:4',
    remoteDid: remoteDid2, remoteMethod: 'did:peer:4',
    didDocument: makeDidDocument(), rfiDigest: newDigest(0x02), remoteTransport: makeTransport(),
  });

  const records = store.list(localDid);
  assert.equal(records.length, 2, 'list must return 2 records');
});

test('list: returns empty array when no records exist', () => {
  const { resolver, store } = makeHarness();
  resolveLocal(resolver, makeDid('local'));
  assert.deepEqual(store.list(makeDid('other')), [], 'list must return empty array');
});
