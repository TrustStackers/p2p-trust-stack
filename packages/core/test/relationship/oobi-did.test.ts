// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Workstream A regression test — OOBI carries the real DID + VID-tolerant
 * relationship lookup.
 *
 *  1. The OOBI codec round-trips an optional 4th `did` item, and a legacy
 *     3-item OOBI still decodes (did undefined).
 *  2. `IdentityResolver.lookupByVid` resolves a CESR VID onto the stable
 *     identity whose `keys` row matches the current ed25519 public key.
 *  3. `RelationshipStore.get` / `getByVid` resolve a relationship by the
 *     ephemeral VID even when the record is keyed by the real DID (the post-A
 *     shape), so TSP_GEN / personhood / reconnect lookups keep working.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/relationship/oobi-did.test.ts
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
import { encodeOobi, decodeOobi } from '../../src/relationship/oobi.js';
import {
  generateEd25519KeyPair,
  ed25519ToX25519,
} from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { buildDidPeer4Document } from '../../src/did/create.js';
import { didToUuid } from '../../src/db/uuid-helpers.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LOCAL_DID = 'did:scid:vh:1:zMyLocal';
const PEER_DID = 'did:scid:vh:1:zPeerDid99';
const PEER_PEER_ID = '12D3KooWPeer99999999999999999999999999999999';

function makeHarness(): { db: DatabaseSync; resolver: IdentityResolver } {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  const resolver = new IdentityResolver(db);
  return { db, resolver };
}

// ---------------------------------------------------------------------------
// 1. OOBI codec — optional 4th `did` item
// ---------------------------------------------------------------------------

test('encodeOobi/decodeOobi round-trips the strict 4-item frame with did', () => {
  const vid = 'DKbNw717Wt5IlBpNvn7xUqhh80cZ3nkKHhkbEC5Vsbpu'; // 44-char CESR ED25519 vid
  const encoded = encodeOobi({ cesrVid: vid, peerId: '12D3KooWTest', multiaddrs: ['/ip4/1.2.3.4/tcp/4001'], did: PEER_DID });
  const decoded = decodeOobi(encoded);
  assert.equal(decoded.cesrVid, vid);
  assert.equal(decoded.peerId, '12D3KooWTest');
  assert.deepEqual(decoded.multiaddrs, ['/ip4/1.2.3.4/tcp/4001']);
  assert.equal(decoded.did, PEER_DID);
});

// ---------------------------------------------------------------------------
// 2 & 3. identity + relationship resolution by VID
// ---------------------------------------------------------------------------

test('lookupByVid + VID-tolerant get resolve a relationship keyed by real DID', () => {
  const { db, resolver } = makeHarness();

  const localEd = generateEd25519KeyPair();
  const localX = ed25519ToX25519(localEd.secretKey);
  const localDoc = buildDidPeer4Document(localEd.publicKey, localX.publicKey);
  resolver.resolveLocalIdentity({
    did: LOCAL_DID,
    method: 'did:scid:vh',
    name: 'me',
    peerId: '12D3KooWLocal',
    cesrVid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, localEd.publicKey),
    didDocumentJson: JSON.stringify({ ...(localDoc as object), id: LOCAL_DID }),
  });

  const peerEd = generateEd25519KeyPair();
  const peerX = ed25519ToX25519(peerEd.secretKey);
  const peerDoc = buildDidPeer4Document(peerEd.publicKey, peerX.publicKey);
  const peerVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, peerEd.publicKey);
  resolver.storeRemoteIdentityCopy({
    uuid: didToUuid(PEER_DID),
    realDid: PEER_DID,
    did: PEER_DID,
    method: 'did:scid:vh',
    name: 'agent99',
    role: 'vta',
    subjectKind: 'human',
    custody: 'local',
    peerId: PEER_PEER_ID,
    vid: peerVid,
    didDocument: { ...(peerDoc as object), id: PEER_DID } as any,
    publicKeys: {
      ed25519: Buffer.from(peerEd.publicKey).toString('base64'),
      x25519: Buffer.from(peerX.publicKey).toString('base64'),
    },
  });

  const store = new RelationshipStore(db, resolver);
  store.insertOutbound({
    localDid: LOCAL_DID,
    localMethod: 'did:scid:vh',
    remoteDid: PEER_DID,
    remoteMethod: 'did:scid:vh',
    remoteTransport: { peerId: PEER_PEER_ID, multiaddrs: ['/ip4/9.9.9.9/tcp/4001'] },
    subjectKind: 'human',
  });

  const byVid = resolver.lookupByVid(peerVid);
  assert.ok(byVid, 'lookupByVid should resolve the peer identity');
  assert.equal(byVid!.identityUuid, didToUuid(PEER_DID));

  const viaGet = store.get(LOCAL_DID, peerVid);
  assert.ok(viaGet, 'get(localDid, remoteDid) should resolve a record keyed by real DID');
  assert.equal(viaGet!.remoteDid, PEER_DID);

  const viaGetByVid = store.getByVid(LOCAL_DID, peerVid);
  assert.ok(viaGetByVid, 'getByVid should resolve the record');
  assert.equal(viaGetByVid!.remoteDid, PEER_DID);
  assert.equal(viaGetByVid!.direction, 'outbound');
});

test('storeRemoteDidDocument (RFA path) does not UNIQUE-fail after a DID-keyed stub', () => {
  const { db, resolver } = makeHarness();

  // Local identity (required by insertOutbound/storeRemoteDidDocument).
  const localEd = generateEd25519KeyPair();
  const localX = ed25519ToX25519(localEd.secretKey);
  const localDoc = buildDidPeer4Document(localEd.publicKey, localX.publicKey);
  resolver.resolveLocalIdentity({
    did: LOCAL_DID,
    method: 'did:scid:vh',
    name: 'me',
    peerId: '12D3KooWLocal',
    cesrVid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, localEd.publicKey),
    didDocumentJson: JSON.stringify({ ...(localDoc as object), id: LOCAL_DID }),
  });

  // sendRfi shape: stub identity keyed by the server's REAL DID with method
  // 'did:scid:vh' (creates one did_documents(identity_id, did) row).
  const serverEd = generateEd25519KeyPair();
  const serverX = ed25519ToX25519(serverEd.secretKey);
  const store = new RelationshipStore(db, resolver);
  store.insertOutbound({
    localDid: LOCAL_DID,
    localMethod: 'did:scid:vh',
    remoteDid: PEER_DID,
    remoteMethod: 'did:scid:vh',
    remoteTransport: { peerId: PEER_PEER_ID, multiaddrs: ['/ip4/5.6.7.8/tcp/4001'] },
    subjectKind: 'organization',
  });

  // RFA arrives carrying the server's real did:scid:vh document. This used to
  // hit UNIQUE constraint failed: did_documents.identity_id, did_documents.did
  // because upsertDidDocument looked up by method ('did:peer:4' hardcoded) and
  // then INSERTed the same did.
  const serverDoc = buildDidPeer4Document(serverEd.publicKey, serverX.publicKey);
  assert.doesNotThrow(() => {
    store.storeRemoteDidDocument(LOCAL_DID, PEER_DID, { ...(serverDoc as object), id: PEER_DID } as any);
  });

  // The same did_documents row should now carry the real method.
  // (uuid-first schema: the column is identity_uuid, not the pre-refactor identity_id.)
  const row = db.prepare(
    'SELECT method FROM did_documents WHERE identity_uuid = ? AND did = ?',
  ).get(resolver.lookupByDid(PEER_DID)!.identityUuid, PEER_DID) as { method: string } | undefined;
  assert.equal(row?.method, 'did:scid:vh');

  // VID→identity resolution must work even though the server's did_document is
  // NOT yet primary (is_primary=0) — the relationship record was named by the
  // real DID, and TSP/personhood/reconnect look it up by the ephemeral VID.
  const serverDid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, serverEd.publicKey);
  const byVid = resolver.lookupByVid(serverDid);
  assert.ok(byVid, 'lookupByVid must resolve an identity whose doc is not yet primary');
  assert.equal(byVid!.identityUuid, didToUuid(PEER_DID));
});

