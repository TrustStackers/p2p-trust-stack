/**
 * Regression test — the second VRC between two agent apps fails when each app
 * holds multiple VTAs.
 *
 * Scenario:
 *   1. App-1 has VTA1 + VTA2; App-2 has VTA1 + VTA2.
 *   2. App-1 VTA1 ↔ App-2 VTA1 forms a VRC — works (one relationship each).
 *   3. App-2 VTA2 ↔ App-1 VTA1 forms a VRC — FAILS.
 *
 * Root cause: `BaseAgent._handlePersonhoodResponse` (the "verified channel"
 * leg of VRC creation) resolved the remote peer with an UNFILTERED
 * `SELECT remote_identity_uuid FROM relationships WHERE local_identity_uuid = ...`
 * — so once a local VTA held TWO relationships it issued the DTG
 * RelationshipCredential against the wrong (oldest) remote.
 *
 * The fix resolves the remote the SAME way `RelationshipStore.get()` does —
 * `lookupByDid(remote) ?? lookupByVid(remote)` — which keys on the specific
 * peer's DID/VID. This test pins that resolution for the two-remote case:
 * the local VTA holds two relationships, and each remote must resolve to its
 * OWN identity/relationship, never to the first row.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/relationship/multi-vta-remote-resolution.test.ts
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

function makeHarness(): { db: DatabaseSync; resolver: IdentityResolver } {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  const resolver = new IdentityResolver(db);
  return { db, resolver };
}

/** Materialise a remote VTA identity (with a primary DID document) and return its CESR VID. */
function addRemote(resolver: IdentityResolver, did: string, name: string): string {
  const ed = generateEd25519KeyPair();
  const x = ed25519ToX25519(ed.secretKey);
  const doc = buildDidPeer4Document(ed.publicKey, x.publicKey);
  const vid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, ed.publicKey);
  resolver.storeRemoteIdentityCopy({
    uuid: didToUuid(did),
    realDid: did,
    did,
    method: 'did:scid:vh',
    name,
    role: 'vta',
    subjectKind: 'human',
    custody: 'local',
    peerId: null,
    vid,
    didDocument: { ...(doc as object), id: did } as any,
    publicKeys: {
      ed25519: Buffer.from(ed.publicKey).toString('base64'),
      x25519: Buffer.from(x.publicKey).toString('base64'),
    },
  });
  return vid;
}

test('a local VTA with two relationships resolves each remote to its own identity', () => {
  const { db, resolver } = makeHarness();

  // Local identity (the VTA that will hold TWO VRC relationships).
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

  // Two distinct remote VTAs (the "other app has VTA1 + VTA2" case).
  const remoteADid = 'did:scid:vh:1:zRemoteA';
  const remoteBDid = 'did:scid:vh:1:zRemoteB';
  const remoteAVid = addRemote(resolver, remoteADid, 'remoteA');
  const remoteBVid = addRemote(resolver, remoteBDid, 'remoteB');

  const store = new RelationshipStore(db, resolver);
  store.insertOutbound({
    localDid: LOCAL_DID,
    localMethod: 'did:scid:vh',
    remoteDid: remoteADid,
    remoteMethod: 'did:scid:vh',
    remoteTransport: { peerId: '12D3KooWRemoteA', multiaddrs: ['/ip4/10.0.0.1/tcp/4001'] },
    subjectKind: 'human',
  });
  store.insertOutbound({
    localDid: LOCAL_DID,
    localMethod: 'did:scid:vh',
    remoteDid: remoteBDid,
    remoteMethod: 'did:scid:vh',
    remoteTransport: { peerId: '12D3KooWRemoteB', multiaddrs: ['/ip4/10.0.0.2/tcp/4001'] },
    subjectKind: 'human',
  });

  // lookupByVid must resolve to the SPECIFIC remote, not "the first identity".
  const resolvedB = resolver.lookupByVid(remoteBVid);
  assert.ok(resolvedB, 'lookupByVid must resolve remote B');
  assert.equal(
    resolvedB!.identityUuid,
    didToUuid(remoteBDid),
    'lookupByVid must key on the specific peer, not the first remote identity',
  );

  // RelationshipStore.get by the SECOND remote's VID must return B, not A.
  const viaGetB = store.get(LOCAL_DID, remoteBVid);
  assert.ok(viaGetB, 'get(localDid, remoteB.vid) must find the remote B relationship');
  assert.equal(
    viaGetB!.remoteDid,
    remoteBDid,
    'get must return the specific remote, not the first relationship',
  );

  const viaGetA = store.get(LOCAL_DID, remoteAVid);
  assert.ok(viaGetA, 'get(localDid, remoteA.vid) must find the remote A relationship');
  assert.equal(viaGetA!.remoteDid, remoteADid);
});
