// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Regression test — G7WIN11 graph / VTC co-admin checklist showing a CESR VID
 * prefix (e.g. `DK…`) instead of the peer's name after agent99 registers a name
 * ("shanster") and rolls its did:scid:vh log.
 *
 * Scenario reproduced (fresh databases, committed HEAD 1f84853 broke):
 *   1. agent99 registers name "shanster" → the did:scid:vh rotation log is
 *      rolled, so the DID document's #key-1 is the PRE-ROTATION/NEXT key (B)
 *      while the agent STILL signs with its live keystore key (A).
 *   2. G7WIN11 receives agent99's identity record (VRC ceremony
 *      `store_remote_vrc` → `storeReceivedDtgVrc` → `storeRemoteIdentityCopy`).
 *      `record.publicKeys` = live key A (authoritative); `record.didDocument`
 *      #key-1 = B (rolled).
 *   3. The real agent99 row must end up keyed to A so the shared-Ed25519-key
 *      canonicalization links it to the handshake stub (which already carries
 *      A). A later `resolveRemoteIdentity()` call that re-extracts the key from
 *      the stale doc (B) must NOT clobber A back to B — that clobber is what
 *      left the stub unlinked and forced the `vid.slice(0,16)+'…'` fallback.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/relationship/identity-key-heal.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

import { runMigrations } from '../../src/db/migrate.js';
import { IdentityResolver } from '../../src/services/identity-resolver.js';
import type { RemoteIdentityRecord } from '../../src/services/identity-resolver.js';
import {
  generateEd25519KeyPair,
  ed25519ToX25519,
} from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { buildDidPeer4Document } from '../../src/did/create.js';
import { didToUuid } from '../../src/db/uuid-helpers.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface Ed25519KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeHarness(): { db: DatabaseSync; resolver: IdentityResolver } {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  const resolver = new IdentityResolver(db);
  return { db, resolver };
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/**
 * Build an identity record exactly like `buildIdentityRecord()` in
 * `src/relationship/ceremony.ts` for a sender whose did:scid:vh log was rolled:
 *   - `didDocument` #key-1 = the ROTATED/NEXT key (B)
 *   - `publicKeys` = the LIVE keystore key (A)
 */
function makeRolledIdentityRecord(params: {
  realDid: string;
  name: string;
  liveEd: Ed25519KeyPair;
  liveX: Uint8Array;
  docEd: Ed25519KeyPair;
  docX: Uint8Array;
}): RemoteIdentityRecord {
  const { realDid, name, liveEd, liveX, docEd, docX } = params;
  const doc = buildDidPeer4Document(docEd.publicKey, docX);
  return {
    uuid: didToUuid(realDid),
    realDid,
    did: realDid,
    method: 'did:scid:vh',
    name,
    role: 'vta',
    subjectKind: 'human',
    custody: 'local',
    peerId: '12D3KooWTestPeerId0000000000000000000000000',
    vid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, liveEd.publicKey),
    didDocument: { ...doc, id: realDid, alsoKnownAs: ['vta:p2pts:shanster'] },
    publicKeys: {
      ed25519: b64(liveEd.publicKey),
      x25519: b64(liveX),
    },
  };
}

function getKeyHex(db: DatabaseSync, identityUuid: string, keyType: string): string | null {
  const row = db.prepare(
    'SELECT public_key FROM keys WHERE identity_uuid = ? AND key_type = ? AND rotation_version = 0',
  ).get(identityUuid, keyType) as { public_key: Uint8Array } | undefined;
  return row ? Buffer.from(row.public_key).toString('hex') : null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('storeRemoteIdentityCopy: explicit live publicKeys win over stale didDocument #key-1', () => {
  const { db, resolver } = makeHarness();

  const realDid = 'did:scid:vh:1:zSenderRolledDid';
  const liveEd = generateEd25519KeyPair();
  const liveX = ed25519ToX25519(liveEd.secretKey);
  const docEd = generateEd25519KeyPair(); // the rolled/next key (B)
  const docX = ed25519ToX25519(docEd.secretKey);

  const record = makeRolledIdentityRecord({
    realDid,
    name: 'agent99',
    liveEd,
    liveX: liveX.publicKey,
    docEd,
    docX: docX.publicKey,
  });

  const resolved = resolver.storeRemoteIdentityCopy(record);

  assert.equal(resolved.identityUuid, didToUuid(realDid));
  assert.equal(
    getKeyHex(db, didToUuid(realDid), 'ed25519'),
    Buffer.from(liveEd.publicKey).toString('hex'),
    'real row must carry the sender LIVE key (A), not the rolled doc key (B)',
  );
});

test('resolveRemoteIdentity with a stale doc must NOT clobber the user-set live key (regression)', () => {
  const { db, resolver } = makeHarness();

  const realDid = 'did:scid:vh:1:zSenderRolledDid';
  const liveEd = generateEd25519KeyPair();
  const liveX = ed25519ToX25519(liveEd.secretKey);
  const docEd = generateEd25519KeyPair(); // rolled/next key (B)
  const docX = ed25519ToX25519(docEd.secretKey);

  const record = makeRolledIdentityRecord({
    realDid,
    name: 'agent99',
    liveEd,
    liveX: liveX.publicKey,
    docEd,
    docX: docX.publicKey,
  });

  // 1. The VRC ceremony copies the sender's real identity (live key A).
  resolver.storeRemoteIdentityCopy(record);

  // 2. A later handshake/stub re-materialization re-resolves the SAME real DID
  //    from its (stale, rolled) did document whose #key-1 is key B.
  const staleDoc = buildDidPeer4Document(docEd.publicKey, docX.publicKey);
  resolver.resolveRemoteIdentity({
    did: realDid,
    method: 'did:scid:vh',
    didDocumentJson: JSON.stringify({ ...staleDoc, id: realDid }),
    isPrimary: false,
    recordedByNode: 'tsp-bridge',
  });

  // 3. The live key MUST survive — this is the exact failure the user saw
  //    (`DK…` VID fallback on G7WIN11's graph + VTC co-admin checklist).
  assert.equal(
    getKeyHex(db, didToUuid(realDid), 'ed25519'),
    Buffer.from(liveEd.publicKey).toString('hex'),
    'doc-extracted key (B) must never overwrite the authoritative live key (A)',
  );
});

test('fresh handshake (doc-only, no explicit keys) still inserts the doc key for a new stub', () => {
  const { db, resolver } = makeHarness();

  const keyEd = generateEd25519KeyPair();
  const keyX = ed25519ToX25519(keyEd.secretKey);
  const doc = buildDidPeer4Document(keyEd.publicKey, keyX.publicKey);
  const stubVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, keyEd.publicKey);

  // Brand-new did:peer:4 stub created during an RFI/RFA handshake — no explicit
  // keys available, so DID-document extraction is the ONLY source and must insert.
  resolver.resolveRemoteIdentity({
    did: stubVid,
    method: 'did:peer:4',
    didDocumentJson: JSON.stringify(doc),
    isPrimary: false,
    recordedByNode: 'tsp-bridge',
  });

  assert.equal(
    getKeyHex(db, didToUuid(stubVid), 'ed25519'),
    Buffer.from(keyEd.publicKey).toString('hex'),
    'doc-only handshake must insert keys for a brand-new stub identity',
  );
});

test('explicit identity copy still heals a stale doc-populated key row', () => {
  const { db, resolver } = makeHarness();

  const realDid = 'did:scid:vh:1:zSenderRolledDid';
  const liveEd = generateEd25519KeyPair();
  const liveX = ed25519ToX25519(liveEd.secretKey);
  const docEd = generateEd25519KeyPair();
  const docX = ed25519ToX25519(docEd.secretKey);

  // 1. Stub/handshake materializes first from the stale doc (key B).
  const staleDoc = buildDidPeer4Document(docEd.publicKey, docX.publicKey);
  resolver.resolveRemoteIdentity({
    did: realDid,
    method: 'did:scid:vh',
    didDocumentJson: JSON.stringify({ ...staleDoc, id: realDid }),
    isPrimary: false,
    recordedByNode: 'tsp-bridge',
  });

  const before = getKeyHex(db, didToUuid(realDid), 'ed25519');
  assert.equal(before, Buffer.from(docEd.publicKey).toString('hex'), 'precondition: doc key stored');

  // 2. The VRC record then arrives with the authoritative live keys — it heals.
  resolver.storeRemoteIdentityCopy(makeRolledIdentityRecord({
    realDid,
    name: 'agent99',
    liveEd,
    liveX: liveX.publicKey,
    docEd,
    docX: docX.publicKey,
  }));

  assert.equal(
    getKeyHex(db, didToUuid(realDid), 'ed25519'),
    Buffer.from(liveEd.publicKey).toString('hex'),
    'authoritative explicit keys must heal a stale doc-populated row',
  );
});
