// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * REGRESSION TEST — connecting an agent to its OWN OOBI.
 *
 * An agent that creates an OOBI and then pastes it back into its own connect
 * box must fail cleanly ("Cannot connect to yourself") WITHOUT creating any
 * pending self-relationship row. Previously `sendRfi` wrote the outbound-
 * pending record BEFORE attempting the send; the send-to-self then failed,
 * leaving a stale pending line in the relationships UI.
 *
 * Uses the app's real wiring (runMigrations -> IdentityResolver ->
 * RelationshipStore -> RelationshipManager) so it exercises the genuine
 * storage layer, not a mock.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/relationship/self-connect.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDatabase } from '../../src/db/connection.js';
import { runMigrations } from '../../src/db/migrate.js';
import { IdentityResolver } from '../../src/services/identity-resolver.js';
import { RelationshipStore } from '../../src/relationship/store.js';
import { RelationshipManager } from '../../src/relationship/manager.js';
import { encodeOobi } from '../../src/relationship/oobi.js';
import { generateEd25519KeyPair, generateX25519KeyPair } from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import type { LocalIdentity } from '../../src/relationship/types.js';
import type { TspTransport, TransportAddress } from '../../src/transport/types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();
type SqliteDb = InstanceType<typeof DatabaseSync>;

function makeIdentity(): { identity: LocalIdentity; db: SqliteDb } {
  const signingKp = generateEd25519KeyPair();
  const agreementKp = generateX25519KeyPair();
  const vid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, signingKp.publicKey);
  const did = `did:peer:4:z${vid.slice(1, 17)}`;
  const db = openDatabase(join(mkdtempSync(join(tmpdir(), 'selfconnect-test-')), 'test.db'));
  runMigrations(db, MIGRATIONS_DIR);
  return {
    identity: {
      // G7g renamed LocalIdentity.vid → cesrVid; this fixture was missed, so
      // `identity.cesrVid` was undefined and every encodeOobi() call here threw
      // "Received empty input code for lookup". The file is not in the root
      // `npm test` script, so the rot went unnoticed.
      cesrVid: vid,
      did,
      didDocument: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        verificationMethod: [],
        authentication: [],
        keyAgreement: [],
        service: [],
      },
      signingKeyPair: signingKp,
      agreementKeyPair: agreementKp,
    },
    db,
  };
}

function buildManager(identity: LocalIdentity, db: SqliteDb) {
  const resolver = new IdentityResolver(db);
  resolver.resolveLocalIdentity({
    did: identity.did,
    method: 'did:peer:4',
    name: 'self',
    peerId: '12D3KooWSelfA',
    cesrVid: identity.cesrVid,
  });
  const store = new RelationshipStore(db, resolver);
  const sent: Array<{ message: Uint8Array; to: TransportAddress }> = [];
  const transport: TspTransport = {
    async start() {},
    async stop() {},
    async send(message: Uint8Array, remoteAddr: TransportAddress): Promise<void> {
      sent.push({ message: new Uint8Array(message), to: remoteAddr });
    },
    onMessage() {},
  };
  const manager = new RelationshipManager({ transport, store, identity });
  manager.start();
  return { store, sent, manager };
}

test('sendRfi: a self-OOBI is rejected and creates NO relationship state', async () => {
  const { identity, db } = makeIdentity();
  const { store, sent, manager } = buildManager(identity, db);

  const selfOobi = encodeOobi({ cesrVid: identity.cesrVid, peerId: '12D3KooWSelfA', multiaddrs: [], did: identity.did });

  await assert.rejects(
    () => manager.sendRfi(selfOobi),
    /Cannot connect to yourself/,
    'self-connect must throw a clear error',
  );

  assert.equal(store.list(identity.did).length, 0, 'no relationship record may be created for a self-connect');
  assert.equal(sent.length, 0, 'no RFI message may be sent for a self-connect');
});

test('sendRfi: a normal peer OOBI still creates the outbound-pending record', async () => {
  const { identity: a, db } = makeIdentity();
  const { store, sent, manager } = buildManager(a, db);

  const peer = makeIdentity().identity;
  const peerOobi = encodeOobi({ cesrVid: peer.cesrVid, peerId: '12D3KooWPeerX', multiaddrs: [], did: peer.did });

  await manager.sendRfi(peerOobi);
  const rec = store.get(a.did, peer.did);
  assert.ok(rec, 'normal peer connect still creates a relationship record');
  assert.equal(rec.direction, 'outbound');
  assert.equal(rec.status, 'pending');
  assert.equal(sent.length, 1, 'normal peer RFI is still sent');
});