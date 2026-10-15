// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for resolvePeerAgentName — the chat UI's peer display-name resolution.
 *
 * The chat UI identifies a peer by their agent login name; the DID stays the
 * machine key. This suite asserts the documented lookup order against a real
 * migrated SQLite schema (runMigrations -> IdentityResolver), not mocks:
 *
 *   - identities.name (captured from the peer's DID-doc alsoKnownAs) wins
 *   - the lookup is keyed by Ed25519 key first, so a peer whose name lives on an
 *     ephemeral did:peer:4 sibling row still resolves (the same shared-key
 *     canonicalization the trust graph relies on)
 *   - name_registry is the fallback, rendered as "name (namespace)"
 *   - an unknown peer returns null (the UI falls back to the DID — no regression)
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/agent/peer-name.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { openDatabase } from '@p2p-trust-stack/core/db/connection.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import { generateEd25519KeyPair } from '@p2p-trust-stack/core/crypto/primitives.js';
import { IdentityResolver } from '@p2p-trust-stack/core/services/identity-resolver.js';
import { resolvePeerAgentName } from '../../src/runtime/peer-name.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();
type SqliteDb = InstanceType<typeof DatabaseSync>;

/** A migrated, isolated database plus its resolver (real schema, no mocks). */
function makeDb(): { db: SqliteDb; resolver: IdentityResolver } {
  const db = openDatabase(join(mkdtempSync(join(tmpdir(), 'peer-name-test-')), 'test.db'));
  runMigrations(db, MIGRATIONS_DIR);
  return { db, resolver: new IdentityResolver(db) };
}

/** Give an identity an Ed25519 public key row (as the handshake would). */
function insertEd25519Key(db: SqliteDb, identityUuid: string, publicKey: Uint8Array): void {
  db.prepare(`
    INSERT INTO keys (uuid, identity_uuid, key_type, public_key, rotation_version, created_at)
    VALUES (?, ?, 'ed25519', ?, 0, unixepoch())
  `).run(generateUuid(), identityUuid, publicKey);
}

/** Register a locally-resolved name for an identity (name_registry fallback). */
function insertRegistryName(db: SqliteDb, identityUuid: string, did: string, namespace: string, name: string): void {
  db.prepare(`
    INSERT INTO name_registry (uuid, namespace, name, identity_uuid, did, claimed_at)
    VALUES (?, ?, ?, ?, ?, unixepoch())
  `).run(generateUuid(), namespace, name, identityUuid, did);
}

// ---------------------------------------------------------------------------
// identities.name — the registered agent login name
// ---------------------------------------------------------------------------

test('resolvePeerAgentName: returns the login name stored on the remote identity', () => {
  const { db, resolver } = makeDb();
  const did = 'did:peer:4:zPeerNamed';
  resolver.resolveRemoteIdentity({ did, method: 'did:peer:4', name: 'bob', recordedByNode: 'tsp-bridge' });

  assert.equal(resolvePeerAgentName(db, { remoteDid: did }), 'bob');
});

test('resolvePeerAgentName: resolves by Ed25519 key when the name lives on a sibling identity row', () => {
  const { db, resolver } = makeDb();
  const key = generateEd25519KeyPair().publicKey;

  // The ephemeral did:peer:4 row the handshake created carries the name ...
  const ephemeralDid = 'did:peer:4:zEphemeralSibling';
  const ephemeral = resolver.resolveRemoteIdentity({
    did: ephemeralDid, method: 'did:peer:4', name: 'dave', recordedByNode: 'tsp-bridge',
  });
  insertEd25519Key(db, ephemeral.identityUuid, key);

  // ... while the peer's real VTA row (what /api/relationships returns) has none.
  const realDid = 'did:scid:vh:zRealVta';
  resolver.resolveRemoteIdentity({ did: realDid, method: 'did:scid:vh' });

  // Key-first lookup bridges the two rows — the shared key bytes are the only
  // reliable signal that they are the same agent.
  assert.equal(resolvePeerAgentName(db, { remoteDid: realDid, remoteEd25519Key: key }), 'dave');

  // Without the key there is nothing to bridge with: the caller falls back to
  // the DID rather than inventing a name.
  assert.equal(resolvePeerAgentName(db, { remoteDid: realDid }), null);
});

// ---------------------------------------------------------------------------
// name_registry fallback
// ---------------------------------------------------------------------------

test('resolvePeerAgentName: falls back to name_registry, rendered as "name (namespace)"', () => {
  const { db, resolver } = makeDb();
  const did = 'did:peer:4:zRegistryOnly';
  const identity = resolver.resolveRemoteIdentity({ did, method: 'did:peer:4' });
  insertRegistryName(db, identity.identityUuid, did, 'example-ns', 'carol');

  assert.equal(resolvePeerAgentName(db, { remoteDid: did }), 'carol (example-ns)');
});

test('resolvePeerAgentName: identities.name outranks a name_registry entry', () => {
  const { db, resolver } = makeDb();
  const did = 'did:peer:4:zBothNamed';
  const identity = resolver.resolveRemoteIdentity({ did, method: 'did:peer:4', name: 'primary-name' });
  insertRegistryName(db, identity.identityUuid, did, 'example-ns', 'registry-name');

  assert.equal(resolvePeerAgentName(db, { remoteDid: did }), 'primary-name');
});

// ---------------------------------------------------------------------------
// Degradation — never invent a name, never throw
// ---------------------------------------------------------------------------

test('resolvePeerAgentName: unknown peer and empty inputs return null', () => {
  const { db } = makeDb();
  assert.equal(resolvePeerAgentName(db, { remoteDid: 'did:peer:4:zNobody' }), null);
  assert.equal(resolvePeerAgentName(db, { remoteDid: '' }), null);
  assert.equal(resolvePeerAgentName(db, { remoteDid: '' , remoteEd25519Key: null }), null);
  assert.equal(resolvePeerAgentName(db, { remoteDid: '', remoteEd25519Key: new Uint8Array(0) }), null);
});

test('resolvePeerAgentName: an unknown key falls back to the DID lookup', () => {
  const { db, resolver } = makeDb();
  const did = 'did:peer:4:zMixedLookup';
  resolver.resolveRemoteIdentity({ did, method: 'did:peer:4', name: 'erin' });

  const unrelatedKey = generateEd25519KeyPair().publicKey;
  assert.equal(resolvePeerAgentName(db, { remoteDid: did, remoteEd25519Key: unrelatedKey }), 'erin');
});
