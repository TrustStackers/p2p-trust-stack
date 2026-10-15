// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for the OOBI introduction-integrity policy (H2 / decision D-2).
 *
 * Until this policy existed, `sendRfi` *reported* an OOBI's ML-DSA-65 signature
 * mismatch and then trusted the introduction anyway — a `✗` in a log is not a
 * control. These tests pin all three modes, including the two distinct rejection
 * reasons `enforce` can produce, using REAL did:peer:4 identities so the document
 * under test publishes a genuine `#key-mldsa`.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test \
 *     test/relationship/oobi-policy.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createDidPeer4 } from '../../src/did/create.js';
import { resolveDidPeer4 } from '../../src/did/resolve.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { runMigrations } from '../../src/db/migrate.js';
import { IdentityResolver } from '../../src/services/identity-resolver.js';
import { RelationshipStore } from '../../src/relationship/store.js';
import { RelationshipManager, type OobiSignaturePolicy } from '../../src/relationship/manager.js';
import { encodeOobi, decodeOobi, signOobi } from '../../src/relationship/oobi.js';
import type { LocalIdentity, OobiPayload } from '../../src/relationship/types.js';
import type { TspTransport, TransportAddress } from '../../src/transport/types.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Captures outbound messages; no handler delivery needed for these tests. */
class MockTransport implements TspTransport {
  public sent: Array<{ message: Uint8Array; to: TransportAddress }> = [];
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  async send(message: Uint8Array, remoteAddr: TransportAddress): Promise<void> {
    this.sent.push({ message: new Uint8Array(message), to: remoteAddr });
  }
  onMessage(): void {}
  isConnected(): boolean { return false; }
  getPeerMultiaddrs(): string[] | undefined { return undefined; }
}

/** A real did:peer:4 identity — its document publishes a genuine #key-mldsa. */
async function makePeer(name: string): Promise<LocalIdentity> {
  const result = await createDidPeer4({ peerId: `peer-${name}`, multiaddrs: ['/ip4/127.0.0.1/tcp/1'] });
  return {
    cesrVid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, result.signingKeyPair.publicKey),
    did: result.did,
    didDocument: await resolveDidPeer4(result.did),
    signingKeyPair: result.signingKeyPair,
    agreementKeyPair: result.agreementKeyPair,
    mlDsa65KeyPair: result.mlDsa65KeyPair,
    hybridKemKeyPair: result.hybridKemKeyPair,
  };
}

/** A manager for `identity` with the given policy and a throwaway SQLite store. */
function makeManager(
  identity: LocalIdentity,
  policy: OobiSignaturePolicy,
  resolvePeerDocument?: (did: string) => Promise<import('../../src/did/types.js').DidDocument | undefined>,
): RelationshipManager {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  const resolver = new IdentityResolver(db);
  resolver.resolveLocalIdentity({
    did: identity.did,
    name: 'policy-test',
    method: 'did:peer:4',
    peerId: `peer-self-${identity.cesrVid.slice(0, 8)}`,
    cesrVid: identity.cesrVid,
    didDocumentJson: JSON.stringify(identity.didDocument),
  });
  return new RelationshipManager({
    transport: new MockTransport(),
    store: new RelationshipStore(db, resolver),
    identity,
    oobiSignaturePolicy: policy,
    resolvePeerDocument,
  });
}

/** The peer's OOBI, unsigned (`encodeOobi` does not sign; `signOobi` does). */
function unsignedOobi(peer: LocalIdentity): string {
  return encodeOobi({
    cesrVid: peer.cesrVid,
    did: peer.did,
    peerId: `peer-${peer.did.slice(-8)}`,
    multiaddrs: ['/ip4/127.0.0.1/tcp/2'],
  });
}

/** A correctly signed OOBI. */
function signedOobi(peer: LocalIdentity): string {
  const payload: OobiPayload = decodeOobi(unsignedOobi(peer));
  return encodeOobi(signOobi(payload, peer.mlDsa65KeyPair!.secretKey));
}

/** A signed OOBI whose 4-item body was altered afterwards (peerId swapped). */
function tamperedOobi(peer: LocalIdentity): string {
  const signed = decodeOobi(signedOobi(peer));
  return encodeOobi({ ...signed, peerId: 'someone-else-entirely' });
}

/** The same store wiring as {@link makeManager}, for tests that need the store. */
function makeStoreFor(identity: LocalIdentity, peerId: string): RelationshipStore {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  const resolver = new IdentityResolver(db);
  resolver.resolveLocalIdentity({
    did: identity.did,
    name: 'policy-test',
    method: 'did:peer:4',
    peerId,
    cesrVid: identity.cesrVid,
    didDocumentJson: JSON.stringify(identity.didDocument),
  });
  return new RelationshipStore(db, resolver);
}

// ---------------------------------------------------------------------------
// warn — the default: report, never abort
// ---------------------------------------------------------------------------

test('policy warn: an UNSIGNED introduction proceeds (and is reported)', async () => {
  const self = await makePeer('warn-self');
  const peer = await makePeer('warn-peer');
  const manager = makeManager(self, 'warn');

  // No throw: warn must never break a legitimate pre-PQ introduction.
  await manager.sendRfi(unsignedOobi(peer));
});

test('policy warn: a TAMPERED introduction proceeds too', async () => {
  const self = await makePeer('warn-self2');
  const peer = await makePeer('warn-peer2');
  const manager = makeManager(self, 'warn');

  await manager.sendRfi(tamperedOobi(peer));
});

// ---------------------------------------------------------------------------
// off — no verification at all
// ---------------------------------------------------------------------------

test('policy off: an unsigned introduction proceeds', async () => {
  const self = await makePeer('off-self');
  const peer = await makePeer('off-peer');
  const manager = makeManager(self, 'off');

  await manager.sendRfi(unsignedOobi(peer));
});

// ---------------------------------------------------------------------------
// enforce — refuse the introduction, with DISTINCT named reasons
// ---------------------------------------------------------------------------

test('policy enforce: a validly signed introduction proceeds', async () => {
  const self = await makePeer('enf-ok-self');
  const peer = await makePeer('enf-ok-peer');
  const manager = makeManager(self, 'enforce');

  await manager.sendRfi(signedOobi(peer));
});

test('policy enforce: an UNSIGNED introduction is REFUSED with oobi_unsigned', async () => {
  const self = await makePeer('enf-uns-self');
  const peer = await makePeer('enf-uns-peer');
  const manager = makeManager(self, 'enforce');

  await assert.rejects(
    () => manager.sendRfi(unsignedOobi(peer)),
    (err: unknown) => {
      assert.match((err as Error).message, /oobi_unsigned/, 'must name the reason');
      assert.match((err as Error).message, /refusing the introduction/i);
      return true;
    },
  );
});

test('policy enforce: a TAMPERED introduction is REFUSED with oobi_signature_invalid', async () => {
  const self = await makePeer('enf-tam-self');
  const peer = await makePeer('enf-tam-peer');
  const manager = makeManager(self, 'enforce');

  await assert.rejects(
    () => manager.sendRfi(tamperedOobi(peer)),
    (err: unknown) => {
      // A DIFFERENT reason from the unsigned case: "altered / rotated" is a
      // different diagnosis from "never signed", and mixing them is how a
      // rotation problem gets mistaken for a stripped artifact.
      assert.match((err as Error).message, /oobi_signature_invalid/);
      assert.doesNotMatch((err as Error).message, /oobi_unsigned/);
      return true;
    },
  );
});

test('policy enforce: a refusal creates NO relationship state', async () => {
  const self = await makePeer('enf-state-self');
  const peer = await makePeer('enf-state-peer');
  const store = makeStoreFor(self, 'peer-self-state');
  const manager = new RelationshipManager({
    transport: new MockTransport(), store, identity: self, oobiSignaturePolicy: 'enforce',
  });

  await assert.rejects(() => manager.sendRfi(unsignedOobi(peer)), /oobi_unsigned/);
  assert.equal(
    store.list(self.did).length,
    0,
    'a refused introduction must not leave a relationship row behind',
  );
});

// ---------------------------------------------------------------------------
// Ordering: the self-connect guard must win over the policy
// ---------------------------------------------------------------------------

test('policy enforce: a SELF-OOBI still reports the self-connect, not a policy failure', async () => {
  const self = await makePeer('self-enf');
  const manager = makeManager(self, 'enforce');

  // `encodeOobi` does not sign, so a policy check running FIRST would report
  // "oobi_unsigned" for what is really a self-connect — a misleading diagnosis
  // of a definite error. The guard runs first.
  await assert.rejects(
    () => manager.sendRfi(unsignedOobi(self)),
    /Cannot connect to yourself/,
  );
});

// ---------------------------------------------------------------------------
// The resolution prerequisite for `enforce` — and the fix
// ---------------------------------------------------------------------------

test('policy enforce: a did:scid:vh OOBI verifies against the PINNED key from an accepted document', async () => {
  const self = await makePeer('scvh-self');
  const peer = await makePeer('scvh-peer'); // supplies a real #key-mldsa pair + document
  const SCVH = 'did:scid:vh:1:6Mkr6cy8emkvrxxEdW2rBfGv61cPpZxHmrBmEFXJS6LyPJ2';

  // Stand up a store in which this peer's document was already accepted under its
  // did:scid:vh DID — i.e. exactly the state after a completed handshake or an
  // identity push. Without this the receiver has no way to obtain the key, which
  // is why every scvh introduction used to report `oobi_key_unresolvable`.
  const db = new DatabaseSync(':memory:');
  runMigrations(db, getMigrationsDir());
  const resolver = new IdentityResolver(db);
  resolver.resolveLocalIdentity({
    did: self.did, name: 'scvh-test', method: 'did:peer:4',
    peerId: 'peer-self-scvh', cesrVid: self.cesrVid,
    didDocumentJson: JSON.stringify(self.didDocument),
  });
  resolver.resolveRemoteIdentity({
    did: SCVH,
    method: 'did:scid:vh',
    isPrimary: false,
    recordedByNode: 'test',
    // Same document, addressed under the peer's scvh DID.
    didDocumentJson: JSON.stringify({ ...(peer.didDocument as object), id: SCVH }),
  });
  const store = new RelationshipStore(db, resolver);

  // The mechanism: the peer's ML-DSA key is readable by DID, even though
  // `DidPeer4Method.resolve(SCVH)` can never work and no relationship row exists
  // yet (the introduction is what would create one).
  assert.ok(
    store.getRemoteMlDsa65Key(SCVH),
    'the accepted document must leave an ML-DSA key pinned against that identity',
  );

  const manager = new RelationshipManager({
    transport: new MockTransport(), store, identity: self, oobiSignaturePolicy: 'enforce',
  });

  // A correctly signed introduction now VERIFIES (no throw) — this is the gap
  // that is now closed for a known scvh peer.
  await manager.sendRfi(encodeOobi(signOobi({
    cesrVid: peer.cesrVid,
    did: SCVH,
    peerId: 'peer-scvh',
    multiaddrs: ['/ip4/127.0.0.1/tcp/9'],
  }, peer.mlDsa65KeyPair!.secretKey)));

  // And the fallback is doing real verification, not just skipping the check: a
  // tampered body still fails, against the PINNED key.
  const signed = decodeOobi(encodeOobi(signOobi({
    cesrVid: peer.cesrVid,
    did: SCVH,
    peerId: 'peer-scvh',
    multiaddrs: ['/ip4/127.0.0.1/tcp/9'],
  }, peer.mlDsa65KeyPair!.secretKey)));
  await assert.rejects(
    () => manager.sendRfi(encodeOobi({ ...signed, peerId: 'someone-else' })),
    /oobi_signature_invalid/,
    'a tampered introduction must be refused against the pinned key, not waved through',
  );
});

test('policy enforce: an OOBI for an UNKNOWN did:scid:vh peer is still refused', async () => {
  const self = await makePeer('scvh-unknown-self');
  const peer = await makePeer('scvh-unknown-peer');
  const manager = makeManager(self, 'enforce');

  // No stored document, no pinned key, no anchor: there is genuinely nothing to
  // verify against on a true first contact with an scvh peer, and inventing a key
  // would be worse than reporting the gap.
  const oobi = encodeOobi(signOobi({
    cesrVid: peer.cesrVid,
    did: 'did:scid:vh:1:7Nkr6cy8emkvrxxEdW2rBfGv61cPpZxHmrBmEFXJS6LyPJ2',
    peerId: 'peer-unknown-scvh',
    multiaddrs: ['/ip4/127.0.0.1/tcp/10'],
  }, peer.mlDsa65KeyPair!.secretKey));

  await assert.rejects(() => manager.sendRfi(oobi), /oobi_key_unresolvable/);
});

// ---------------------------------------------------------------------------
// The anchored lookup — what finishes the story for a first contact
// ---------------------------------------------------------------------------

test('policy enforce: an ANCHORED lookup makes a first-contact did:scid:vh OOBI verifiable', async () => {
  const self = await makePeer('anchor-self');
  const peer = await makePeer('anchor-peer');
  const SCVH = 'did:scid:vh:1:8Pkr6cy8emkvrxxEdW2rBfGv61cPpZxHmrBmEFXJS6LyPJ2';

  // The anchor (agent → its VTA's `exchange:identity-lookup`; server → its own DB)
  // holds the peer's document under its did:scid:vh DID. This is the ONLY source
  // that can work for a first contact: the DID is not resolvable locally and
  // nothing is pinned yet.
  let lookedUp: string | undefined;
  const manager = makeManager(self, 'enforce', async (did) => {
    lookedUp = did;
    if (did !== SCVH) return undefined;
    return { ...(peer.didDocument as object), id: SCVH } as never;
  });

  await manager.sendRfi(encodeOobi(signOobi({
    cesrVid: peer.cesrVid,
    did: SCVH,
    peerId: 'peer-anchored',
    multiaddrs: ['/ip4/127.0.0.1/tcp/11'],
  }, peer.mlDsa65KeyPair!.secretKey)));

  assert.equal(lookedUp, SCVH, 'the anchor must be consulted for the OOBI DID');
});

test('policy enforce: the anchored key is used for REAL verification (wrong key ⇒ refused)', async () => {
  const self = await makePeer('anchor-wrong-self');
  const peer = await makePeer('anchor-wrong-peer');
  const impostor = await makePeer('anchor-impostor');
  const SCVH = 'did:scid:vh:1:9Qkr6cy8emkvrxxEdW2rBfGv61cPpZxHmrBmEFXJS6LyPJ2';

  // The anchor answers for that DID, but with a DIFFERENT identity's document —
  // i.e. the signature cannot verify. The check must refuse rather than accept the
  // presence of an answer as proof.
  const manager = makeManager(self, 'enforce', async () => ({
    ...(impostor.didDocument as object),
    id: SCVH,
  }) as never);

  await assert.rejects(
    () => manager.sendRfi(encodeOobi(signOobi({
      cesrVid: peer.cesrVid,
      did: SCVH,
      peerId: 'peer-anchored-wrong',
      multiaddrs: ['/ip4/127.0.0.1/tcp/12'],
    }, peer.mlDsa65KeyPair!.secretKey))),
    /oobi_signature_invalid/,
  );
});

test('policy enforce: an anchor that does not know the peer (or throws) leaves it unverifiable', async () => {
  const self = await makePeer('anchor-miss-self');
  const peer = await makePeer('anchor-miss-peer');
  const SCVH = 'did:scid:vh:1:6Rkr6cy8emkvrxxEdW2rBfGv61cPpZxHmrBmEFXJS6LyPJ2';
  const oobi = encodeOobi(signOobi({
    cesrVid: peer.cesrVid,
    did: SCVH,
    peerId: 'peer-anchor-miss',
    multiaddrs: ['/ip4/127.0.0.1/tcp/13'],
  }, peer.mlDsa65KeyPair!.secretKey));

  // Unknown to the anchor.
  await assert.rejects(
    () => makeManager(self, 'enforce', async () => undefined).sendRfi(oobi),
    /oobi_key_unresolvable/,
  );

  // Anchor unreachable. Must stay a refusal that NAMES the failure — never a crash
  // and never a silent pass.
  await assert.rejects(
    () => makeManager(self, 'enforce', async () => { throw new Error('VTA unreachable'); }).sendRfi(oobi),
    /oobi_key_unresolvable/,
  );
});



test('policy enforce: a DID this process cannot resolve is REFUSED (oobi_key_unresolvable)', async () => {
  const self = await makePeer('unres-self');
  const peer = await makePeer('unres-peer');
  const manager = makeManager(self, 'enforce');

  // A did:scid:vh peer. The check resolves the peer's ML-DSA key from the OOBI's
  // own `did`, but:
  //   - DidPeer4Method.resolve() handles only did:peer:4 (a long-form peer4 DID
  //     is self-contained, which is why peer4 works), and
  //   - ScidVhMethod.resolve() needs a rotation-log store FOR THAT DID.
  // So an agent cannot obtain a did:scid:vh peer's key before the handshake —
  // which makes `enforce` unusable against did:scid:vh peers (including the
  // utility server) until resolution is anchored somewhere the receiver can
  // reach. Pinned here so flipping the default is an informed decision rather
  // than a discovery made in production.
  const scvhOobi = encodeOobi({
    cesrVid: peer.cesrVid,
    peerId: 'peer-scvh',
    multiaddrs: ['/ip4/127.0.0.1/tcp/3'],
    did: 'did:scid:vh:1:6Mkr6cy8emkvrxxEdW2rBfGv61cPpZxHmrBmEFXJS6LyPJ2',
  });

  await assert.rejects(
    () => manager.sendRfi(scvhOobi),
    (err: unknown) => {
      assert.match(
        (err as Error).message,
        /oobi_key_unresolvable|oobi_no_published_key/,
        'a DID we cannot resolve must be refused as an unresolved/unpublished key',
      );
      return true;
    },
  );
});

test('policy warn: the same unresolvable DID is reported but still attempted', async () => {
  const self = await makePeer('unres-warn-self');
  const peer = await makePeer('unres-warn-peer');
  const manager = makeManager(self, 'warn');

  const scvhOobi = encodeOobi({
    cesrVid: peer.cesrVid,
    peerId: 'peer-scvh-warn',
    multiaddrs: ['/ip4/127.0.0.1/tcp/4'],
    did: 'did:scid:vh:1:6Mkr6cy8emkvrxxEdW2rBfGv61cPpZxHmrBmEFXJS6LyPJ2',
  });

  await manager.sendRfi(scvhOobi);
});


// ---------------------------------------------------------------------------
// Default: nothing configured ⇒ warn (never enforce)
// ---------------------------------------------------------------------------

test('policy default: an unsigned introduction proceeds when nothing is configured', async () => {
  const self = await makePeer('def-self');
  const peer = await makePeer('def-peer');
  const store = makeStoreFor(self, 'peer-self-def');
  const manager = new RelationshipManager({
    transport: new MockTransport(), store, identity: self,
  });

  // Guards the DEFAULT: flipping it to `enforce` without the documented
  // prerequisites would break every pre-PQ peer, so this test is what makes such
  // a flip a deliberate, visible change.
  await manager.sendRfi(unsignedOobi(peer));
});


