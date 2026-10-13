/**
 * End-to-end LARGE-PAYLOAD tests — the regression guard for the `--E#####`
 * Big-counter outage class.
 *
 * ## Why this file exists
 *
 * Every live body in `e2e-direct-mode.test.ts` is 13-26 bytes. The codec-level
 * tests added in G1 cover 12 KB / 40 KB / 1 MB, but **nothing drove a large body
 * through the real transport, the relationship manager and the codec together** —
 * and that is exactly how the `--E#####` defect survived: the encoder emitted a
 * Big counter that the decoder rejected, so every payload above ~10.7 KB was
 * **silently dropped** by the receiver (the sender then timed out at 30 s), while
 * 381 green unit tests coexisted with a broken system.
 *
 * The heaviest real payloads are `exchange:identity` (a full DID document plus
 * every profile, claim and credential) and the VTC/VMC fan-out. Both grow as an
 * agent accumulates credentials, which is why the system degraded with use
 * rather than failing uniformly — so these tests size bodies at the boundary
 * (12 KB), well past it (40 KB), and in a realistic JSON shape.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test \
 *     test/relationship/e2e-large-payload.test.ts
 *
 * ## How to prove these tests guard the right thing
 *
 * Temporarily make `peekCounter` / `tspOpen` reject the Big (`--E#####`) form
 * again (i.e. revert the G1 acceptance) and these tests MUST fail. A green run
 * against a decoder that cannot read the encoder's own output is exactly the
 * failure mode this file exists to prevent.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { tspSeal } from '../../src/tsp/v3/message.js';
import { startPair, bodyOfSize } from './e2e-harness.js';

/** The framing prefix of the CESR **Big** counter form (`--E#####`). */
const BIG_COUNTER_PREFIX = '--E';

/**
 * Assert a sealed message uses the Big counter form. This guards the *test*:
 * if a body were ever small enough to take the small form, the case would stop
 * exercising the boundary without failing.
 */
function assertBigCounterForm(sealed: Uint8Array, what: string): void {
  const prefix = new TextDecoder().decode(sealed.slice(0, 3));
  assert.equal(
    prefix,
    BIG_COUNTER_PREFIX,
    `${what} must be framed with the Big counter (--E#####); got ${JSON.stringify(prefix)}`,
  );
}

// ---------------------------------------------------------------------------
// 1. 12 KB — the first size that crosses the ~10.7 KB boundary
// ---------------------------------------------------------------------------

test('e2e large payload: 12 KB TSP_GEN body survives byte-identically', async () => {
  const pair = await startPair();
  try {
    await pair.connect();

    const body = bodyOfSize(12 * 1024, 1);

    // The manager seals internally, so pin the framing separately: at this size
    // the encoder MUST emit the Big counter, which is precisely what the
    // pre-G1 decoder could not read.
    const probe = tspSeal({
      vidSender: pair.identityA.did,
      vidReceiver: pair.identityB.did,
      payload: { type: 'TSP_GEN', body },
      signingSecretKey: pair.identityA.signingKeyPair.secretKey,
    });
    assertBigCounterForm(probe, 'a 12 KB TSP_GEN');

    await pair.managerA.sendMessage(pair.identityB.did, body);
    await pair.receivedByB.waitForCount(1);

    const received = pair.receivedByB.received[0];
    assert.equal(received.body.length, body.length, 'B must receive a 12 KB body, not a truncated one');
    assert.deepEqual(received.body, body, 'B must receive the exact 12 KB bytes A sent');
    assert.equal(received.confidential, false, 'a plain sendMessage() must arrive non-confidential');
    assert.equal(received.remoteDid, pair.identityA.did, 'B must see A as the sender');
  } finally {
    await pair.stop();
  }
});

// ---------------------------------------------------------------------------
// 2. 40 KB — far past the boundary, plus an identity-push-shaped JSON body
// ---------------------------------------------------------------------------

test('e2e large payload: 40 KB body and a realistic identity-push body round-trip', async () => {
  const pair = await startPair();
  try {
    await pair.connect();

    const big = bodyOfSize(40 * 1024, 2);
    await pair.managerA.sendMessage(pair.identityB.did, big);
    await pair.receivedByB.waitForCount(1);
    assert.equal(pair.receivedByB.received[0].body.length, big.length, 'B must receive all 40 KB');
    assert.deepEqual(pair.receivedByB.received[0].body, big, 'B must receive the exact 40 KB bytes');

    // A realistically shaped `exchange:identity` body: DID document, a profile,
    // and a credential set big enough to push the sealed message past the
    // boundary the way a real agent's push does as it accumulates VRCs.
    //
    // SIZING NOTE: each credential embeds two *long-form* did:peer:4 strings
    // (issuer + subject), and a long-form DID is ~4.5 KB because it carries the
    // whole document in the identifier. So a credential set is heavy: ~9 KB per
    // credential. 15 credentials is already ~135 KB — far past the ~10.7 KB
    // boundary this file guards, and safely under the transport's 1 MB frame
    // cap (see the dedicated over-limit case below, which asserts that crossing
    // that cap fails LOUDLY rather than being dropped).
    const credentials = Array.from({ length: 15 }, (_, i) => ({
      id: `urn:uuid:00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
      type: ['VerifiableCredential', 'VerifiableRelationshipCredential'],
      issuer: pair.identityB.did,
      issuanceDate: '2026-01-01T00:00:00Z',
      credentialSubject: {
        id: pair.identityA.did,
        relationship: 'peer',
        permissions: ['name:resolve', 'vtc:join', 'message:send'],
      },
      proof: { type: 'Ed25519Signature2020', proofValue: 'z' + 'A'.repeat(86) },
    }));
    const identityPush = new TextEncoder().encode(JSON.stringify({
      type: 'exchange:identity',
      did: pair.identityA.did,
      didDocument: pair.identityA.didDocument,
      profiles: [{ name: 'e2e-agent-a', kind: 'organization' }],
      credentials,
    }));
    assert.ok(
      identityPush.length >= 20 * 1024,
      `the identity-push body must be realistically large; got ${identityPush.length} bytes`,
    );
    assert.ok(
      identityPush.length < 512 * 1024,
      `this case must stay under the transport frame cap; got ${identityPush.length} bytes`,
    );

    await pair.managerA.sendMessage(pair.identityB.did, identityPush);
    await pair.receivedByB.waitForCount(2);
    const receivedPush = pair.receivedByB.received[1];
    assert.equal(receivedPush.body.length, identityPush.length, 'the full identity push must arrive');
    assert.deepEqual(receivedPush.body, identityPush, 'the identity push must arrive byte-identically');

    // Decode it too: a mis-slice that still produced the right length would be
    // caught by the structural assertions below.
    const decoded = JSON.parse(new TextDecoder().decode(receivedPush.body)) as {
      type: string;
      credentials: unknown[];
    };
    assert.equal(decoded.type, 'exchange:identity');
    assert.equal(decoded.credentials.length, credentials.length);
  } finally {
    await pair.stop();
  }
});

// ---------------------------------------------------------------------------
// 5. Over the transport frame cap — must fail LOUDLY, never silently
// ---------------------------------------------------------------------------

test('e2e large payload: a body over the transport frame cap fails loudly, not silently', async () => {
  const pair = await startPair();
  try {
    await pair.connect();

    // A credential set this large is reachable in production (it is why the
    // outage degraded with use rather than failing uniformly). Whatever the
    // policy decision about the cap, the failure must be a named, thrown error
    // the caller can act on — the opposite of the pre-G1 silent drop.
    const oversized = bodyOfSize(1_500_000, 6);
    await assert.rejects(
      () => pair.managerA.sendMessage(pair.identityB.did, oversized),
      (err: unknown) => {
        assert.equal((err as Error).name, 'TransportFrameTooLargeError', 'must be the named transport error');
        assert.match((err as Error).message, /too large/i);
        return true;
      },
      'an over-cap body must throw a named TransportFrameTooLargeError',
    );

    // And it must not have been half-delivered.
    await new Promise(resolve => setTimeout(resolve, 250));
    assert.equal(pair.receivedByB.received.length, 0, 'B must not receive a truncated frame');
  } finally {
    await pair.stop();
  }
});

// ---------------------------------------------------------------------------
// 3. 40 KB CONFIDENTIAL — the hybrid path, where the cipher is a single
//    HPKE-Base primitive rather than a `-Z##` group
// ---------------------------------------------------------------------------

test('e2e large payload: 40 KB confidential body round-trips through the hybrid KEM', async () => {
  const pair = await startPair();
  try {
    await pair.connect();

    const secret = bodyOfSize(40 * 1024, 3);
    await pair.managerA.sendConfidentialMessage(pair.identityB.did, secret);
    await pair.receivedByB.waitForCount(1);

    const received = pair.receivedByB.received[0];
    assert.equal(received.confidential, true, 'a confidential send must arrive confidential=true');
    assert.equal(received.body.length, secret.length, 'B must receive all 40 KB of plaintext');
    assert.deepEqual(received.body, secret, 'the 40 KB plaintext must survive the hybrid seal/open');

    // And the reverse direction, to prove both sides can open what they sealed.
    const secretBack = bodyOfSize(40 * 1024, 4);
    await pair.managerB.sendConfidentialMessage(pair.identityA.did, secretBack);
    await pair.receivedByA.waitForCount(1);
    assert.deepEqual(pair.receivedByA.received[0].body, secretBack, 'A must open B\'s 40 KB confidential body');
  } finally {
    await pair.stop();
  }
});

// ---------------------------------------------------------------------------
// 4. An RFI whose inline DID document is >= 20 KB
// ---------------------------------------------------------------------------

test('e2e large payload: RFI with a >= 20 KB inline DID document completes the handshake', async () => {
  // A's published document is legitimately large (many service endpoints), not
  // padded: a long-form did:peer:4 hash commits to the document body, so padded
  // JSON would fail didMethod.verify on B's side.
  const pair = await startPair({ aExtraMultiaddrs: 400 });
  try {
    const docSize = JSON.stringify(pair.identityA.didDocument).length;
    assert.ok(docSize >= 20 * 1024, `A's inline DID document must be >= 20 KB; got ${docSize} bytes`);

    // The handshake itself is the assertion: the RFI carries the large inline
    // document, so B cannot reach 'bidirectional' unless tspOpen/peekEnvelope
    // framed, read and parseDidDocument'd it correctly.
    await pair.connect();

    const recordB = pair.storeB.get(pair.identityB.did, pair.identityA.did);
    assert.ok(recordB, 'B must have a relationship record keyed by A\'s DID');
    assert.equal(recordB!.direction, 'bidirectional');
    assert.ok(recordB!.remoteEd25519Key, 'B must have extracted A\'s Ed25519 key from the large document');

    const recordA = pair.storeA.get(pair.identityA.did, pair.identityB.did);
    assert.equal(recordA!.direction, 'bidirectional');

    // And the relationship is usable afterwards — a normal body on a link whose
    // handshake carried 20 KB+.
    const body = bodyOfSize(1024, 5);
    await pair.managerA.sendMessage(pair.identityB.did, body);
    await pair.receivedByB.waitForCount(1);
    assert.deepEqual(pair.receivedByB.received[0].body, body);
  } finally {
    await pair.stop();
  }
});

