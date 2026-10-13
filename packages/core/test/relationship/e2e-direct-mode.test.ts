/**
 * End-to-end Direct Mode test — Step 6.
 *
 * Two real libp2p nodes, two real did:peer:4 identities, two real
 * RelationshipManagers. Drives through the full Step 6 scenario:
 *
 *   6.1 — Two Node.js instances, each with a did:peer:4 VID
 *   6.2 — Exchange OOBI out of band (in-memory string pass)
 *   6.3 — Complete RFI/RFA handshake over real libp2p transport
 *   6.4 — Exchange signed, non-confidential application messages (TSP_GEN)
 *   6.5 — Confirm relationship-table state matches on both sides
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test \
 *     test/relationship/e2e-direct-mode.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { Libp2pTransport } from '../../src/transport/index.js';
import { RelationshipManager } from '../../src/relationship/manager.js';
import { encodeOobi } from '../../src/relationship/oobi.js';
import { tspSeal } from '../../src/tsp/v3/message.js';
import { generateEd25519KeyPair } from '../../src/crypto/primitives.js';

// The node/identity/store helpers and the waiters live in ./e2e-harness.ts so
// the large-payload suite (e2e-large-payload.test.ts) can drive the same stack
// without forking them.
import {
  makeLibp2pNode,
  makeLocalIdentity,
  makeStore,
  waitForBidirectional,
  waitForGenMessage,
} from './e2e-harness.js';

// ---------------------------------------------------------------------------
// Test 1: Full handshake + bidirectional application message exchange (6.1–6.5)
// ---------------------------------------------------------------------------

test('e2e Direct Mode: full RFI/RFA handshake + TSP_GEN message exchange', async () => {
  // 6.1 — Two Node.js instances, each with a did:peer:4 VID
  const nodeA = await makeLibp2pNode();
  const nodeB = await makeLibp2pNode();

  const identityA = await makeLocalIdentity(nodeA);
  const identityB = await makeLocalIdentity(nodeB);

  const transportA = new Libp2pTransport(nodeA);
  const transportB = new Libp2pTransport(nodeB);
  await transportA.start();
  await transportB.start();

  const storeA = makeStore(identityA, nodeA.peerId.toString());
  const storeB = makeStore(identityB, nodeB.peerId.toString());

  const managerA = new RelationshipManager({ transport: transportA, store: storeA, identity: identityA });
  const managerB = new RelationshipManager({ transport: transportB, store: storeB, identity: identityB });
  managerA.start();
  managerB.start();

  try {
    // 6.2 — B encodes OOBI; A decodes it (simulating out-of-band exchange)
    const bOobi = encodeOobi({
      cesrVid: identityB.cesrVid,
      did: identityB.did,
      peerId: nodeB.peerId.toString(),
      multiaddrs: nodeB.getMultiaddrs().map(a => a.toString()),
    });

    // 6.3 — A sends RFI; wait for both sides to reach bidirectional
    await managerA.sendRfi(bOobi);

    await waitForBidirectional(storeA, identityA.did, identityB.did);
    await waitForBidirectional(storeB, identityB.did, identityA.did);

    // 6.4 — Exchange signed, non-confidential application messages
    const bodyAtoB = new TextEncoder().encode('Hello from A!');
    const bodyBtoA = new TextEncoder().encode('Hello from B!');

    const receivedByB = waitForGenMessage(managerB);
    const receivedByA = waitForGenMessage(managerA);

    await managerA.sendMessage(identityB.did, bodyAtoB);
    await managerB.sendMessage(identityA.did, bodyBtoA);

    const msgAtB = await receivedByB;
    const msgAtA = await receivedByA;

    // Verify message bodies are byte-identical
    assert.deepEqual(
      msgAtB.body,
      bodyAtoB,
      'B must receive the exact bytes A sent',
    );
    assert.deepEqual(
      msgAtA.body,
      bodyBtoA,
      'A must receive the exact bytes B sent',
    );

    // Verify sender VIDs are correct
    assert.equal(msgAtB.remoteDid, identityA.did, 'B must see A as the sender');
    assert.equal(msgAtA.remoteDid, identityB.did, 'A must see B as the sender');

    // 6.5 — Confirm relationship-table state matches on both sides
    const recordA = storeA.get(identityA.did, identityB.did);
    const recordB = storeB.get(identityB.did, identityA.did);

    assert.ok(recordA, 'A must have a relationship record for B');
    assert.equal(recordA!.direction, 'bidirectional', 'A record must be bidirectional');
    assert.equal(recordA!.status, 'established', 'A record must be established');
    assert.ok(recordA!.remoteTransport, 'A record must have remoteTransport for B');
    assert.equal(
      recordA!.remoteTransport!.peerId,
      nodeB.peerId.toString(),
      'A record remoteTransport.peerId must be B\'s peerId',
    );

    assert.ok(recordB, 'B must have a relationship record for A');
    assert.equal(recordB!.direction, 'bidirectional', 'B record must be bidirectional');
    assert.equal(recordB!.status, 'established', 'B record must be established');
    assert.ok(recordB!.remoteTransport, 'B record must have remoteTransport for A');
    assert.equal(
      recordB!.remoteTransport!.peerId,
      nodeA.peerId.toString(),
      'B record remoteTransport.peerId must be A\'s peerId',
    );

    // Verify cross-referenced keys are stored (via FK join to the keys table)
    assert.ok(recordA!.remoteEd25519Key, 'A record must have B\'s Ed25519 key');
    assert.ok(recordB!.remoteEd25519Key, 'B record must have A\'s Ed25519 key');

  } finally {
    await transportA.stop();
    await transportB.stop();
    await nodeA.stop();
    await nodeB.stop();
  }
});

// ---------------------------------------------------------------------------
// Test 2: TSP_GEN from unknown sender is silently discarded
// ---------------------------------------------------------------------------

test('e2e Direct Mode: TSP_GEN from unknown sender is discarded', async () => {
  const nodeA = await makeLibp2pNode();
  const nodeC = await makeLibp2pNode(); // third party — no relationship with A

  const identityA = await makeLocalIdentity(nodeA);
  const identityC = await makeLocalIdentity(nodeC);

  const transportA = new Libp2pTransport(nodeA);
  const transportC = new Libp2pTransport(nodeC);
  await transportA.start();
  await transportC.start();

  const storeA = makeStore(identityA, nodeA.peerId.toString());

  const managerA = new RelationshipManager({ transport: transportA, store: storeA, identity: identityA });
  managerA.start();

  let genMessageFired = false;
  managerA.onGenMessage(() => {
    genMessageFired = true;
  });

  try {
    // C sends a raw TSP_GEN directly to A without any relationship.
    const body = new TextEncoder().encode('Unauthorized message from C');
    const sealed = tspSeal({
      vidSender: identityC.did,
      vidReceiver: identityA.did,
      payload: { type: 'TSP_GEN', body },
      signingSecretKey: identityC.signingKeyPair.secretKey,
    });

    const aAddr = {
      peerId: nodeA.peerId.toString(),
      multiaddrs: nodeA.getMultiaddrs().map(a => a.toString()),
    };
    await transportC.send(sealed, aAddr);

    // Wait long enough for the message to be processed (fire-and-forget handler).
    await new Promise(resolve => setTimeout(resolve, 200));

    assert.equal(genMessageFired, false, 'A must NOT invoke onGenMessage for unknown sender C');
  } finally {
    await transportA.stop();
    await transportC.stop();
    await nodeA.stop();
    await nodeC.stop();
  }
});

// ---------------------------------------------------------------------------
// Test 3: H1 — a forged RFI whose inline document is not the claimed sender
// ---------------------------------------------------------------------------

/**
 * The substitution H1 is about. The RFI/RFA self-addressing digest covers the
 * sender VID and the nonce but NOT the inlined DID document — and the inline
 * document is where the receiver takes the signing key from. So Mallory can put
 * a victim's identity in the sender slot (which the digest covers, and which
 * several paths treat as the peer's identity) while supplying her own document,
 * signed with her own key. Every check the receiver had passed.
 *
 * The paired control is what makes this test meaningful: the SAME Mallory, with
 * only the sender slot corrected to her own DID, completes the handshake. So a
 * rejection cannot be an artefact of the forged message being malformed.
 */
test('e2e Direct Mode: an RFI whose document is not the claimed sender is refused', async () => {
  const nodeA = await makeLibp2pNode();       // the receiver
  const nodeM = await makeLibp2pNode();       // Mallory

  const identityA = await makeLocalIdentity(nodeA);
  const identityM = await makeLocalIdentity(nodeM);

  const transportA = new Libp2pTransport(nodeA);
  const transportM = new Libp2pTransport(nodeM);
  await transportA.start();
  await transportM.start();

  const storeA = makeStore(identityA, nodeA.peerId.toString());
  const storeM = makeStore(identityM, nodeM.peerId.toString());

  const managerA = new RelationshipManager({ transport: transportA, store: storeA, identity: identityA });
  const managerM = new RelationshipManager({ transport: transportM, store: storeM, identity: identityM });
  managerA.start();
  managerM.start();

  const aAddr = {
    peerId: nodeA.peerId.toString(),
    multiaddrs: nodeA.getMultiaddrs().map(a => a.toString()),
  };

  try {
    // ── The forgery ────────────────────────────────────────────────────────
    // Sender slot = A (the claimed identity the digest covers), document =
    // Mallory's, signature = Mallory's key over a Mallory-signed message. The
    // addressee is A, so the receiver's addressee check passes too.
    const nonce = new Uint8Array(16).fill(0x9c);
    const forged = tspSeal({
      vidSender: identityA.did,
      vidReceiver: identityA.did,
      payload: { type: 'TSP_RFI', nonce, didDocument: identityM.didDocument },
      signingSecretKey: identityM.signingKeyPair.secretKey,
    });
    await transportM.send(forged, aAddr);
    await new Promise(resolve => setTimeout(resolve, 300));

    // A must not have created ANY relationship from it — neither for the claimed
    // identity nor for the identity whose document was supplied.
    assert.equal(
      storeA.get(identityA.did, identityA.did),
      undefined,
      'no relationship may be recorded for the claimed identity',
    );
    assert.equal(
      storeA.get(identityA.did, identityM.did),
      undefined,
      'no relationship may be recorded for the document owner either',
    );
    assert.equal(storeA.list(identityA.did).length, 0, 'A must have no relationship rows at all');

    // ── The control: the same Mallory, honestly self-identified ────────────
    const oobiA = encodeOobi({
      cesrVid: identityA.cesrVid,
      did: identityA.did,
      peerId: nodeA.peerId.toString(),
      multiaddrs: nodeA.getMultiaddrs().map(a => a.toString()),
    });
    await managerM.sendRfi(oobiA);

    await waitForBidirectional(storeA, identityA.did, identityM.did);
    await waitForBidirectional(storeM, identityM.did, identityA.did);

    // The legitimate handshake worked, so the refusal above was the binding
    // mismatch and not a broken path. The forged message left no residue.
    assert.equal(storeA.list(identityA.did).length, 1, 'exactly one relationship after the control');
  } finally {
    await transportA.stop();
    await transportM.stop();
    await nodeA.stop();
    await nodeM.stop();
  }
});


// ---------------------------------------------------------------------------
// Test 4: Step 7 — confidential message exchange (TSP_GEN_CONFIDENTIAL)
// ---------------------------------------------------------------------------

test('e2e Direct Mode Step 7: confidential message exchange between two did:peer:4 endpoints', async () => {
  const nodeA = await makeLibp2pNode();
  const nodeB = await makeLibp2pNode();
  await nodeA.start();
  await nodeB.start();

  const identityA = await makeLocalIdentity(nodeA);
  const identityB = await makeLocalIdentity(nodeB);

  const transportA = new Libp2pTransport(nodeA);
  const transportB = new Libp2pTransport(nodeB);
  await transportA.start();
  await transportB.start();

  const storeA = makeStore(identityA, nodeA.peerId.toString());
  const storeB = makeStore(identityB, nodeB.peerId.toString());

  const managerA = new RelationshipManager({ transport: transportA, store: storeA, identity: identityA });
  const managerB = new RelationshipManager({ transport: transportB, store: storeB, identity: identityB });
  managerA.start();
  managerB.start();

  // Track received messages on both sides.
  const receivedByA: Array<{ remoteDid: string; body: Uint8Array; confidential: boolean }> = [];
  const receivedByB: Array<{ remoteDid: string; body: Uint8Array; confidential: boolean }> = [];

  managerA.onGenMessage((remoteDid, body, confidential) => {
    receivedByA.push({ remoteDid, body, confidential });
  });
  managerB.onGenMessage((remoteDid, body, confidential) => {
    receivedByB.push({ remoteDid, body, confidential });
  });

  try {
    // 7.4.0 — Complete RFI/RFA handshake first (same as Step 6 Test 1).
    const oobiB = encodeOobi({
      cesrVid: identityB.cesrVid,
      did: identityB.did,
      peerId: nodeB.peerId.toString(),
      multiaddrs: nodeB.getMultiaddrs().map(ma => ma.toString()),
    });

    await managerA.sendRfi(oobiB);
    await new Promise(resolve => setTimeout(resolve, 500));

    const recordA = managerA.getRelationship(identityB.did);
    const recordB = managerB.getRelationship(identityA.did);
    assert.ok(recordA, 'A must have a relationship record for B after handshake');
    assert.ok(recordB, 'B must have a relationship record for A after handshake');
    assert.equal(recordA!.direction, 'bidirectional', 'A→B relationship must be bidirectional');
    assert.equal(recordB!.direction, 'bidirectional', 'B→A relationship must be bidirectional');

    // 7.4.1 — A sends a confidential message to B.
    const secretFromA = new TextEncoder().encode('Secret from A to B!');
    await managerA.sendConfidentialMessage(identityB.did, secretFromA);
    await new Promise(resolve => setTimeout(resolve, 300));

    // 7.4.2 — B sends a confidential message to A.
    const secretFromB = new TextEncoder().encode('Secret from B to A!');
    await managerB.sendConfidentialMessage(identityA.did, secretFromB);
    await new Promise(resolve => setTimeout(resolve, 300));

    // 7.4.3 — Assert both onGenMessage callbacks fired with correct body and confidential=true.
    assert.equal(receivedByB.length, 1, 'B must have received exactly 1 message from A');
    assert.deepEqual(receivedByB[0].body, secretFromA, 'B must receive the correct plaintext from A');
    assert.equal(receivedByB[0].confidential, true, 'B must see confidential=true for TSP_GEN_CONFIDENTIAL');
    assert.equal(receivedByB[0].remoteDid, identityA.did, 'B must see A\'s VID as the sender');

    assert.equal(receivedByA.length, 1, 'A must have received exactly 1 message from B');
    assert.deepEqual(receivedByA[0].body, secretFromB, 'A must receive the correct plaintext from B');
    assert.equal(receivedByA[0].confidential, true, 'A must see confidential=true for TSP_GEN_CONFIDENTIAL');
    assert.equal(receivedByA[0].remoteDid, identityB.did, 'A must see B\'s VID as the sender');

    // 7.4.4 — Assert non-confidential sendMessage() still works (confidential=false).
    const plainFromA = new TextEncoder().encode('Plain message from A');
    await managerA.sendMessage(identityB.did, plainFromA);
    await new Promise(resolve => setTimeout(resolve, 300));

    assert.equal(receivedByB.length, 2, 'B must have received 2 messages total (1 confidential + 1 plain)');
    assert.deepEqual(receivedByB[1].body, plainFromA, 'B must receive the correct plaintext from A (non-confidential)');
    assert.equal(receivedByB[1].confidential, false, 'B must see confidential=false for TSP_GEN');
  } finally {
    await transportA.stop();
    await transportB.stop();
    await nodeA.stop();
    await nodeB.stop();
  }
});

test('e2e Direct Mode: sendMessage() throws before relationship is established', async () => {
  const nodeA = await makeLibp2pNode();
  const identityA = await makeLocalIdentity(nodeA);

  const transportA = new Libp2pTransport(nodeA);
  await transportA.start();

  const storeA = makeStore(identityA, nodeA.peerId.toString());

  const managerA = new RelationshipManager({ transport: transportA, store: storeA, identity: identityA });
  managerA.start();

  try {
    // Generate a random VID that has no relationship with A.
    const unknownKp = generateEd25519KeyPair();
    const unknownVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, unknownKp.publicKey);

    await assert.rejects(
      () => managerA.sendMessage(unknownVid, new TextEncoder().encode('test')),
      /no bidirectional relationship/,
      'sendMessage must throw when no bidirectional relationship exists',
    );
  } finally {
    await transportA.stop();
    await nodeA.stop();
  }
});
