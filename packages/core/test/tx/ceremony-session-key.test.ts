/**
 * Regression test for the ceremony never completing.
 *
 * Each agent's VrcCeremonyStore is keyed by (local_did, remote_did).
 *   - On receipt of a personhood_ack / local press, acknowledgePeer() creates
 *     the ceremony session with (ctx.identity.cesrVid, remoteDid)  -> both VIDs.
 *   - Later, the peer delivers its VRC via store_remote_vrc; the receive side
 *     (VrcReceiveParticipant.prepare) marks the mirrored session
 *     peer_vrc_received=true by calling ensureSession(subjectDid, issuerVid).
 *
 * Invariant under test: on ONE agent's store, the ceremony session it created
 * and the session the receive side targets MUST be the SAME row, so the flag
 * actually lands on the ceremony the driver is advancing. If either side keys
 * by a DID instead of a VID (or orders the pair differently), they diverge and
 * the ceremony stalls forever at peerVrcReceived=false.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { TX_SCHEMA_SQL } from '../../src/tx/schema.js';
import { VrcCeremonyStore } from '../../src/tx/vrc-ceremony-store.js';

test('receive-side session key equals the ceremony session key (DID, DID)', async () => {
  const ds = new SqliteDataSource(':memory:');
  await ds.exec(TX_SCHEMA_SQL);
  const store = new VrcCeremonyStore(ds);

  // Bob is this agent; Alice is the remote peer. Sessions are keyed by real
  // DIDs (stable), not the ephemeral VID.
  const bobDid = 'did:scid:vh:1:zBob';
  const aliceDid = 'did:scid:vh:1:zAlice';

  // Bob acknowledges Alice -> ceremony session keyed (bobDid, aliceDid).
  const ceremonySession = await store.ensureSession(bobDid, aliceDid);

  // Bob receives Alice's VRC. Bob is the subject (his DID), Alice is the
  // issuer (Alice's DID relayed). The receive side must hit the SAME row.
  const receiveSession = await store.ensureSession(bobDid, aliceDid);
  assert.equal(receiveSession.sessionId, ceremonySession.sessionId);

  // Simulate VrcReceiveParticipant setting the flag on the receive session.
  await store.setLeg(receiveSession.sessionId, { peerVrcReceived: true });
  const after = await store.getById(ceremonySession.sessionId);
  assert.equal(after.peerVrcReceived, true, 'flag must land on the ceremony session the driver advances');

  // The reverse direction (Alice's own store) uses the inverse pair.
  const aliceOwn = await store.ensureSession(aliceDid, bobDid);
  assert.notEqual(aliceOwn.sessionId, ceremonySession.sessionId);
  assert.equal(aliceOwn.localDid, aliceDid);
  assert.equal(aliceOwn.remoteDid, bobDid);
});
