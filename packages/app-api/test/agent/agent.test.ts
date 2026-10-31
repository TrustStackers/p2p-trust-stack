// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Integration tests for the Agent module.
 *
 * Uses real libp2p nodes (tcp, yamux, noise, identify) — no mocks.
 * Uses a temporary directory for each test to avoid cross-test pollution.
 *
 * Covers:
 *   - Agent.create(): creates a new agent, persists keys + metadata
 *   - Agent.unlock(): loads and decrypts an existing agent
 *   - Agent.list(): enumerates agents from the registry
 *   - Agent.start() / stop(): boots and shuts down the real libp2p node
 *   - generateOobi(): produces a valid CESR-encoded OOBI after start()
 *   - connectToPeer(): completes a real RFI/RFA handshake
 *   - sendMessage() / onMessage(): plain TSP_GEN message exchange
 *   - sendConfidentialMessage() / onMessage(): HPKE-Auth encrypted message exchange
 *   - Wrong passphrase throws on unlock
 *   - Duplicate agent name throws on create
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/agent/agent.test.ts
 */

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { Agent } from '../../src/runtime/agent.js';
import type { AgentHandle } from '../../src/runtime/handle.js';
import { AgentRegistry } from '../../src/runtime/agent-registry.js';
import { RelationshipAlreadyExistsError } from '@p2p-trust-stack/core/relationship/types.js';
import { decodeOobi } from '@p2p-trust-stack/core/relationship/oobi.js';
import { ML_DSA_65_SIG_BYTES } from '@p2p-trust-stack/core/crypto/pqc.js';
import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { getVtaPaths } from '@p2p-trust-stack/core/platform/p2pts-home.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Create a temporary directory for a test and return a registry scoped to it.
 * The directory is cleaned up after the test.
 */
function makeTempRegistry(): { registry: AgentRegistry; dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'lp2ptoip-test-'));
  // AgentRegistry(dbPath?, keystorePath?, p2ptsHome?) — passing `dir` as the
  // single arg would set it as dbPath while P2PTS_HOME stays the real user dir,
  // which pollutes/interferes with the real on-disk store. Pass it as p2ptsHome
  // so the whole VTA tree (db + keystore) is isolated under the temp dir.
  const registry = new AgentRegistry(undefined, undefined, dir);
  return {
    registry,
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/**
 * Wait for a relationship to become bidirectional, or throw after timeout.
 */
async function waitForBidirectional(
  agent: AgentHandle,
  remoteDid: string,
  timeoutMs = 8000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const record = agent.getRelationship(remoteDid);
    if (record?.direction === 'bidirectional') return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`waitForBidirectional: timed out after ${timeoutMs}ms`);
}

/**
 * Wait for a relationship record to disappear (personhood ceremony expiry
 * teardown), or throw after timeout.
 */
async function waitForRelationshipGone(
  agent: AgentHandle,
  remoteDid: string,
  timeoutMs = 20000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!agent.getRelationship(remoteDid)) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`waitForRelationshipGone: relationship with ${remoteDid.slice(0, 12)} was not cleared within ${timeoutMs}ms`);
}

/**
 * Wait for a relationship's personhood status to reach 'verified' (the local
 * mirror of the ceremony completed: mutual ack + both VRCs exchanged), or throw
 * with the status that was actually observed.
 */
async function waitForPersonhoodVerified(
  agent: AgentHandle,
  remoteDid: string,
  timeoutMs = 60_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const record = agent.getRelationship(remoteDid);
    if (record?.personhoodStatus === 'verified') return;
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  const record = agent.getRelationship(remoteDid);
  const status = agent.getCeremonyStatus
    ? await agent.getCeremonyStatus(remoteDid)
    : null;
  throw new Error(
    `waitForPersonhoodVerified: ${remoteDid.slice(0, 12)}... did not reach 'verified' within ${timeoutMs}ms ` +
    `(personhoodStatus=${record?.personhoodStatus ?? 'undefined'}, ` +
    `phase=${status?.phase ?? 'n/a'}, failedStep=${status?.failedStep ?? 'n/a'}, ` +
    `lastError=${status?.lastError ?? 'n/a'})`,
  );
}

/**
 * Read an Agent's TspClientModule through its (protected) field so a test can
 * assert the TSP transport is wired, without adding a production accessor.
 */
function readTspClient(agent: AgentHandle): { isInitialized(): boolean } {
  return (agent as unknown as { tspClient: { isInitialized(): boolean } }).tspClient;
}

/**
 * Directly mark a relationship's personhood ceremony as 'verified' in the
 * agent's SQLite DB (per-agent dir at p2ptsHome/vta/<agentName>/p2pts-database.db).
 *
 * Simulates a FULLY completed ceremony (both VRCs minted and exchanged) so the
 * re-paste guard can be tested deterministically. The real coordinator
 * ceremony cannot finish in this environment because the peer_delivery legs
 * to the OTHER agent's transaction coordinator abort without the utility
 * server / P2P delivery path that the full app provides.
 */
function setPersonhoodVerified(p2ptsHome: string, agentName: string, localDid: string, remoteDid: string): void {
  const db = new DatabaseSync(getVtaPaths(agentName, p2ptsHome).dbPath);
  try {
    const result = db.prepare(`
      UPDATE relationships
      SET personhood_status = 'verified', updated_at = unixepoch()
      WHERE local_identity_uuid = (
        SELECT i.uuid FROM identities i
        JOIN did_documents d ON d.identity_uuid = i.uuid AND d.did = ?
      )
      AND remote_identity_uuid = (
        SELECT i.uuid FROM identities i
        JOIN did_documents d ON d.identity_uuid = i.uuid AND d.did = ?
      )
    `).run(localDid, remoteDid) as { changes: number } | undefined;
    if (!result || result.changes === 0) {
      throw new Error(
        `setPersonhoodVerified: no relationship row for ${localDid.slice(0, 12)} ↔ ${remoteDid.slice(0, 12)}`,
      );
    }
  } finally {
    db.close();
  }
}

// ---------------------------------------------------------------------------
// Test: Agent.create() and Agent.list()
// ---------------------------------------------------------------------------

test('Agent.create: creates agent, persists metadata, appears in list', async () => {
  const { registry, cleanup } = makeTempRegistry();
  after(cleanup);

  const agent = await Agent.create({ name: 'alice', passphrase: 'test-pass-1' }, registry);

  assert.equal(agent.getName(), 'alice');
  assert.ok(agent.getVid().startsWith('D'), 'VID must be a CESR-encoded Ed25519 key (starts with D)');
  assert.ok(agent.getDid().startsWith('did:scid:vh'), 'DID must be a did:scid:vh string');

  const list = Agent.list(registry);
  assert.equal(list.length, 1, 'registry must list exactly one agent');
  assert.equal(list[0].name, 'alice');
  assert.equal(list[0].vid, agent.getVid());
  assert.equal(list[0].did, agent.getDid());
});

test('Agent.create: persists PQ roots of trust in the keystore (H4)', async () => {
  const { registry, cleanup } = makeTempRegistry();
  after(cleanup);

  const agent = await Agent.create({ name: 'pqcheck', passphrase: 'test-pass-2' }, registry);
  const vid = agent.getVid();

  // The DID document publishes #key-mldsa / #key-kem from the start, and
  // `loadIdentity()` reads the SECRETS from the keystore by label. Nothing used
  // to write them, so the pair lived in the document and nowhere else: every
  // agent created this way logged "no ML-DSA-65 key", could not sign its OOBI,
  // could not sign a rotation, and stayed classical on confidential traffic.
  const keystore = new SqliteKeyStore(registry.getKeystorePath('pqcheck'));
  try {
    for (const keyType of ['ml_dsa_65', 'mlkem768_x25519'] as const) {
      const pair = await keystore.retrieveKeyPairAsync(vid, keyType, 'test-pass-2');
      assert.ok(pair.publicKey.length > 0, `${keyType} must be stored under the agent's VID label`);
      assert.ok(pair.secretKey.length > 0, `${keyType} must be stored WITH its secret half`);
    }
    // The classical keys stay where they were (no regression to the old path).
    const ed = await keystore.retrieveKeyPairAsync(vid, 'ed25519', 'test-pass-2');
    assert.ok(ed.secretKey.length > 0, 'ed25519 must still be persisted');
  } finally {
    keystore.close();
  }
});


test('Agent.create: throws if agent name already exists', async () => {
  const { registry, cleanup } = makeTempRegistry();
  after(cleanup);

  await Agent.create({ name: 'bob', passphrase: 'pass-1' }, registry);

  await assert.rejects(
    () => Agent.create({ name: 'bob', passphrase: 'pass-2' }, registry),
    /already exists/,
    'creating a duplicate agent name must throw',
  );
});

// ---------------------------------------------------------------------------
// Test: Agent.unlock() round-trip
// ---------------------------------------------------------------------------

test('Agent.unlock: loads and decrypts keys correctly', async () => {
  const { registry, cleanup } = makeTempRegistry();
  after(cleanup);

  const created = await Agent.create({ name: 'carol', passphrase: 'my-passphrase' }, registry);
  const unlocked = await Agent.unlock({ name: 'carol', passphrase: 'my-passphrase' }, registry);

  assert.equal(unlocked.getVid(), created.getVid(), 'unlocked VID must match created VID');
  assert.equal(unlocked.getDid(), created.getDid(), 'unlocked DID must match created DID');
});

// ---------------------------------------------------------------------------
// Test: Agent.unlock() throws on wrong passphrase
// ---------------------------------------------------------------------------

test('Agent.unlock: throws on wrong passphrase', async () => {
  const { registry, cleanup } = makeTempRegistry();
  after(cleanup);

  await Agent.create({ name: 'dave', passphrase: 'correct-pass' }, registry);

  await assert.rejects(
    () => Agent.unlock({ name: 'dave', passphrase: 'wrong-pass' }, registry),
    /decryption failed/,
    'wrong passphrase must throw a decryption error',
  );
});

// ---------------------------------------------------------------------------
// Test: Agent.unlock() throws if agent does not exist
// ---------------------------------------------------------------------------

test('Agent.unlock: throws if agent does not exist', async () => {
  const { registry, cleanup } = makeTempRegistry();
  after(cleanup);

  await assert.rejects(
    () => Agent.unlock({ name: 'nonexistent', passphrase: 'pass' }, registry),
    /not found/,
    'unlocking a nonexistent agent must throw',
  );
});

// ---------------------------------------------------------------------------
// Test: Agent.start() / stop() lifecycle
// ---------------------------------------------------------------------------

test('Agent.start/stop: boots real libp2p node and shuts down cleanly', async () => {
  const { registry, cleanup } = makeTempRegistry();
  after(cleanup);

  const agent = await Agent.create({ name: 'eve', passphrase: 'pass' }, registry);
  await agent.start();

  try {
    assert.ok(agent.getPeerId().length > 0, 'PeerID must be non-empty after start');
    assert.ok(agent.getMultiaddrs().length > 0, 'must have at least one multiaddr after start');
  } finally {
    await agent.stop();
  }
});

// ---------------------------------------------------------------------------
// Test: generateOobi() after start()
// ---------------------------------------------------------------------------

test('Agent.generateOobi: returns a valid CESR-encoded OOBI after start', async () => {
  const { registry, cleanup } = makeTempRegistry();
  after(cleanup);

  const agent = await Agent.create({ name: 'frank', passphrase: 'pass' }, registry);
  await agent.start();

  try {
    const oobi = agent.generateOobi();
    assert.ok(typeof oobi === 'string', 'OOBI must be a string');
    assert.ok(oobi.length > 0, 'OOBI must be non-empty');
    // CESR group frame: `-TA` plus a count code. An UNSIGNED OOBI (4 items:
    // vid, peerId, multiaddrs, did) is `-TAE`; a SIGNED one appends the ML-DSA-65
    // signature as a 5th item, so it is `-TAF`. This assertion used to demand
    // `-TAE` — i.e. it pinned the UNSIGNED form as the contract, which is how the
    // missing PQ persistence stayed invisible.
    assert.ok(
      oobi.startsWith('-TAF'),
      `a PQ-provisioned agent must emit the 5-item signed OOBI frame, got "${oobi.slice(0, 8)}"`,
    );

    // H4: the introduction must actually be SIGNED. The DID document published a
    // #key-mldsa from the start, but nothing ever stored the secret — so
    // `loadIdentity()` reported "no ML-DSA-65 key" for a brand-new agent and this
    // OOBI came out unsigned (a receiver under the `enforce` policy would refuse
    // it). Verification against the document's key is covered by the manager and
    // OOBI tests; what this pins is that the agent HAD a key to sign with.
    const payload = decodeOobi(oobi);
    assert.ok(
      payload.mlDsa65Signature,
      'a freshly created agent must be able to ML-DSA-sign its own introduction',
    );
    assert.equal(
      payload.mlDsa65Signature!.length,
      ML_DSA_65_SIG_BYTES,
      'the signature must be a full ML-DSA-65 signature, not a truncated one',
    );
  } finally {
    await agent.stop();
  }
});

// ---------------------------------------------------------------------------
// Test: generateOobi() throws before start()
// ---------------------------------------------------------------------------

test('Agent.generateOobi: throws if agent not started', async () => {
  const { registry, cleanup } = makeTempRegistry();
  after(cleanup);

  const agent = await Agent.create({ name: 'grace', passphrase: 'pass' }, registry);

  assert.throws(
    () => agent.generateOobi(),
    /not started/,
    'generateOobi must throw if agent not started',
  );
});

// ---------------------------------------------------------------------------
// Test: Full RFI/RFA handshake between two real agents
// ---------------------------------------------------------------------------

test('Agent: full RFI/RFA handshake between two real agents', async () => {
  const { registry: regA, cleanup: cleanA } = makeTempRegistry();
  const { registry: regB, cleanup: cleanB } = makeTempRegistry();
  after(cleanA);
  after(cleanB);

  const agentA = await Agent.create({ name: 'alice', passphrase: 'pass-a' }, regA);
  const agentB = await Agent.create({ name: 'bob', passphrase: 'pass-b' }, regB);

  await agentA.start();
  await agentB.start();

  try {
    // B generates OOBI; A connects to B
    const bOobi = agentB.generateOobi();
    await agentA.connectToPeer(bOobi);

    // Wait for both sides to reach bidirectional
    await waitForBidirectional(agentA, agentB.getVid());
    await waitForBidirectional(agentB, agentA.getVid());

    const recA = agentA.getRelationship(agentB.getVid());
    const recB = agentB.getRelationship(agentA.getVid());

    assert.ok(recA, 'A must have a relationship record for B');
    assert.equal(recA!.direction, 'bidirectional', 'A→B must be bidirectional');
    assert.equal(recA!.status, 'established', 'A→B must be established');

    assert.ok(recB, 'B must have a relationship record for A');
    assert.equal(recB!.direction, 'bidirectional', 'B→A must be bidirectional');
    assert.equal(recB!.status, 'established', 'B→A must be established');
  } finally {
    await agentA.stop();
    await agentB.stop();
  }
});

// ---------------------------------------------------------------------------
// Test: Plain message exchange (TSP_GEN)
// ---------------------------------------------------------------------------

test('Agent: plain message exchange (TSP_GEN) after handshake', async () => {
  const { registry: regA, cleanup: cleanA } = makeTempRegistry();
  const { registry: regB, cleanup: cleanB } = makeTempRegistry();
  after(cleanA);
  after(cleanB);

  const agentA = await Agent.create({ name: 'alice', passphrase: 'pass-a' }, regA);
  const agentB = await Agent.create({ name: 'bob', passphrase: 'pass-b' }, regB);

  await agentA.start();
  await agentB.start();

  const receivedByB: Array<{ remoteDid: string; body: string; confidential: boolean }> = [];
  const receivedByA: Array<{ remoteDid: string; body: string; confidential: boolean }> = [];

  agentB.onMessage(msg => {
    receivedByB.push({
      remoteDid: msg.remoteDid,
      body: new TextDecoder().decode(msg.body),
      confidential: msg.confidential,
    });
  });
  agentA.onMessage(msg => {
    receivedByA.push({
      remoteDid: msg.remoteDid,
      body: new TextDecoder().decode(msg.body),
      confidential: msg.confidential,
    });
  });

  try {
    const bOobi = agentB.generateOobi();
    await agentA.connectToPeer(bOobi);

    await waitForBidirectional(agentA, agentB.getVid());
    await waitForBidirectional(agentB, agentA.getVid());

    await agentA.sendMessage(agentB.getVid(), new TextEncoder().encode('Hello from A!'));
    await agentB.sendMessage(agentA.getVid(), new TextEncoder().encode('Hello from B!'));

    // Wait for messages to arrive
    await new Promise(resolve => setTimeout(resolve, 500));

    assert.equal(receivedByB.length, 1, 'B must receive exactly 1 message from A');
    assert.equal(receivedByB[0].body, 'Hello from A!', 'B must receive correct message body');
    assert.equal(receivedByB[0].confidential, false, 'plain message must have confidential=false');
    assert.equal(receivedByB[0].remoteDid, agentA.getDid(), 'B must see A as sender');

    assert.equal(receivedByA.length, 1, 'A must receive exactly 1 message from B');
    assert.equal(receivedByA[0].body, 'Hello from B!', 'A must receive correct message body');
    assert.equal(receivedByA[0].confidential, false, 'plain message must have confidential=false');
    assert.equal(receivedByA[0].remoteDid, agentB.getDid(), 'A must see B as sender');
  } finally {
    await agentA.stop();
    await agentB.stop();
  }
});

// ---------------------------------------------------------------------------
// Test: Confidential message exchange (TSP_GEN_CONFIDENTIAL)
// ---------------------------------------------------------------------------

test('Agent: confidential message exchange (TSP_GEN_CONFIDENTIAL) after handshake', async () => {
  const { registry: regA, cleanup: cleanA } = makeTempRegistry();
  const { registry: regB, cleanup: cleanB } = makeTempRegistry();
  after(cleanA);
  after(cleanB);

  const agentA = await Agent.create({ name: 'alice', passphrase: 'pass-a' }, regA);
  const agentB = await Agent.create({ name: 'bob', passphrase: 'pass-b' }, regB);

  await agentA.start();
  await agentB.start();

  const receivedByB: Array<{ body: string; confidential: boolean }> = [];
  const receivedByA: Array<{ body: string; confidential: boolean }> = [];

  agentB.onMessage(msg => {
    receivedByB.push({ body: new TextDecoder().decode(msg.body), confidential: msg.confidential });
  });
  agentA.onMessage(msg => {
    receivedByA.push({ body: new TextDecoder().decode(msg.body), confidential: msg.confidential });
  });

  try {
    const bOobi = agentB.generateOobi();
    await agentA.connectToPeer(bOobi);

    await waitForBidirectional(agentA, agentB.getVid());
    await waitForBidirectional(agentB, agentA.getVid());

    await agentA.sendConfidentialMessage(agentB.getVid(), new TextEncoder().encode('Secret from A!'));
    await agentB.sendConfidentialMessage(agentA.getVid(), new TextEncoder().encode('Secret from B!'));

    await new Promise(resolve => setTimeout(resolve, 500));

    assert.equal(receivedByB.length, 1, 'B must receive exactly 1 confidential message');
    assert.equal(receivedByB[0].body, 'Secret from A!', 'B must decrypt A\'s secret correctly');
    assert.equal(receivedByB[0].confidential, true, 'confidential message must have confidential=true');

    assert.equal(receivedByA.length, 1, 'A must receive exactly 1 confidential message');
    assert.equal(receivedByA[0].body, 'Secret from B!', 'A must decrypt B\'s secret correctly');
    assert.equal(receivedByA[0].confidential, true, 'confidential message must have confidential=true');
  } finally {
    await agentA.stop();
    await agentB.stop();
  }
});

// ---------------------------------------------------------------------------
// Test: Agent.list() with multiple agents
// ---------------------------------------------------------------------------

test('Agent.list: returns all agents sorted by creation time', async () => {
  const { registry, cleanup } = makeTempRegistry();
  after(cleanup);

  await Agent.create({ name: 'first', passphrase: 'p1' }, registry);
  // Small delay to ensure different createdAt timestamps
  await new Promise(resolve => setTimeout(resolve, 10));
  await Agent.create({ name: 'second', passphrase: 'p2' }, registry);
  await new Promise(resolve => setTimeout(resolve, 10));
  await Agent.create({ name: 'third', passphrase: 'p3' }, registry);

  const list = Agent.list(registry);
  assert.equal(list.length, 3, 'must list all 3 agents');
  assert.equal(list[0].name, 'first', 'first agent must be oldest');
  assert.equal(list[1].name, 'second');
  assert.equal(list[2].name, 'third');
});

// ---------------------------------------------------------------------------
// Test: onRelationshipChange fires when handshake completes
// ---------------------------------------------------------------------------

test('Agent.onRelationshipChange: fires when relationship becomes bidirectional', async () => {
  const { registry: regA, cleanup: cleanA } = makeTempRegistry();
  const { registry: regB, cleanup: cleanB } = makeTempRegistry();
  after(cleanA);
  after(cleanB);

  const agentA = await Agent.create({ name: 'alice', passphrase: 'pass-a' }, regA);
  const agentB = await Agent.create({ name: 'bob', passphrase: 'pass-b' }, regB);

  await agentA.start();
  await agentB.start();

  const changesOnA: string[] = [];
  agentA.onRelationshipChange(record => {
    changesOnA.push(`${record.direction}:${record.status}`);
  });

  try {
    const bOobi = agentB.generateOobi();
    await agentA.connectToPeer(bOobi);

    await waitForBidirectional(agentA, agentB.getVid());

    // Give the polling interval time to fire
    await new Promise(resolve => setTimeout(resolve, 300));

    assert.ok(changesOnA.length > 0, 'onRelationshipChange must have fired at least once');
    assert.ok(
      changesOnA.some(s => s === 'bidirectional:established'),
      `must have fired with bidirectional:established, got: ${changesOnA.join(', ')}`,
    );
  } finally {
    await agentA.stop();
    await agentB.stop();
  }
});
// ---------------------------------------------------------------------------
// Test: Re-pasting an OOBI for an already-verified relationship is refused
// ---------------------------------------------------------------------------

test('Agent: re-paste OOBI for an already-verified relationship throws RelationshipAlreadyExistsError (no RFI sent)', async () => {
  const { registry: regA, cleanup: cleanA, dir: dirA } = makeTempRegistry();
  const { registry: regB, cleanup: cleanB } = makeTempRegistry();
  after(cleanA);
  after(cleanB);

  const agentA = await Agent.create({ name: 'alice', passphrase: 'pass-a' }, regA);
  const agentB = await Agent.create({ name: 'bob', passphrase: 'pass-b' }, regB);

  await agentA.start();
  await agentB.start();

  try {
    // Complete the OOBI exchange + connect handshake.
    const bOobi = agentB.generateOobi();
    await agentA.connectToPeer(bOobi);
    await waitForBidirectional(agentA, agentB.getVid());
    await waitForBidirectional(agentB, agentA.getVid());

    // Simulate a fully completed ceremony (VRCs minted + exchanged): both
    // sides would be personhood 'verified'.
    setPersonhoodVerified(dirA, 'alice', agentA.getDid(), agentB.getDid());
    assert.equal(
      agentA.getRelationship(agentB.getVid())?.personhoodStatus,
      'verified',
      'patched relationship must read back as verified',
    );

    // Re-pasting B's OOBI must be refused with the acknowledgment-required
    // error — no duplicate RFI may be sent for an existing relationship.
    await assert.rejects(
      () => agentA.connectToPeer(bOobi),
      (err: unknown) => {
        assert.ok(
          err instanceof RelationshipAlreadyExistsError,
          `expected RelationshipAlreadyExistsError, got ${(err as Error)?.constructor?.name}: ${(err as Error)?.message}`,
        );
        assert.equal((err as RelationshipAlreadyExistsError).code, 'RELATIONSHIP_EXISTS');
        assert.equal((err as RelationshipAlreadyExistsError).statusCode, 409);
        return true;
      },
      're-paste of an already-verified relationship must throw RelationshipAlreadyExistsError',
    );

    // The relationship must be left untouched by the refused re-paste.
    const intact = agentA.getRelationship(agentB.getVid());
    assert.equal(intact?.direction, 'bidirectional', 'relationship must remain bidirectional');
    assert.equal(intact?.status, 'established', 'relationship must remain established');
    assert.equal(intact?.personhoodStatus, 'verified', 'relationship must remain verified');
  } finally {
    await agentA.stop();
    await agentB.stop();
  }
});

// ---------------------------------------------------------------------------
// Test: Uncompleted ceremony expires after the deadline → state cleared + retry
// ---------------------------------------------------------------------------

test('Agent: uncompleted personhood ceremony expires after the ack deadline — connection cleared, fresh OOBI re-paste succeeds', async () => {
  const { registry: regA, cleanup: cleanA } = makeTempRegistry();
  const { registry: regB, cleanup: cleanB } = makeTempRegistry();
  after(cleanA);
  after(cleanB);

  const agentA = await Agent.create({ name: 'carol', passphrase: 'pass-c' }, regA);
  const agentB = await Agent.create({ name: 'dave', passphrase: 'pass-d' }, regB);

  await agentA.start();
  await agentB.start();

  const prevTimeout = process.env.LP2P_CEREMONY_ACK_TIMEOUT_MS;
  const bOobi = agentB.generateOobi();
  try {
    await agentA.connectToPeer(bOobi);
    await waitForBidirectional(agentA, agentB.getVid());
    await waitForBidirectional(agentB, agentA.getVid());

    // Neither side pushes "I know this person". Shorten the ack deadline so
    // the ceremony driver (4s tick) sweeps the stale ceremony and clears the
    // connection attempt on both sides.
    process.env.LP2P_CEREMONY_ACK_TIMEOUT_MS = '500';

    await waitForRelationshipGone(agentA, agentB.getVid());
    await waitForRelationshipGone(agentB, agentA.getVid());
  } finally {
    if (prevTimeout === undefined) delete process.env.LP2P_CEREMONY_ACK_TIMEOUT_MS;
    else process.env.LP2P_CEREMONY_ACK_TIMEOUT_MS = prevTimeout;
  }

  // With the stale connection attempt cleared, a fresh OOBI exchange + connect
  // succeeds (no "already connected" refusal) and re-establishes the
  // relationship so the ceremony can be completed this time.
  try {
    await agentA.connectToPeer(bOobi);
    await waitForBidirectional(agentA, agentB.getVid());
    await waitForBidirectional(agentB, agentA.getVid());

    const reA = agentA.getRelationship(agentB.getVid());
    const reB = agentB.getRelationship(agentA.getVid());
    assert.equal(reA?.direction, 'bidirectional', 'A→B must be bidirectional after retry');
    assert.equal(reB?.direction, 'bidirectional', 'B→A must be bidirectional after retry');
  } finally {
    await agentA.stop();
    await agentB.stop();
  }
});

// ---------------------------------------------------------------------------
// Test: pure peer-to-peer personhood ceremony — NO utility server
// ---------------------------------------------------------------------------

/**
 * The peer-to-peer-only exchange ("I know this person" pressed by both with no
 * accessible utility server) must run the whole ceremony to completion and must
 * NOT depend on the utility-server configuration path.
 *
 * Regression guarded here: `TspBridge.init()` used to be called ONLY from
 * `configureUtilityServer()`, which never runs when no utility server is
 * discovered. `TspBridge.init()` is the single writer of the TspClientModule's
 * send function, so in this scenario `sendFn` stayed null and EVERY
 * `TspClientModule.request()` threw
 * `TspClientModule.request: not initialized. Call init() first.`. Every
 * ceremony coordinator leg that reaches the peer (ack_delivery, peer_delivery)
 * therefore aborted, the retry ladder ran, the 60 s ack window closed, and the
 * relationship + ceremony state was torn down and reset. The bridge is now
 * wired in `start()`, as soon as the RelationshipManager exists.
 */
test('Agent: pure peer-to-peer personhood ceremony completes with NO utility server', async () => {
  const { registry: regA, cleanup: cleanA } = makeTempRegistry();
  const { registry: regB, cleanup: cleanB } = makeTempRegistry();
  after(cleanA);
  after(cleanB);

  const agentA = await Agent.create({ name: 'p2p-alice', passphrase: 'pass-a' }, regA);
  const agentB = await Agent.create({ name: 'p2p-bob', passphrase: 'pass-b' }, regB);

  // Deliberately NO configureUtilityServer() call — this is the pure
  // peer-to-peer deployment (no accessible utility server), which is exactly
  // the case where the TSP bridge used to be left unwired.
  await agentA.start();
  await agentB.start();

  // Record the completion hand-off each agent makes to its UI. With the bug
  // under test this list stayed EMPTY even after both agents had run every
  // peer-to-peer leg — the saga reported `phase=complete` while the relationship
  // still read 'acknowledged', so the UI never left the waiting state.
  const completionsA: string[] = [];
  const completionsB: string[] = [];
  agentA.onCeremonyComplete?.(remoteDid => completionsA.push(remoteDid));
  agentB.onCeremonyComplete?.(remoteDid => completionsB.push(remoteDid));

  try {
    // ── Regression: start() alone must wire the TSP client ────────────────
    for (const [label, agent] of [['A', agentA], ['B', agentB]] as const) {
      const client = readTspClient(agent);
      assert.ok(client, `agent ${label} must expose a TspClientModule`);
      assert.equal(
        client.isInitialized(),
        true,
        `agent ${label}'s TspClientModule must be initialized by start() even with no utility server ` +
        `(otherwise every peer coordinator leg throws 'not initialized' and the ceremony can never complete)`,
      );
    }

    // ── OOBI paste → RFI/RFA → bidirectional ──────────────────────────────
    const bOobi = agentB.generateOobi();
    await agentA.connectToPeer(bOobi);
    await waitForBidirectional(agentA, agentB.getVid());
    await waitForBidirectional(agentB, agentA.getVid());

    // Nobody has pressed yet: the window is open and neither side is acked.
    const preStatus = await agentA.getCeremonyStatus!(agentB.getVid());
    assert.ok(preStatus, 'A must report a ceremony status for B');
    assert.equal(preStatus!.localAcked, false, 'A must not be locally acked before the press');
    assert.equal(preStatus!.remoteAcked, false, 'A must not see B as acked before B presses');
    assert.equal(preStatus!.ack.active, true, 'the personhood-ack window must be open before the press');

    // ── Both press "I know this person" ───────────────────────────────────
    // This is the peer-to-peer-only signaling: the ack must be delivered by the
    // `ack_delivery` coordinator leg over the peer transport.
    await agentA.acknowledgeRemotePeer!(agentB.getVid());
    await agentB.acknowledgeRemotePeer!(agentA.getVid());

    // Both mirrors must reach 'verified' — mutual ack + each VRC exchanged with
    // the peer, with no server involved.
    await waitForPersonhoodVerified(agentA, agentB.getVid());
    await waitForPersonhoodVerified(agentB, agentA.getVid());

    const statusA = await agentA.getCeremonyStatus!(agentB.getVid());
    const statusB = await agentB.getCeremonyStatus!(agentA.getVid());

    assert.equal(
      statusA?.complete,
      true,
      `A's ceremony must be complete (phase=${statusA?.phase}, failedStep=${statusA?.failedStep}, ` +
      `lastError=${statusA?.lastError}, attempt=${statusA?.attempt})`,
    );
    assert.equal(
      statusB?.complete,
      true,
      `B's ceremony must be complete (phase=${statusB?.phase}, failedStep=${statusB?.failedStep}, ` +
      `lastError=${statusB?.lastError}, attempt=${statusB?.attempt})`,
    );

    // `phase` is the authority on completion: a ceremony that exhausted its
    // retries would read 'failed'. Note that `failedStep`/`lastError` are
    // deliberately NOT asserted on here — with no utility server the archive leg
    // records `current_step='server_archive_deferred'` and its informational
    // message in `last_error`, so both fields are non-empty even on a perfectly
    // healthy peer-to-peer completion.
    assert.equal(
      statusA?.phase,
      'complete',
      `A's saga must be 'complete', not 'failed' (got ${statusA?.phase})`,
    );
    assert.equal(
      statusB?.phase,
      'complete',
      `B's saga must be 'complete', not 'failed' (got ${statusB?.phase})`,
    );

    // The completion signal must have reached each agent's UI exactly once —
    // this is what the dashboard's chat-ready/verified state is driven from.
    assert.equal(
      completionsA.length,
      1,
      `A must fire onCeremonyComplete exactly once (got ${completionsA.length})`,
    );
    assert.equal(completionsA[0], agentB.getDid(), 'A\'s completion signal must name B');
    assert.equal(
      completionsB.length,
      1,
      `B must fire onCeremonyComplete exactly once (got ${completionsB.length})`,
    );
    assert.equal(completionsB[0], agentA.getDid(), 'B\'s completion signal must name A');

    // A completed ceremony is chat-ready on both sides.
    assert.equal(
      agentA.getRelationship(agentB.getVid())?.personhoodStatus,
      'verified',
      'A→B must remain verified after completion',
    );
    assert.equal(
      agentB.getRelationship(agentA.getVid())?.personhoodStatus,
      'verified',
      'B→A must remain verified after completion',
    );
  } finally {
    await agentA.stop();
    await agentB.stop();
  }
});

