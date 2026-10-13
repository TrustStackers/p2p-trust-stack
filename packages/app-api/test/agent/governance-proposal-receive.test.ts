/**
 * Phase B — GovernanceProposalReceiveParticipant: the agent side of the durable
 * `exchange:governance-proposal` fan-out. It mirrors a pushed proposal into the local
 * tx DB so the Rules UI can show it (and the agent can co-sign).
 *
 * Run:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/agent/governance-proposal-receive.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { TX_SCHEMA_SQL, applyTxSchemaAdditions } from '@p2p-trust-stack/core/tx/schema.js';
import { GovernanceChangeStore } from '@p2p-trust-stack/core/tx/governance-change-store.js';
import { GovernanceProposalReceiveParticipant } from '../../src/runtime/tx/governance-proposal-receive-participant.js';

async function makeParticipant(): Promise<{ txDb: SqliteDataSource; participant: GovernanceProposalReceiveParticipant }> {
  const appDb = new SqliteDataSource(':memory:');
  const txDb = new SqliteDataSource(':memory:');
  await txDb.exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(txDb);
  const participant = new GovernanceProposalReceiveParticipant('peer:agent', appDb, txDb);
  return { txDb, participant };
}

const PUSH = {
  proposalId: 'p1', communityUuid: 'c1', communityDid: 'did:scid:vh:club',
  proposalHash: 'HASH-1', scope: 'admins' as const, requiredApproverCount: 2,
  change: { adminThresholdM: 3 }, expiresAt: 999,
};

test('only exchange:governance-proposal is claimed', async () => {
  const { participant } = await makeParticipant();
  assert.equal(participant.handlesOperation({ op: 'exchange:governance-proposal' } as never), true);
  assert.equal(participant.handlesOperation({ op: 'exchange:governance' } as never), false);
});

test('mirrors a pushed proposal into the local tx DB (like the future Rules UI reads)', async () => {
  const { txDb, participant } = await makeParticipant();

  const vote = await participant.prepare('tx-1', [
    { op: 'exchange:governance-proposal', params: { ...PUSH } } as never,
  ]);
  assert.equal(vote, 'yes');

  const mirrored = await new GovernanceChangeStore(txDb).getProposal('p1');
  assert.ok(mirrored, 'the proposal is mirrored locally');
  assert.equal(mirrored!.status, 'pending');
  assert.equal(mirrored!.proposalHash, 'HASH-1');
  assert.equal(mirrored!.communityDid, 'did:scid:vh:club');
  assert.equal(mirrored!.requiredApproverCount, 2);
  assert.deepEqual(mirrored!.change, { adminThresholdM: 3 });
});

test('a malformed push is refused and mirrors nothing', async () => {
  const { txDb, participant } = await makeParticipant();
  const vote = await participant.prepare('tx-2', [
    { op: 'exchange:governance-proposal', params: { proposalId: 'p1' } } as never, // no hash
  ]);
  assert.equal(vote, 'no');
  assert.equal(await new GovernanceChangeStore(txDb).getProposal('p1'), null);
});

test('re-delivery is idempotent (the proposal is immutable)', async () => {
  const { txDb, participant } = await makeParticipant();
  await participant.prepare('tx-3', [{ op: 'exchange:governance-proposal', params: { ...PUSH } } as never]);
  await participant.prepare('tx-4', [{ op: 'exchange:governance-proposal', params: { ...PUSH } } as never]);
  const all = await txDb.all<{ proposal_id: string }>('SELECT proposal_id FROM governance_change_proposals');
  assert.equal(all.length, 1, 'INSERT OR IGNORE keeps a single row');
});

// ── The arrival signal (what lets the Rules page stop polling) ───────────────

test('a mirrored proposal is ANNOUNCED — this is the only observer of an arrival', async () => {
  // Without this hook the only way to notice a proposal is to ask, which is what `rules.html` did every 4 s.
  const announced: Array<{ proposalId: string; communityUuid: string }> = [];
  const appDb = new SqliteDataSource(':memory:');
  const txDb = new SqliteDataSource(':memory:');
  await txDb.exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(txDb);
  const participant = new GovernanceProposalReceiveParticipant(
    'peer:agent', appDb, txDb, (p) => announced.push(p),
  );

  const vote = await participant.prepare('tx-announce', [
    { op: 'exchange:governance-proposal', params: { ...PUSH } } as never,
  ]);

  assert.equal(vote, 'yes');
  assert.deepEqual(announced, [{ proposalId: 'p1', communityUuid: 'c1' }]);
});

test('a THROWING observer cannot abort the transaction that already mirrored the proposal', async () => {
  // `prepare()` votes 'no' on any throw, so an unguarded announcement would turn a successful delivery into a
  // refusal — the transaction's data is already written by the time the observer runs. This is the exact
  // defect the credential signal shipped with and had to fix.
  const appDb = new SqliteDataSource(':memory:');
  const txDb = new SqliteDataSource(':memory:');
  await txDb.exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(txDb);
  const participant = new GovernanceProposalReceiveParticipant('peer:agent', appDb, txDb, () => {
    throw new Error('observer exploded');
  });

  const vote = await participant.prepare('tx-throwing', [
    { op: 'exchange:governance-proposal', params: { ...PUSH } } as never,
  ]);

  assert.equal(vote, 'yes', 'the vote must not be decided by a side effect');
  assert.ok(await new GovernanceChangeStore(txDb).getProposal('p1'), 'the proposal is still mirrored');
});

test('a REFUSED push announces nothing', async () => {
  // A malformed push mirrors nothing, so there is no arrival to announce.
  const announced: unknown[] = [];
  const appDb = new SqliteDataSource(':memory:');
  const txDb = new SqliteDataSource(':memory:');
  await txDb.exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(txDb);
  const participant = new GovernanceProposalReceiveParticipant(
    'peer:agent', appDb, txDb, (p) => announced.push(p),
  );

  const vote = await participant.prepare('tx-refused', [
    { op: 'exchange:governance-proposal', params: { proposalId: 'p1' } } as never, // no hash
  ]);

  assert.equal(vote, 'no');
  assert.deepEqual(announced, [], 'a refusal is not an arrival');
});

