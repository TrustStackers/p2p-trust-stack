/**
 * Tests for coordinator recovery (G5b).
 *
 * ## 1. Which participant owns the SECOND phase?
 *
 * The coordinator tracks the responder-side participant per txId in an
 * in-memory `preparedBy` Map. When the process restarts between the two phases —
 * routine for the utility server (relay expiry, deploy, crash) — that Map is
 * empty, and `tx_commit` / `tx_abort` / `tx_inquiry` used to fall through to
 * `allParticipants()[0]`: the FIRST REGISTERED participant, which is generally not
 * the one that prepared. The commit then "succeeded" against the wrong
 * participant while the real one was never finalised.
 *
 * `transactionCoordinator(log, { resolvePreparedPid })` reads the pid from durable
 * `tx_participant_state` instead.
 *
 * ## 2. Nested child compensation
 *
 * `Transaction.run(child)` pushes a `_compensateChild` descriptor onto the PARENT,
 * so a parent abort can undo an already-committed child (the nested
 * `exchange:identity` push inside `registerNameViaCoordinator` relies on this).
 * Without a registered handler the executor logged
 * `no CompensationHandler registered for type '_compensateChild'` and the child's
 * effects stood.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tx/coordinator-recovery.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { TX_SCHEMA_SQL } from '../../src/tx/schema.js';
import {
  DataSourceLogSink,
  TransactionLog,
  TransactionCoordinator,
  TransactionManager,
  CompensationExecutor,
  makePreparedPidResolver,
} from '../../src/tx/index.js';
import type { Operation, Outcome, Participant, Vote } from '../../src/tx/types.js';

/** A participant that durably records 'prepared' and logs every phase call. */
class FakeParticipant implements Participant {
  readonly pid: string;
  readonly calls: string[] = [];
  private readonly ds: SqliteDataSource;

  constructor(pid: string, ds: SqliteDataSource) {
    this.pid = pid;
    this.ds = ds;
  }

  async prepare(txId: string, _operations: Operation[]): Promise<Vote> {
    this.calls.push('prepare');
    await this.ds.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome) VALUES (?, ?, 'prepared')`,
      txId, this.pid,
    );
    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    this.calls.push('commit');
    await this.ds.run(
      `UPDATE tx_participant_state SET outcome = 'committed' WHERE tx_id = ? AND pid = ?`,
      txId, this.pid,
    );
  }

  async abort(txId: string): Promise<void> {
    this.calls.push('abort');
    await this.ds.run(
      `UPDATE tx_participant_state SET outcome = 'aborted' WHERE tx_id = ? AND pid = ?`,
      txId, this.pid,
    );
  }

  async compensate(txId: string): Promise<void> {
    this.calls.push('compensate');
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.ds.get<{ outcome: string }>(
      'SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?', txId, this.pid,
    );
    return (row?.outcome as Outcome) ?? 'unknown';
  }
}

function makeTxDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  ds.getRawDb().exec(TX_SCHEMA_SQL);
  return ds;
}

const REAL_PID = 'server:us-1#name-registry';
const DECOY_PID = 'server:us-1#vtc-creation';

test('tx_commit after a restart reaches the participant that PREPARED, not allParticipants()[0]', async () => {
  const ds = makeTxDb();
  const sink = new DataSourceLogSink(ds);
  const txId = 'tx-restart-1';

  // ── Process 1: the prepare happens here (durable 'prepared' row + in-memory map).
  const real = new FakeParticipant(REAL_PID, ds);
  const c1 = new TransactionCoordinator(new TransactionLog(sink), {
    resolvePreparedPid: makePreparedPidResolver(ds),
  });
  c1.registerParticipant(real);
  const prep = await c1.handleInboundTxMessage({
    kind: 'tx_prepare', txId, operations: [{ op: 'name_register', params: {} }],
  });
  assert.equal(prep?.kind, 'tx_prepare_result');
  assert.deepEqual(real.calls, ['prepare']);

  // ── Process 2: a NEW coordinator over the same durable state. The DECOY is
  //    registered FIRST, so `allParticipants()[0]` is the wrong participant.
  const decoy = new FakeParticipant(DECOY_PID, ds);
  const same = new FakeParticipant(REAL_PID, ds);
  const c2 = new TransactionCoordinator(new TransactionLog(sink), {
    resolvePreparedPid: makePreparedPidResolver(ds),
  });
  c2.registerParticipant(decoy);
  c2.registerParticipant(same);

  const committed = await c2.handleInboundTxMessage({ kind: 'tx_commit', txId });
  assert.deepEqual(committed, { kind: 'tx_commit_result', txId, ok: true });

  assert.deepEqual(same.calls, ['commit'], 'the participant that prepared is committed');
  assert.deepEqual(decoy.calls, [], 'the decoy (first registered) must NOT be committed');

  await ds.close();
});

test('without a prepared-pid resolver the pre-fix behaviour is reproduced (documents the bug)', async () => {
  const ds = makeTxDb();
  const sink = new DataSourceLogSink(ds);
  const txId = 'tx-restart-2';

  const real = new FakeParticipant(REAL_PID, ds);
  const c1 = new TransactionCoordinator(new TransactionLog(sink));
  c1.registerParticipant(real);
  await c1.handleInboundTxMessage({
    kind: 'tx_prepare', txId, operations: [{ op: 'name_register', params: {} }],
  });

  const decoy = new FakeParticipant(DECOY_PID, ds);
  const same = new FakeParticipant(REAL_PID, ds);
  const c2 = new TransactionCoordinator(new TransactionLog(sink)); // no resolver
  c2.registerParticipant(decoy);
  c2.registerParticipant(same);

  await c2.handleInboundTxMessage({ kind: 'tx_commit', txId });

  assert.deepEqual(decoy.calls, ['commit'], 'first registered participant is committed (the bug)');
  assert.deepEqual(same.calls, [], 'the participant that actually prepared is skipped');

  await ds.close();
});

test('a parent abort compensates an already-committed nested child (_compensateChild handler)', async () => {
  const ds = makeTxDb();
  const sink = new DataSourceLogSink(ds);
  const coordinator = new TransactionCoordinator(new TransactionLog(sink));
  const compensation = new CompensationExecutor();

  // The handler the bootstraps now register.
  compensation.register({
    type: '_compensateChild',
    async execute(desc) {
      const child = (desc as unknown as { child?: { compensate: () => Promise<void> } }).child;
      if (child) await child.compensate();
    },
  });

  const manager = new TransactionManager(coordinator, compensation);
  const parentPart = new FakeParticipant('local-db', ds);
  const childPart = new FakeParticipant('peer:child', ds);

  const parent = manager.begin();
  parent.enlist(parentPart, [{ op: 'finalize_rotation', params: {} }]);

  // A nested child transaction that COMMITS (its own 2PC).
  await parent.run(async (child) => {
    child.enlist(childPart, [{ op: 'exchange:identity', params: {} }]);
  });
  assert.deepEqual(childPart.calls, ['prepare', 'commit'], 'the child committed');

  // The parent then aborts: the committed child must be compensated.
  await parent.abort();

  assert.ok(
    childPart.calls.includes('compensate'),
    'the committed child was compensated when the parent aborted',
  );

  await ds.close();
});
