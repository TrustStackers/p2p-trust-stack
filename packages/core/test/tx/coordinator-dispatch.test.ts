/**
 * Regression test for the VRC ceremony failure: the transaction coordinator's
 * initiator-side dispatch previously selected the FIRST participant registered
 * for a pid. Because VtcReceive, VrcCeremony and VrcReceive all share the pid
 * `peer:{agentDid}`, the local `mint_vrc` operation was routed to
 * VtcReceiveParticipant (registered first), which does not mint — the tx
 * "committed" with zero credential rows. This test proves the dispatch now
 * routes a shared-pid operation to the participant that handles it.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import {
  TX_SCHEMA_SQL,
  TransactionLog,
  DataSourceLogSink,
  TransactionCoordinator,
} from '../../src/tx/index.js';
import type { Operation, Outcome, Participant, Vote } from '../../src/tx/types.js';

class TrackingParticipant implements Participant {
  pid: string;
  preparedOps: string[] = [];
  private readonly handled: string[];

  constructor(pid: string, handled: string[]) {
    this.pid = pid;
    this.handled = handled;
  }

  handlesOperation(op: Operation): boolean {
    return this.handled.includes(op.op);
  }

  async prepare(_txId: string, operations: Operation[]): Promise<Vote> {
    this.preparedOps.push(...operations.map((o) => o.op));
    return 'yes';
  }

  async commit(): Promise<void> { /* no-op */ }
  async abort(): Promise<void> { /* no-op */ }
  async compensate(): Promise<void> { /* no-op */ }
  async inquiry(): Promise<Outcome> { return 'committed'; }
}

test('shared-pid dispatch routes mint_vrc to the participant that handles it', async () => {
  const ds = new SqliteDataSource(':memory:');
  await ds.exec(TX_SCHEMA_SQL);
  const log = new TransactionLog(new DataSourceLogSink(ds));
  const coord = new TransactionCoordinator(log);

  // Three local participants share the same pid (peer:{agentDid}), mirroring
  // VtcReceive / VrcCeremony / VrcReceive in base-agent.
  const vtc = new TrackingParticipant('peer:agent', ['vtc_upsert']);
  const ceremony = new TrackingParticipant('peer:agent', ['mint_vrc', 'push_vrc']);
  const receive = new TrackingParticipant('peer:agent', ['store_remote_vrc']);
  coord.registerParticipant(vtc);
  coord.registerParticipant(ceremony);
  coord.registerParticipant(receive);

  const res = await coord.execute({
    participants: [{ pid: 'peer:agent', operations: [{ op: 'mint_vrc', params: {} }] }],
  });

  assert.equal(res.outcome, 'committed');
  assert.ok(ceremony.preparedOps.includes('mint_vrc'), 'mint_vrc must be prepared by the ceremony participant');
  assert.ok(!vtc.preparedOps.includes('mint_vrc'), 'the first-registered (vtc) participant must NOT receive mint_vrc');
  assert.ok(!receive.preparedOps.includes('mint_vrc'), 'store_remote_vrc participant must NOT receive mint_vrc');
}, { timeout: 10_000 });

test('store_remote_vrc routes to the receive participant, not the first registered', async () => {
  const ds = new SqliteDataSource(':memory:');
  await ds.exec(TX_SCHEMA_SQL);
  const log = new TransactionLog(new DataSourceLogSink(ds));
  const coord = new TransactionCoordinator(log);

  const vtc = new TrackingParticipant('peer:agent', ['vtc_upsert']);
  const receive = new TrackingParticipant('peer:agent', ['store_remote_vrc']);
  coord.registerParticipant(vtc);
  coord.registerParticipant(receive);

  const res = await coord.execute({
    participants: [{ pid: 'peer:agent', operations: [{ op: 'store_remote_vrc', params: {} }] }],
  });

  assert.equal(res.outcome, 'committed');
  assert.ok(receive.preparedOps.includes('store_remote_vrc'), 'store_remote_vrc must reach the receive participant');
  assert.ok(!vtc.preparedOps.length, 'vtc participant must not receive store_remote_vrc');
}, { timeout: 10_000 });
