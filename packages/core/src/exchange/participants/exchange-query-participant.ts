// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * ExchangeQueryParticipant — server-side read-only participant that answers
 * `exchange:<name>` queries by dispatching to the RecordSet catalog: materialize
 * + ACL role gate + N6 privacy validator. This generalizes the legacy read-only
 * participants (NameLookup, IdentityLookup — both since retired) into one query op.
 *
 * Registered unconditionally on the server's TransactionCoordinator. Read-only:
 * prepare/commit/abort only record participant state.
 */
import type { DataSource } from '../../db/data-source.js';
import type { Operation, Outcome, Participant, Vote } from '../../tx/types.js';
import { getMaterialize, getRecordSet } from '../catalog.js';
import { assertSafeProjection } from '../engine.js';
import { ExchangeError } from '../types.js';
import type { ExchangeContext, ExchangeRequest, RecordSetName } from '../types.js';

export class ExchangeQueryParticipant implements Participant {
  readonly pid: string;
  private readonly appDb: DataSource;
  private readonly txDb: DataSource;

  constructor(pid: string, appDb: DataSource, txDb: DataSource) {
    this.pid = pid;
    this.appDb = appDb;
    this.txDb = txDb;
  }

  handlesOperation(op: Operation): boolean {
    // Only claim PULL-deliverable recordsets. This participant is the read-only
    // query side: if a push op (exchange:identity / exchange:rcard) were claimed
    // here, the coordinator would dispatch it to exchangePushParticipant's
    // sibling — this one — whose prepare() is a read-only stub that votes YES
    // without applying anything, silently swallowing profile/identity pushes.
    if (typeof op.op !== 'string' || !op.op.startsWith('exchange:')) return false;
    const name = op.op.slice('exchange:'.length) as RecordSetName;
    try {
      return getRecordSet(name).transport.delivery === 'pull';
    } catch {
      return false;
    }
  }

  async prepare(txId: string, _operations: Operation[]): Promise<Vote> {
    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome) VALUES (?, ?, 'prepared')`,
      txId,
      this.pid,
    );
    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'committed' WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
  }

  async abort(txId: string): Promise<void> {
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'aborted' WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
  }

  async compensate(txId: string): Promise<void> {
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.txDb.get<{ outcome: string }>(
      'SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?',
      txId,
      this.pid,
    );
    return (row?.outcome as Outcome) ?? 'unknown';
  }

  async query(op: string, params?: Record<string, unknown>): Promise<unknown> {
    if (!op.startsWith('exchange:')) {
      throw new Error(`ExchangeQueryParticipant does not handle query '${op}'`);
    }
    const name = op.slice('exchange:'.length) as RecordSetName;
    const def = getRecordSet(name);
    if (def.transport.delivery !== 'pull') {
      return {
        ok: false,
        error: { code: 'permanent', message: `recordset '${name}' is not pull-deliverable` },
      };
    }
    const req = (params ?? {}) as ExchangeRequest;

    // ACL role gate — deny by default (design §9).
    const role = req.requester?.role;
    if (!role || !def.acl.roles.includes(role)) {
      return {
        ok: false,
        error: {
          code: 'denied',
          message: `role '${role ?? 'none'}' not allowed for recordset '${name}'`,
        },
      };
    }

    try {
      const materialize = getMaterialize(name);
      const ctx: ExchangeContext = { ...req };
      const rows = await materialize(this.appDb, ctx);
      assertSafeProjection(rows, name);
      return { ok: true, data: rows };
    } catch (err) {
      if (err instanceof ExchangeError) {
        return { ok: false, error: { code: err.code, message: err.message } };
      }
      throw err;
    }
  }
}
