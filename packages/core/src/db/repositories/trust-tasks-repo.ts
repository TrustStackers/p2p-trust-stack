// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Repository: `trust_tasks` table (migration 0018, shared core + utility).
 *
 * The durable record of a Trust Task document. The ceremony/envelope side lives in
 * `src/services/trust-tasks/`; this module is only the store + query surface and
 * carries no envelope knowledge — it persists/reads documents, it does not build
 * them. Payload/proof are stored as JSON TEXT.
 */

import type { DataSource } from '../data-source.js';

export type TrustTaskDirection = 'request' | 'response';

export interface TrustTaskRow {
  uuid: string;
  threadId: string;
  type: string;
  direction: TrustTaskDirection;
  issuerDid: string | null;
  recipientDid: string | null;
  parentThreadId: string | null;
  payload: string | null;
  proof: string | null;
  status: string;
  recordedByNode: string | null;
  replicatedAt: number | null;
  createdAt: number | null;
  updatedAt: number | null;
}

export interface RecordTrustTaskInput {
  /** The document id — used as the row's primary key. */
  uuid: string;
  threadId: string;
  type: string;
  direction: TrustTaskDirection;
  issuerDid?: string;
  recipientDid?: string;
  parentThreadId?: string;
  payload?: unknown;
  proof?: unknown;
  status?: string;
  recordedByNode?: string;
}

interface RawRow {
  uuid: string;
  thread_id: string;
  type: string;
  direction: string;
  issuer_did: string | null;
  recipient_did: string | null;
  parent_thread_id: string | null;
  payload: string | null;
  proof: string | null;
  status: string;
  recorded_by_node: string | null;
  replicated_at: number | null;
  created_at: number | null;
  updated_at: number | null;
}

function rowToTrustTask(row: RawRow): TrustTaskRow {
  return {
    uuid: row.uuid,
    threadId: row.thread_id,
    type: row.type,
    direction: row.direction as TrustTaskDirection,
    issuerDid: row.issuer_did,
    recipientDid: row.recipient_did,
    parentThreadId: row.parent_thread_id,
    payload: row.payload,
    proof: row.proof,
    status: row.status,
    recordedByNode: row.recorded_by_node,
    replicatedAt: row.replicated_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** Insert a task document; returns the stored row. */
export async function record(db: DataSource, input: RecordTrustTaskInput): Promise<TrustTaskRow> {
  const now = Math.floor(Date.now() / 1000);
  const payloadJson = input.payload === undefined ? null : JSON.stringify(input.payload);
  const proofJson = input.proof === undefined ? null : JSON.stringify(input.proof);
  await db.run(
    `INSERT INTO trust_tasks
       (uuid, thread_id, type, direction, issuer_did, recipient_did, parent_thread_id,
        payload, proof, status, recorded_by_node, replicated_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    input.uuid,
    input.threadId,
    input.type,
    input.direction,
    input.issuerDid ?? null,
    input.recipientDid ?? null,
    input.parentThreadId ?? null,
    payloadJson,
    proofJson,
    input.status ?? 'recorded',
    input.recordedByNode ?? null,
    null,
    now,
    now,
  );
  return (await findByUuid(db, input.uuid))!;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<TrustTaskRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM trust_tasks WHERE uuid = ?', uuid);
  return row ? rowToTrustTask(row) : null;
}

export interface TrustTaskThread {
  threadId: string;
  /** Every task `type` seen in the thread, in first-seen order. */
  types: string[];
  /** Total documents (requests + responses). */
  documentCount: number;
  firstAt: number | null;
  lastAt: number | null;
  /** Statuses seen, deduplicated — a `denied` here means something was refused. */
  statuses: string[];
}

/**
 * Summarise every thread — the index behind the ceremony task log.
 *
 * A thread is one ceremony RUN. Its id names the ceremony only by convention
 * (`vtc-establish` uses the ceremony id, member onboarding a fresh uuid,
 * governance-change the proposal id), so a caller that wants to name the ceremony
 * should read `types` against the catalog rather than trust the id.
 *
 * Callers must order the thread's rows with `listByThread` (see the ordering note
 * there) to render steps in record order.
 */
export async function listThreads(db: DataSource): Promise<TrustTaskThread[]> {
  const rows = await db.all<{
    thread_id: string; type: string; status: string; created_at: number | null;
  }>('SELECT thread_id, type, status, created_at FROM trust_tasks ORDER BY created_at, uuid');

  const byThread = new Map<string, TrustTaskThread>();
  for (const row of rows) {
    let thread = byThread.get(row.thread_id);
    if (!thread) {
      thread = {
        threadId: row.thread_id, types: [], documentCount: 0,
        firstAt: null, lastAt: null, statuses: [],
      };
      byThread.set(row.thread_id, thread);
    }
    if (!thread.types.includes(row.type)) thread.types.push(row.type);
    if (!thread.statuses.includes(row.status)) thread.statuses.push(row.status);
    thread.documentCount += 1;
    if (row.created_at !== null) {
      if (thread.firstAt === null || row.created_at < thread.firstAt) thread.firstAt = row.created_at;
      if (thread.lastAt === null || row.created_at > thread.lastAt) thread.lastAt = row.created_at;
    }
  }
  // Newest ceremony first.
  return [...byThread.values()].sort((a, b) => (b.lastAt ?? 0) - (a.lastAt ?? 0));
}

/**
 * Every document in a ceremony, in record order.
 *
 * Record order is `(created_at, uuid)` and `created_at` is SECOND-resolution, so the
 * ordering is only as good as the ids: they are UUIDv7 (time-ordered) precisely so
 * that several steps committed within the same second still come back in the order
 * they were recorded. A v4 id would make the order arbitrary within a second.
 */
export async function listByThread(db: DataSource, threadId: string): Promise<TrustTaskRow[]> {
  const rows = await db.all<RawRow>(
    'SELECT * FROM trust_tasks WHERE thread_id = ? ORDER BY created_at, uuid',
    threadId,
  );
  return rows.map(rowToTrustTask);
}
