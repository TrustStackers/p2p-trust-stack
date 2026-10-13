/**
 * Repository: messages table.
 *
 * TSP messages, routed to specific DID service endpoints (DID-document
 * level, not identity-level) — schema per migrations/0012_messages.sql.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export interface MessageRow {
  uuid: string;
  fromDidDocumentUuid: string | null;
  toDidDocumentUuid: string | null;
  type: string | null;
  payload: Uint8Array | null;
  decryptedPayload: string | null;
  read: boolean;
  createdAt: number | null;
}

export interface CreateMessageInput {
  fromDidDocumentUuid?: string | null;
  toDidDocumentUuid?: string | null;
  type?: string;
  payload?: Uint8Array;
  decryptedPayload?: string;
}

interface RawRow {
  uuid: string;
  from_did_document_uuid: string | null;
  to_did_document_uuid: string | null;
  type: string | null;
  payload: Uint8Array | null;
  decrypted_payload: string | null;
  read: number;
  created_at: number | null;
}

function rowToMessage(row: RawRow): MessageRow {
  return {
    uuid: row.uuid,
    fromDidDocumentUuid: row.from_did_document_uuid,
    toDidDocumentUuid: row.to_did_document_uuid,
    type: row.type,
    payload: row.payload,
    decryptedPayload: row.decrypted_payload,
    read: !!row.read,
    createdAt: row.created_at,
  };
}

export async function create(db: DataSource, input: CreateMessageInput): Promise<string> {
  const rowUuid = generateUuid();
  await db.run(
    `INSERT INTO messages (uuid, from_did_document_uuid, to_did_document_uuid, type, payload, decrypted_payload, read, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    rowUuid,
    input.fromDidDocumentUuid ?? null,
    input.toDidDocumentUuid ?? null,
    input.type ?? null,
    input.payload ?? null,
    input.decryptedPayload ?? null,
    0,
    Math.floor(Date.now() / 1000),
  );
  return rowUuid;
}

export async function findByUuid(db: DataSource, uuid: string): Promise<MessageRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM messages WHERE uuid = ?', uuid);
  return row ? rowToMessage(row) : null;
}

export interface ListMessagesFilter {
  didDocumentUuid?: string;
  unreadOnly?: boolean;
}

export async function findForDidDocument(
  db: DataSource,
  filter: ListMessagesFilter,
): Promise<MessageRow[]> {
  const clauses: string[] = [];
  const params: (number | string)[] = [];

  if (filter.didDocumentUuid !== undefined) {
    clauses.push('(to_did_document_uuid = ? OR from_did_document_uuid = ?)');
    params.push(filter.didDocumentUuid, filter.didDocumentUuid);
  }
  if (filter.unreadOnly) {
    clauses.push('read = 0');
  }

  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = await db.all<RawRow>(`SELECT * FROM messages ${where} ORDER BY created_at, uuid`, ...params);
  return rows.map(rowToMessage);
}

export async function markRead(db: DataSource, uuid: string): Promise<void> {
  await db.run('UPDATE messages SET read = 1 WHERE uuid = ?', uuid);
}