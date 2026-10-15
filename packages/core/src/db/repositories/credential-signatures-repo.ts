// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Repository: credential_signatures table (uuid-first, 0018).
 *
 * One row per collected signature. For a single-issuer credential this is
 * exactly one row. For an M-of-N credential, rows accumulate until
 * credentials.threshold_required is met and status flips
 * 'pending_signatures' -> 'issued'.
 */

import type { DataSource } from '../data-source.js';
import { generateUuid } from '../uuid-helpers.js';

export interface CredentialSignatureRow {
  uuid: string;
  credentialUuid: string;
  signerIdentityUuid: string;
  signerDidDocumentUuid: string | null;
  signature: Uint8Array;
  signedAt: number | null;
}

export interface CreateCredentialSignatureInput {
  credentialUuid: string;
  signerIdentityUuid: string;
  signerDidDocumentUuid?: string;
  signature: Uint8Array;
}

interface RawRow {
  uuid: string;
  credential_uuid: string;
  signer_identity_uuid: string;
  signer_did_document_uuid: string | null;
  signature: Uint8Array;
  signed_at: number | null;
}

function rowToSignature(row: RawRow): CredentialSignatureRow {
  return {
    uuid: row.uuid,
    credentialUuid: row.credential_uuid,
    signerIdentityUuid: row.signer_identity_uuid,
    signerDidDocumentUuid: row.signer_did_document_uuid,
    signature: row.signature,
    signedAt: row.signed_at,
  };
}

/** Create a signature row. Returns the new row's uuid. */
export async function create(db: DataSource, input: CreateCredentialSignatureInput): Promise<string> {
  const rowUuid = generateUuid();
  const result = await db.run(
    `INSERT INTO credential_signatures (credential_uuid, signer_identity_uuid, signer_did_document_uuid, signature, uuid, signed_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    input.credentialUuid, input.signerIdentityUuid, input.signerDidDocumentUuid ?? null, input.signature,
    rowUuid,
    Math.floor(Date.now() / 1000),
  );
  void result;
  return rowUuid;
}

export async function findForCredential(db: DataSource, credentialUuid: string): Promise<CredentialSignatureRow[]> {
  const rows = await db.all<RawRow>('SELECT * FROM credential_signatures WHERE credential_uuid = ? ORDER BY uuid', credentialUuid);
  return rows.map(rowToSignature);
}

export async function countForCredential(db: DataSource, credentialUuid: string): Promise<number> {
  const row = await db.get<{ n: number }>('SELECT COUNT(*) AS n FROM credential_signatures WHERE credential_uuid = ?', credentialUuid);
  return row?.n ?? 0;
}

export async function findBySignerForCredential(
  db: DataSource, credentialUuid: string, signerIdentityUuid: string,
): Promise<CredentialSignatureRow | null> {
  const row = await db.get<RawRow>(
    'SELECT * FROM credential_signatures WHERE credential_uuid = ? AND signer_identity_uuid = ?',
    credentialUuid, signerIdentityUuid,
  );
  return row ? rowToSignature(row) : null;
}
