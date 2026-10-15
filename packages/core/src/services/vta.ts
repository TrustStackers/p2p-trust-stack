// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * VTA creation service — composed action for POST /vtas.
 */

import type { DataSource } from '../db/data-source.js';
import { createDidPeer4 } from '../did/create.js';
import { ScidVhMethod, type ScidVhMethodCreateResult } from '../did/scid-vh-method.js';
import { encryptSecretKey } from '../keystore/sqlite-keystore.js';
import { didToUuid, generateUuid } from '../db/uuid-helpers.js';
import { cesrEncode, CESR_CODES } from '../crypto/cesr.js';
import * as identitiesRepo from '../db/repositories/identities-repo.js';
import type { Identity, SubjectKind } from '../db/repositories/identities-repo.js';
import * as didDocumentsRepo from '../db/repositories/did-documents-repo.js';
import type { DidDocumentRow } from '../db/repositories/did-documents-repo.js';
import * as keysRepo from '../db/repositories/keys-repo.js';
import { setActiveEndpoint } from '../db/repositories/peer-endpoints-repo.js';
import { extractEd25519PublicKey } from '../relationship/key-extract.js';

export type { Identity, SubjectKind } from '../db/repositories/identities-repo.js';

export interface CreateVtaInput {
  name: string;
  subjectKind: SubjectKind;
  method?: 'peer4' | 'scidvh';
  passphrase: string;
  peerId?: string;
  nodeId?: string;
  keystorePath?: string;
  /** Deterministic 32-byte seed (seed-phrase import) — makes the did:scid:vh DID reproducible. */
  identitySeed?: Uint8Array;
}

export interface CreateVtaResult {
  identity: Identity;
  didDocument: DidDocumentRow;
  publicKeys: { ed25519: string; x25519: string; };
  /** The root Ed25519 signing keypair (local custody only — undefined for remote). */
  signingKeyPair?: { secretKey: Uint8Array; publicKey: Uint8Array };
}

const MIN_PASSPHRASE_LENGTH = 8;
export class CreateVtaValidationError extends Error {}

export async function createVta(
  db: DataSource,
  input: CreateVtaInput,
): Promise<CreateVtaResult> {
  if (!input.name || !input.name.trim()) throw new CreateVtaValidationError('name is required');
  if (!input.subjectKind) throw new CreateVtaValidationError('subjectKind is required');
  if (!input.passphrase || input.passphrase.length < MIN_PASSPHRASE_LENGTH) throw new CreateVtaValidationError(`passphrase is required and must be at least ${MIN_PASSPHRASE_LENGTH} characters`);

  const method = input.method ?? 'scid-vh';
  let did: string; let document: object;
  let signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array };
  let agreementKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array };
  let rotationLog: Array<{ version: number; didDocument: object }> | undefined;
  let nextSigningKeyPairs: Array<{ secretKey: Uint8Array; publicKey: Uint8Array }> | undefined;
  let mlDsa65KeyPair: { secretKey: Uint8Array; publicKey: Uint8Array } | undefined;
  let hybridKemKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array } | undefined;

  if (method === 'scid-vh' || method === 'scidvh') {
    const scidVhMethod = new ScidVhMethod({ store: undefined });
    const result = (await scidVhMethod.create(
      undefined,
      input.identitySeed ? { identitySeed: input.identitySeed } : undefined,
    )) as ScidVhMethodCreateResult;
    did = result.did; document = result.document;
    signingKeyPair = result.signingKeyPair; agreementKeyPair = result.agreementKeyPair;
    rotationLog = result.log; nextSigningKeyPairs = result.nextSigningKeyPairs;
    mlDsa65KeyPair = result.mlDsa65KeyPair; hybridKemKeyPair = result.hybridKemKeyPair;
  } else {
    const transport = input.peerId ? { peerId: input.peerId, multiaddrs: [] } : undefined;
    const result = await createDidPeer4(transport);
    did = result.did; document = result.document;
    signingKeyPair = result.signingKeyPair; agreementKeyPair = result.agreementKeyPair;
    mlDsa65KeyPair = result.mlDsa65KeyPair; hybridKemKeyPair = result.hybridKemKeyPair;
  }

  const identityUuid = didToUuid(did);
  const cesrVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, signingKeyPair.publicKey);

  await identitiesRepo.create(db, {
    uuid: identityUuid, realDid: did, role: 'vta', subjectKind: input.subjectKind, custody: 'local',
    name: input.name.trim(), vid: cesrVid, peerId: input.peerId, recordedByNode: input.nodeId,
  });

  const didMethodStr = (method === 'scid-vh' || method === 'scidvh') ? 'did:scid:vh' : 'did:peer:4';
  const didDocumentUuid = await didDocumentsRepo.create(db, {
    identityUuid, did, method: didMethodStr,
    documentJson: JSON.stringify(document), isPrimary: true, recordedByNode: input.nodeId,
  });

  const edEncrypted = await encryptSecretKey(signingKeyPair.secretKey, input.passphrase);
  await keysRepo.createWithSecret(db, {
    identityUuid, didDocumentUuid, keyType: 'ed25519',
    publicKey: signingKeyPair.publicKey, encryptedSecretKey: edEncrypted.ciphertext,
    salt: edEncrypted.salt, nonce: edEncrypted.nonce, authTag: edEncrypted.authTag,
  });

  const xEncrypted = await encryptSecretKey(agreementKeyPair.secretKey, input.passphrase);
  await keysRepo.createWithSecret(db, {
    identityUuid, didDocumentUuid, keyType: 'x25519',
    publicKey: agreementKeyPair.publicKey, encryptedSecretKey: xEncrypted.ciphertext,
    salt: xEncrypted.salt, nonce: xEncrypted.nonce, authTag: xEncrypted.authTag,
  });

  // Post-quantum roots of trust. Persisted alongside the classical keys so the
  // identity's ML-DSA-65 / MLKEM768-X25519 keys are resolvable locally (and can be
  // backed up / replicated) rather than existing only in the DID document.
  if (mlDsa65KeyPair) {
    const pqEncrypted = await encryptSecretKey(mlDsa65KeyPair.secretKey, input.passphrase);
    await keysRepo.createWithSecret(db, {
      identityUuid, didDocumentUuid, keyType: 'ml_dsa_65',
      publicKey: mlDsa65KeyPair.publicKey, encryptedSecretKey: pqEncrypted.ciphertext,
      salt: pqEncrypted.salt, nonce: pqEncrypted.nonce, authTag: pqEncrypted.authTag,
    });
  }
  if (hybridKemKeyPair) {
    const kemEncrypted = await encryptSecretKey(hybridKemKeyPair.secretKey, input.passphrase);
    await keysRepo.createWithSecret(db, {
      identityUuid, didDocumentUuid, keyType: 'mlkem768_x25519',
      publicKey: hybridKemKeyPair.publicKey, encryptedSecretKey: kemEncrypted.ciphertext,
      salt: kemEncrypted.salt, nonce: kemEncrypted.nonce, authTag: kemEncrypted.authTag,
    });
  }

  // Rotation log for did:scid:vh
  if (rotationLog && rotationLog.length > 0) {
    const { generateUuid } = await import('../db/uuid-helpers.js');
    for (const entry of rotationLog) {
      const nextKeyCommitments: Uint8Array[] = (entry as any).nextKeyCommitments ?? [];
      const nextKeyCommitmentBlob = Buffer.from(JSON.stringify(nextKeyCommitments.map((k: Uint8Array) => Buffer.from(k).toString('base64'))));
      const prevHash = (entry as any).prevHash ?? null;
      const entryDigest: Uint8Array = (entry as any).digest ?? new Uint8Array(32);
      const entrySig: Uint8Array = (entry as any).signature ?? new Uint8Array(64);

      const docJson = new TextEncoder().encode(JSON.stringify((entry as any).didDocument));
      const paramsJson = new TextEncoder().encode(JSON.stringify((entry as any).parameters ?? null));
      const packed = new Uint8Array(4 + docJson.length + 4 + paramsJson.length + 32 + 64);
      const view = new DataView(packed.buffer);
      view.setUint32(0, docJson.length, false); packed.set(docJson, 4);
      view.setUint32(4 + docJson.length, paramsJson.length, false);
      packed.set(paramsJson, 4 + docJson.length + 4);
      const offset = 4 + docJson.length + 4 + paramsJson.length;
      packed.set(entryDigest, offset); packed.set(entrySig, offset + 32);

      const rowUuid = generateUuid();
      try {
        await db.run(`INSERT INTO rotation_log (did_document_uuid, version, previous_hash, new_public_key, signed_entry, uuid, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
          didDocumentUuid, (entry as any).version ?? 0,
          prevHash ? Buffer.from(prevHash) : null,
          nextKeyCommitmentBlob, Buffer.from(packed), rowUuid,
          (entry as any).createdAt ?? Math.floor(Date.now() / 1000));
      } catch { /* ignore duplicate */ }
    }
  }

  // Keystore backup
  if (input.keystorePath) {
    const { SqliteKeyStore } = await import('../keystore/sqlite-keystore.js');
    const keystore = new SqliteKeyStore(input.keystorePath);
    await keystore.storeKeyPairAsync(cesrVid, 'ed25519', signingKeyPair, input.passphrase);
    await keystore.storeKeyPairAsync(cesrVid, 'x25519', agreementKeyPair, input.passphrase);
    if ((method === 'scid-vh' || method === 'scidvh') && nextSigningKeyPairs && nextSigningKeyPairs.length > 0) {
      for (let i = 0; i < nextSigningKeyPairs.length; i++) {
        const label = i === 0 ? 'ed25519-next' : `ed25519-next-${i}`;
        await keystore.storeKeyPairAsync(cesrVid, label, nextSigningKeyPairs[i], input.passphrase);
      }
    }
    // PQ roots of trust (only when the method provisioned them).
    if (mlDsa65KeyPair) {
      await keystore.storeKeyPairAsync(cesrVid, 'ml_dsa_65', mlDsa65KeyPair, input.passphrase);
    }
    if (hybridKemKeyPair) {
      await keystore.storeKeyPairAsync(cesrVid, 'mlkem768_x25519', hybridKemKeyPair, input.passphrase);
    }
    keystore.close();
  }

  const identity = await identitiesRepo.findByUuid(db, identityUuid);
  const didDocument = await didDocumentsRepo.findByUuid(db, didDocumentUuid);

  return {
    identity: identity!, didDocument: didDocument!,
    publicKeys: {
      ed25519: Buffer.from(signingKeyPair.publicKey).toString('base64'),
      x25519: Buffer.from(agreementKeyPair.publicKey).toString('base64'),
    },
    signingKeyPair,
  };
}

/**
 * The VID a peer signs its **operation proofs** with.
 *
 * An agent signs with its **live identity key**: `meta.vid` is the CESR encoding of its
 * Ed25519 keystore key, and the push's `publicKeys.ed25519` IS that live key ("this push
 * makes the live key authoritative for verification" — see createRemoteVta above). Verified
 * against the field log: CESR-encoding the key published for `shannon` reproduces the
 * `DIdB25_WgIXu…` actor prefix exactly.
 *
 * Deriving rather than storing is deliberate — a key rotation can never leave a stale VID
 * here. It is also why the server must PUBLISH its own VID (it signs with the permanent TSP
 * key, which no peer can derive from its identity key): see `ensureServerVta`.
 *
 * Returns `undefined` when the key is unknown, so the verifier reports the sender binding
 * `indeterminate` — never a false `invalid` (the F-031 discipline).
 */
export async function resolveOperationVid(
  db: DataSource,
  didDocumentUuid?: string | null,
): Promise<string | undefined> {
  if (!didDocumentUuid) return undefined;
  const key = await keysRepo.findCurrentForDidDocument(db, didDocumentUuid, 'ed25519');
  if (!key?.publicKey) return undefined;
  const pk = key.publicKey instanceof Uint8Array
    ? key.publicKey
    : new Uint8Array(key.publicKey as ArrayBufferLike);
  return cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, pk);
}

/**
 * Sync the authoritative public keys from an agent identity_push onto an
 * EXISTING utility-server identity. The agent's `publicKeys` reflect its LIVE
 * keystore keys; re-extracting from the DID document would risk storing a stale
 * (pre-rotation/next) key that breaks shared-key canonicalization downstream.
 * Updates the row in place when a rotation changed the key; inserts when the
 * row is missing.
 */
async function syncRemotePublicKeys(
  db: DataSource,
  identityUuid: string,
  didDocumentUuid: string | undefined,
  publicKeys: { ed25519: string; x25519: string },
  recordedByNode?: string,
): Promise<void> {
  const entries: Array<{ keyType: 'ed25519' | 'x25519'; publicKey: Buffer }> = [];
  if (publicKeys.ed25519) entries.push({ keyType: 'ed25519', publicKey: Buffer.from(publicKeys.ed25519, 'base64') });
  if (publicKeys.x25519) entries.push({ keyType: 'x25519', publicKey: Buffer.from(publicKeys.x25519, 'base64') });

  const now = Math.floor(Date.now() / 1000);
  for (const entry of entries) {
    // ONE active key per (identity_uuid, key_type, rotation_version=0).
    //
    // The row's `did_document_uuid` linkage must NOT decide identity: the
    // handshake writes the key it extracted from the document IT upserted (often
    // the non-primary handshake-stub row), while identity_push writes the primary
    // document's uuid. A purely doc-scoped upsert therefore INSERTED A SECOND row
    // instead of updating, leaving `keys` with two ed25519/rv-0 rows for one
    // identity. `DsRelationshipStore.get()` then picked between them with no
    // deterministic order, so the server intermittently verified TSP signatures
    // with the wrong key — the observed `tspOpen: signature verification failed`
    // on otherwise valid messages. Here the live key from identity_push always
    // wins and the row converges onto the passed (primary) document.
    const existingKey = await db.get<{ uuid: string; public_key: Buffer | Uint8Array }>(
      `SELECT uuid, public_key FROM keys
        WHERE identity_uuid = ? AND key_type = ? AND rotation_version = 0
        ORDER BY created_at DESC, uuid DESC LIMIT 1`,
      identityUuid,
      entry.keyType,
    );

    if (existingKey) {
      const previous = Buffer.from(
        existingKey.public_key instanceof Uint8Array ? existingKey.public_key : new Uint8Array(existingKey.public_key),
      ).toString('hex');
      const next = Buffer.from(entry.publicKey).toString('hex');
      const updateRow = () => db.run(
        `UPDATE keys
            SET public_key = ?, did_document_uuid = COALESCE(?, did_document_uuid),
                recorded_by_node = ?, replicated_at = ?
          WHERE uuid = ?`,
        entry.publicKey, didDocumentUuid ?? null, recordedByNode ?? null, now, existingKey.uuid,
      );
      try {
        await updateRow();
      } catch (err) {
        if (!isUniqueViolation(err)) throw err;
        // Two rv-0 rows already exist for this (identity, key_type) with DIFFERENT
        // did_document_uuid values — the handshake-stub vs identity_push state documented
        // above. Because did_document_uuid is PART of the unique tuple, moving THIS row's
        // linkage onto the passed document collides with the sibling that already holds it.
        // That aborts the enclosing push, and the agent's durable outbox replays it forever:
        // observed 2026-09-25 as a rapid tx_prepare → vote 'no' → tx_abort loop naming this
        // exact constraint. It is deterministic, not a race — the failed UPDATE changes
        // nothing, so every replay collides identically.
        //
        // Converge instead of aborting: drop the sibling that already holds the passed
        // document, then re-point this row (which keeps the live key AND the newer
        // recorded_at ordering). One row per (identity, key_type, rotation_version) remains,
        // which is this function's stated invariant — and the duplicate was what made
        // verification-key resolution non-deterministic.
        await db.run(
          `DELETE FROM keys
            WHERE identity_uuid = ? AND key_type = ? AND rotation_version = 0
              AND uuid <> ? AND did_document_uuid = ?`,
          identityUuid, entry.keyType, existingKey.uuid, didDocumentUuid ?? null,
        );
        await updateRow();
      }
      if (previous !== next) {
        console.log(
          `[vta] keys.${entry.keyType} updated for ${identityUuid.slice(0, 8)}…: ` +
          `${previous.slice(0, 16)}… → ${next.slice(0, 16)}… (live key from identity_push wins)`,
        );
      }
      continue;
    }

    // Absent → atomic upsert. Kept because two concurrent identity_push
    // transactions (e.g. both agents of a VRC pair archiving the same co-admin
    // identity) can both observe "absent", and the UNIQUE tuple must merge them
    // instead of aborting the whole 2PC on prepare() (see
    // utility-server/test/db/keys-upsert.test.ts).
    const keyUuid = generateUuid();
    await db.run(
      `INSERT INTO keys
         (identity_uuid, did_document_uuid,
          key_type, public_key, rotation_version, uuid,
          recorded_by_node, replicated_at, created_at)
       VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)
       ON CONFLICT (identity_uuid, did_document_uuid, key_type, rotation_version)
       DO UPDATE SET
         public_key        = excluded.public_key,
         did_document_uuid = COALESCE(excluded.did_document_uuid, keys.did_document_uuid),
         recorded_by_node  = excluded.recorded_by_node,
         replicated_at     = excluded.replicated_at`,
      identityUuid,
      didDocumentUuid ?? null, entry.keyType, entry.publicKey, keyUuid,
      recordedByNode ?? null, now, now,
    );
  }
}

/**
 * True when an error is a UNIQUE-constraint violation (SQLite or PostgreSQL /
 * YugabyteDB). Used to turn an insert race into an adopt-the-winner path
 * instead of aborting the enclosing identity_push transaction.
 */
function isUniqueViolation(err: unknown): boolean {
  const code = (err as { code?: string } | null)?.code;
  if (code === '23505' || code === 'SQLITE_CONSTRAINT_UNIQUE' || code === 'SQLITE_CONSTRAINT') {
    return true;
  }
  const message = (err as Error | null)?.message ?? '';
  return /unique constraint|duplicate key|UNIQUE constraint failed/i.test(message);
}

/**
 * Ensure the identity's DID document row for `realDid` exists and is the
 * identity's PRIMARY document — without ever creating a second row for the same
 * DID, and without writing one DID's document into another DID's row.
 *
 * Why this exists (two bugs it closes):
 *
 * 1. **Duplicate row.** `did_documents.did` is globally `UNIQUE` (migrations
 *    0002 / 0019). The TSP-bridge RFI/RFA handshake and the per-message
 *    endpoint recording both materialize handshake stubs with `is_primary = 0`
 *    (`DsIdentityResolver.resolveRemoteIdentity`), so a stub identity ALWAYS
 *    already has a row for its DID. Inserting a second one raised a
 *    unique-constraint violation that aborted the identity_push 2PC
 *    (`prepare()` votes `no`) — the exact reverse of the intended self-heal.
 *
 * 2. **Wrong row updated.** Resolving via `findPrimaryForIdentity()` returns
 *    whatever row is primary, which may belong to a DIFFERENT DID (context
 *    C-DID / M-DID rows are `is_primary = 0`, but a legacy peer:4 row could be
 *    primary while the agent now presents a did:scid:vh). Overwriting that row's
 *    `document_json` made `document_json` disagree with `did`.
 *
 * The row is therefore resolved BY DID, updated, and — if it is not already
 * primary — promoted via `setPrimary()`, which clears `is_primary` on the
 * identity's other documents so every identity keeps exactly one primary.
 *
 * Concurrency: two identity_push transactions (both agents of a VRC pair
 * archiving the same co-admin identity) can still interleave between the read
 * and the insert. That race is handled by ADOPTING the winning row when the
 * insert loses to the UNIQUE(did) constraint, rather than propagating the
 * error (which would vote `no` and abort the push).
 *
 * @returns the row for `realDid`, or null if it could not be resolved.
 */
export async function ensurePrimaryDidDocument(
  db: DataSource,
  input: {
    identityUuid: string;
    realDid: string;
    documentJson: string;
    recordedByNode?: string;
  },
): Promise<DidDocumentRow | null> {
  const method = input.realDid.startsWith('did:scid:vh:') ? 'did:scid:vh' : 'did:peer:4';
  const now = Math.floor(Date.now() / 1000);

  let doc = await didDocumentsRepo.findByRealDid(db, input.realDid);

  if (doc) {
    // The row for this DID already exists (handshake stub or a previous push).
    // Update in place — never insert a duplicate.
    await db.run(
      'UPDATE did_documents SET document_json = ?, method = ?, updated_at = ? WHERE uuid = ?',
      input.documentJson,
      method,
      now,
      doc.uuid,
    );
  } else {
    try {
      const docUuid = await didDocumentsRepo.create(db, {
        identityUuid: input.identityUuid,
        did: input.realDid,
        method,
        documentJson: input.documentJson,
        // Inserted non-primary on purpose: the promote step below clears any
        // OTHER primary on this identity, so no code path can leave an identity
        // with two primary documents.
        isPrimary: false,
        recordedByNode: input.recordedByNode,
      });
      doc = await didDocumentsRepo.findByUuid(db, docUuid);
      console.log(`[vta] Materialized DID document for stub identity: ${input.realDid}`);
    } catch (err) {
      if (!isUniqueViolation(err)) throw err;
      // Lost an insert race against a concurrent push for the same DID —
      // adopt the winner's row instead of failing the transaction.
      doc = await didDocumentsRepo.findByRealDid(db, input.realDid);
      if (!doc) throw err;
      console.log(`[vta] Adopted concurrently-created DID document for ${input.realDid}`);
    }
  }

  if (!doc) return null;

  if (doc.identityUuid !== input.identityUuid) {
    // The single row for this DID is bound to a DIFFERENT identity uuid (the
    // orphaned-stub family: the handshake keyed the stub by didToUuid(did) while
    // the agent reports its own legacy/authoritative uuid). Deliberately return
    // null so the caller fails LOUDLY instead of writing this push's document
    // and keys across identity rows. Merging such orphans is a distinct
    // reconciliation step (one row per DID, re-bound to the authoritative
    // identity) and must not happen implicitly on a push.
    console.warn(
      `[vta] did_document for ${input.realDid} is bound to identity ${doc.identityUuid}, ` +
      `not the pushed identity ${input.identityUuid} — refusing to write across identities`,
    );
    return null;
  }

  if (doc.isPrimary !== 1) {
    // Promote the row we resolved/created. `setPrimary` clears is_primary on
    // this identity's OTHER documents first, so an identity always ends with
    // exactly one primary — and this DID never gains a second row.
    await didDocumentsRepo.setPrimary(db, doc.uuid, input.identityUuid);
    console.log(`[vta] Promoted DID document to primary for ${input.realDid} (promoted in place, no duplicate row)`);
    return await didDocumentsRepo.findByUuid(db, doc.uuid);
  }

  return doc;
}

export async function createRemoteVta(
  db: DataSource,
  input: { realDid: string; name?: string; subjectKind?: SubjectKind; didDocument: object; publicKeys: { ed25519: string; x25519: string; }; peerId?: string; multiaddrs?: string[]; recordedByNode?: string; uuid?: string; },
): Promise<CreateVtaResult> {
  // Diagnostic: the document's #key-1 (what the TSP handshake stores as the peer's
  // verification key) versus the LIVE keystore key the agent reports on every push.
  // These legitimately differ whenever VM[0] is a Slot-A transport key or a
  // pre-rotation/next key — which is exactly how a server ends up verifying TSP
  // signatures with a key the agent never signs with, surfacing as
  // `tspOpen: signature verification failed` on every message from that agent.
  // The push below makes the live key authoritative; this line says so out loud.
  try {
    const docKey = Buffer.from(
      extractEd25519PublicKey(input.didDocument as Parameters<typeof extractEd25519PublicKey>[0]),
    ).toString('hex');
    const liveKey = Buffer.from(input.publicKeys.ed25519, 'base64').toString('hex');
    if (docKey !== liveKey) {
      console.warn(
        `[vta] ${input.realDid}: DID-document #key-1 (${docKey.slice(0, 16)}…) differs from the pushed ` +
        `live keystore key (${liveKey.slice(0, 16)}…) — the handshake stores #key-1 while the agent signs ` +
        `TSP messages with the live key; this push makes the live key authoritative for verification.`,
      );
    }
  } catch { /* document or key not parseable — nothing to compare */ }

  // The identity key is deterministic (UUIDv5 of the real DID) so every node
  // that materialises this identity arrives at the same uuid. When the payload
  // carries the creator's identityUuid (agent identity_push), prefer it — this
  // is the agent's authoritative key and must be preserved verbatim so the
  // utility server's copy matches what the agent reports back in ceremonies.
  const identityUuid = input.uuid ?? didToUuid(input.realDid);
  const existing = (input.uuid ? await identitiesRepo.findByUuid(db, input.uuid) : null)
    ?? await identitiesRepo.findByRealDid(db, input.realDid);
  if (existing) {
    // Sync the stored DID document with the pushed one (e.g. the agent added
    // alsoKnownAs during name registration; identity_push sends the full
    // document on every push). Resolved BY DID and promoted, never duplicated:
    // see ensurePrimaryDidDocument() for both failure modes it closes.
    const existingDoc = await ensurePrimaryDidDocument(db, {
      identityUuid: existing.uuid,
      realDid: input.realDid,
      documentJson: JSON.stringify(input.didDocument),
      recordedByNode: input.recordedByNode,
    });
    if (existingDoc) {
      // Backfill the definitive agent fields (peer, name, subject_kind) onto
      // a previously-created stub/fake so the utility server's copy becomes a
      // real VTA. Prior to this, an identity that first appeared as a
      // TSP-bridge fake (no endpoint) was never upgraded, which broke
      // VTC founding (createVtc rejects founding admins without an endpoint).
      // The agent's identity_push is authoritative for these public fields;
      // never overwrite a non-null value with a null/absent one.
      const sets: string[] = [];
      const vals: unknown[] = [];
      const setDescs: string[] = [];
      if (input.name) { sets.push('name = ?'); vals.push(input.name); setDescs.push(`name = ${JSON.stringify(input.name)}`); }
      if (input.subjectKind) { sets.push('subject_kind = ?'); vals.push(input.subjectKind); setDescs.push(`subject_kind = ${JSON.stringify(input.subjectKind)}`); }
      if (sets.length > 0) {
        await db.run(`UPDATE identities SET ${sets.join(', ')} WHERE uuid = ?`, ...vals, existing.uuid);
        console.log(`[vta] Backfilled identity fields for ${input.realDid}: ${setDescs.join(', ')}`);
      }

      // Record the agent's live endpoint through the guarded peer_endpoints
      // write (refuses cross-identity claims, retires superseded endpoints).
      //
      // `multiaddrs` is carried through when the push supplies it: the
      // ConnectivitySupervisor dials these to (re)reach the member, and without
      // them an agent endpoint has NO direct address at all (see
      // IdentityPushPayload.multiaddrs).
      if (input.peerId) {
        const result = await setActiveEndpoint(db, {
          identityUuid: existing.uuid,
          peerId: input.peerId,
          multiaddrs: input.multiaddrs,
          recordedByNode: input.recordedByNode,
        });
        if (result.applied) {
          console.log(`[vta] Recorded active endpoint for ${input.realDid}`);
        }
      }

      // Sync the public keys from the authoritative identity_push payload. The
      // agent's `publicKeys` reflect its LIVE keystore keys; re-extracting from
      // the DID document would risk storing a stale (pre-rotation/next) key that
      // breaks shared-key canonicalization downstream. Update in place when a
      // rotation changed the key; insert when the row is missing.
      await syncRemotePublicKeys(db, existing.uuid, existingDoc.uuid, input.publicKeys, input.recordedByNode);

      const refreshed = await identitiesRepo.findByUuid(db, existing.uuid);
      console.log(`[vta] Updated DID document for existing identity: ${input.realDid}`);
      return {
        identity: refreshed ?? existing,
        didDocument: { ...existingDoc, documentJson: JSON.stringify(input.didDocument) },
        publicKeys: input.publicKeys,
      };
    }
    throw new Error(
      `createRemoteVta: could not resolve or materialize the DID document for ${input.realDid} ` +
      `(identity ${existing.uuid}) — see the [vta] warning above`,
    );
  }

  // A brand-new identity can be materialized concurrently by BOTH agents of a
  // VRC pair (each identity_push archives the ceremony partner). Create it in a
  // serializable transaction so the identity → did_document → keys writes are
  // atomic and coordinate with a concurrent first-push (serialization-failure
  // retry is handled by the DataSource transaction implementation).
  const { identityUuid: createdIdentityUuid, didDocumentUuid: createdDidDocumentUuid } = await db.transaction(async (tx) => {
    const id = await identitiesRepo.create(tx, {
      uuid: identityUuid, realDid: input.realDid, role: 'vta', subjectKind: input.subjectKind ?? 'human',
      custody: 'remote', name: input.name, peerId: input.peerId, recordedByNode: input.recordedByNode,
    });

    const docUuid = await didDocumentsRepo.create(tx, {
      identityUuid: id, did: input.realDid,
      method: input.realDid.startsWith('did:scid:vh:') ? 'did:scid:vh' : 'did:peer:4',
      documentJson: JSON.stringify(input.didDocument), isPrimary: true, recordedByNode: input.recordedByNode,
    });

    if (input.publicKeys.ed25519) {
      await keysRepo.create(tx, { identityUuid: id, didDocumentUuid: docUuid, keyType: 'ed25519', publicKey: Buffer.from(input.publicKeys.ed25519, 'base64'), recordedByNode: input.recordedByNode });
    }
    if (input.publicKeys.x25519) {
      await keysRepo.create(tx, { identityUuid: id, didDocumentUuid: docUuid, keyType: 'x25519', publicKey: Buffer.from(input.publicKeys.x25519, 'base64'), recordedByNode: input.recordedByNode });
    }
    return { identityUuid: id, didDocumentUuid: docUuid };
  });

  const identity = await identitiesRepo.findByUuid(db, createdIdentityUuid);
  const didDocument = await didDocumentsRepo.findByUuid(db, createdDidDocumentUuid);
  return { identity: identity!, didDocument: didDocument!, publicKeys: input.publicKeys };
}