/**
 * Identity / DID-document / verification-key reconciliation.
 *
 * A one-shot operator pass over data that accumulated structural damage during
 * the TSP v2→v3 migration and before the write-side fixes. It is READ-ONLY by
 * default; `fix: true` applies only the three repairs that stay WITHIN a single
 * identity row (so no cross-row merging and no identity deletion):
 *
 *  1. **more than one primary `did_documents` row** for an identity → keep the
 *     best candidate, demote the rest (an identity must have exactly one primary;
 *     `Identity.did` — and therefore a plain `did ?? uuid` OOBI — is read from it,
 *     see D12);
 *  2. **no primary document** at all (the handshake wrote stubs with
 *     `is_primary = 0`, which is what made `createRemoteVta` throw before the
 *     promote fix) → promote the best existing candidate;
 *  3. **duplicate active `keys` rows** for one `(identity, key_type, rv=0)` —
 *     created when the handshake linked the key to the document *it* upserted
 *     while identity_push linked it to the primary document, so the doc-scoped
 *     upsert inserted instead of updating. Those duplicates are what made
 *     signature verification pick a key arbitrarily. The keeper is the row linked
 *     to the identity's primary document, else the newest; the others are removed.
 *
 * Also REPORTED (never auto-applied — these need a human decision):
 *  - **non-canonical identities**: `uuid !== didToUuid(primaryDid)`, i.e. rows
 *    keyed by something other than their DID (the pre-v3 VID-keyed stubs), with
 *    whether a canonical row also exists (a merge candidate);
 *  - **orphan identities**: identities with no `did_documents` row at all
 *    (endpoint-less "TSP-bridge fake" carriers). G3b stops new ones;
 *    deleting/merging existing rows is deliberately left to a reviewed step.
 */

import type { DataSource } from './data-source.js';
import { didToUuid } from './uuid-helpers.js';
import * as didDocumentsRepo from './repositories/did-documents-repo.js';

export interface ReconcileOptions {
  /** Apply the three in-identity repairs. Default `false` = report only. */
  fix?: boolean;
}

export interface DocumentFix {
  identityUuid: string;
  keptDocUuid: string;
  keptDid: string;
  /** Docs demoted (or, for a missing primary, the promoted one's former peers). */
  otherDocUuids: string[];
  kind: 'multiple-primaries' | 'missing-primary';
}

export interface KeyFix {
  identityUuid: string;
  keyType: string;
  keptKeyUuid: string;
  removedKeyUuids: string[];
}

export interface NonCanonicalIdentity {
  identityUuid: string;
  primaryDid: string | null;
  expectedUuid: string | null;
  canonicalRowExists: boolean;
}

export interface OrphanIdentity {
  identityUuid: string;
  custody: string;
  name: string | null;
}

export interface ReconcileReport {
  scanned: { identities: number; documents: number; keyRows: number };
  multiplePrimaries: DocumentFix[];
  missingPrimary: DocumentFix[];
  duplicateActiveKeys: KeyFix[];
  nonCanonicalIdentities: NonCanonicalIdentity[];
  orphanIdentities: OrphanIdentity[];
  applied: { documentFixes: number; keyFixes: number };
}

interface DocRow {
  uuid: string;
  identity_uuid: string;
  did: string;
  is_primary: number;
  created_at: number | null;
}

interface KeyRow {
  uuid: string;
  identity_uuid: string;
  did_document_uuid: string | null;
  key_type: string;
  created_at: number | null;
}

/**
 * Rank a document: one that the rest of the graph already REFERENCES wins (a
 * relationship row pointing at it), then one an active key row is linked to,
 * then the newest. Deterministic (uuid as the final tie-break) so a report run
 * and a fix run always agree on the same keeper.
 */
function rankDoc(
  doc: DocRow,
  referencedDocs: Set<string>,
  keyLinkedDocs: Set<string>,
): [number, number, string] {
  const score = (referencedDocs.has(doc.uuid) ? 2 : 0) + (keyLinkedDocs.has(doc.uuid) ? 1 : 0);
  return [score, doc.created_at ?? 0, doc.uuid];
}

function compareRank(a: [number, number, string], b: [number, number, string]): number {
  if (a[0] !== b[0]) return b[0] - a[0];
  if (a[1] !== b[1]) return b[1] - a[1];
  return a[2] < b[2] ? 1 : a[2] > b[2] ? -1 : 0;
}

export async function reconcileIdentities(
  db: DataSource,
  opts: ReconcileOptions = {},
): Promise<ReconcileReport> {
  const fix = opts.fix === true;

  const identities = await db.all<{ uuid: string; custody: string; name: string | null }>(
    'SELECT uuid, custody, name FROM identities',
  );
  const docs = await db.all<DocRow>(
    'SELECT uuid, identity_uuid, did, is_primary, created_at FROM did_documents',
  );
  const keys = await db.all<KeyRow>(
    `SELECT uuid, identity_uuid, did_document_uuid, key_type, created_at
       FROM keys WHERE rotation_version = 0`,
  );
  const referencedRows = await db.all<{ doc_uuid: string | null }>(
    `SELECT local_did_document_uuid AS doc_uuid FROM relationships WHERE local_did_document_uuid IS NOT NULL
     UNION
     SELECT remote_did_document_uuid AS doc_uuid FROM relationships WHERE remote_did_document_uuid IS NOT NULL`,
  );

  const referencedDocs = new Set(referencedRows.map((r) => r.doc_uuid!).filter(Boolean));
  const keyLinkedDocs = new Set(keys.map((k) => k.did_document_uuid).filter((u): u is string => !!u));

  const docsByIdentity = new Map<string, DocRow[]>();
  for (const doc of docs) {
    const list = docsByIdentity.get(doc.identity_uuid) ?? [];
    list.push(doc);
    docsByIdentity.set(doc.identity_uuid, list);
  }

  const multiplePrimaries: DocumentFix[] = [];
  const missingPrimary: DocumentFix[] = [];
  const orphanIdentities: OrphanIdentity[] = [];
  const nonCanonicalIdentities: NonCanonicalIdentity[] = [];

  for (const identity of identities) {
    const owned = docsByIdentity.get(identity.uuid) ?? [];

    if (owned.length === 0) {
      orphanIdentities.push({ identityUuid: identity.uuid, custody: identity.custody, name: identity.name });
      continue;
    }

    const primaries = owned.filter((d) => d.is_primary === 1);
    const ranked = [...owned].sort(
      (a, b) => compareRank(rankDoc(a, referencedDocs, keyLinkedDocs), rankDoc(b, referencedDocs, keyLinkedDocs)),
    );
    // With several primaries, keep the best-ranked PRIMARY (never silently swap
    // the identity's DID); with none, promote the best-ranked document overall.
    const keeper = primaries.length > 0
      ? [...primaries].sort(
          (a, b) => compareRank(rankDoc(a, referencedDocs, keyLinkedDocs), rankDoc(b, referencedDocs, keyLinkedDocs)),
        )[0]
      : ranked[0];

    if (primaries.length > 1) {
      multiplePrimaries.push({
        identityUuid: identity.uuid,
        keptDocUuid: keeper.uuid,
        keptDid: keeper.did,
        otherDocUuids: owned.filter((d) => d.uuid !== keeper.uuid).map((d) => d.uuid),
        kind: 'multiple-primaries',
      });
    } else if (primaries.length === 0) {
      missingPrimary.push({
        identityUuid: identity.uuid,
        keptDocUuid: keeper.uuid,
        keptDid: keeper.did,
        otherDocUuids: owned.filter((d) => d.uuid !== keeper.uuid).map((d) => d.uuid),
        kind: 'missing-primary',
      });
    }

    // Canonicality: the identity key should be UUIDv5 of its primary DID.
    const expectedUuid = didToUuid(keeper.did);
    if (identity.uuid !== expectedUuid) {
      nonCanonicalIdentities.push({
        identityUuid: identity.uuid,
        primaryDid: keeper.did,
        expectedUuid,
        canonicalRowExists: identities.some((i) => i.uuid === expectedUuid),
      });
    }
  }

  // Duplicate active keys: keep the row linked to the identity's primary document
  // (the one the relationship store prefers when it resolves the peer's key).
  const keysByIdentityType = new Map<string, KeyRow[]>();
  for (const key of keys) {
    const groupKey = `${key.identity_uuid}|${key.key_type}`;
    const list = keysByIdentityType.get(groupKey) ?? [];
    list.push(key);
    keysByIdentityType.set(groupKey, list);
  }

  const duplicateActiveKeys: KeyFix[] = [];
  for (const group of keysByIdentityType.values()) {
    if (group.length < 2) continue;
    const [first] = group;
    const primaryDocUuid = docsByIdentity
      .get(first.identity_uuid)
      ?.find((d) => d.is_primary === 1)?.uuid;
    const rankedKeys = [...group].sort((a, b) => {
      const aPrimary = a.did_document_uuid && a.did_document_uuid === primaryDocUuid ? 1 : 0;
      const bPrimary = b.did_document_uuid && b.did_document_uuid === primaryDocUuid ? 1 : 0;
      if (aPrimary !== bPrimary) return bPrimary - aPrimary;
      const at = a.created_at ?? 0;
      const bt = b.created_at ?? 0;
      if (at !== bt) return bt - at;
      return a.uuid < b.uuid ? 1 : -1;
    });
    duplicateActiveKeys.push({
      identityUuid: first.identity_uuid,
      keyType: first.key_type,
      keptKeyUuid: rankedKeys[0].uuid,
      removedKeyUuids: rankedKeys.slice(1).map((k) => k.uuid),
    });
  }

  let applied = { documentFixes: 0, keyFixes: 0 };

  if (fix) {
    // ONE transaction for the whole repair pass. Both reasons are operator-facing:
    //
    //  - `setPrimary()` is itself TWO statements (clear `is_primary` on every other
    //    document, then set it on the keeper). Without a transaction, a crash
    //    between them leaves the identity with NO primary document — precisely the
    //    damage repair #2 above exists to fix. The repair must not be able to
    //    create the condition it repairs.
    //  - a half-applied loop leaves a database the operator's report no longer
    //    describes, and the report is the only record of what the run intended.
    //
    // The writes are computed above from a pre-read snapshot and are idempotent
    // (set-primary, delete-by-uuid), so a YugabyteDB serialization retry re-running
    // this callback is harmless — as is re-running `--fix` after a rolled-back run.
    applied = await db.transaction(async (tx) => {
      const counts = { documentFixes: 0, keyFixes: 0 };
      // Document repairs first, so the duplicate-key keeper (which prefers the
      // primary-linked row) is chosen against the POST-fix primary.
      for (const fixEntry of [...multiplePrimaries, ...missingPrimary]) {
        // Writes go through the transaction-bound DataSource, not the outer one.
        await didDocumentsRepo.setPrimary(tx, fixEntry.keptDocUuid, fixEntry.identityUuid);
        counts.documentFixes += 1;
      }
      for (const keyFix of duplicateActiveKeys) {
        const placeholders = keyFix.removedKeyUuids.map(() => '?').join(', ');
        await tx.run(`DELETE FROM keys WHERE uuid IN (${placeholders})`, ...keyFix.removedKeyUuids);
        counts.keyFixes += 1;
      }
      return counts;
    });
  }

  return {
    scanned: { identities: identities.length, documents: docs.length, keyRows: keys.length },
    multiplePrimaries,
    missingPrimary,
    duplicateActiveKeys,
    nonCanonicalIdentities,
    orphanIdentities,
    applied,
  };
}
