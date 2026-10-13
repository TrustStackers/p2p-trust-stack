/**
 * rotation-log-sync — persist an agent-pushed `did:scid:vh` rotation log on the
 * utility server.
 *
 * ## Why
 *
 * A `did:scid:vh` DID is a bare SCID hash: resolving it means replaying the
 * append-only rotation log. The utility server only ever held a log for
 * identities it created ITSELF — an agent's `identity_push` carried the current
 * DID document but not the log, so a pushed remote identity could only be
 * served from a cached snapshot (the resolver reports this as
 * `didResolutionMetadata.source: 'cache'`).
 *
 * This module closes that gap: the agent includes its log in the push
 * (`IdentityPushPayload.rotationLog`), and the server writes it into the same
 * `rotation_log` table the resolver reads, so the DID resolves as
 * `source: 'log'` with a verifiable chain.
 *
 * ## Idempotency
 *
 * A push re-sends the WHOLE log on every roll, so this is insert-if-absent per
 * `(did_document_uuid, version)` — never an update, never a unique-violation.
 * Re-running the same push is a no-op.
 *
 * ## Never fatal
 *
 * `applyIdentityPush` runs inside the coordinator's `prepare()`, so a throw here
 * would vote `no` and abort the push — and the agent's durable outbox would then
 * replay it forever (the failure mode documented in `syncRemotePublicKeys`). The
 * caller therefore treats this as best-effort: the document/key/profile sync is
 * load-bearing, the log is a fidelity improvement.
 */

import type { DataSource } from '../db/data-source.js';
import { insertIfAbsent } from '../db/repositories/rotation-repo.js';
import {
  packRotationEntry,
  rotationEntryFromJson,
  type RotationEntryJson,
} from '../did/rotation-entry-codec.js';

export interface PersistRotationLogResult {
  /** Versions newly written. */
  inserted: number;
  /** Versions already held (or rejected as malformed). */
  skipped: number;
  /** Entries offered. */
  total: number;
}

/** A pushed entry is usable only if it carries the fields the chain needs. */
function isUsable(json: unknown): json is RotationEntryJson {
  if (!json || typeof json !== 'object') return false;
  const e = json as Partial<RotationEntryJson>;
  return (
    typeof e.version === 'number' &&
    typeof e.digest === 'string' &&
    typeof e.signature === 'string' &&
    !!e.didDocument &&
    typeof e.didDocument === 'object'
  );
}

/**
 * Write an agent-pushed rotation log for `didDocumentUuid`, inserting only
 * versions not already held.
 */
export async function persistPushedRotationLog(
  db: DataSource,
  didDocumentUuid: string,
  entries: unknown,
): Promise<PersistRotationLogResult> {
  if (!Array.isArray(entries) || entries.length === 0) {
    return { inserted: 0, skipped: 0, total: 0 };
  }

  let inserted = 0;
  let skipped = 0;

  // Ascending version order, so a partial failure still leaves a coherent
  // prefix of the chain rather than a gap.
  const sorted = [...entries].sort(
    (a, b) => Number((a as RotationEntryJson)?.version ?? 0) - Number((b as RotationEntryJson)?.version ?? 0),
  );

  for (const raw of sorted) {
    if (!isUsable(raw)) {
      skipped++;
      continue;
    }
    const entry = rotationEntryFromJson(raw);
    const ok = await insertIfAbsent(db, {
      didDocumentUuid,
      version: entry.version,
      previousHash: entry.prevHash ?? undefined,
      // Same encoding the agent's own RotationLogStore writes: a JSON array of
      // base64 next-key commitments (legacy single-key rows are raw bytes).
      newPublicKey: Buffer.from(
        JSON.stringify(entry.nextKeyCommitments.map((k) => Buffer.from(k).toString('base64'))),
      ),
      signedEntry: Buffer.from(
        packRotationEntry({
          didDocument: entry.didDocument,
          parameters: entry.parameters,
          digest: entry.digest,
          signature: entry.signature,
          mlDsa65Signature: entry.mlDsa65Signature,
        }),
      ),
      createdAt: entry.createdAt,
    });
    if (ok) inserted++;
    else skipped++;
  }

  return { inserted, skipped, total: sorted.length };
}
