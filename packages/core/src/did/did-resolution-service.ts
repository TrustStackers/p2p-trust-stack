/**
 * DidResolutionService — DataSource-backed `did:scid:vh` / `did:peer:4` resolution
 * for the public DID resolution surface.
 *
 * This is the shared core behind `utility-server/src/resolver-app.ts`. It is the
 * server-side counterpart of `DidResolver` (`src/did/did-resolver.ts`): where
 * `DidResolver` orchestrates a `RotationLogSource` (local store, or an HTTP
 * fetch from a resolution endpoint), this service reads the log straight out of
 * the shared `did_documents` + `rotation_log` tables and replays it with
 * `ScidVhMethod.resolveFromLog()`.
 *
 * ## Two tiers, honestly labelled
 *
 * A `did:scid:vh` DID is a bare SCID hash — resolving it means fetching and
 * replaying the append-only rotation log. Two cases are distinguished:
 *
 *   - `source: 'log'`   — rotation-log rows exist and the chain validated. The
 *                         document is a VERIFIED replay; `versionId`,
 *                         `witnessAttested` and the rotation history are real.
 *   - `source: 'cache'` — no log on this server (or the chain did not validate).
 *                         The document is served from the last-known
 *                         `did_documents.document_json` snapshot and is NOT
 *                         chain-verified. The marker says so, rather than
 *                         presenting a cached document as if it were resolved.
 *   - `source: 'offline'` — `did:peer:4`, whose document is embedded in the DID.
 *
 * Callers must not treat a `'cache'` result as a resolution in the DID Core
 * sense; the `source` marker exists precisely so they can tell the difference.
 */

import type { DataSource } from '../db/data-source.js';
import * as didDocumentsRepo from '../db/repositories/did-documents-repo.js';
import { ScidVhMethod } from './scid-vh-method.js';
import { resolveDidPeer4 } from './resolve.js';
import {
  parseNextKeyCommitments,
  toUint8Array,
  unpackRotationEntry,
} from './rotation-entry-codec.js';
import type { DidDocument } from './types.js';
import type { RotationLogEntry } from './rotation-types.js';
import type { DidResolutionMetadata, DidDocumentMetadata } from './did-resolver.js';

/** The W3C DID Resolution envelope `@context`. */
export const DID_RESOLUTION_CONTEXT = 'https://w3id.org/did-resolution/v1';

/** Where the resolved document actually came from. */
export type ResolutionSource = 'log' | 'cache' | 'offline';

/** Resolution metadata, extended with this server's provenance marker. */
export interface ResolverMetadata extends DidResolutionMetadata {
  /** Where the document came from — see the file header. */
  source?: ResolutionSource;
  /** `did:scid:vh` only — the replayed chain validated. */
  chainValid?: boolean;
  /**
   * `did:scid:vh` only — rotation-log rows were found for this DID, regardless
   * of whether they validated. Distinguishes "the server has never been sent a
   * log" from "a log is held but it is broken".
   */
  logHeld?: boolean;
  /**
   * `source: 'cache'` only — WHY the log could not be used:
   *   - `no-log-held`   — the server holds only a cached document. Expected for
   *                       an agent identity that has not pushed its log.
   *   - `chain-invalid` — a log IS held but did not validate (divergence,
   *                       tampering, or a partial write). Worth investigating.
   */
  cacheReason?: 'no-log-held' | 'chain-invalid';
}

/** The W3C DID Resolution result, with our provenance-extended metadata. */
export interface ResolverResolutionResult {
  '@context': string;
  didResolutionMetadata: ResolverMetadata;
  didDocument: DidDocument | null;
  didDocumentMetadata: DidDocumentMetadata;
}

/** Everything a renderer needs about one resolution attempt. */
export interface DidResolutionReport {
  did: string;
  source: ResolutionSource | 'none';
  result: ResolverResolutionResult;
  /** The replayed rotation log — present only when `source === 'log'`. */
  log: RotationLogEntry[] | null;
  /** Witness attestation count per rotation version. */
  attestationsByVersion: Record<number, number>;
}

export interface ResolveOptions {
  /** Pin resolution to a rotation-log version (or lower). */
  versionId?: string;
  /** Pin resolution to entries created at or before this ISO-8601 time. */
  versionTime?: string;
  /** DID URL `src` resolution hint, attached to the resolved document. */
  src?: string;
}

/** A raw `rotation_log` row as the DataSource returns it. */
interface RotationLogDbRow {
  uuid: string;
  did_document_uuid: string;
  version: number;
  previous_hash: Uint8Array | null;
  new_public_key: Uint8Array;
  signed_entry: Uint8Array;
  created_at: number | null;
}

export class DidResolutionService {
  private readonly db: DataSource;
  private readonly scidVhMethod: ScidVhMethod;

  constructor(db: DataSource, opts: { scidVhMethod?: ScidVhMethod } = {}) {
    this.db = db;
    // No store (we supply the log ourselves) and no witnessVtc policy: witness
    // attestations are reported as metadata, not enforced as a resolution gate,
    // so a DID with a valid chain but no attestations still resolves.
    this.scidVhMethod = opts.scidVhMethod ?? new ScidVhMethod({});
  }

  /** Resolve a DID string to its document + provenance. */
  async resolve(did: string, options: ResolveOptions = {}): Promise<DidResolutionReport> {
    if (did.startsWith('did:peer:4')) return this.resolvePeer4(did);
    if (did.startsWith('did:scid:vh')) return this.resolveScidVh(did, options);
    return this.failure(did, 'methodNotSupported');
  }

  /**
   * The replayed rotation log for a `did:scid:vh` DID plus per-version witness
   * attestation counts. `null` when this server has no `did_documents` row for
   * the DID. Used by the `/…/did.jsonl` endpoint.
   */
  async resolveLog(
    did: string,
  ): Promise<{ entries: RotationLogEntry[]; attestationsByVersion: Record<number, number> } | null> {
    const loaded = await this.loadScidVh(did);
    if (!loaded) return null;
    return { entries: loaded.entries, attestationsByVersion: loaded.attestationsByVersion };
  }

  // -------------------------------------------------------------------------
  // did:scid:vh
  // -------------------------------------------------------------------------

  private async resolveScidVh(did: string, options: ResolveOptions): Promise<DidResolutionReport> {
    const loaded = await this.loadScidVh(did);
    if (!loaded) return this.failure(did, 'notFound');

    const { docRow, entries, attestationsByVersion } = loaded;
    const deactivated = docRow.status === 'deactivated';
    /** Whether a log exists here at all — separates "never sent one" from "broken". */
    const logHeld = entries.length > 0;

    // ── Tier 2: replay the rotation log (the real resolution path) ──────────
    if (entries.length > 0) {
      const effective = pinVersion(entries, options);
      if (effective.length > 0) {
        try {
          const doc = this.scidVhMethod.resolveFromLog(did, effective, options.src);
          const last = effective[effective.length - 1];
          return {
            did,
            source: 'log',
            log: entries,
            attestationsByVersion,
            result: {
              '@context': DID_RESOLUTION_CONTEXT,
              didResolutionMetadata: {
                source: 'log',
                chainValid: true,
                logHeld: true,
                ...(last.version > 0 ? { rotated: true } : {}),
              },
              didDocument: doc,
              didDocumentMetadata: {
                created: toIso8601(entries[0].createdAt),
                updated: toIso8601(last.createdAt),
                versionId: String(last.version),
                deactivated,
                witnessAttested: (attestationsByVersion[last.version] ?? 0) > 0,
              },
            },
          };
        } catch {
          // Chain did not validate — fall through to the cached snapshot rather
          // than failing outright. The `source` marker tells the caller this is
          // a cache, not a verified replay.
        }
      }
    }

    // ── Tier 1: cached snapshot (not chain-verified) ────────────────────────
    const cached = parseDocumentJson(docRow.documentJson);
    if (!cached) return this.failure(did, 'notFound');

    const latest = entries[entries.length - 1];
    return {
      did,
      source: 'cache',
      log: null,
      attestationsByVersion,
      result: {
        '@context': DID_RESOLUTION_CONTEXT,
        didResolutionMetadata: {
          source: 'cache',
          // Say WHICH cache case this is: a server that has never been sent a
          // log is a different problem (and a different fix) from one holding a
          // log that does not validate.
          logHeld,
          cacheReason: logHeld ? 'chain-invalid' : 'no-log-held',
        },
        didDocument: { ...cached, id: cached.id ?? did },
        didDocumentMetadata: {
          created: toIso8601(docRow.createdAt ?? undefined),
          updated: toIso8601(docRow.updatedAt ?? docRow.createdAt ?? undefined),
          ...(latest ? { versionId: String(latest.version) } : {}),
          deactivated,
          witnessAttested: latest ? (attestationsByVersion[latest.version] ?? 0) > 0 : false,
        },
      },
    };
  }

  private async loadScidVh(did: string): Promise<{
    docRow: didDocumentsRepo.DidDocumentRow;
    rows: RotationLogDbRow[];
    entries: RotationLogEntry[];
    attestationsByVersion: Record<number, number>;
  } | null> {
    const docRow = await didDocumentsRepo.findByRealDid(this.db, did);
    if (!docRow) return null;

    const rows = await this.db.all<RotationLogDbRow>(
      `SELECT uuid, did_document_uuid, version, previous_hash, new_public_key, signed_entry, created_at
         FROM rotation_log
        WHERE did_document_uuid = ?
        ORDER BY version ASC`,
      docRow.uuid,
    );

    return {
      docRow,
      rows,
      entries: rows.map(rowToRotationEntry),
      attestationsByVersion: await this.attestationCounts(docRow.uuid),
    };
  }

  /** Witness attestation count per rotation version for a DID document. */
  private async attestationCounts(didDocumentUuid: string): Promise<Record<number, number>> {
    const rows = await this.db.all<{ version: number; n: number | string }>(
      `SELECT rl.version AS version, COUNT(wa.uuid) AS n
         FROM rotation_log rl
         LEFT JOIN witness_attestations wa ON wa.rotation_log_uuid = rl.uuid
        WHERE rl.did_document_uuid = ?
        GROUP BY rl.version`,
      didDocumentUuid,
    );
    const counts: Record<number, number> = {};
    for (const row of rows) counts[Number(row.version)] = Number(row.n);
    return counts;
  }

  // -------------------------------------------------------------------------
  // did:peer:4
  // -------------------------------------------------------------------------

  private resolvePeer4(did: string): DidResolutionReport {
    try {
      return {
        did,
        source: 'offline',
        log: null,
        attestationsByVersion: {},
        result: {
          '@context': DID_RESOLUTION_CONTEXT,
          didResolutionMetadata: { source: 'offline' },
          didDocument: resolveDidPeer4(did),
          didDocumentMetadata: {},
        },
      };
    } catch {
      return this.failure(did, 'invalidDid');
    }
  }

  private failure(did: string, error: ResolverMetadata['error']): DidResolutionReport {
    return {
      did,
      source: 'none',
      log: null,
      attestationsByVersion: {},
      result: {
        '@context': DID_RESOLUTION_CONTEXT,
        didResolutionMetadata: { error },
        didDocument: null,
        didDocumentMetadata: {},
      },
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Truncate a log to the requested `versionId` / `versionTime` (inclusive). */
function pinVersion(entries: RotationLogEntry[], options: ResolveOptions): RotationLogEntry[] {
  let out = entries;
  if (options.versionId !== undefined) {
    const v = Number.parseInt(options.versionId, 10);
    if (Number.isFinite(v)) out = out.filter((e) => e.version <= v);
  }
  if (options.versionTime !== undefined) {
    const t = Date.parse(options.versionTime);
    if (Number.isFinite(t)) out = out.filter((e) => e.createdAt * 1000 <= t);
  }
  return out;
}

function rowToRotationEntry(row: RotationLogDbRow): RotationLogEntry {
  const unpacked = unpackRotationEntry(toUint8Array(row.signed_entry));
  return {
    version: Number(row.version),
    parameters: unpacked.parameters,
    didDocument: unpacked.didDocument,
    prevHash: row.previous_hash ? toUint8Array(row.previous_hash) : null,
    nextKeyCommitments: parseNextKeyCommitments(toUint8Array(row.new_public_key)),
    createdAt: Number(row.created_at ?? 0),
    digest: unpacked.digest,
    signature: unpacked.signature,
    mlDsa65Signature: unpacked.mlDsa65Signature,
    witnessAttestations: [],
  };
}

function parseDocumentJson(json: string | null): DidDocument | null {
  if (!json) return null;
  try {
    const parsed = JSON.parse(json) as DidDocument;
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

/** Unix seconds → ISO-8601. `undefined`/non-finite passes through untouched. */
function toIso8601(unixSeconds: number | undefined): string | undefined {
  if (unixSeconds === undefined || !Number.isFinite(unixSeconds)) return undefined;
  return new Date(unixSeconds * 1000).toISOString();
}
