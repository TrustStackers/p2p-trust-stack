/**
 * RotationLogSource — acquisition of did:scid:vh rotation logs.
 *
 * A did:scid:vh DID is a bare SCID hash; it cannot be resolved without first
 * obtaining the append-only rotation log that produced it. This interface and
 * its implementations are the "discovery" layer for that fetch:
 *
 *   - LocalRotationLogSource — the owner node's own RotationLogStore
 *     (existing behavior: the DID resolves only where its log already lives).
 *   - HttpRotationLogSource — fetches the log from a resolution endpoint
 *     (the utility server, acting as the de-facto DID Resolution endpoint in
 *     this DNS-free deployment), honoring an optional `src` hint.
 */

import type { RotationLogEntry } from './rotation-types.js';
import type { RotationLogStore } from './rotation-log-store.js';

export interface RotationLogSource {
  /**
   * Return the rotation log for a DID, ordered by version ascending.
   *
   * @param did  The full DID string (e.g. "did:scid:vh:1:<SCID>").
   * @param src  Optional resolution hint (spec-defined `src` DID URL param);
   *             e.g. a URI that locates the log when it is not otherwise
   *             discoverable.
   */
  getLog(did: string, src?: string): Promise<RotationLogEntry[]>;
}

/** Resolves from a local RotationLogStore (the node that owns the identity). */
export class LocalRotationLogSource implements RotationLogSource {
  private readonly store: RotationLogStore;

  constructor(store: RotationLogStore) {
    this.store = store;
  }

  async getLog(did: string): Promise<RotationLogEntry[]> {
    return this.store.getLog(did);
  }
}

/**
 * Fetches a rotation log over HTTP from a resolution endpoint.
 *
 * By default the endpoint is a utility server exposing the rotation log for a
 * DID (see utility-server/src/routes/layer1-infrastructure/rotation.ts). When a
 * `src` hint is provided it is honored as the full log location, in keeping
 * with the `did:webvh` DID-to-HTTPS resolution model.
 */
export class HttpRotationLogSource implements RotationLogSource {
  private readonly endpoint: string;
  private readonly fetchFn: typeof fetch;

  constructor(options: { endpoint: string; fetchFn?: typeof fetch }) {
    this.endpoint = options.endpoint.replace(/\/$/, '');
    this.fetchFn = options.fetchFn ?? ((input, init) => fetch(input, init));
  }

  async getLog(did: string, src?: string): Promise<RotationLogEntry[]> {
    const url = this.logUrl(did, src);
    const response = await this.fetchFn(url, { headers: { Accept: 'application/json' } });
    if (!response.ok) {
      if (response.status === 404) return [];
      throw new Error(`HttpRotationLogSource: GET ${url} failed (${response.status})`);
    }

    const body = (await response.json()) as RotationLogResponse;
    return normalizeRotationLog(body);
  }

  private logUrl(did: string, src?: string): string {
    if (src) return src;
    // Utility server endpoint: /did-documents/by-did/:did/rotation-log
    return `${this.endpoint}/did-documents/by-did/${encodeURIComponent(did)}/rotation-log`;
  }
}

// ---------------------------------------------------------------------------
// Response normalization
// ---------------------------------------------------------------------------

/**
 * Accept the two shapes a log endpoint may return and normalize to an
 * ordered RotationLogEntry[]:
 *   - a plain array of entries;
 *   - an envelope: `{ log: [...] }` or `{ entries: [...] }`.
 */
type RotationLogResponse = RotationLogEntry[] | { log?: RotationLogEntry[]; entries?: RotationLogEntry[] };

function normalizeRotationLog(body: RotationLogResponse): RotationLogEntry[] {
  const raw = Array.isArray(body) ? body : body.entries ?? body.log ?? [];
  // Ensure ascending version order and coerce byte fields (JSON turns
  // Uint8Array into objects/arrays depending on the wire serialization).
  return raw
    .map(coerceEntry)
    .sort((a, b) => a.version - b.version);
}

function coerceEntry(entry: any): RotationLogEntry {
  return {
    version: entry.version,
    parameters: entry.parameters,
    didDocument: entry.didDocument,
    prevHash: entry.prevHash != null ? toUint8Array(entry.prevHash) : null,
    nextKeyCommitments: (entry.nextKeyCommitments ?? []).map(toUint8Array),
    createdAt: entry.createdAt ?? 0,
    digest: toUint8Array(entry.digest),
    signature: toUint8Array(entry.signature),
    witnessAttestations: entry.witnessAttestations ?? [],
  };
}

function toUint8Array(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  if (typeof value === 'string') return new Uint8Array(Buffer.from(value, 'base64'));
  if (value && typeof value === 'object' && 'type' in (value as object) && (value as any).type === 'Buffer') {
    return new Uint8Array((value as any).data);
  }
  throw new Error('RotationLogSource: cannot coerce field to Uint8Array');
}
