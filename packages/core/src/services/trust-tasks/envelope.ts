/**
 * Trust Task envelope — builder and parser.
 *
 * Adopts the interoperable envelope SHAPE (the field names below) so JSON documents can
 * cross systems, while keeping our own identifiers and our own validation: `type` is our
 * `task:p2pts:…` namespace (see `type-uris.ts`), and `proof` is never verified here.
 *
 *   - required: `id`, `type`, `payload`
 *   - optional: `threadId`, `parentThreadId`, `issuer`, `recipient`, `issuedAt`,
 *     `expiresAt`, `@context`, `proof`
 *   - `additionalProperties: true` — unknown members are preserved, not rejected
 *   - `type` carries the reserved `#request` / `#response` fragment
 *
 * ## The correctness rule (docs/08 §7)
 *
 * This bridge MUST NOT verify `proof` — cryptographic verification belongs to
 * `GovernanceGuard`. But it MUST NOT silently ignore it either: verifying a proof
 * establishes *who asked*, never *that they may*. A document carrying a `proof` with
 * no authenticated-transport identity binding therefore evaluates to
 * `indeterminate`, not `allow`. `isIndeterminateForProof()` encodes that decision;
 * the transport-authentication verdict is supplied by the caller, because only the
 * caller saw the transport.
 */

import { randomUUID } from 'node:crypto';
import { TRUST_TASK_ERROR_TYPE } from './type-uris.js';

export interface TrustTaskDocument {
  /** Globally unique document id — UUIDv4 is RECOMMENDED (§4.3). */
  id: string;
  /** Type URI, optionally with `#request` / `#response`. */
  type: string;
  threadId?: string;
  parentThreadId?: string;
  /** Verifiable Identifier (DID) of the party responsible for the content (§4.8). */
  issuer?: string;
  /** Verifiable Identifier (DID) of the party expected to act (§4.8). */
  recipient?: string;
  /** RFC 3339 timestamp the document was produced (§4.2). */
  issuedAt?: string;
  /** RFC 3339 timestamp after which the document is no longer valid. */
  expiresAt?: string;
  /** Task-specific body, governed by the task's own payload schema (§4.5). */
  payload: unknown;
  /** W3C Data Integrity Proof binding content to issuer (§4.7). */
  proof?: unknown;
  /** Unknown members are preserved per `additionalProperties: true`. */
  [key: string]: unknown;
}

export interface TrustTaskBuildOptions {
  id?: string;
  threadId?: string;
  parentThreadId?: string;
  issuer?: string;
  recipient?: string;
  /** Defaults to now. */
  issuedAt?: string;
  expiresAt?: string;
  payload: unknown;
  proof?: unknown;
}

/** Build a `#request` document. `type` is the task type URI without a fragment. */
export function buildTrustTask(typeUri: string, options: TrustTaskBuildOptions): TrustTaskDocument {
  return {
    id: options.id ?? randomUUID(),
    type: typeUri,
    ...(options.threadId ? { threadId: options.threadId } : {}),
    ...(options.parentThreadId ? { parentThreadId: options.parentThreadId } : {}),
    ...(options.issuer ? { issuer: options.issuer } : {}),
    ...(options.recipient ? { recipient: options.recipient } : {}),
    issuedAt: options.issuedAt ?? new Date().toISOString(),
    ...(options.expiresAt ? { expiresAt: options.expiresAt } : {}),
    ...(options.proof ? { proof: options.proof } : {}),
    payload: options.payload,
  };
}

/**
 * Build a `#response` to a request. Echoes the `threadId`, swaps `issuer`/`recipient`,
 * and swaps the `#request` fragment for `#response` (§4.4.1). Correlation is the
 * `threadId`; a response with no `threadId` on its request is still conforming but the
 * exchange is then uncorrelated.
 */
export function buildResponse(
  request: TrustTaskDocument,
  payload: unknown,
  options: { issuer?: string; recipient?: string } = {},
): TrustTaskDocument {
  const baseType = request.type.replace(/#(request|response)$/, '');
  return {
    id: randomUUID(),
    type: `${baseType}#response`,
    ...(request.threadId ? { threadId: request.threadId } : {}),
    ...(request.parentThreadId ? { parentThreadId: request.parentThreadId } : {}),
    issuer: options.issuer ?? request.recipient,
    recipient: options.recipient ?? request.issuer,
    issuedAt: new Date().toISOString(),
    payload,
  };
}

/** An error response payload, matching the registry's `errorCodes` shape. */
export interface TrustTaskError {
  code: string;
  message: string;
  retryable?: boolean;
  details?: unknown;
}

/**
 * Build an error `#response`. The registry carries errors as response documents whose
 * payload is `{code, message, …}` (see `policy/evaluate`'s `errorCodes`, and the
 * framework's `malformedRequest` / `expired` / `proofInvalid` codes) — not as a
 * separate error type, so this emits a task `#response` with an error payload.
 */
export function buildError(
  request: TrustTaskDocument | undefined,
  error: TrustTaskError,
): TrustTaskDocument {
  const typeUri = request
    ? request.type.replace(/#(request|response)$/, '') + '#response'
    : `${TRUST_TASK_ERROR_TYPE}#response`;
  return {
    id: randomUUID(),
    type: typeUri,
    ...(request?.threadId ? { threadId: request.threadId } : {}),
    ...(request ? { issuer: request.recipient, recipient: request.issuer } : {}),
    issuedAt: new Date().toISOString(),
    payload: error,
  };
}

export type ParseResult =
  | { ok: true; document: TrustTaskDocument }
  | { ok: false; code: string; message: string };

/**
 * Parse an inbound document. Structural only: validates the envelope's required
 * members (§7.2 item 1) and returns the typed document. It does NOT verify `proof`
 * and does NOT apply the task-level payload schema (that is selected from `type`).
 */
export function parseTrustTask(raw: unknown): ParseResult {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { ok: false, code: 'malformedRequest', message: 'document must be a JSON object' };
  }
  const doc = raw as Record<string, unknown>;
  if (typeof doc.id !== 'string' || doc.id.length === 0) {
    return { ok: false, code: 'malformedRequest', message: 'id is required' };
  }
  if (typeof doc.type !== 'string' || doc.type.length === 0) {
    return { ok: false, code: 'malformedRequest', message: 'type is required' };
  }
  if (typeof doc.payload !== 'object' || doc.payload === null) {
    return { ok: false, code: 'malformedRequest', message: 'payload must be an object' };
  }
  return { ok: true, document: doc as unknown as TrustTaskDocument };
}

/**
 * Encode the "do not silently ignore `proof`" rule. When a document carries a proof
 * but the transport did not authenticate the `issuer`, the exchange is INDETERMINATE:
 * the content is cryptographically attributable to whoever made it, but we cannot bind
 * that to a principal we trust, so we must not treat the document as an authorized
 * request. The transport verdict is caller-supplied.
 */
export function isIndeterminateForProof(
  document: TrustTaskDocument,
  issuerAuthenticated: boolean,
): boolean {
  return document.proof !== undefined && !issuerAuthenticated;
}