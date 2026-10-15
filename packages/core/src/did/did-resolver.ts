// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * DidResolver — unified DID resolution facade (W3C DID Core + DID Resolution).
 *
 * Provides a single entry point that resolves any supported DID string to its
 * DID document, and dereferences DID URLs (e.g. a `proof.verificationMethod`
 * like `did:...:...#key-1`) to the key material and the verification
 * relationships that authorize it.
 *
 * ## Method dispatch
 *
 *   - did:peer:4   — the DID document is embedded in the long-form DID string.
 *                    Resolution is a pure, offline decode (resolveDidPeer4).
 *   - did:scid:vh  — the SCID is a hash; resolution requires fetching and
 *                    replaying the append-only rotation log, then validating
 *                    the chain. The log is obtained from a RotationLogSource
 *                    (local store on the owner node, or the utility server as
 *                    the de-facto resolution endpoint).
 *
 * This is additive to (not a replacement for) the `DidMethod.resolve()` used
 * by the agent layer. `ScidVhMethod.resolve` remains the chain validator and
 * local resolver; this facade orchestrates log acquisition + dereferencing.
 */

import { base58btc } from 'multiformats/bases/base58';
import { resolveDidPeer4 } from './resolve.js';
import { ScidVhMethod } from './scid-vh-method.js';
import type { DidDocument, DidService, VerificationMethod } from './types.js';
import type { RotationLogEntry } from './rotation-types.js';
import type { RotationLogSource } from './rotation-log-source.js';

// ---------------------------------------------------------------------------
// Resolution result types (W3C DID Resolution shape)
// ---------------------------------------------------------------------------

export interface DidResolutionMetadata {
  /**
   * F-006 (2026-09-24): **deliberately not set on the resolve path.**
   *
   * `contentType` describes a *representation*, and it belongs to the **dereferencing**
   * result — resolution metadata carries `error` (plus this codebase's `rotated`
   * extension). The resolver used to stamp it on every resolve return, which is a
   * contract violation the DIF resolution shape does not permit.
   *
   * The field stays optional rather than deleted so a caller that genuinely has a
   * representation to describe can state it, and so the interface remains compatible.
   */
  contentType?: 'application/did+ld+json' | 'application/did+json';
  error?: 'invalidDid' | 'notFound' | 'representationNotSupported' | 'methodNotSupported' | 'deactivated';
  /** did:scid:vh only — the log advanced past version 0 during this resolution. */
  rotated?: boolean;
}

export interface DidDocumentMetadata {
  /** ISO-8601 (F-006), not unix seconds — the spec's shape for these timestamps. */
  created?: string;
  /** ISO-8601 (F-006). */
  updated?: string;
  /**
   * did:scid:vh only — the rotation-log version the document reflects, as a **string**
   * (F-006). The spec types `versionId` as a string; it used to carry the raw integer.
   */
  versionId?: string;
  deactivated?: boolean;
  /** did:scid:vh only — the trusted entry carried valid witness attestations. */
  witnessAttested?: boolean;
}

/** Unix seconds → ISO-8601. `undefined`/non-finite passes through untouched. */
function toIso8601(unixSeconds: number | undefined): string | undefined {
  if (unixSeconds === undefined || !Number.isFinite(unixSeconds)) return undefined;
  return new Date(unixSeconds * 1000).toISOString();
}

export interface DidResolutionResult {
  didResolutionMetadata: DidResolutionMetadata;
  didDocument: DidDocument | null;
  didDocumentMetadata: DidDocumentMetadata;
}

/** The result of dereferencing a DID URL to a verification method. */
export interface DereferencedVerificationMethod {
  /** Full DID URL (as given). */
  didUrl: string;
  /** The `id` fragment of the verification method (e.g. `#key-1`). */
  fragment: string;
  /** Multikey publicKeyMultibase string (with multicodec prefix). */
  publicKeyMultibase: string;
  /** Decoded raw key bytes (multicodec prefix stripped). */
  rawKey: Uint8Array;
  /**
   * The controller of the verification method (F-01).
   *
   * Taken from the method's declared `controller`, or — when the document omits
   * it (our did:peer:4 documents carry `controller: ''`) — the DID portion of the
   * verification method id. Either way it is non-empty, so a caller can bind the
   * key to the credential's issuer (the forgery defence Data Integrity §2.6 and
   * the audit's F-01 both require: `issuer: did:X` signed by a key under
   * `did:Y` must be rejected).
   */
  controller: string;
  /** Verification relationships that reference this key (DID Core §5.3). */
  proofPurposes: string[];
}

// ---------------------------------------------------------------------------
// DidResolver
// ---------------------------------------------------------------------------

/**
 * Resolver configuration. All fields optional; defaults favor offline
 * did:peer:4 resolution and a local rotation-log source.
 */
export interface DidResolverConfig {
  /** Source of did:scid:vh rotation logs. Defaults to a local source. */
  logSource?: RotationLogSource;
  /** Pre-configured ScidVhMethod (e.g. with a witness VTC policy). */
  scidVhMethod?: ScidVhMethod;
}

export class DidResolver {
  private readonly logSource: RotationLogSource | undefined;
  private readonly scidVhMethod: ScidVhMethod;

  constructor(config: DidResolverConfig = {}) {
    this.logSource = config.logSource;
    this.scidVhMethod = config.scidVhMethod ?? new ScidVhMethod({});
  }

  /**
   * Resolve a DID string to its DID document + resolution metadata.
   *
   * Async because did:scid:vh resolution may fetch the rotation log from a
   * remote source.
   */
  async resolve(did: string, options?: { src?: string }): Promise<DidResolutionResult> {
    if (did.startsWith('did:peer:4')) {
      return this.resolvePeer4(did);
    }
    if (did.startsWith('did:scid:vh')) {
      return this.resolveScidVh(did, options?.src);
    }

    return {
      didResolutionMetadata: { error: 'methodNotSupported' },
      didDocument: null,
      didDocumentMetadata: {},
    };
  }

  /**
   * Dereference a DID URL to a verification method, returning the decoded
   * public key plus the verification relationships that authorize it.
   *
   * Used by Data Integrity proof verification to turn
   * `proof.verificationMethod` into key bytes and confirm proofPurpose.
   */
  async dereferenceVerificationMethod(didUrl: string): Promise<DereferencedVerificationMethod | null> {
    const { did, fragment } = splitDidUrl(didUrl);
    if (!fragment) return null;

    const result = await this.resolve(did);
    const doc = result.didDocument;
    if (!doc) return null;

    const vm = findVerificationMethod(doc, fragment);
    if (!vm) return null;

    const rawKey = decodeMultibasePublicKey(vm.publicKeyMultibase);
    const relationshipMap = verificationRelationships(doc);
    const proofPurposes = Object.keys(relationshipMap).filter(
      (purpose) => relationshipMap[purpose].includes(fragment),
    );

    // F-01: controllers may be declared on the method, or omitted (our did:peer:4
    // documents use `controller: ''`). Fall back to the DID portion of the URL so
    // the caller always has a value to bind against the credential's issuer.
    const controller = vm.controller && vm.controller !== '' ? vm.controller : did;

    return { didUrl, fragment, publicKeyMultibase: vm.publicKeyMultibase, rawKey, controller, proofPurposes };
  }

  /**
   * Dereference a DID URL to a service endpoint, if present.
   */
  async dereferenceService(didUrl: string): Promise<DidService | null> {
    const { did, fragment } = splitDidUrl(didUrl);
    const result = await this.resolve(did);
    const doc = result.didDocument;
    if (!doc?.service) return null;

    if (!fragment) return doc.service[0];
    return doc.service.find((s) => s.id === `#${fragment}` || s.id === didUrl) ?? null;
  }

  // -------------------------------------------------------------------------
  // did:peer:4
  // -------------------------------------------------------------------------

  private resolvePeer4(did: string): DidResolutionResult {
    try {
      const doc = resolveDidPeer4(did);
      return {
        didResolutionMetadata: {},
        didDocument: doc,
        didDocumentMetadata: {},
      };
    } catch {
      return {
        didResolutionMetadata: { error: 'invalidDid' },
        didDocument: null,
        didDocumentMetadata: {},
      };
    }
  }

  // -------------------------------------------------------------------------
  // did:scid:vh
  // -------------------------------------------------------------------------

  private async resolveScidVh(did: string, src?: string): Promise<DidResolutionResult> {
    if (!this.logSource) {
      return {
        didResolutionMetadata: { error: 'notFound' },
        didDocument: null,
        didDocumentMetadata: {},
      };
    }

    const log: RotationLogEntry[] = await this.logSource.getLog(did, src);
    if (log.length === 0) {
      return {
        didResolutionMetadata: { error: 'notFound' },
        didDocument: null,
        didDocumentMetadata: {},
      };
    }

    try {
      // Reuse the chain validator from ScidVhMethod, operating on the fetched log.
      const doc = this.scidVhMethod.resolveFromLog(did, log, src);

      const lastEntry = log[log.length - 1];
      const versionId = lastEntry.version;
      const rotated = versionId > 0;

      return {
        didResolutionMetadata: { ...(rotated ? { rotated } : {}) },
        didDocument: doc,
        didDocumentMetadata: {
          // F-006: the spec's shape for these is a STRING versionId and ISO-8601
          // timestamps — not the raw unix seconds and integer the log carries. The
          // numeric form leaked the internal representation into a standard interface.
          updated: toIso8601(lastEntry.createdAt),
          ...(versionId !== undefined ? { versionId: String(versionId) } : {}),
          witnessAttested: lastEntry.witnessAttestations.length > 0,
        },
      };
    } catch (err) {
      const msg = (err as Error)?.message ?? String(err);
      const deactivated = /\bdeactivated\b/i.test(msg);
      return {
        didResolutionMetadata: {
          error: deactivated ? 'deactivated' : 'notFound',
        },
        didDocument: null,
        didDocumentMetadata: {},
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Split a DID URL into its DID portion and optional `#fragment`. */
function splitDidUrl(input: string): { did: string; fragment?: string } {
  const hashIdx = input.indexOf('#');
  if (hashIdx === -1) return { did: input };
  return { did: input.slice(0, hashIdx), fragment: input.slice(hashIdx + 1) };
}

/** Find a verification method by its fragment (e.g. `key-1`) or full id. */
function findVerificationMethod(doc: DidDocument, fragment: string): VerificationMethod | undefined {
  return (
    doc.verificationMethod.find((m) => m.id === `#${fragment}`) ??
    doc.verificationMethod.find((m) => m.id === fragment)
  );
}

/** Build a map of verification relationship name → referenced key fragments. */
function verificationRelationships(doc: DidDocument): Record<string, string[]> {
  const map: Record<string, string[]> = {};
  const normalize = (refs: string[] | undefined) =>
    (refs ?? []).map((r) => (r.startsWith('#') ? r.slice(1) : r));
  map.authentication = normalize(doc.authentication);
  map.assertionMethod = normalize(doc.assertionMethod);
  map.keyAgreement = normalize(doc.keyAgreement);
  return map;
}

/**
 * Decode a Multikey publicKeyMultibase string to raw key bytes (the 2-byte
 * multicodec prefix is stripped). Accepts Ed25519 (0xed01) and X25519 (0xec01).
 */
function decodeMultibasePublicKey(publicKeyMultibase: string): Uint8Array {
  const decoded = base58btc.decode(publicKeyMultibase);
  if (decoded.length < 2) {
    throw new Error(`decodeMultibasePublicKey: key too short (${decoded.length} bytes)`);
  }
  return decoded.slice(2);
}
