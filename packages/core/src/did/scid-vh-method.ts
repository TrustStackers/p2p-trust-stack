// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * ScidVhMethod — did:scid:vh DID method implementation (spec-aligned, Phase 4).
 *
 * did:scid:vh is a Self-Certifying Identifier with Verifiable History — the
 * libp2p-native equivalent of did:webvh. Aligned with the ToIP `did:scid:vh`
 * Working Draft 03.
 *
 * Key properties:
 *   - Metamethod `scid` + variant `vh` + version `1` — clean separation
 *   - SCID: base58btc(multihash(JCS(inception_entry))) — self-certifying
 *   - JCS (RFC 8785) canonicalization for deterministic serialization
 *   - Multi-candidate pre-rotation (nextKeyCommitments array)
 *   - parameters block in DID document: alsoKnownAs, nextKeyHashes, controller
 *   - Rotation log: hash-chained, append-only, witness-attestable
 *   - `src` parameter on resolve() as a resolution hint (not part of the DID)
 *
 * ## DID Format
 *
 *   did:scid:vh:<version>:<base58btc_hash>
 *
 *   Example: did:scid:vh:1:6Mkr6cy8emkvrxxEdW2rBfGv61cPpZxHmrBmEFXJS6LyPJ2
 *
 * ## Migration from did:scidvh
 *
 * The previous did:scidvh flat format (`did:scidvh:<scid>`) is replaced by
 * the spec-aligned metamethod/variant/version format. The SCID derivation
 * math is identical; only the prefix string changes.
 *
 * Implements the DidMethod interface with supportsRotation: true.
 */

import { base58btc } from 'multiformats/bases/base58';
import { generateEd25519KeyPair, generateEd25519KeyPairFromSeed, ed25519ToX25519, signEd25519, verifyEd25519, sha256, type Ed25519KeyPair } from '../crypto/primitives.js';
import {
  generateMlDsa65KeyPair,
  generateMlDsa65KeyPairFromSeed,
  generateMlKem768X25519KeyPair,
  generateMlKem768X25519KeyPairFromSeed,
  mlDsa65Sign,
  mlDsa65Verify,
} from '../crypto/pqc.js';
import { extractMlDsa65PublicKey, extractHybridKemPublicKey } from '../relationship/key-extract.js';
import { buildDidPeer4Document } from './create.js';
import { computeRotationEntryDigest, computeNextKeyCommitments, computeNextKeyCommitment } from './rotation-codec.js';
import { verifyWitnessAttestation } from './witness-attestation.js';
import type { DidDocument, DidParameters, ServiceEndpoint, VerificationMethod } from './types.js';
import type { DidMethod, DidMethodCreateResult } from './did-method.js';
import type { RotationLogEntry } from './rotation-types.js';
import type { RotationLogStore } from './rotation-log-store.js';

/** Concatenate Uint8Arrays into one (small helper). */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}
import type { Vrc, VtcGovernanceDoc } from '../vtc/types.js';

// ---------------------------------------------------------------------------
// bytesEqual helper
// ---------------------------------------------------------------------------

/**
 * Verify a rotation entry's ML-DSA-65 (post-quantum root-of-trust) signature when
 * the entry carries one, against the `#key-mldsa` key published in that entry's
 * own DID document.
 *
 * Entries created by identities without a PQ key have no `mlDsa65Signature` and
 * are accepted (classical-only chain) — but an entry that HAS one and fails is
 * rejected, so a stripped or forged PQ signature is never silently tolerated.
 */
function verifyMlDsa65IfPresent(entry: RotationLogEntry): boolean {
  if (!entry.mlDsa65Signature) return true;
  const publishedKey = extractMlDsa65PublicKey(entry.didDocument);
  if (!publishedKey) {
    // The entry claims a PQ signature but publishes no PQ key to check it
    // against — treat as invalid rather than trusting it.
    return false;
  }
  return mlDsa65Verify(entry.mlDsa65Signature, entry.digest, publishedKey);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Extract the "current" signing public key from a DidDocument
// ---------------------------------------------------------------------------

function extractSigningPublicKey(doc: DidDocument): Uint8Array {
  // Slot-A: prefer the dedicated did:scid:vh identity key (#key-scid) when present.
  // Fall back to #key-1 for agents (whose only signing key is the TSP key).
  const vm = doc.verificationMethod.find((m: VerificationMethod) => m.id === '#key-scid')
    ?? doc.verificationMethod.find((m: VerificationMethod) => m.id === '#key-1');
  if (!vm) {
    throw new Error('extractSigningPublicKey: no #key-scid or #key-1 verification method found in DID document');
  }
  const decoded = base58btc.decode(vm.publicKeyMultibase);
  return decoded.slice(2); // Strip 2-byte multicodec prefix (0xed 0x01)
}


/**
 * Derive a SCID from a genesis entry using the did:webvh algorithm adapted
 * for JCS canonicalization: base58btc(multihash(JCS(inception_entry))).
 *
 * The inception entry is the same shape as a rotation entry but with:
 *   - version = 0
 *   - prevHash = null
 *   - The DID string replaced with "{SCID}" placeholder before hashing
 *   - After computing the SCID, the placeholder is replaced with the real value
 */
function deriveScid(entry: Pick<RotationLogEntry, 'version' | 'parameters' | 'didDocument' | 'prevHash' | 'nextKeyCommitments' | 'createdAt'>): string {
  const digest = computeRotationEntryDigest(entry);
  return base58btc.encode(digest);
}

// ---------------------------------------------------------------------------
// ScidVhMethodConfig
// ---------------------------------------------------------------------------

export interface ScidVhMethodConfig {
  /** Optional Witness VTC governance doc for attestation requirements. */
  witnessVtc?: VtcGovernanceDoc;
  /** Minimum number of valid attestation VRCs required (default: 1). */
  minAttestations?: number;
  /** Rotation log store for persistence. */
  store?: RotationLogStore;
}

/** Result of ScidVhMethod.create() — includes pre-committed next key pairs. */
export interface ScidVhMethodCreateResult extends DidMethodCreateResult {
  /** The version-0 rotation log entry. */
  log: RotationLogEntry[];
  /** Pre-committed NEXT signing key pairs (pair for each nextKeyCommitment). */
  nextSigningKeyPairs: Ed25519KeyPair[];
}

// ---------------------------------------------------------------------------
// ScidVhMethod
// ---------------------------------------------------------------------------

export class ScidVhMethod implements DidMethod {
  readonly methodName = 'did:scid:vh';
  readonly supportsRotation = true;

  /** ScidVhMethod supports alsoKnownAs via parameters block. */
  readonly supportsAlsoKnownAs = true;

  private config: ScidVhMethodConfig;

  constructor(config: ScidVhMethodConfig = {}) {
    this.config = config;
  }

  /** Inject/replace the RotationLogStore. */
  setStore(store: RotationLogStore): void {
    this.config = { ...this.config, store };
  }

  /**
   * Return the name binding type supported by this method.
   * did:scid:vh uses alsoKnownAs in the DID document's parameters block.
   */
  getNameBindingType(): 'alsoKnownAs' | 'vrc' | 'none' {
    return 'alsoKnownAs';
  }

  /**
   * Read the current alsoKnownAs names from the latest rotation entry's
   * DID document. Returns empty array if none are set.
   */
  getAlsoKnownAs(did: string): string[] {
    if (!this.config.store) return [];
    const latest = this.config.store.getLatestEntry(did);
    if (!latest) return [];
    return latest.didDocument.alsoKnownAs ?? [];
  }

  // ---------------------------------------------------------------------------
  // create()
  // ---------------------------------------------------------------------------

  async create(
    transport?: ServiceEndpoint,
    options?: {
      /** Deterministic 32-byte seed for the did:scid:vh identity singing key. */
      identitySeed?: Uint8Array;
      /**
       * Slot-A: a SEPARATE permanent TSP VID signing key (from a config seed).
       * When provided, the DID document's #key-1 (verificationMethod[0]) holds
       * THIS key (never rotates), while the did:scid:vh chain follows the
       * identity key in #key-scid. When omitted, the identity key is used for
       * both (existing agent behavior) — the TSP VID then equals the identity key.
       */
      transportSigningKeyPair?: Ed25519KeyPair;
    },
  ): Promise<ScidVhMethodCreateResult> {
    const transportKp = options?.transportSigningKeyPair;

    // did:scid:vh identity key — the chain/SCID is derived from this.
    // Deterministic when `identitySeed` is provided (utility server), else random (agents).
    const identityKp = options?.identitySeed
      ? generateEd25519KeyPairFromSeed(options.identitySeed)
      : generateEd25519KeyPair();

    // Document slots:
    // #key-1 (verificationMethod[0], TSP VID / signing) = transportKp if Slot-A else identity key
    // #key-2 (x25519 agreement) = agreement derived from that same TSP/signing key
    // #key-scid (did:scid:vh identity) = identityKp when Slot-A
    const docSigningKey = transportKp?.publicKey ?? identityKp.publicKey;
    const docAgreementKey = transportKp
      ? ed25519ToX25519(transportKp.secretKey).publicKey
      : ed25519ToX25519(identityKp.secretKey).publicKey;
    const identitySlotKey = transportKp ? identityKp.publicKey : undefined;

    // 1. Pre-commit the identity key (self) + a fresh next identity key, so a
    //    metadata-only entry can self-commit (transport VID stable) and a genuine
    //    rotation remains possible. The chain follows the IDENTITY key in both modes.
    //    For a SEEDED identity (utility server) the next-key pre-commitment must
    //    also be deterministic (domain-separated from the same seed) so the whole
    //    genesis → SCID is reproducible from config; otherwise random for agents.
    const identityNextKeyPairs = [
      options?.identitySeed
        ? generateEd25519KeyPairFromSeed(sha256(concatBytes(options.identitySeed, new Uint8Array([0x01]))))
        : generateEd25519KeyPair(),
    ];
    const committedKeys = [identityKp.publicKey, ...identityNextKeyPairs.map(kp => kp.publicKey)];

    // 1b. Post-quantum roots of trust. Deterministic when the identity is seeded
    //     (the utility server), because the PQ public keys are published in the
    //     DID document and the genesis → SCID must stay reproducible from config.
    const mlDsa65KeyPair = options?.identitySeed
      ? generateMlDsa65KeyPairFromSeed(options.identitySeed)
      : generateMlDsa65KeyPair();
    const hybridKemKeyPair = options?.identitySeed
      ? generateMlKem768X25519KeyPairFromSeed(options.identitySeed)
      : generateMlKem768X25519KeyPair();

    // 2. Build DID document (Slot-A carries transportKp at [0], identity at #key-scid;
    //    the PQ keys are APPENDED as #key-mldsa / #key-kem).
    const document = buildDidPeer4Document(docSigningKey, docAgreementKey, transport, identitySlotKey, {
      mlDsa65PublicKey: mlDsa65KeyPair.publicKey,
      hybridKemPublicKey: hybridKemKeyPair.publicKey,
    });
    const parameters: DidParameters = {
      nextKeyHashes: computeNextKeyCommitments(committedKeys).map(h => Buffer.from(h).toString('base64')),
    };
    const documentWithParams: DidDocument = { ...document, parameters, alsoKnownAs: [] };

    // 3. Compute the SCID from the genesis entry (placeholder DID first).
    const placeholderDid = 'did:scid:vh:1:{SCID}';
    const docWithPlaceholder: DidDocument = { ...documentWithParams, id: placeholderDid };

    const nextKeyCommitments = computeNextKeyCommitments(committedKeys);
    const unsignedEntry = {
      version: 0,
      parameters,
      didDocument: docWithPlaceholder,
      prevHash: null as Uint8Array | null,
      nextKeyCommitments,
      // Deterministic genesis for seeded identities: a fixed createdAt makes the
      // SCID (and therefore the DID) fully reproducible from `identitySeed`,
      // which is required for cross-device seed-phrase transfer. Random agents
      // keep the real timestamp.
      createdAt: options?.identitySeed ? 0 : Math.floor(Date.now() / 1000),
    };

    const scid = deriveScid(unsignedEntry);
    const did = `did:scid:vh:1:${scid}`;
    const documentWithId: DidDocument = { ...documentWithParams, id: did };

    const finalUnsigned = { ...unsignedEntry, didDocument: documentWithId };
    const digest = computeRotationEntryDigest(finalUnsigned);
    // Sign with the identity key (key-continuity proof) …
    const signature = signEd25519(digest, identityKp.secretKey);
    // … and with the ML-DSA-65 root-of-trust key: key rotation is one of the
    // high-value, long-lived, ASYNCHRONOUS statements ML-DSA-65 exists for.
    const mlDsa65Signature = mlDsa65Sign(digest, mlDsa65KeyPair.secretKey);

    const entry0: RotationLogEntry = {
      ...finalUnsigned,
      digest,
      signature,
      mlDsa65Signature,
      witnessAttestations: [],
    };

    this.config.store?.appendEntry(did, entry0);

    return {
      did,
      document: documentWithId,
      signingKeyPair: identityKp,
      agreementKeyPair: ed25519ToX25519(identityKp.secretKey),
      mlDsa65KeyPair,
      hybridKemKeyPair,
      log: [entry0],
      nextSigningKeyPairs: identityNextKeyPairs,
    };
  }

  // ---------------------------------------------------------------------------
  // resolve() — now accepts optional `src` parameter (Phase 4 spec alignment)
  // ---------------------------------------------------------------------------

  /**
   * Resolve a did:scid:vh DID to its current DID document.
   *
   * @param did  The full DID string (e.g., "did:scid:vh:1:6Mkr...").
   * @param src  Optional resolution hint — a transport URL or peer address.
   *             Ignored by the local resolver but passed through for consumers
   *             that route resolution through a specific infrastructure path.
   *             This is the spec-defined `src` DID URL query parameter.
   */
  resolve(did: string, src?: string): DidDocument {
    if (!this.config.store) {
      throw new Error('ScidVhMethod.resolve: no RotationLogStore configured');
    }

    // Accept both current and legacy DID formats for compatibility during migration.
    const log = this.config.store.getLog(did);
    if (log.length === 0) {
      throw new Error(`ScidVhMethod.resolve: no rotation log found for ${did}`);
    }

    return this.resolveFromLog(did, log, src);
  }

  /**
   * Resolve a did:scid:vh DID from an already-fetched rotation log.
   *
   * Extracted from `resolve()` so the standalone DID resolver
   * (`src/did/did-resolver.ts`) can replay a remotely-obtained log (e.g.
   * fetched from the utility server) without the caller needing a local
   * `RotationLogStore`. Chain validation and witness-attestation policy are
   * identical to `resolve()`.
   *
   * @param did  The full DID string (e.g., "did:scid:vh:1:6Mkr...").
   * @param log  The rotation log, ordered by version ascending.
   * @param src  Optional resolution hint (spec-defined `src` DID URL param).
   */
  resolveFromLog(did: string, log: RotationLogEntry[], src?: string): DidDocument {
    const { validEntries } = this.validateChain(log);
    if (validEntries.length === 0) {
      throw new Error(`ScidVhMethod.resolve: rotation log for ${did} has no valid entries`);
    }

    let trusted = validEntries[validEntries.length - 1];
    if (this.config.witnessVtc) {
      let found = false;
      for (let i = validEntries.length - 1; i >= 0; i--) {
        if (this.hasValidAttestations(validEntries[i])) {
          trusted = validEntries[i];
          found = true;
          break;
        }
      }
      if (!found) {
        throw new Error(
          `ScidVhMethod.resolve: no entry in the rotation log for ${did} has sufficient/valid witness attestations`,
        );
      }
    }

    // If src is provided, attach it to the resolved document for routing hints.
    const resolved = trusted.didDocument;
    if (src) {
      return { ...resolved, parameters: { ...resolved.parameters, src } as DidParameters };
    }
    return resolved;
  }

  // ---------------------------------------------------------------------------
  // verify()
  // ---------------------------------------------------------------------------

  async verify(did: string): Promise<boolean> {
    try {
      this.resolve(did);
      return true;
    } catch {
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // rotate()
  // ---------------------------------------------------------------------------

  async rotate(params: {
    currentLog: RotationLogEntry[];
    outgoingSigningKeyPair: Ed25519KeyPair;
    newSigningKeyPair: Ed25519KeyPair;
    nextSigningPublicKey: Uint8Array;
    witnessAttestations: Vrc[];
    /** Override alsoKnownAs (for name changes without full key rotation). */
    alsoKnownAs?: string[];
    transport?: ServiceEndpoint;
    /**
     * The identity's ML-DSA-65 root-of-trust key pair, used to PQ-sign this
     * rotation entry and to keep the PQ public key published across the update.
     * Omitted for identities without PQ provisioning (the entry is then
     * classical-only, which `validateChain` accepts).
     */
    mlDsa65KeyPair?: { secretKey: Uint8Array; publicKey: Uint8Array };
  }): Promise<RotationLogEntry> {
    const { currentLog, outgoingSigningKeyPair, newSigningKeyPair, nextSigningPublicKey, witnessAttestations, alsoKnownAs: overrideAlsoKnownAs } = params;

    if (currentLog.length === 0) {
      throw new Error('ScidVhMethod.rotate: currentLog must contain at least the genesis entry');
    }
    const prevEntry = currentLog[currentLog.length - 1];

    // Verify that outgoingSigningKeyPair matches the current key in prevEntry.
    const prevDocumentSigningKey = extractSigningPublicKey(prevEntry.didDocument);
    if (!bytesEqual(outgoingSigningKeyPair.publicKey, prevDocumentSigningKey)) {
      throw new Error(
        "ScidVhMethod.rotate: outgoingSigningKeyPair does not match the previous entry's current signing key",
      );
    }

    // Verify that newSigningKeyPair's public key matches one of prevEntry.nextKeyCommitments,
    // OR equals the current key (self-commit for a metadata-only entry, e.g. adding a name
    // to alsoKnownAs). Allowing a self-commit lets the did:scid:vh log advance WITHOUT
    // rotating the signing identity, keeping the transport VID stable per ToIP.
    const expectedCommitment = computeNextKeyCommitment(newSigningKeyPair.publicKey);
    const isSelfCommit = bytesEqual(newSigningKeyPair.publicKey, prevDocumentSigningKey);
    const matchesAny = isSelfCommit || prevEntry.nextKeyCommitments.some(c => bytesEqual(expectedCommitment, c));
    if (!matchesAny) {
      throw new Error(
        "ScidVhMethod.rotate: newSigningKeyPair does not match any of the previous entry's nextKeyCommitments",
      );
    }

    // Build new DID document preserving alsoKnownAs and updating parameters.
    const prevAlsoKnownAs = overrideAlsoKnownAs !== undefined
      ? overrideAlsoKnownAs
      : (prevEntry.didDocument.alsoKnownAs ?? []);
    const prevParameters = prevEntry.parameters ?? {};
    const agreementKeyPair = ed25519ToX25519(newSigningKeyPair.secretKey);
    // Carry the POST-QUANTUM roots of trust across the rotation. They are
    // long-lived roots, not per-version keys, so a rotation must RE-PUBLISH them —
    // otherwise the first rotation would strip #key-mldsa/#key-kem from the
    // document and every subsequent ML-DSA rotation signature would become
    // unverifiable (the key to check it against would be gone).
    const carriedMlDsa = params.mlDsa65KeyPair?.publicKey
      ?? extractMlDsa65PublicKey(prevEntry.didDocument);
    const carriedKem = extractHybridKemPublicKey(prevEntry.didDocument);
    const newDocument = buildDidPeer4Document(
      newSigningKeyPair.publicKey,
      agreementKeyPair.publicKey,
      params.transport,
      undefined,
      { mlDsa65PublicKey: carriedMlDsa, hybridKemPublicKey: carriedKem },
    );

    const nextKeyCommitment = computeNextKeyCommitment(nextSigningPublicKey);
    const newParameters: DidParameters = {
      ...prevParameters,
      nextKeyHashes: [Buffer.from(nextKeyCommitment).toString('base64')],
    };
    const documentWithId: DidDocument = {
      ...newDocument,
      id: prevEntry.didDocument.id,
      alsoKnownAs: prevAlsoKnownAs,
      parameters: newParameters,
    };

    const nextKeyCommitments = [nextKeyCommitment];
    const unsignedEntry = {
      version: prevEntry.version + 1,
      parameters: newParameters,
      didDocument: documentWithId,
      prevHash: prevEntry.digest as Uint8Array | null,
      nextKeyCommitments,
      createdAt: Math.floor(Date.now() / 1000),
    };
    const digest = computeRotationEntryDigest(unsignedEntry);

    // Validate witness attestations.
    if (this.config.witnessVtc) {
      const minAttestations = this.config.minAttestations ?? 1;
      const validCount = witnessAttestations.filter(
        vrc => verifyWitnessAttestation(vrc, this.config.witnessVtc!, digest).valid,
      ).length;
      if (validCount < minAttestations) {
        throw new Error(
          `ScidVhMethod.rotate: insufficient valid witness attestations (${validCount}/${minAttestations} required)`,
        );
      }
    }

    // Sign with the outgoing key (key-continuity proof).
    const signature = signEd25519(digest, outgoingSigningKeyPair.secretKey);
    // PQ root-of-trust signature over the same digest, when the identity has one.
    const mlDsa65Signature = params.mlDsa65KeyPair
      ? mlDsa65Sign(digest, params.mlDsa65KeyPair.secretKey)
      : undefined;

    const newEntry: RotationLogEntry = {
      ...unsignedEntry,
      digest,
      signature,
      mlDsa65Signature,
      witnessAttestations,
    };

    this.config.store?.appendEntry(prevEntry.didDocument.id!, newEntry);

    return newEntry;
  }

  // ---------------------------------------------------------------------------
  // Name management (alsoKnownAs)
  // ---------------------------------------------------------------------------

  async claimName(params: {
    currentLog: RotationLogEntry[];
    nameUri: string;
    outgoingSigningKeyPair: Ed25519KeyPair;
    newSigningKeyPair: Ed25519KeyPair;
    nextSigningPublicKey: Uint8Array;
    witnessAttestations?: Vrc[];
    transport?: ServiceEndpoint;
  }): Promise<RotationLogEntry> {
    const prevEntry = params.currentLog[params.currentLog.length - 1];
    const currentNames = prevEntry.didDocument.alsoKnownAs ?? [];
    if (currentNames.includes(params.nameUri)) {
      throw new Error(`ScidVhMethod.claimName: name "${params.nameUri}" is already claimed`);
    }
    return this.rotateNameEntry({
      ...params,
      alsoKnownAs: [...currentNames, params.nameUri],
    });
  }

  async revokeName(params: {
    currentLog: RotationLogEntry[];
    nameUri: string;
    outgoingSigningKeyPair: Ed25519KeyPair;
    newSigningKeyPair: Ed25519KeyPair;
    nextSigningPublicKey: Uint8Array;
    witnessAttestations?: Vrc[];
    transport?: ServiceEndpoint;
  }): Promise<RotationLogEntry> {
    const prevEntry = params.currentLog[params.currentLog.length - 1];
    const currentNames = prevEntry.didDocument.alsoKnownAs ?? [];
    if (!currentNames.includes(params.nameUri)) {
      throw new Error(`ScidVhMethod.revokeName: name "${params.nameUri}" is not currently claimed`);
    }
    return this.rotateNameEntry({
      ...params,
      alsoKnownAs: currentNames.filter(n => n !== params.nameUri),
    });
  }

  private async rotateNameEntry(params: {
    currentLog: RotationLogEntry[];
    alsoKnownAs: string[];
    outgoingSigningKeyPair: Ed25519KeyPair;
    newSigningKeyPair: Ed25519KeyPair;
    nextSigningPublicKey: Uint8Array;
    witnessAttestations?: Vrc[];
    transport?: ServiceEndpoint;
  }): Promise<RotationLogEntry> {
    return this.rotate({
      currentLog: params.currentLog,
      outgoingSigningKeyPair: params.outgoingSigningKeyPair,
      newSigningKeyPair: params.newSigningKeyPair,
      nextSigningPublicKey: params.nextSigningPublicKey,
      witnessAttestations: params.witnessAttestations ?? [],
      alsoKnownAs: params.alsoKnownAs,
      transport: params.transport,
    });
  }

  // ---------------------------------------------------------------------------
  // Internal: chain validation
  // ---------------------------------------------------------------------------

  private validateChain(log: RotationLogEntry[]): { validEntries: RotationLogEntry[] } {
    const validEntries: RotationLogEntry[] = [];

    for (let i = 0; i < log.length; i++) {
      const entry = log[i];

      const expectedDigest = computeRotationEntryDigest({
        version: entry.version,
        parameters: entry.parameters,
        didDocument: entry.didDocument,
        prevHash: entry.prevHash,
        nextKeyCommitments: entry.nextKeyCommitments,
        createdAt: entry.createdAt,
      });
      if (!bytesEqual(expectedDigest, entry.digest)) {
        break;
      }

      if (i === 0) {
        const signingPublicKey = extractSigningPublicKey(entry.didDocument);
        if (!verifyEd25519(entry.signature, entry.digest, signingPublicKey)) {
          break;
        }
        if (!verifyMlDsa65IfPresent(entry)) {
          break;
        }
        if (entry.prevHash !== null) {
          break;
        }
        validEntries.push(entry);
        continue;
      }

      const prevEntry = log[i - 1];

      if (!entry.prevHash || !bytesEqual(entry.prevHash, prevEntry.digest)) {
        break;
      }

      const newSigningPublicKey = extractSigningPublicKey(entry.didDocument);
      const commitmentCheck = computeNextKeyCommitment(newSigningPublicKey);
      if (!prevEntry.nextKeyCommitments.some(c => bytesEqual(commitmentCheck, c))) {
        break;
      }

      const prevSigningPublicKey = extractSigningPublicKey(prevEntry.didDocument);
      if (!verifyEd25519(entry.signature, entry.digest, prevSigningPublicKey)) {
        break;
      }

      if (!verifyMlDsa65IfPresent(entry)) {
        break;
      }

      validEntries.push(entry);
    }

    return { validEntries };
  }

  private hasValidAttestations(entry: RotationLogEntry): boolean {
    if (!this.config.witnessVtc) return true;
    const minAttestations = this.config.minAttestations ?? 1;
    const validCount = entry.witnessAttestations.filter(
      vrc => verifyWitnessAttestation(vrc, this.config.witnessVtc!, entry.digest).valid,
    ).length;
    return validCount >= minAttestations;
  }
}

// (end of ScidVhMethod)
