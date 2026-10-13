/**
 * did:peer:4 VID module — Step 2.
 *
 * Public API:
 *   createDidPeer4()   — generate keypairs + DID document + long-form DID string
 *   resolveDidPeer4()  — decode long-form DID string → DID document (offline)
 *   verifyDidPeer4()   — recompute hash, confirm self-certification
 */

export { createDidPeer4, buildDidPeer4Document } from './create.js';
export { resolveDidPeer4 } from './resolve.js';
export { verifyDidPeer4 } from './verify.js';
export { encodePeer4, decodePeer4, verifyPeer4Hash } from './numalgo4.js';
export { DidPeer4Method } from './did-peer4-method.js';
export type { DidMethod, DidMethodCreateResult } from './did-method.js';
export type {
  DidDocument,
  VerificationMethod,
  ServiceEndpoint,
  DidService,
  DidPeer4Result,
} from './types.js';

// ---------------------------------------------------------------------------
// Step 11 — Witness VTC + did:webvh-style Rotation
// ---------------------------------------------------------------------------

export type { RotationLogEntry } from './rotation-types.js';
export {
  computeRotationEntryDigest,
  computeNextKeyCommitment,
  encodeRotationLogEntry,
  decodeRotationLogEntry,
} from './rotation-codec.js';
// Spec-aligned did:scid:vh method
export {
  ScidVhMethod,
  type ScidVhMethodConfig,
  type ScidVhMethodCreateResult,
} from './scid-vh-method.js';
export {
  collectWitnessAttestations,
  verifyWitnessAttestation,
  verifyWitnessAttestationResolved,
  type RequestWitnessAttestationParams,
} from './witness-attestation.js';
export { createGenesisWitnessVtc, type CreateGenesisWitnessVtcParams } from './genesis-witness-vtc.js';
export { RotationLogStore } from './rotation-log-store.js';

// ---------------------------------------------------------------------------
// DID Resolution (W3C DID Core + DID Resolution) — unified resolver facade
// + did:scid:vh rotation-log acquisition
// ---------------------------------------------------------------------------

export {
  DidResolver,
  type DidResolverConfig,
  type DidResolutionResult,
  type DidResolutionMetadata,
  type DidDocumentMetadata,
  type DereferencedVerificationMethod,
} from './did-resolver.js';
export {
  LocalRotationLogSource,
  HttpRotationLogSource,
  type RotationLogSource,
} from './rotation-log-source.js';

// ---------------------------------------------------------------------------
// Agent names (scidvh-agent-name-plan)
// ---------------------------------------------------------------------------

export { parseNameUri, buildNameUri, isValidNameUri, type NameUri } from './name-uri.js';
export { issueNameClaim, verifyNameClaim } from './name-vrc.js';
export { NameService, type NameServiceConfig, type RegisterNameParams, type NameEntry } from './name-service.js';
export { resolveNameFromLocalDb, resolveNameFromDid, extractPeerTarget, type PeerTarget } from './name-resolver.js';
