/**
 * Verified Channel Service — Personhood proof via nonce challenge/response
 * leading to VRC issuance between two VTAs.
 *
 * ## Flow
 * 1. Agent A selects a bidirectional relationship with Agent B
 * 2. Agent A initiates: sends a personhood_challenge TSP_GEN message with a nonce
 * 3. Agent B receives: auto-signs the nonce with its Ed25519 private key
 * 4. Agent B responds: sends a personhood_response TSP_GEN with the signature
 * 5. Agent A verifies: checks signature against public key from relationship
 * 6. Agent A records personhood_events (challenged, asserted)
 * 7. Agent A issues a VRC (vc_type='vrc') with the nonce digest as proof
 * 8. Agent A notifies Agent B via TSP_CRED_ISSUED
 *
 * ## TSP Message Format
 *
 * challenge: { action: 'personhood_challenge', nonce: <base64url>, identityUuid: <uuid> }
 * response:  { action: 'personhood_response', nonce: <base64url>, signature: <base64>, identityUuid: <uuid> }
 */

import { randomBytes } from 'node:crypto';
import { sha256, signEd25519, verifyEd25519 } from '../crypto/primitives.js';
import * as noncesRepo from '../db/repositories/nonces-repo.js';
import * as credentialsRepo from '../db/repositories/credentials-repo.js';
import * as identitiesRepo from '../db/repositories/identities-repo.js';

import {
  deserializeDtgCredential,
} from './dtg-credential.js';

import type { DataSource } from "../db/data-source.js";

// ── Types ──────────────────────────────────────────────────────────────

export interface PersonhoodChallenge {
  action: 'personhood_challenge';
  nonce: string;        // base64url-encoded 32 random bytes
  identityUuid: string; // challenger's identity UUID
}

export interface PersonhoodResponse {
  action: 'personhood_response';
  nonce: string;        // the original nonce
  signature: string;    // base64-encoded Ed25519 signature over nonce
  identityUuid: string; // responder's identity UUID
}

export interface VerifiedChannelResult {
  verified: boolean;
  reason: string;
  vrcUuid?: string;
  /** Claim object (when verified — for deferred credential minting via CredentialFactory). */
  claim?: Record<string, unknown>;
  /** Issuer identity UUID (when verified). */
  issuerUuid?: string;
  /** Subject identity UUID (when verified). */
  subjectUuid?: string;
}

const NONCE_EXPIRY_SECONDS = 5 * 60; // 5 minutes
const PERSONHOOD_PURPOSE = 'personhood';

// ── Challenge ──────────────────────────────────────────────────────────

/**
 * Generate a personhood challenge for a target identity.
 * Returns the nonce and stores it for replay protection.
 */
export async function generatePersonhoodChallenge(
  db: DataSource,
  challengerIdentityUuid: string,
): Promise<PersonhoodChallenge> {
  const nonce = randomBytes(32).toString('base64url');
  const now = Math.floor(Date.now() / 1000);

  await noncesRepo.create(db, {
    identityUuid: challengerIdentityUuid,
    nonce,
    purpose: PERSONHOOD_PURPOSE,
    expiresAt: now + NONCE_EXPIRY_SECONDS,
  });

  return {
    action: 'personhood_challenge',
    nonce,
    identityUuid: challengerIdentityUuid,
  };
}

// ── Response (sign) ────────────────────────────────────────────────────

/**
 * Sign a personhood challenge with an Ed25519 private key.
 * Called by the responding agent (Agent B).
 */
export function signPersonhoodChallenge(
  nonce: string,
  ed25519SecretKey: Uint8Array,
  responderIdentityUuid: string,
): PersonhoodResponse {
  const message = new TextEncoder().encode(nonce);
  const signature = signEd25519(message, ed25519SecretKey);
  return {
    action: 'personhood_response',
    nonce,
    signature: Buffer.from(signature).toString('base64'),
    identityUuid: responderIdentityUuid,
  };
}

// ── Verify & Complete ──────────────────────────────────────────────────

/**
 * Verify a personhood response and complete the proof.
 *
 * 1. Validates the nonce exists and hasn't expired
 * 2. Verifies the Ed25519 signature against the responder's public key
 * 3. Consumes the nonce (one-time use)
 *
 * Does NOT create the credential row — that is deferred to the caller
 * (typically CredentialFactory.mint()).
 */
export async function verifyAndCompletePersonhood(
  db: DataSource,
  response: PersonhoodResponse,
  challengerIdentityUuid: string,
  responderIdentityUuid: string,
  responderEd25519PublicKey: Uint8Array,
): Promise<VerifiedChannelResult> {
  // 1. Look up the nonce
  const nonceRow = await noncesRepo.findByIdentityAndNonce(db, challengerIdentityUuid, response.nonce);
  if (!nonceRow) {
    return { verified: false, reason: 'nonce not found or already consumed' };
  }

  // Consume immediately
  await noncesRepo.consume(db, nonceRow.uuid);

  // Check expiry
  const now = Math.floor(Date.now() / 1000);
  if (nonceRow.expiresAt !== null && nonceRow.expiresAt < now) {
    return { verified: false, reason: 'nonce expired' };
  }

  if (!nonceRow.purpose || !nonceRow.purpose.startsWith(PERSONHOOD_PURPOSE)) {
    return { verified: false, reason: 'nonce was not issued for personhood proof' };
  }

  // 2. Verify signature
  const message = new TextEncoder().encode(response.nonce);
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = new Uint8Array(Buffer.from(response.signature, 'base64'));
  } catch {
    return { verified: false, reason: 'signature is not valid base64' };
  }

  const sigValid = verifyEd25519(signatureBytes, message, responderEd25519PublicKey);
  if (!sigValid) {
    return { verified: false, reason: 'Ed25519 signature verification failed' };
  }

  // 3. Record personhood events
  // "challenged" event by the issuer
  const issuer = await identitiesRepo.findByUuid(db, challengerIdentityUuid);
  const subject = await identitiesRepo.findByUuid(db, responderIdentityUuid);
  if (!issuer || !subject) {
    return { verified: false, reason: 'identity not found' };
  }

  // Personhood events are for VTC membership ceremonies (FK to memberships).
  // For peer-to-peer DTG VRC issuance, the credential in w3c_vc_json is the audit trail.

  // 4. Build the claim (credential row creation deferred to CredentialFactory)
  const claim = {
    type: 'personhood_verification',
    nonceDigest: Buffer.from(sha256(message)).toString('base64'),
    method: 'ed25519_signature_challenge',
    verifiedAt: now,
  };

  return {
    verified: true,
    reason: 'personhood verified',
    claim,
    issuerUuid: issuer.uuid,
    subjectUuid: subject.uuid,
  };
}

/**
 * Check if a verified channel (VRC) exists between two identities.
 */
export async function isVerifiedChannel(
  db: DataSource,
  identityA: string,
  identityB: string,
): Promise<boolean> {
  const creds = await credentialsRepo.list(db, { vcType: 'vrc' });
  return creds.some(c =>
    c.status === 'issued' &&
    ((c.issuerIdentityUuid === identityA && c.subjectIdentityUuid === identityB) ||
     (c.issuerIdentityUuid === identityB && c.subjectIdentityUuid === identityA))
  );
}

// ── DTG RelationshipCredential Issuance ────────────────────────────────

/**
 * Input parameters for producing a DTG RelationshipCredential after successful
 * personhood verification.
 */
export interface DtgVerifiedChannelInput {
  /** Database handle. */
  db: DataSource;
  /** The signed personhood response from Agent B. */
  response: PersonhoodResponse;
  /** Agent A's (challenger's) identity UUID. */
  challengerIdentityUuid: string;
  /** Agent B's (responder's) identity UUID. */
  responderIdentityUuid: string;
  /** Agent B's Ed25519 public key (32 bytes). */
  responderEd25519PublicKey: Uint8Array;
  /** Agent A's DID string (from did_documents.did, JOINed via identity_uuid). */
  issuerDid: string;
  /** Agent B's DID string. */
  subjectDid: string;
  /** Agent A's DID URL for proof verificationMethod
   *  (e.g. "did:peer:4:z..." + "#" + multikey fingerprint). */
  issuerVerificationMethod: string;
  /** Agent A's Ed25519 secret key (64 bytes) for signing the VC proof. */
  issuerSecretKey: Uint8Array;
}

/**
 * Verify personhood AND produce a DTG-compliant RelationshipCredential.
 *
 * This wraps {@link verifyAndCompletePersonhood} and delegates credential
 * minting to {@link CredentialFactoryImpl.mint()}, which handles:
 * 1. DTG `RelationshipCredential` W3C VC construction with full JSON-LD envelope
 * 2. Storage of the serialized VC in `credentials.w3c_vc_json`
 * 3. Self-addressing digest computation
 *
 * The caller is responsible for providing DID strings and signing keys;
 * this function does NOT mint R-DIDs — that is the caller's responsibility
 * (see Agent's R-DID generation via IdentityResolver).
 */
export async function verifyAndIssueDtgRelationshipCredential(
  input: DtgVerifiedChannelInput,
): Promise<VerifiedChannelResult> {
  const {
    db,
    response,
    challengerIdentityUuid,
    responderIdentityUuid,
    responderEd25519PublicKey,
    issuerDid,
    subjectDid,
    issuerVerificationMethod,
    issuerSecretKey,
  } = input;

  // Step 1: Run the core personhood verification (nonce, signature).
  const verifyResult = await verifyAndCompletePersonhood(
    db,
    response,
    challengerIdentityUuid,
    responderIdentityUuid,
    responderEd25519PublicKey,
  );

  if (!verifyResult.verified) {
    return verifyResult;
  }

  // Step 2: Delegate credential minting to the CredentialFactory.
  // VRC is peer-to-peer — no GovernanceGuard needed.
  const { CredentialFactoryImpl } = await import('./credential-factory/credential-factory-impl.js');
  const factory = new CredentialFactoryImpl(db);

  const mintResult = await factory.mint({
    kind: 'RelationshipCredential',
    scenario: 'peer-verification',
    issuerDid,
    subjectDid,
    claim: verifyResult.claim ?? {},
    signerSecretKey: issuerSecretKey,
    verificationMethod: issuerVerificationMethod,
    extension: {
      issuerIdentityUuid: verifyResult.issuerUuid,
      subjectIdentityUuid: verifyResult.subjectUuid,
    },
  });

  return {
    verified: true,
    reason: 'personhood verified — DTG RelationshipCredential issued',
    vrcUuid: mintResult.credentialUuid,
  };
}

/**
 * Check if a DTG RelationshipCredential (W3C VC) exists between two identities.
 *
 * Unlike {@link isVerifiedChannel} which checks for any `vc_type='vrc'`,
 * this specifically looks for credentials with `w3c_vc_json` populated
 * (indicating a DTG-shaped credential was produced).
 */
export async function isDtgVerifiedChannel(
  db: DataSource,
  identityA: string,
  identityB: string,
): Promise<boolean> {
  const creds = await credentialsRepo.list(db, { vcType: 'vrc' });
  return creds.some(c =>
    c.status === 'issued' &&
    c.w3cVcJson !== null &&
    ((c.issuerIdentityUuid === identityA && c.subjectIdentityUuid === identityB) ||
     (c.issuerIdentityUuid === identityB && c.subjectIdentityUuid === identityA))
  );
}

/**
 * Retrieve the DTG RelationshipCredential(s) for a relationship pair.
 * Returns the deserialized W3C VC JSON objects.
 */
export async function getDtgRelationshipCredentials(
  db: DataSource,
  identityA: string,
  identityB: string,
): Promise<{ credential: Record<string, unknown>; direction: 'issued' | 'received' }[]> {
  const creds = await credentialsRepo.list(db, { vcType: 'vrc' });
  const results: { credential: Record<string, unknown>; direction: 'issued' | 'received' }[] = [];

  for (const c of creds) {
    if (c.status !== 'issued' || !c.w3cVcJson) continue;

    const isIssuedToB = c.issuerIdentityUuid === identityA && c.subjectIdentityUuid === identityB;
    const isReceivedFromB = c.issuerIdentityUuid === identityB && c.subjectIdentityUuid === identityA;

    if (isIssuedToB || isReceivedFromB) {
      try {
        const dtg = deserializeDtgCredential(c.w3cVcJson);
        results.push({
          credential: dtg as unknown as Record<string, unknown>,
          direction: isIssuedToB ? 'issued' : 'received',
        });
      } catch {
        // Skip malformed JSON.
      }
    }
  }

  return results;
}
