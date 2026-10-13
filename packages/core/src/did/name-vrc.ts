/**
 * VRC-based name claims for DID methods that don't support alsoKnownAs
 * (e.g., did:peer:4).
 *
 * Issues and verifies self-signed VRCs where the claim type is 'AgentName'.
 */

import { sha256, signEd25519, verifyEd25519, type Ed25519KeyPair } from '../crypto/primitives.js';
import type { Vrc, VrcSignature, VrcClaim } from '../vtc/types.js';
import { extractEd25519PublicKey } from '../relationship/key-extract.js';
import type { DidDocument } from './types.js';
import { isValidNameUri } from './name-uri.js';

/** Compute a self-addressing digest for a name claim VRC. */
function computeNameClaimDigest(params: {
  subjectVid: string;
  issuerVid: string;
  claim: VrcClaim;
  issuedAt: number;
  expiresAt?: number | undefined;
}): Uint8Array {
  const canonical = JSON.stringify({
    subjectVid: params.subjectVid,
    issuerVid: params.issuerVid,
    claim: params.claim,
    issuedAt: params.issuedAt,
    expiresAt: params.expiresAt ?? null,
  });
  return sha256(new TextEncoder().encode(canonical));
}

/**
 * Issue a self-signed VRC claiming an agent name.
 * The VRC is signed by the agent's own Ed25519 key and can be verified
 * against the DID document's verificationMethod.
 */
export function issueNameClaim(params: {
  nameUri: string;
  did: string;
  signingKeyPair: Ed25519KeyPair;
  expiresAt?: number;
}): Vrc {
  if (!isValidNameUri(params.nameUri)) {
    throw new Error(`issueNameClaim: invalid name URI "${params.nameUri}"`);
  }

  const now = Math.floor(Date.now() / 1000);
  const vid = `did:key:${Buffer.from(params.signingKeyPair.publicKey).toString('base64url')}`;

  const claim: VrcClaim = {
    type: 'AgentName',
    nameUri: params.nameUri,
    did: params.did,
  };

  const digest = computeNameClaimDigest({
    subjectVid: vid,
    issuerVid: vid,
    claim,
    issuedAt: now,
    expiresAt: params.expiresAt,
  });

  const signature = signEd25519(digest, params.signingKeyPair.secretKey);

  const sigEntry: VrcSignature = {
    signerVid: vid,
    signature,
  };

  return {
    subjectVid: vid,
    issuerVid: vid,
    claim,
    issuedAt: now,
    expiresAt: params.expiresAt,
    digest,
    signatures: [sigEntry],
  };
}

/**
 * Verify a name claim VRC against a DID document's verificationMethod.
 * Returns true if the VRC signature is valid and the claim type is 'AgentName'.
 */
export function verifyNameClaim(vrc: Vrc, didDocument: DidDocument): boolean {
  if (typeof vrc.claim.type !== 'string' || vrc.claim.type !== 'AgentName') return false;
  if (!vrc.signatures || vrc.signatures.length === 0) return false;

  try {
    const publicKey = extractEd25519PublicKey(didDocument);
    const sig = vrc.signatures[0];

    // Verify the self-addressing digest matches
    const expectedDigest = computeNameClaimDigest({
      subjectVid: vrc.subjectVid,
      issuerVid: vrc.issuerVid,
      claim: vrc.claim,
      issuedAt: vrc.issuedAt,
      expiresAt: vrc.expiresAt,
    });

    // Compare digests
    if (expectedDigest.length !== vrc.digest.length) return false;
    for (let i = 0; i < expectedDigest.length; i++) {
      if (expectedDigest[i] !== vrc.digest[i]) return false;
    }

    return verifyEd25519(sig.signature, vrc.digest, publicKey);
  } catch {
    return false;
  }
}