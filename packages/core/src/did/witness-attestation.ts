// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Witness attestation flow — Step 11, Task 11.3.
 *
 * A thin wrapper over Step 10's issueVrc()/verifyVrc() using claim type
 * 'rotation-witness'. No new claim machinery, no new signature scheme —
 * 'rotation-witness' is simply added to a Witness VTC's allowedClaimTypes.
 *
 * Note on 'witness-member' vs 'rotation-witness': a VTA must typically hold
 * a 'witness-member' VRC from the Witness VTC (proving membership, Step 10)
 * before its co-signature on a 'rotation-witness' VRC is meaningful — but
 * Step 11 does not enforce this membership check in code (that's Step 12's
 * join/approve flow). verifyWitnessAttestation() only checks that signers
 * are on the governance doc's current adminVids list (same mechanism
 * verifyVrc() already uses) — i.e., "witness" and "admin" of the Witness VTC
 * are treated as the same list in Step 11. This is a simplification, not a
 * final design (see docs/implementation-plan-step11.md §4, §12).
 *
 * Reference: docs/implementation-plan-step11.md §4.
 */

import { issueVrc, verifyVrc, verifyVrcResolved } from '../vtc/vtc.js';
import type { DidResolver } from '../did/did-resolver.js';
import type { Ed25519KeyPair } from '../crypto/primitives.js';
import type { CesrVid } from '../tsp/v3/types.js';
import type { Vrc, VrcVerifyResult, VtcGovernanceDoc } from '../vtc/types.js';

// ---------------------------------------------------------------------------
// collectWitnessAttestations()
// ---------------------------------------------------------------------------

export interface RequestWitnessAttestationParams {
  governanceDoc: VtcGovernanceDoc;      // the Witness VTC (Step 10 shape)
  /**
   * Subject of the attestation = the rotating VTA **key**.
   *
   * Typed `CesrVid` deliberately: the attestation is encoded by the VTC/VRC
   * binary codec (`encodeVrc`), whose VID fields are CESR-encoded Ed25519 public
   * keys, and the witness is attesting to a key rotation — so the subject is
   * identified by its key VID, not by a DID. A DID or UUID here cannot be
   * encoded and is rejected (at compile time, and by `asCesrVrc` at runtime).
   */
  rotatingVid: CesrVid;
  rotationEntryDigest: Uint8Array;       // claim.rotationDigest
  observedAt: number;
  /** Witness signing key pairs — caller-supplied (Step 10.4-style simplification). */
  witnesses: Array<{ vid: CesrVid; signingKeyPair: Ed25519KeyPair }>;
}

/** Builds and co-signs 'rotation-witness' VRCs — thin wrapper over Step 10's issueVrc(). */
export function collectWitnessAttestations(params: RequestWitnessAttestationParams): Vrc {
  return issueVrc({
    governanceDoc: params.governanceDoc,
    subjectVid: params.rotatingVid,
    claim: {
      type: 'rotation-witness',
      rotationDigest: Buffer.from(params.rotationEntryDigest).toString('base64'),
      observedAt: params.observedAt,
    },
    signers: params.witnesses,
  });
}

// ---------------------------------------------------------------------------
// verifyWitnessAttestation()
// ---------------------------------------------------------------------------

/** Verifies a rotation-witness Vrc against the Witness VTC's governance doc + expected rotation digest. */
export function verifyWitnessAttestation(
  vrc: Vrc,
  governanceDoc: VtcGovernanceDoc,
  expectedRotationDigest: Uint8Array,
): VrcVerifyResult {
  // 1. claim.type === 'rotation-witness' and claim.rotationDigest === expectedRotationDigest, else reason 'wrong-claim'
  if (vrc.claim.type !== 'rotation-witness') {
    return { valid: false, validSignatureCount: 0, reason: 'wrong-claim' };
  }
  const expectedB64 = Buffer.from(expectedRotationDigest).toString('base64');
  if (vrc.claim.rotationDigest !== expectedB64) {
    return { valid: false, validSignatureCount: 0, reason: 'wrong-claim' };
  }

  // 2. delegates signature/threshold checking to Step 10's verifyVrc()
  return verifyVrc(vrc, governanceDoc);
}

/**
 * Resolution-aware witness attestation verification.
 *
 * Same claim checks as {@link verifyWitnessAttestation}, but delegates
 * signature/threshold checking to {@link verifyVrcResolved} so that a witness
 * admin's rotated key is honored: the signing VID must still be present in the
 * witness's current DID document `assertionMethod`.
 */
export async function verifyWitnessAttestationResolved(
  vrc: Vrc,
  governanceDoc: VtcGovernanceDoc,
  expectedRotationDigest: Uint8Array,
  resolver: DidResolver,
): Promise<VrcVerifyResult> {
  // 1. claim.type === 'rotation-witness' and claim.rotationDigest === expectedRotationDigest, else reason 'wrong-claim'
  if (vrc.claim.type !== 'rotation-witness') {
    return { valid: false, validSignatureCount: 0, reason: 'wrong-claim' };
  }
  const expectedB64 = Buffer.from(expectedRotationDigest).toString('base64');
  if (vrc.claim.rotationDigest !== expectedB64) {
    return { valid: false, validSignatureCount: 0, reason: 'wrong-claim' };
  }

  // 2. delegates to resolution-aware verifyVrcResolved()
  return verifyVrcResolved(vrc, governanceDoc, resolver);
}
