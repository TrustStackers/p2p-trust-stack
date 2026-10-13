/**
 * Genesis Witness VTC bootstrapping — Step 11, Task 11.5.
 *
 * Creates (or returns fixed test fixture data for) a small, well-known
 * "genesis" Witness VTC intended for development and early-adopter use.
 *
 * NOT intended as a permanent production trust anchor — real deployments
 * are expected to replace/supplement this with their own Witness VTC(s).
 * Flagged explicitly (see docs/cross-layer-integration-plan.md Open Question #1)
 * so this doesn't quietly become a permanent centralization point.
 *
 * This is a thin convenience wrapper over Step 10's createVtc() — no new
 * mechanism. Its purpose is purely documentation + a clearly-named,
 * discoverable entry point so nobody accidentally treats an ad hoc test VTC
 * as "the" genesis one. This VTC's admin keys are dev-only and must be
 * rotated out / replaced before any real deployment (migration story
 * explicitly deferred, per Open Question #1).
 *
 * Reference: docs/implementation-plan-step11.md §6.
 */

import { createVtc } from '../vtc/vtc.js';
import type { Ed25519KeyPair } from '../crypto/primitives.js';
import type { Vid } from '../tsp/v3/types.js';
import type { VtcIdentity } from '../vtc/types.js';

export interface CreateGenesisWitnessVtcParams {
  /** Fixed/documented dev keys for the founding admins. */
  founders: Array<{ vid: Vid; signingKeyPair: Ed25519KeyPair }>;
  threshold: number;
}

/**
 * Create the "genesis-witness-vtc (DEV ONLY — replace for production)" VTC.
 *
 * allowedClaimTypes includes both 'witness-member' (Step 10 membership) and
 * 'rotation-witness' (Step 11 rotation attestation).
 */
export function createGenesisWitnessVtc(params: CreateGenesisWitnessVtcParams): Promise<VtcIdentity> {
  return createVtc({
    name: 'genesis-witness-vtc (DEV ONLY — replace for production)',
    founders: params.founders,
    threshold: params.threshold,
    allowedClaimTypes: ['witness-member', 'rotation-witness'],
  });
}
