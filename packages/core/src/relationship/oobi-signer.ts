// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Holds the function that ML-DSA-65-signs the OOBIs this PROCESS issues.
 *
 * ## Why a holder
 *
 * An OOBI is the out-of-band introduction. Signing it needs the identity's
 * ML-DSA-65 secret key, but the two places that *build* OOBIs — the shared
 * VTC-invite builder (`src/relationship/vtc-invite.ts`) and the utility server's
 * `POST /relationships/oobi` route — are far from the one place that *loads* the
 * key (server boot, in `utility-server/src/index.ts`). This is the same
 * "set once at startup, read where the node isn't available" need that
 * `utility-server/src/services/server-node-info.ts` already solves for the
 * server's peerId/multiaddrs/did, so it uses the same shape.
 *
 * ## Why a FUNCTION and not the key
 *
 * `getOobiSigner()` returning `null` is an explicit, checkable "this process
 * cannot sign" (an identity that predates PQ provisioning) rather than a key that
 * silently produces invalid signatures — and a caller can produce a signed
 * introduction without being able to extract the signing key.
 *
 * ## What this does and does not achieve
 *
 * It makes the OOBI carry a verifiable signature. Whether a RECEIVER can check it
 * is a separate question: `sendRfi` resolves the ML-DSA key from the OOBI's own
 * `did`, so a receiver must be able to resolve that DID locally — self-contained
 * for a long-form `did:peer:4`, but requiring a rotation-log store or a pinned
 * document for `did:scid:vh` (see `checkOobiIntroductionIntegrity`). Signing is
 * therefore necessary but not sufficient to make the `enforce` policy usable
 * against a did:scid:vh peer.
 */

import { signOobi } from './oobi.js';
import type { OobiPayload } from './types.js';

/** A function that returns a copy of the OOBI carrying an ML-DSA-65 signature. */
export type OobiSigner = (oobi: OobiPayload) => OobiPayload;

/**
 * Which DID (subject of the OOBI) this process is entitled to sign FOR.
 *
 * An OOBI signature is checked against the ML-DSA key published in the document
 * of the OOBI's own `did`. So a signature is only meaningful when the signer
 * holds the key of THAT identity — signing someone else's OOBI produces an
 * artifact that can never verify, and under the `enforce` policy would be
 * refused. `'*'` means "any DID" and exists only for tests.
 */
export type OobiSignerAuthority = string | '*';

let signer: OobiSigner | null = null;
let authority: OobiSignerAuthority | null = null;

/**
 * Install the process-wide OOBI signer and the DID it may sign for.
 *
 * @param next   the signer, or `null` to uninstall
 * @param forDid the DID this signer is authoritative for (`'*'` in tests only)
 */
export function setOobiSigner(next: OobiSigner | null, forDid: OobiSignerAuthority = '*'): void {
  signer = next;
  authority = next ? forDid : null;
}

/**
 * Install a signer backed by a raw ML-DSA-65 secret key, scoped to the identity
 * that key belongs to.
 *
 * @param opts.forDid the DID whose document publishes this key — the ONLY OOBI
 *   subject this signer will sign for.
 */
export function setOobiSignerFromKey(
  mlDsa65SecretKey: Uint8Array | undefined,
  opts: { forDid: string },
): void {
  if (!mlDsa65SecretKey) {
    signer = null;
    authority = null;
    return;
  }
  signer = (oobi: OobiPayload) => signOobi(oobi, mlDsa65SecretKey);
  authority = opts.forDid;
}

/** The installed signer regardless of subject (diagnostics and tests). */
export function getOobiSigner(): OobiSigner | null {
  return signer;
}

/**
 * The signer to use for an OOBI naming `did`, or `null` when this process is not
 * the authority for that identity — the check that stops a call site emitting a
 * signature under the wrong key.
 */
export function getOobiSignerFor(did: string): OobiSigner | null {
  if (!signer || !authority) return null;
  return authority === '*' || authority === did ? signer : null;
}

/**
 * Return `oobi` signed when this process is the authority for the DID it names,
 * unchanged otherwise.
 *
 * Callers that need to report which happened should read the returned payload
 * (`!!payload.mlDsa65Signature`) or {@link getOobiSignerFor}.
 */
export function maybeSignOobi(oobi: OobiPayload): OobiPayload {
  const forThisDid = getOobiSignerFor(oobi.did);
  return forThisDid ? forThisDid(oobi) : oobi;
}
