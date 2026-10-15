// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Compile-time invariants for the **D-5b** distinction (CESR key vs DID).
 *
 * ## Why this file exists, and why it lives in `src/`
 *
 * Decision D-5b (2026-09-24) settled that a VTC/VRC identifier stays a **CESR key**
 * rather than migrating to DIDs, and that the *types* must make the distinction
 * explicit instead. The distinction is carried by two things:
 *
 *   1. the `CesrVid` brand (`src/tsp/v3/types.ts`) — a plain `string` is not assignable
 *      to it, so key-valued positions force an explicit `asCesrVid()` conversion;
 *   2. the encoded model (`CesrVrc`), whose VID fields are branded, versus the general
 *      model (`Vrc`), whose fields legitimately also hold DIDs/UUIDs from the store.
 *
 * Both are **compile-time** guarantees, and a guarantee nobody checks decays. A
 * regression is silent: widen `CesrVid` back to `string` and every guard still runs,
 * every test still passes, and the trap H17 described (`the type system says DID while
 * the codec requires a key`) quietly returns.
 *
 * The obvious place for a type assertion is a test file — and that is exactly where it
 * would be **worthless** here: the root `tsconfig.json` includes only `src/**` and
 * `agent-app/**`, so `tsc --noEmit` never reads `test/`, and node's type-stripping
 * loader does not type-check either. A `@ts-expect-error` in `test/` would pass without
 * testing anything — the same false-assurance shape as the ack-gating tests that were
 * red because they asserted against a schema the runtime did not use.
 *
 * So the assertions live here, in a file the build DOES check, and the values are
 * exported so a runtime test can prove the file is still present and still true.
 * `tsc --noEmit` is the enforcing mechanism; the test is the tripwire on the tripwire.
 */

import type { CesrVid, Vid } from '../tsp/v3/types.js';
import type { CesrVrc, CesrVrcSignature, Vrc } from './types.js';

/** 1. The encoded model's VID fields ARE the branded CESR-key type. */
type EncodedSubjectIsBranded = CesrVrc['subjectVid'] extends CesrVid ? true : false;
type EncodedIssuerIsBranded = CesrVrc['issuerVid'] extends CesrVid ? true : false;
type EncodedSignerIsBranded = CesrVrcSignature['signerVid'] extends CesrVid ? true : false;

/** 2. A plain `string` is NOT a `CesrVid` — the brand is what forces `asCesrVid()`. */
type PlainStringIsNotCesrVid = string extends CesrVid ? false : true;

/** 3. One-way flow: a `CesrVid` IS a `string`, so encoded values still reach
 *     `Vid`-typed code (digest computation, etc.) without ceremony. */
type CesrVidFlowsIntoGeneralModel = CesrVid extends Vid ? true : false;

/** 4. The general model is deliberately NOT narrowed: the store persists DIDs there,
 *     so narrowing `Vrc.subjectVid` to `CesrVid` would be a lie (and D-5b rejected
 *     the migration that would have made it true). */
type GeneralModelStillAcceptsDids = Vid extends CesrVrc['subjectVid'] ? false : true;

/**
 * The invariant set. Every field must be `true`; if an invariant breaks, the
 * annotation below stops accepting the literal and **`tsc --noEmit` fails**, naming
 * this file. That is the entire point: a build-time tripwire, not a comment.
 *
 * Checked by `tsc` (this file is under `src/`), and asserted at runtime by
 * `test/vtc/type-invariants.test.ts` so deleting the file is also caught.
 */
export const D5B_TYPE_INVARIANTS: {
  encodedSubjectIsBranded: EncodedSubjectIsBranded;
  encodedIssuerIsBranded: EncodedIssuerIsBranded;
  encodedSignerIsBranded: EncodedSignerIsBranded;
  plainStringIsNotCesrVid: PlainStringIsNotCesrVid;
  cesrVidFlowsIntoGeneralModel: CesrVidFlowsIntoGeneralModel;
  generalModelStillAcceptsDids: GeneralModelStillAcceptsDids;
} = {
  encodedSubjectIsBranded: true,
  encodedIssuerIsBranded: true,
  encodedSignerIsBranded: true,
  plainStringIsNotCesrVid: true,
  cesrVidFlowsIntoGeneralModel: true,
  generalModelStillAcceptsDids: true,
};

/**
 * A `Vrc` with DID-form identifiers is a legitimate value of the general model — this
 * function exists so the compiler keeps proving it. If `Vrc`'s VID fields were ever
 * narrowed to `CesrVid`, this call would stop compiling, which is the signal that a
 * model change (not a cleanup) is being made.
 */
export function generalModelAcceptsDidFormVids(did: string, didVrc: Vrc): Vrc {
  return { ...didVrc, subjectVid: did };
}
