// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import { logger } from '../../util/logger.js';

/**
 * DTG statement-profile policy (F-002, decided 2026-09-25).
 *
 * ## What this gates
 *
 * The DTG Credentials Core Specification v1.0 replaced the WD02 concrete
 * `EndorsementCredential` / `WitnessCredential` types with **predicate profiles
 * of one `StatementCredential` (VSC)**. Verbatim:
 *
 * > "The endorsement and witness credentials of Working Draft 02 are predicate
 * > profiles of the VSC, not types."
 *
 * and the migration keeps the old names only as profile names:
 *
 * > "Name retained for the profile; no longer a W3C type string."
 *
 * So a conformant VEC/VWC is
 *
 *   type: ["VerifiableCredential", "DTGCredential", "StatementCredential"]
 *   credentialSubject: { id, predicate: "dtg:endorses" | "dtg:witnessed", object }
 *
 * with the predicate carrying the distinction the type string used to carry.
 *
 * ## Why a policy gate
 *
 * The change alters the canonical bytes of a credential and therefore its
 * digest, so a credential issued before the change no longer verifies against
 * the new form. `off` reproduces the WD02 bytes exactly; `warn` emits WD02 and
 * reports what would change; `enforce` emits the v1.0 profile.
 *
 * **The default is `enforce`** — the owner's `Y6-yes` ruling (2026-09-25): the
 * repo should emit the type the current spec defines. `TSP_DTG_PROFILE_POLICY=off`
 * (or `warn`) is the compatibility escape hatch for a deployment holding
 * credentials issued in the WD02 form.
 *
 * Follows the same `off|warn|enforce` shape as `src/tx/operation-proof.ts` and
 * `src/services/membership-presentation.ts`, but deliberately departs from their
 * `warn` default — those gate a *refusal*, this gates a conformance fix the owner
 * asked for outright.
 */

export const DTG_PROFILE_POLICY_ENV = 'TSP_DTG_PROFILE_POLICY';

export type DtgProfilePolicy = 'off' | 'warn' | 'enforce';

/** The default when the env var is unset or unrecognised. See the note above. */
export const DEFAULT_DTG_PROFILE_POLICY: DtgProfilePolicy = 'enforce';

/**
 * Resolve the policy.
 *
 * An unrecognised value falls back to the **default** rather than to a chosen
 * policy: the env var exists to *deviate* from the default, so a typo that cannot
 * be honoured should land on the default, loudly, not on an unrequested third
 * behaviour.
 */
export function resolveDtgProfilePolicy(
  raw: string | undefined = process.env[DTG_PROFILE_POLICY_ENV],
): DtgProfilePolicy {
  const value = (raw ?? '').trim().toLowerCase();
  if (value === '') return DEFAULT_DTG_PROFILE_POLICY;
  if (value === 'off' || value === 'warn' || value === 'enforce') return value;
  logger.warn(
    `[dtg-profile] unrecognised ${DTG_PROFILE_POLICY_ENV}="${raw}" — using ` +
      `"${DEFAULT_DTG_PROFILE_POLICY}"`,
  );
  return DEFAULT_DTG_PROFILE_POLICY;
}

/** True when a profile-capable credential must be emitted in the v1.0 form. */
export function emitsDtgStatementProfile(
  raw: string | undefined = process.env[DTG_PROFILE_POLICY_ENV],
): boolean {
  return resolveDtgProfilePolicy(raw) === 'enforce';
}

/** The single concrete subtype a DTG statement credential carries. */
export const STATEMENT_CREDENTIAL_TYPE = 'StatementCredential';

/**
 * The two predicate profiles the DTG Credentials Specification defines. The
 * predicate term is a CURIE resolved through the DTG JSON-LD context.
 */
export const DTG_PREDICATE_ENDORSES = 'dtg:endorses';
export const DTG_PREDICATE_WITNESSED = 'dtg:witnessed';

/** A VSC statement: the predicate plus the object the statement is about. */
export interface DtgStatement {
  /** e.g. `dtg:witnessed`. A verifier MUST reject a predicate it does not accept. */
  predicate: string;
  /** e.g. `{ digestMultibase: 'zQm…' }` or `{ id: 'did:…' }`. */
  object: Record<string, unknown>;
}
