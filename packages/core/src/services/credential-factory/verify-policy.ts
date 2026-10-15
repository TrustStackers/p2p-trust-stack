// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import { logger } from '../../util/logger.js';

/**
 * Credential verification policy for the RECEIVE path (F-003).
 *
 * The audit finding this closes: `CredentialFactoryImpl.verify()` is fully
 * implemented — it resolves the proof's verificationMethod, checks the key's
 * purpose, verifies the DataIntegrityProof — and **nothing called it**. Every
 * credential the stack received was persisted unverified, so every
 * verification-side result described dead code.
 *
 * This module holds the policy and the verdict classifier; the receive
 * participant calls it. Following the OOBI-integrity precedent
 * (`TSP_OOBI_SIGNATURE_POLICY`), the default is `warn` so an existing
 * deployment's behaviour does not change until an operator opts in.
 *
 *   off      — do not verify (pre-F-003 behaviour, byte-for-byte)
 *   warn     — verify, log the verdict, STORE regardless            (default)
 *   enforce  — verify, log, and REFUSE to persist a definitely-invalid credential
 *
 * The `enforce` refusal is deliberately narrow — see `classifyCredentialVerdict`.
 */

export const CREDENTIAL_VERIFY_POLICY_ENV = 'TSP_CREDENTIAL_VERIFY_POLICY';

/**
 * Binding policy — the SECOND, independent question this receive path asks
 * (audit F-001/F-026).
 *
 * The audit's finding: a membership fact is asserted by the community alone — the
 * guard trusts roster rows, admission requires no presentation, and the
 * credential is minted single-issuer. Part of what makes that one-sided is that
 * the member's own acceptance was **context-free**: `verify()` takes only bytes,
 * so a perfectly valid VMC minted for somebody else verified exactly as well as
 * one addressed to the recipient.
 *
 * This policy governs the context check: is this credential FOR me, FROM the
 * issuer the delivery names, and internally consistent (`memberOf` = issuer)?
 * It is deliberately a separate switch from proof verification so an operator can
 * enable either independently.
 */
export const CREDENTIAL_BINDING_POLICY_ENV = 'TSP_CREDENTIAL_BINDING_POLICY';

export type CredentialVerifyPolicy = 'off' | 'warn' | 'enforce';

export type CredentialBindingPolicy = 'off' | 'warn' | 'enforce';

/**
 * Resolve the effective policy: explicit option → environment → `warn`.
 *
 * An unrecognised value warns and falls back to `warn` — never to `enforce`,
 * because a typo must not start refusing credentials.
 */
function resolvePolicy(envName: string, explicit?: string): 'off' | 'warn' | 'enforce' {
  if (explicit === 'off' || explicit === 'warn' || explicit === 'enforce') return explicit;
  const raw = (process.env[envName] ?? '').trim().toLowerCase();
  if (raw === 'off' || raw === 'warn' || raw === 'enforce') return raw;
  if (raw) {
    logger.warn(`[credential-verify] ${envName}="${raw}" is not one of off|warn|enforce — using "warn"`);
  }
  return 'warn';
}

export function resolveCredentialVerifyPolicy(explicit?: CredentialVerifyPolicy): CredentialVerifyPolicy {
  return resolvePolicy(CREDENTIAL_VERIFY_POLICY_ENV, explicit);
}

export function resolveCredentialBindingPolicy(explicit?: CredentialBindingPolicy): CredentialBindingPolicy {
  return resolvePolicy(CREDENTIAL_BINDING_POLICY_ENV, explicit);
}

/** A verification outcome, or the error thrown while trying to obtain one. */
export interface CredentialVerdictInput {
  /** Verbatim `CredentialFactoryImpl.verify()` result, when it returned. */
  result?: { valid: boolean; reason?: string; detectedKind?: string } | undefined;
  /** Set when verification itself threw, which `verify()` normally does not do. */
  error?: unknown;
  /**
   * Whether the delivery carried a VC payload at all (`w3cVcJson`). A credential
   * with no payload is INDETERMINATE, not invalid — see the classifier below.
   */
  hasPayload: boolean;
}

export type CredentialVerdict = 'verified' | 'invalid' | 'indeterminate';

export interface CredentialVerdictDecision {
  verdict: CredentialVerdict;
  /** Whether the credential may be persisted. */
  store: boolean;
  /** Log severity the caller should use. */
  level: 'info' | 'warn' | 'error';
  /** Operator-facing message (the verifier's own reason is included verbatim). */
  message: string;
}

/**
 * Classify a verification attempt. Pure, so every branch is unit-testable
 * without a real signature.
 *
 * **The distinction this exists to preserve (audit F-031): "could not verify" is
 * not "invalid".** A verifier that returns `valid: false` because the issuer's
 * key is not resolvable locally has NOT established forgery, and treating it as
 * forgery would refuse legitimate credentials from any peer whose DID document
 * this agent has not seen yet. So `enforce` refuses only when the verifier
 * actually parsed a credential and actually rejected its proof:
 *
 *   - no VC payload                       → indeterminate (store)
 *   - verifier threw                      → indeterminate (store)
 *   - `valid: true`                       → verified     (store)
 *   - `valid: false` with a DEFINITE verdict reason → invalid (enforce refuses)
 *   - `valid: false` for any other reason → indeterminate (store) — the verifier
 *                                            never obtained a verdict, which is
 *                                            NOT evidence of forgery
 *
 * The discriminator is deliberately NOT `detectedKind`: that only proves the
 * credential *parsed*, and "verificationMethod could not be dereferenced" must
 * stay indeterminate — refusing an unresolvable-key credential under `enforce`
 * would reject every peer whose DID document this node has not seen yet.
 *
 * **Known brittleness:** the verdict/no-verdict split keys on the verifier's
 * reason strings, because `CredentialVerifyResult` has no tri-state. The durable
 * fix is to give that type `valid: true | false | null` (the shape the HTTP route
 * already uses: `null = unverifiable`, see `routes/layer3-tasks/credentials.ts`).
 * Until then these two patterns are the verdict, and anything else is not.
 */
const DEFINITE_INVALID_REASON = /(signature verification failed|is not authorized for proof purpose)/i;

export function classifyCredentialVerdict(
  input: CredentialVerdictInput,
  policy: CredentialVerifyPolicy,
): CredentialVerdictDecision {
  const enforce = policy === 'enforce';

  if (!input.hasPayload) {
    return {
      verdict: 'indeterminate',
      store: true,
      level: 'warn',
      message: 'no VC payload on the delivery — nothing to verify (indeterminate, not invalid)',
    };
  }

  if (input.error) {
    return {
      verdict: 'indeterminate',
      store: true,
      level: 'error',
      message: `verification could not run: ${(input.error as Error)?.message ?? String(input.error)}`
        + ' (indeterminate, not invalid)',
    };
  }

  const result = input.result;
  if (!result) {
    return {
      verdict: 'indeterminate',
      store: true,
      level: 'error',
      message: 'verification returned no result (indeterminate, not invalid)',
    };
  }

  if (result.valid) {
    return {
      verdict: 'verified',
      store: true,
      level: 'info',
      message: `proof verified${result.detectedKind ? ` (kind=${result.detectedKind})` : ''}`,
    };
  }

  // `valid: false` — but did the verifier obtain a VERDICT, or merely fail to?
  const reason = result.reason ?? '';
  if (!DEFINITE_INVALID_REASON.test(reason)) {
    return {
      verdict: 'indeterminate',
      store: true,
      level: 'warn',
      message: `no verdict obtained — ${reason || 'no reason given'} (indeterminate, not invalid)`
        + ' — an unresolvable key is not evidence of forgery',
    };
  }

  return {
    verdict: 'invalid',
    store: !enforce,
    level: 'error',
    message: `proof INVALID — ${reason}`
      + (enforce ? ' — refusing to persist (policy=enforce)' : ' — persisted anyway (policy=warn)'),
  };
}

/** The three fields a binding check compares, as read from the VC JSON. */
export interface CredentialBindingInput {
  /** This agent's own DID (from the participant id `peer:{did}`), when known. */
  selfDid?: string | null | undefined;
  /** The issuer DID the delivery payload names (`issuerDid`). */
  payloadIssuerDid?: string | null | undefined;
  /** The VC's own `issuer`. */
  vcIssuer?: string | null | undefined;
  /** The VC's `credentialSubject.id`. */
  vcSubjectId?: string | null | undefined;
  /** The VC's `credentialSubject.memberOf`, for membership credentials. */
  vcMemberOf?: string | null | undefined;
  /** False when the payload carried no VC, or it could not be parsed. */
  hasPayload: boolean;
}

export type CredentialBindingVerdict = 'bound' | 'mismatch' | 'indeterminate';

export interface CredentialBindingDecision {
  verdict: CredentialBindingVerdict;
  /** Whether the credential may be persisted. */
  store: boolean;
  level: 'info' | 'warn' | 'error';
  message: string;
}

/**
 * Classify the CONTEXT of a delivered credential (audit F-001/F-026).
 *
 * Three definite mismatches are checked, each a distinct real-world confusion:
 *
 *   1. **subject ≠ self** — a valid credential minted for another identity. The
 *      receive path used to accept this silently, because `verify()` has no notion
 *      of a recipient.
 *   2. **issuer ≠ the issuer the payload names** — the delivery contradicts
 *      itself: two independently produced fields disagree about who issued it.
 *   3. **memberOf ≠ issuer** (membership credentials only) — the community the
 *      subject claims membership of is not the community that signed.
 *
 * Everything else is `indeterminate` and stored, on the same principle as the
 * proof verdict: a VC with no DID-form identifiers, an unparseable payload, or a
 * missing `selfDid` has not been shown to be mis-bound — refusing it would reject
 * legitimate credentials (audit F-031's lesson, applied again).
 */
export function classifyCredentialBinding(
  input: CredentialBindingInput,
  policy: CredentialBindingPolicy,
): CredentialBindingDecision {
  const enforce = policy === 'enforce';

  if (!input.hasPayload) {
    return {
      verdict: 'indeterminate',
      store: true,
      level: 'info',
      message: 'no VC payload — nothing to bind (indeterminate)',
    };
  }

  const definite = (reason: string): CredentialBindingDecision => ({
    verdict: 'mismatch',
    store: !enforce,
    level: 'error',
    message: `binding MISMATCH — ${reason}`
      + (enforce ? ' — refusing to persist (policy=enforce)' : ' — persisted anyway (policy=warn)'),
  });

  if (input.selfDid && input.vcSubjectId && input.vcSubjectId !== input.selfDid) {
    return definite(
      `credentialSubject.id ${truncate(input.vcSubjectId)} is not this agent ${truncate(input.selfDid)}`,
    );
  }

  if (input.payloadIssuerDid && input.vcIssuer && input.vcIssuer !== input.payloadIssuerDid) {
    return definite(
      `VC issuer ${truncate(input.vcIssuer)} disagrees with the delivery's issuerDid ${truncate(input.payloadIssuerDid)}`,
    );
  }

  if (input.vcMemberOf && input.vcIssuer && input.vcMemberOf !== input.vcIssuer) {
    return definite(
      `credentialSubject.memberOf ${truncate(input.vcMemberOf)} is not the signing issuer ${truncate(input.vcIssuer)}`,
    );
  }

  const missing: string[] = [];
  if (!input.selfDid) missing.push('no self DID to bind against');
  if (!input.vcSubjectId) missing.push('VC has no credentialSubject.id');
  if (!input.vcIssuer) missing.push('VC has no issuer');

  if (missing.length === 0) {
    return {
      verdict: 'bound',
      store: true,
      level: 'info',
      message: 'bound: subject, issuer and memberOf all agree',
    };
  }

  return {
    verdict: 'indeterminate',
    store: true,
    level: 'warn',
    message: `bound as far as it could be — ${missing.join('; ')} (indeterminate)`,
  };
}

/** Short, log-safe form of a DID/UUID. */
function truncate(value: string): string {
  return value.length > 16 ? `${value.slice(0, 16)}…` : value;
}
