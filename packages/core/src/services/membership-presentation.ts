// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Membership admission presentation — audit F-026, decision **F-001b** (2026-09-24).
 *
 * The audit's finding: a membership fact in this stack is asserted by the community
 * alone. The community mints its own VMC, the guard trusts roster rows, and
 * **admission requires no presentation of any kind** — so the member's own key is
 * never exercised, and nothing proves the party being admitted is the party who
 * asked. The guard therefore proves only the community's half of a two-party fact.
 *
 * Decision F-001b closes the admission half **without changing the credential
 * model**: the VMC stays single-issuer (the community's), and instead the member
 * proves possession of its key over the membership claim, bound to a
 * community-issued nonce. That is the "presentation-only" option — it does not
 * produce the member's own half of the claim (that is option (a), the full
 * two-party model, still open), it makes admission non-anonymous and non-replayable.
 *
 * ## The F-031 discipline applies here too
 *
 * Three outcomes are kept apart, because treating "I cannot check" as "this is
 * forged" would reject every honest member whose key this node has not yet seen:
 *
 *   verified       — the signature verifies against a locally-known key, and the nonce
 *   invalid        — a definite failure: bad signature, replayed/expired/unknown nonce
 *   indeterminate  — no locally-known key for the member, so no verdict is available
 *   absent         — no presentation was supplied at all (pre-F-001b behaviour)
 *
 * Only `invalid` is ever refused, and only under `enforce`.
 */

import type { DataSource } from '../db/data-source.js';
import * as keysRepo from '../db/repositories/keys-repo.js';
import * as didDocumentsRepo from '../db/repositories/did-documents-repo.js';
import * as noncesRepo from '../db/repositories/nonces-repo.js';
import { verifyEd25519 } from '../crypto/primitives.js';

export const MEMBERSHIP_PRESENTATION_POLICY_ENV = 'TSP_MEMBERSHIP_PRESENTATION_POLICY';

/**
 *   off      — do not check a presentation (pre-F-001b behaviour, byte-for-byte)
 *   warn     — check, log the verdict, ADMIT regardless              (default)
 *   enforce  — check, log, and REFUSE a definitely-absent/-invalid presentation
 *
 * `warn` is the default for the same reason as `TSP_CREDENTIAL_VERIFY_POLICY`: every
 * deployed peer predates this, and a policy change must not start rejecting the
 * membership requests of installations that have not been updated.
 */
export type MembershipPresentationPolicy = 'off' | 'warn' | 'enforce';

export const MEMBERSHIP_PRESENTATION_PURPOSE = 'membership-admission';

/** The presentation a joining member supplies with its request. */
export interface MembershipPresentation {
  /** The nonce string from `POST /nonces/challenge`. */
  nonce: string;
  /** base64url Ed25519 signature over `admissionChallenge(...)`. */
  signature: string;
}

export type PresentationVerdict = 'verified' | 'invalid' | 'indeterminate' | 'absent';

export interface PresentationOutcome {
  verdict: PresentationVerdict;
  reason: string;
  /** True when the admission may proceed under `enforce`. */
  admissible: boolean;
}

/**
 * The exact bytes the member signs. Canonical, and defined in exactly one place —
 * a challenge string assembled separately at each end is the classic way for a
 * challenge/response scheme to silently never verify.
 *
 * `role` is included so a presentation authorises the role actually granted: without
 * it, a signature collected for a `member` join could be replayed for an `admin` one.
 */
export function admissionChallenge(input: {
  communityUuid: string;
  memberIdentityUuid: string;
  role?: string;
  nonce: string;
}): string {
  return [
    'tsp-membership-admission:v1',
    input.communityUuid,
    input.memberIdentityUuid,
    input.role ?? '',
    input.nonce,
  ].join(':');
}

/** Resolve the policy: explicit option → environment → `warn`. Unknown → `warn`. */
export function resolveMembershipPresentationPolicy(
  raw: string | undefined = process.env[MEMBERSHIP_PRESENTATION_POLICY_ENV],
): MembershipPresentationPolicy {
  const v = (raw ?? '').trim().toLowerCase();
  if (v === 'off' || v === 'warn' || v === 'enforce') return v;
  if (v.length > 0) {
    console.warn(
      `[membership-presentation] unrecognised ${MEMBERSHIP_PRESENTATION_POLICY_ENV}="${raw}" — falling back to "warn"`,
    );
  }
  return 'warn';
}

/** The member's current Ed25519 public key, or null when this node has none. */
async function findMemberEd25519Key(
  db: DataSource,
  memberIdentityUuid: string,
): Promise<Uint8Array | null> {
  // Prefer the primary DID document when one exists: key material must belong to
  // the identity presenting, not to some other document of the same identity.
  const primary = await didDocumentsRepo.findPrimaryForIdentity(db, memberIdentityUuid);
  if (!primary) {
    // No document at all: this node cannot tie any key to the member. That is
    // "cannot check", not "checked and failed".
    return null;
  }
  const keys = await keysRepo.findByIdentityUuid(db, memberIdentityUuid);
  // Highest rotation version wins, mirroring the credential verifier (F-003) so the
  // two paths agree on which key is current.
  const ed = keys
    .filter((k) => k.keyType === 'ed25519')
    .sort((a, b) => (b.rotationVersion ?? 0) - (a.rotationVersion ?? 0))[0];
  return ed ? new Uint8Array(ed.publicKey) : null;
}

/**
 * Classify a membership presentation. **Side effect:** on a `verified` verdict the
 * nonce is consumed, which is what makes a replay of the same presentation fail as
 * `invalid` rather than being admitted twice.
 *
 * The nonce is deliberately NOT consumed on a failure or on `indeterminate`: a member
 * whose key has not reached this node yet should be able to retry with the same
 * challenge while it is still live, and burning the nonce on our own inability to
 * check would turn a local data gap into a permanent denial.
 */
export async function classifyMembershipPresentation(
  db: DataSource,
  input: {
    communityUuid: string;
    memberIdentityUuid: string;
    role?: string;
    presentation?: MembershipPresentation | null;
  },
): Promise<PresentationOutcome> {
  if (!input.presentation || !input.presentation.nonce || !input.presentation.signature) {
    return {
      verdict: 'absent',
      reason: 'no presentation supplied (the member did not prove possession of its key)',
      admissible: false,
    };
  }

  const { nonce, signature } = input.presentation;
  const now = Math.floor(Date.now() / 1000);

  const row = await noncesRepo.findByIdentityAndNonce(db, input.memberIdentityUuid, nonce);
  if (!row) {
    // Either never issued, issued for a different identity, or already consumed
    // (a replay of a successful presentation lands here).
    return {
      verdict: 'invalid',
      reason: 'the nonce is unknown, or was issued to a different identity, or has already been used',
      admissible: false,
    };
  }
  if (row.expiresAt !== null && row.expiresAt < now) {
    return { verdict: 'invalid', reason: 'the nonce has expired', admissible: false };
  }

  const publicKey = await findMemberEd25519Key(db, input.memberIdentityUuid);
  if (!publicKey) {
    // F-031 discipline: cannot check is not the same as checked-and-failed.
    return {
      verdict: 'indeterminate',
      reason: 'no locally-known Ed25519 key for this identity — the signature could not be checked',
      admissible: true,
    };
  }

  const challenge = new TextEncoder().encode(
    admissionChallenge({
      communityUuid: input.communityUuid,
      memberIdentityUuid: input.memberIdentityUuid,
      role: input.role,
      nonce,
    }),
  );

  let ok = false;
  try {
    ok = verifyEd25519(Buffer.from(signature, 'base64url'), challenge, publicKey);
  } catch (err) {
    return {
      verdict: 'invalid',
      reason: `the presentation could not be verified: ${(err as Error)?.message ?? 'malformed signature'}`,
      admissible: false,
    };
  }

  if (!ok) {
    return {
      verdict: 'invalid',
      reason: 'the signature does not verify against the member\'s key over the admission challenge',
      admissible: false,
    };
  }

  await noncesRepo.consume(db, row.uuid);
  return {
    verdict: 'verified',
    reason: 'the member proved possession of its key over the admission challenge',
    admissible: true,
  };
}

/**
 * Should the admission be refused? Under `enforce` ONLY a definite `invalid` or a
 * missing presentation blocks; `indeterminate` always admits.
 */
export function refusesAdmission(
  policy: MembershipPresentationPolicy,
  outcome: PresentationOutcome,
): boolean {
  if (policy !== 'enforce') return false;
  return outcome.verdict === 'invalid' || outcome.verdict === 'absent';
}

/** The result of gating one admission attempt. */
export interface AdmissionGate {
  policy: MembershipPresentationPolicy;
  /** null when the policy is `off`: nothing was checked. */
  outcome: PresentationOutcome | null;
  /** True when the caller must refuse the admission. */
  refuse: boolean;
}

/**
 * Gate a membership admission — the single entry point both admission paths call
 * (`POST /communities/:uuid/memberships` and `POST /vtcs/:uuid/join`), so the two
 * cannot drift apart on what "may be admitted" means.
 *
 * Under `off` nothing is classified at all, which matters beyond performance: a
 * classification CONSUMES a valid nonce on success, and an operator who has the
 * policy off must not have challenges spent behind their back.
 */
export async function gateMembershipAdmission(
  db: DataSource,
  input: {
    communityUuid: string;
    memberIdentityUuid: string;
    role?: string;
    presentation?: MembershipPresentation | null;
    /** Overrides the environment policy — used by tests and by callers with their own. */
    policy?: MembershipPresentationPolicy;
  },
): Promise<AdmissionGate> {
  const policy = input.policy ?? resolveMembershipPresentationPolicy();
  if (policy === 'off') {
    return { policy, outcome: null, refuse: false };
  }

  const outcome = await classifyMembershipPresentation(db, input);
  const refuse = refusesAdmission(policy, outcome);

  if (refuse) {
    console.warn(
      `[membership-presentation] REFUSED admission of ${input.memberIdentityUuid.slice(0, 8)}… ` +
      `to community ${input.communityUuid.slice(0, 8)}…: ${outcome.verdict} — ${outcome.reason}`,
    );
  } else {
    console.log(
      `[membership-presentation] admission of ${input.memberIdentityUuid.slice(0, 8)}… ` +
      `to ${input.communityUuid.slice(0, 8)}…: ${outcome.verdict} (policy=${policy})`,
    );
  }

  return { policy, outcome, refuse };
}

