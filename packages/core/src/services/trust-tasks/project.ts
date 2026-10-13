/**
 * Projection from our policy engine model to the trusttasks.org decision vocabulary.
 *
 * The interoperable surface we share with the trusttasks.org interpretation is the
 * DECISION vocabulary — `allow`/`deny`/`requireStepUp`/`requireConsent`, and
 * `requireConsent.approverSet`/`minApprovals`. `resultToPolicyDecision` projects our
 * `PolicyResult` onto it, losslessly except for one documented case.
 *
 * We deliberately do NOT project onto their `PolicyInput`: it is vault/device-shaped
 * (required `site`; `sideEffects`/`exposure` that their spec requires to come from an
 * authoritative handler classification), and a community-governance decision has no
 * truthful value for those fields. No such projection is provided.
 */

import type { PolicyResult, PolicyConsentRequirement } from '../policy-engine.js';

/** The trusttasks.org decision vocabulary (their `PolicyDecision`). */
export interface TrustTaskPolicyDecision {
  decision: 'allow' | 'deny' | 'requireStepUp' | 'requireConsent';
  explanation?: string;
  requireConsent?: {
    approverSet: string;
    excludeRequester?: boolean;
    minApprovals?: number;
  };
}

const EXPLANATION_MAX_LENGTH = 1024;

/**
 * Project a `PolicyResult` onto the shared decision vocabulary.
 *
 * `decision` maps 1:1 — our `PolicyDecisionKind` is the same four values, adopted
 * verbatim from the spec. `requireConsent.approverSet` and `excludeRequester` map
 * directly.
 *
 * The one lossy case: our `minApprovalsFromFact` names a FACT (e.g. `threshold_m`),
 * while the spec's `requireConsent.minApprovals` is an integer count. A fact name has
 * no integer field to land in, so it is OMITTED rather than coerced — the enforcement
 * point resolves the fact to a concrete `minApprovals`. A literal `minApprovals`
 * passes through unchanged.
 */
export function resultToPolicyDecision(result: PolicyResult): TrustTaskPolicyDecision {
  const source = result.decision;
  if (!source) {
    // Engine lead path always sets `decision`; this fallback keeps callers that only
    // read `allowed` working without inventing an explanation.
    return { decision: result.allowed ? 'allow' : 'deny' };
  }
  const decision: TrustTaskPolicyDecision = { decision: source.decision };
  if (source.explanation) {
    decision.explanation =
      source.explanation.length > EXPLANATION_MAX_LENGTH
        ? source.explanation.slice(0, EXPLANATION_MAX_LENGTH)
        : source.explanation;
  }
  if (source.requireConsent) {
    decision.requireConsent = projectConsent(source.requireConsent);
  }
  return decision;
}

function projectConsent(
  consent: PolicyConsentRequirement,
): NonNullable<TrustTaskPolicyDecision['requireConsent']> {
  const out: { approverSet: string; excludeRequester?: boolean; minApprovals?: number } = {
    approverSet: consent.approverSet,
  };
  if (typeof consent.excludeRequester === 'boolean') {
    out.excludeRequester = consent.excludeRequester;
  }
  // Only a LITERAL minimum maps. `minApprovalsFromFact` is a fact name, not a number,
  // and the spec's `minApprovals` is an integer — emitting the fact name there would
  // corrupt the decision, so it is left for the enforcement point to resolve.
  if (typeof consent.minApprovals === 'number' && consent.minApprovals >= 1) {
    out.minApprovals = consent.minApprovals;
  }
  return out;
}
