/**
 * Trust Tasks — type identifiers and the action↔type map.
 *
 * ## Our own namespace (interop, not conformance)
 *
 * docs/08 §7 originally pointed at the trusttasks.org registry as the vocabulary. We
 * chose OUR OWN interpretation instead: a name is a namespace-scoped identifier resolved
 * by a peer (`did:peer4` / libp2p peer ID), never by a domain. Trust Task `type`
 * identifiers therefore follow the same convention as agent names (`vta:p2pts:erika`):
 *
 *     task:{namespace}:{family}:{slug}:{version}
 *
 * e.g. `task:p2pts:policy:evaluate:0.1`. It is a URI (scheme `task`), but nothing
 * resolves it over DNS — the namespace is a label, the authority is a peer. Interop with
 * the trusttasks.org interpretation is expressed in `TASK_TO_TRUSTTASKS_URI`, OUT-OF-BAND,
 * never baked into our identifiers.
 *
 * ## The namespace authority (deferred)
 *
 * A dedicated "trust task authority" utility server (a peer under this namespace) will
 * eventually publish the task vocabulary. Until the bridging design exists, the
 * vocabulary is a small, fixed set (the four P4 policy operations) defined here.
 */

/** The namespace label for this stack. Agent names share it (`vta:p2pts:…`). */
export const P2PTS_NAMESPACE = 'p2pts';

/** Reserved fragments that may follow a type identifier. */
export const REQUEST_FRAGMENT = '#request';
export const RESPONSE_FRAGMENT = '#response';

/** Build a type identifier: `task:{namespace}:{family}:{slug}:{version}`. */
export function taskType(
  family: string,
  slug: string,
  version: string,
  namespace: string = P2PTS_NAMESPACE,
): string {
  return `task:${namespace}:${family}:${slug}:${version}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// The minimal task vocabulary — the four P4 policy operations
// ─────────────────────────────────────────────────────────────────────────────

export const POLICY_UPSERT_TYPE = taskType('policy', 'upsert', '0.1');
export const POLICY_EVALUATE_TYPE = taskType('policy', 'evaluate', '0.1');
export const POLICY_TEST_TYPE = taskType('policy', 'test', '0.1');
export const POLICY_VALIDATE_TYPE = taskType('policy', 'validate', '0.1');

/** Envelope-level error type (ours — see `envelope.ts` `buildError`). */
export const TRUST_TASK_ERROR_TYPE = taskType('error', 'trust-task', '0.1');

// The VTC-establishment ceremony (the "first ceremony").
// These are NOT policy operations — they route to the agent's createVtc ceremony,
// not to `gatePolicy`; they sit beside the policy family in the same namespace.
export const VTC_ESTABLISH_TYPE = taskType('vtc', 'establish', '0.1');
/** Founding-member VMC issuance — a step within an establishment thread. */
export const MEMBERSHIP_VMC_TYPE = taskType('credential', 'membership-vmc', '0.1');

// ── The policy-gated ceremonies (they DO hit the engine) ─────────────────────

/**
 * The `policy` gate for membership VMC issuance. Its action is `issue_credential`,
 * evaluated by `GovernanceGuard.authorize` against the community's policy.
 */
export const MEMBERSHIP_VMC_AUTHORIZED_TYPE = taskType('policy', 'membership-vmc-authorized', '0.1');
/**
 * A single member's VMC raise — the EFFECT half of the member-onboarding ceremony
 * (gated by `MEMBERSHIP_VMC_AUTHORIZED_TYPE`). Distinct from `MEMBERSHIP_VMC_TYPE`,
 * which *documents* an already-minted founding VMC; this one actually MINTS.
 */
export const ONBOARDING_VMC_TYPE = taskType('credential', 'onboarding-vmc', '0.1');
/**
 * The `policy` gate for issuing a Verified Invitation Credential (a VIC). Its action is
 * `issue_credential`, and the baseline `vic-issue` rule requires `actor_is_admin` — so
 * "only an admin may invite" is a community policy rule, not a hard-coded check.
 */
export const INVITATION_VIC_AUTHORIZED_TYPE = taskType('policy', 'invitation-vic-authorized', '0.1');
/**
 * The EFFECT step that MINTS the signed VIC: the credential carrying the community's
 * authorization to onboard the named prospective member, with the OOBI transport
 * artifact wrapped in `credentialSubject.invitation`. Distinct from
 * `ONBOARDING_VMC_TYPE`, which mints the membership credential a member holds once
 * they accept.
 */
export const INVITATION_VIC_TYPE = taskType('credential', 'invitation-vic', '0.1');
/**
 * Peer-relationship VRC minting — the effect step of the VRC personhood ceremony.
 * Peer-to-peer: there is no community policy gate (the gate is the mutual personhood
 * ack), so the ceremony is effect-only, like `vtc-establish`.
 */
export const RELATIONSHIP_VRC_TYPE = taskType('credential', 'relationship-vrc', '0.1');

// ── Ceremony names (the `ceremony_templates.name` lookup key) ────────────────

/** The founding ceremony: establish the community, then document each founding VMC. */
export const CEREMONY_VTC_ESTABLISH = 'vtc-establish';
/** Gate → mint a single member's VMC. */
export const CEREMONY_MEMBER_ONBOARDING = 'member-onboarding';
/** Gate → mint a signed invitation (VIC) naming one prospective member. */
export const CEREMONY_MEMBER_INVITATION = 'member-invitation';
/** Effect-only: mint the peer VRC after mutual personhood. */
export const CEREMONY_VRC_PERSONHOOD = 'vrc-personhood';

// ── The governance-change consent ceremony (Phase B) ─────────────────────────

/**
 * The `policy` gate for a community governance-rule change. Its action is
 * `update_governance`, evaluated by `GovernanceGuard.authorize` against the
 * community's policy (the proposer must be an admin). The CONSENSUS (how many
 * approvers, and whose) is data-driven — resolved from the setting's approval scope
 * at proposal `begin` time and enforced by verified Ed25519 signatures over the
 * proposal hash, exactly as crystallization is.
 */
export const GOVERNANCE_CHANGE_AUTHORIZED_TYPE = taskType('policy', 'governance-change-authorized', '0.1');
/**
 * The EFFECT step that APPLIES an approved governance change: threshold updates plus
 * binding add/remove/update ops. Runs only after the consent gate passes.
 */
export const GOVERNANCE_CHANGE_APPLY_TYPE = taskType('governance', 'apply-change', '0.1');
/** The ceremony name (the `ceremony_templates.name` lookup key). */
export const CEREMONY_GOVERNANCE_CHANGE = 'governance-change';

// ── Ceremony COORDINATION events (recorded, never driven) ────────────────────
//
// These are deliberately NOT catalog steps and are NEVER executed by the ceremony
// driver. They are the COORDINATION half of a founding ceremony, which happens
// BEFORE the `vtc-establish` steps run: `CeremonyCoordinatorParticipant` records
// them into `trust_tasks` directly (request + response, under the same `threadId`
// as the ceremony's steps) so that one founding is ONE auditable thread —
// proposal, then each named admin's co-signature, then the establishment steps.
//
// A co-signature is the ACCEPTANCE of a named admin role: naming someone an admin
// is a request, and their own Ed25519 signature over the proposal hash is what
// makes them one. Like `TRUST_TASK_ERROR_TYPE`, these live in the vocabulary
// without a `trust_task_templates` row — the catalog holds what is EXECUTABLE.

/** The proposer's request to found a community (`ceremony_begin`). */
export const CEREMONY_PROPOSE_TYPE = taskType('ceremony', 'propose', '0.1');
/** A founding admin's co-signature — acceptance of the named admin role (`ceremony_approve`). */
export const CEREMONY_CO_SIGN_TYPE = taskType('ceremony', 'co-sign', '0.1');

/** A document-layer policy operation this stack exposes (the P4 routes). */
export type PolicyDocumentOperation = 'upsert' | 'evaluate' | 'test' | 'validate';

/** The action↔type map: our operations → our canonical task types. */
export const POLICY_OPERATION_TO_TYPE: Readonly<Record<PolicyDocumentOperation, string>> = {
  upsert: POLICY_UPSERT_TYPE,
  evaluate: POLICY_EVALUATE_TYPE,
  test: POLICY_TEST_TYPE,
  validate: POLICY_VALIDATE_TYPE,
};

/** Reverse of the map above: route an inbound `type` identifier to our operation. */
export function typeUriToOperation(typeUri: string): PolicyDocumentOperation | undefined {
  const base = typeUri.replace(/#(request|response)$/, '');
  for (const [op, uri] of Object.entries(POLICY_OPERATION_TO_TYPE)) {
    if (uri === base) return op as PolicyDocumentOperation;
  }
  return undefined;
}

/**
 * Interop map — OUR type identifier to the trusttasks.org task URI that expresses the
 * same intent. This is a boundary concern: our documents carry OUR identifiers; this map
 * is how a trusttasks.org peer bridges, and only at the envelope/decision level — their
 * policy body is Rego, ours is structured JSON, so payloads are not interchangeable.
 *
 * `test` and `validate` are intentionally ABSENT: trusttasks.org has no direct target
 * (`test` ≈ their `policy/evaluate` with `candidateModule`; `validate` ≈ the pre-persist
 * half of their `policy/upsert`), and emitting a near-miss would over-claim interop.
 */
export const TASK_TO_TRUSTTASKS_URI: Readonly<Partial<Record<PolicyDocumentOperation, string>>> = {
  upsert: 'https://trusttasks.org/spec/policy/upsert/0.2',
  evaluate: 'https://trusttasks.org/spec/policy/evaluate/0.3',
};
