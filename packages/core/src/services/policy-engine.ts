// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * PolicyEngine — pluggable governance policy evaluation.
 *
 * Fork A: structured JSON policy documents (see docs/03_PolicyEngine-json-plan.md).
 * The engine is pure — it evaluates a policy document against `PolicyData` that
 * `GovernanceGuard` assembles from the database. This keeps it testable and lets
 * an `OpaSidecarPolicyEngine` (Fork C) swap in behind the same interface later.
 *
 * Separation of concerns:
 *   - Signature verification (Ed25519, threshold counting) → GovernanceGuard
 *   - Authorization policy (who can do what)              → PolicyEngine
 */

/**
 * The governance actions a policy can authorize.
 *
 * The first eight are the original action set. The remainder were added with the v2
 * document (P1): they are the actions other subsystems already perform and that a
 * community will want to gate — revocation, join requests, role changes, personhood,
 * delegations/grants, name registration and key rotation.
 *
 * Exported as a runtime array so `validatePolicy()` can reject an unknown action at
 * SAVE time; the type is derived from it, so the two cannot drift.
 */
export const POLICY_ACTIONS = [
  'issue_credential',
  'approve_membership',
  'revoke_membership',
  'add_admin',
  'remove_admin',
  'update_governance',
  'affiliate_vtc',
  'unaffiliate_vtc',
  // ── v2 additions ──────────────────────────────────────────────────────
  'revoke_credential',
  'request_membership',
  'change_member_role',
  'assert_personhood',
  'create_delegation',
  'create_grant',
  'revoke_grant',
  'register_name',
  'rotate_key',
  // ── P3 additions: the two decisions that used to be hardwired in the guard ──
  /** A ceremony proposal is ready to crystallize (M-of-N admin approval). */
  'crystallize_ceremony',
  /**
   * Does the parent VTN permit a child of this kind?
   *
   * Deliberately separate from `affiliate_vtc`: that action is admin-initiated and
   * asks "may this actor affiliate a child?", while this one asks only "does the
   * parent's own policy allow this child KIND?" — a question with no actor.
   */
  'parent_accepts_child',
] as const;

export type PolicyAction = (typeof POLICY_ACTIONS)[number];

/** The admission request being evaluated. */
export interface PolicyQuery {
  action: PolicyAction;
  communityDid: string;
  actorDid: string;
  params?: Record<string, unknown>;
}

// ═══════════════════════════════════════════════════════════════════════════
// Decision vocabulary (v2)
//
// These four values are the standard vocabulary from the trusttasks.org
// `policy/_shared` `PolicyDecision` schema. Adopting them verbatim is what lets a
// local decision be projected onto a Trust Task `policy/evaluate` response without
// translation — and `requireConsent` is the important one: it carries
// `approverSet` + `minApprovals`, which is exactly the M-of-N admin model this
// stack already implements in `governance.admin_threshold_m`/`_n`. Encoding the
// threshold as `requireConsent` means the caller learns *what it needs* (two of
// three admins) rather than just "denied".
// ═══════════════════════════════════════════════════════════════════════════

/** Outcome of an authorization decision. */
export type PolicyDecisionKind = 'allow' | 'deny' | 'requireStepUp' | 'requireConsent';

/** The `requireConsent` constraint — who must approve, and how many of them. */
export interface PolicyConsentRequirement {
  /** Named approver set the enforcement point resolves (e.g. 'community-admins'). */
  approverSet: string;
  /** Literal minimum number of distinct approvers. */
  minApprovals?: number;
  /**
   * Minimum number of approvers taken from a FACT rather than a literal — this is
   * how a policy says "the community's own threshold" without the number being
   * baked into the document. Resolves `data.governance.thresholdM`.
   */
  minApprovalsFromFact?: string;
  /** When true, the requester may not also be an approver. */
  excludeRequester?: boolean;
}

/** A full decision, as returned in `PolicyResult.decision`. */
export interface PolicyDecision {
  decision: PolicyDecisionKind;
  explanation?: string;
  requireConsent?: PolicyConsentRequirement;
}

// ═══════════════════════════════════════════════════════════════════════════
// v2 check tree
//
// `require` is an implicit AND (it is an array). Inside it, a check is one of:
//   { fact, is }                  boolean equality
//   { fact, op, value }           numeric comparison against a literal
//   { fact, op, valueFact }       numeric comparison against ANOTHER fact
//                                 (this is `approval_count >= threshold_m`)
//   { fact, includes }            collection contains a literal
//   { fact, subsetOf }            collection ⊆ another fact's collection
//   { any|all|not }               grouping
// ═══════════════════════════════════════════════════════════════════════════

/** Numeric comparison operators. */
export type PolicyCheckOp = 'lt' | 'lte' | 'eq' | 'gte' | 'gt';

/** One check inside a rule's `require` list. */
export interface PolicyCheck {
  /** The fact this check reads. Must be a declared fact (see `policy-facts.ts`). */
  fact?: string;
  /** Boolean equality: `fact === is`. */
  is?: boolean;
  /** Numeric comparison applied to `value` or `valueFact`. */
  op?: PolicyCheckOp;
  /** Literal to compare against (numeric comparison, or `includes` membership). */
  value?: unknown;
  /** Name of another fact to compare against, for `op` comparisons. */
  valueFact?: string;
  /** Collection containment: the fact's collection includes `value`. */
  includes?: unknown;
  /** Collection subset: the fact's collection ⊆ the named fact's collection. */
  subsetOf?: string;
  // ── grouping ──────────────────────────────────────────────────────────
  /** At least one sub-check must pass. */
  any?: PolicyCheck[];
  /** Every sub-check must pass. */
  all?: PolicyCheck[];
  /** Negate a sub-check. */
  not?: PolicyCheck;
}

/** A v2 rule: `when` selects, `require` gates, `decision` answers. */
export interface PolicyRuleV2 {
  id: string;
  /** Selector. Omitting `action` makes the rule apply to every action. */
  when?: { action?: PolicyAction; kind?: string };
  /** Conditions, implicitly ANDed. Omitted/empty means the selector alone matches. */
  require?: PolicyCheck[];
  /** What to answer when the selector and conditions match. */
  decision: PolicyDecision;
  /** 0–1000, higher evaluated first. Default 0. */
  priority?: number;
  /** Default true. `false` disables the rule without deleting it. */
  enabled?: boolean;
}

/**
 * A structured policy document.
 *
 * Shaped to the trusttasks.org `PolicyModule` envelope (`id`/`name`/`description`/
 * `appliesTo`/`priority`/`enabled`), with a `rules` body this engine interprets.
 * The community-metadata keys (`role`, `threshold`, `adminUuids`, `adminVids`,
 * `adminNames`, `allowedClaimTypes`, `notes`) are PRESERVED verbatim — they were
 * written by `createVtc` and are read by `resolveEffectivePolicy()` and the
 * agent-side `vtc/store.ts`, so removing them would break those readers.
 */
export interface JsonPolicyV2 {
  engine: 'p2pts';
  version: '2';
  /** `PolicyModule` envelope. */
  id?: string;
  name?: string;
  description?: string;
  /** Contexts this policy applies to; `[]` means every context. */
  appliesTo?: string[];
  /** Document-level ordering, 0–1000. */
  priority?: number;
  /** `false` suspends the whole document without deleting it. */
  enabled?: boolean;
  /** Community metadata — preserved, not interpreted by the engine. */
  role?: string;
  threshold?: number;
  adminUuids?: string[];
  adminVids?: string[];
  adminNames?: string[];
  allowedClaimTypes?: string[];
  notes?: string;
  /** Answer when no rule matches. A decision, not a bare allow/deny string. */
  default: PolicyDecision;
  rules: PolicyRuleV2[];
  /**
   * Facts this document reads. Optional; the engine can always derive the set by
   * walking `rules`. Declaring it lets a caller assemble only what is needed
   * (cost control) without re-deriving the walk.
   */
  facts?: string[];
}

/**
 * The structured policy document.
 *
 * Note the runtime is deliberately MORE tolerant than this type: input that is not a
 * recognised document (no `engine`, no `rules`) is treated as "no rules" and falls
 * back to the default decision, rather than throwing — see `normalizePolicy()` in
 * `local-policy-engine.ts`.
 */
export type JsonPolicy = JsonPolicyV2;

/** The data the engine evaluates against, assembled by GovernanceGuard. */
export interface PolicyData {
  policy: JsonPolicy;
  governance: {
    /** DIDs of the community's admins, plus the community DID itself. */
    adminDids: string[];
    thresholdM: number | null;
    thresholdN: number | null;
  };
  /** The community roster, in DID space. */
  memberships: Array<{ did: string; status: string }>;
  /** Whether the subject DID belongs to this community context. */
  subjectIsCommunityMember: boolean;
  /**
   * Supplementary facts, keyed by fact name (see `policy-facts.ts`).
   *
   * Precedence: `facts[name]` wins when present, otherwise the fact is derived
   * from the typed fields above. This bag is how new facts are added without
   * widening this interface every time — the assembly side (P3) populates it.
   */
  facts?: Record<string, unknown>;
}

export interface PolicyResult {
  /** The allow/deny answer. Unchanged — every existing caller reads this. */
  allowed: boolean;
  reason?: string;
  matchedRules?: string[];
  /**
   * The full decision, when the engine produced one. ADDITIVE and optional, so
   * existing callers that only read `allowed`/`reason` are unaffected.
   */
  decision?: PolicyDecision;
  /**
   * True when the answer could not be fully determined — a check read a fact that
   * had no value for this query. The result is still `allowed: false` (deny by
   * default), but the caller can tell "I cannot check" apart from "checked and
   * refused". Same three-outcome discipline as the membership-presentation gate.
   */
  indeterminate?: boolean;
  /** Which document version decided. Diagnostic only. */
  policyVersion?: number;
}

/**
 * What to do when a check reads a fact that has no value for the request.
 *
 *   deny  — fail closed: the check fails and the result carries `indeterminate: true`.
 *           Default, and the production behaviour.
 *   error — same refusal, but a `PolicyFactError` is thrown first, so a mis-wired fact
 *           assembly fails LOUDLY instead of quietly denying. For development.
 *
 * Defined here, with the other shared types, so both the engine and its configuration
 * can depend on it without importing each other.
 */
export type UnknownFactPolicy = 'deny' | 'error';

/** The recognised `UnknownFactPolicy` values, as a runtime list for validation. */
export const UNKNOWN_FACT_POLICIES = ['deny', 'error'] as const;

/**
 * Thrown by an engine configured with `unknownFact: 'error'` when a check cannot be
 * determined — a fact the document references has no value for this request.
 *
 * Catching this by type is why it is declared here rather than in the implementation
 * module: a caller should not have to import the engine to handle its failure.
 */
export class PolicyFactError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyFactError';
  }
}

/** The pluggable policy evaluation contract. */
export interface PolicyEngine {
  evaluate(query: PolicyQuery, data: PolicyData): PolicyResult;
  validatePolicy(policy: unknown): PolicyResult;
  defaultPolicy(kind: 'vtc' | 'vtn'): JsonPolicyV2;
}

/**
 * The default baseline policy for a newly created community.
 *
 * Emits a complete document. Encodes what the hardwired rules already enforce, and
 * nothing more: admins may issue credentials and manage the community, and a VMC is
 * not re-issued to an already-active member.
 *
 * Deliberately restricted to the three facts `GovernanceGuard` assembles TODAY
 * (`actor_is_admin`, `subject_is_active_member`, `subject_is_community_member`), so
 * a freshly created community evaluates correctly before any fact-assembly work
 * lands. A rule that referenced a fact with no value would deny — fail-closed, but
 * it would also make the default policy useless.
 *
 * ## VTC vs VTN — the `kind` is now load-bearing
 *
 * This used to ignore `kind` entirely, and `GovernanceGuard` passed `'vtc'` for both
 * roles. That is a latent bug the moment the two diverge, so the divergence is
 * encoded here, on a semantic that the code already implements:
 *
 * `affiliateVtc` / `unaffiliateVtc` are driven from the **VTN** routes
 * (`utility-server/src/routes/layer5-applications/vtns.ts`) — the network accepts or
 * removes a child community. A VTC cannot affiliate *itself* into a network; its
 * parent decides. So the VTN baseline grants those two actions to its admins, and the
 * VTC baseline deliberately does not.
 *
 * The remaining rules are shared because they provably should be. A VTN-specific
 * child-kind rule (the `child_kind_allowed` fact) was added by P3 — see
 * `parent-accepts-child` below — and it lives only in the VTN baseline, so it cannot
 * change a child's decisions.
 *
 * @param kind - the community role this document will govern.
 */
export function defaultPolicy(kind: 'vtc' | 'vtn'): JsonPolicyV2 {
  const isVtn = kind === 'vtn';

  const rules: PolicyRuleV2[] = [
    {
      id: 'vmc-issue',
      when: { action: 'issue_credential', kind: 'MembershipCredential' },
      require: [
        { fact: 'actor_is_admin', is: true },
        // Closes the original intent: a member already active must not be re-issued a VMC.
        { fact: 'subject_is_active_member', is: false },
      ],
      decision: { decision: 'allow' },
    },
    {
      id: 'vec-issue',
      when: { action: 'issue_credential', kind: 'EndorsementCredential' },
      require: [{ fact: 'actor_is_admin', is: true }],
      decision: { decision: 'allow' },
    },
    {
      id: 'vwc-issue',
      when: { action: 'issue_credential', kind: 'WitnessCredential' },
      require: [{ fact: 'actor_is_admin', is: true }],
      decision: { decision: 'allow' },
    },
    {
      id: 'vic-issue',
      when: { action: 'issue_credential', kind: 'InvitationCredential' },
      require: [{ fact: 'actor_is_admin', is: true }],
      decision: { decision: 'allow' },
    },
    {
      id: 'approve-membership',
      when: { action: 'approve_membership' },
      require: [{ fact: 'actor_is_admin', is: true }],
      decision: { decision: 'allow' },
    },
    {
      id: 'revoke-membership',
      when: { action: 'revoke_membership' },
      require: [{ fact: 'actor_is_admin', is: true }],
      decision: { decision: 'allow' },
    },
    {
      id: 'add-admin',
      when: { action: 'add_admin' },
      require: [{ fact: 'actor_is_admin', is: true }],
      decision: { decision: 'allow' },
    },
    {
      id: 'remove-admin',
      when: { action: 'remove_admin' },
      require: [{ fact: 'actor_is_admin', is: true }],
      decision: { decision: 'allow' },
    },
    {
      id: 'update-governance',
      when: { action: 'update_governance' },
      require: [{ fact: 'actor_is_admin', is: true }],
      decision: { decision: 'allow' },
    },

    // ── Ceremony crystallization — formerly hardwired in validateCrystallization ──
    //
    // The two VTC minimums were imperative TypeScript ("VTCs require at least 2
    // admins", "VTC threshold must be >= 2"). They are `deny` rules so they
    // short-circuit the quorum rules below whatever order they are evaluated in.
    {
      id: 'vtc-min-admins',
      when: { action: 'crystallize_ceremony', kind: 'vtc' },
      require: [{ fact: 'admin_count', op: 'lt', value: 1 }],
      decision: {
        decision: 'deny',
        explanation: 'a VTC requires at least 1 admin',
      },
    },
    {
      id: 'vtc-min-threshold',
      when: { action: 'crystallize_ceremony', kind: 'vtc' },
      require: [{ fact: 'threshold_m', op: 'lt', value: 1 }],
      decision: { decision: 'deny', explanation: 'a VTC threshold must be >= 1' },
    },
    // The quorum, split into two mutually exclusive rules so the short case can say
    // WHAT it needs. This is what `requireConsent` is for: the caller learns "two of
    // three admins" instead of just "denied".
    //
    // The bar is `threshold_n` — the NUMBER OF DECLARED ADMINISTRATORS — not
    // `threshold_m`. A community is founded only once EVERY founding admin has
    // co-signed. The creator cannot found a community on someone else's behalf by
    // simply naming them an admin: being named is a REQUEST to administer, and
    // co-signing the proposal hash with the named identity's own Ed25519 key is the
    // ACCEPTANCE. (`threshold_m` remains the community's change-approval quorum —
    // a different decision, evaluated against `update_governance`.)
    {
      id: 'crystallize-quorum-met',
      when: { action: 'crystallize_ceremony' },
      require: [{ fact: 'approval_count', op: 'gte', valueFact: 'threshold_n' }],
      decision: { decision: 'allow' },
    },
    {
      id: 'crystallize-quorum-short',
      when: { action: 'crystallize_ceremony' },
      require: [{ fact: 'approval_count', op: 'lt', valueFact: 'threshold_n' }],
      decision: {
        decision: 'requireConsent',
        explanation: 'not every founding admin has co-signed the ceremony yet',
        requireConsent: {
          approverSet: 'community-admins',
          minApprovalsFromFact: 'threshold_n',
          excludeRequester: true,
        },
      },
    },
  ];

  if (isVtn) {
    // Parent-side actions only. See the doc comment above.
    rules.push(
      {
        id: 'affiliate-vtc',
        when: { action: 'affiliate_vtc' },
        require: [{ fact: 'actor_is_admin', is: true }],
        decision: { decision: 'allow' },
      },
      {
        id: 'unaffiliate-vtc',
        when: { action: 'unaffiliate_vtc' },
        require: [{ fact: 'actor_is_admin', is: true }],
        decision: { decision: 'allow' },
      },
      // Replaces `validateParentVtnPolicy`'s `allowedChildKinds` check. An allow rule
      // on a derived boolean, so an unrestricted parent (or no declared list) allows
      // via `child_kind_allowed: true` and a restricted one falls to the default deny.
      {
        id: 'parent-accepts-child',
        when: { action: 'parent_accepts_child' },
        require: [{ fact: 'child_kind_allowed', is: true }],
        decision: { decision: 'allow' },
      },
    );
  }

  return {
    engine: 'p2pts',
    version: '2',
    id: isVtn ? 'default-vtn' : 'default-vtc',
    name: isVtn ? 'P2PTS default policy (VTN)' : 'P2PTS default policy (VTC)',
    description:
      'Baseline governance persisted at community creation. Admins may issue ' +
      'credentials and manage the community; a VMC is not re-issued to an active member.' +
      (isVtn ? ' A VTN additionally accepts and removes child communities.' : ''),
    // `appliesTo` is checked against the community's role by `validatePolicy()`, so
    // a VTC document cannot be silently installed on a VTN.
    appliesTo: [kind],
    role: kind,
    default: { decision: 'deny', explanation: 'no rule matched' },
    rules,
  };
}
