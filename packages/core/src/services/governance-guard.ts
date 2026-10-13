/**
 * GovernanceGuard — centralized governance validation for ceremonies,
 * memberships, and credential issuance.
 *
 * Stateless: receives a DataSource (the application DB) and validates rules.
 * Called by participants during prepare(); returns { allowed, reason }.
 * A 'no' result causes the participant to vote 'no', aborting the transaction.
 *
 * ## F-012 — the authorization decision has exactly one home
 *
 * The engine is a **required** constructor argument. It used to be optional, and
 * `validateCredentialIssuance` ended with `if (this.policyEngine) { … } return
 * { allowed: true }` — so a guard built without one **allowed every issuance it
 * was asked about**, protected only by each call site remembering to pass an
 * engine. Making the argument required turns that fail-open path into a compile
 * error, so the policy layer cannot be bypassed by omission. (Same compile-time
 * tripwire style as `src/vtc/type-invariants.ts`; `tsc --noEmit` is the test.)
 *
 * ## F-012 stage 3 — PolicyData is DID-space, and it was being fed UUIDs
 *
 * Making the engine required closed the *fail-open* hole, but the facts it
 * evaluates were still being assembled wrong. `LocalPolicyEngine` compares
 * `data.governance.adminDids.includes(query.actorDid)` and
 * `data.memberships.some(m => m.did === subjectDid && m.status === 'active')` —
 * both DID-space, because both `actorDid` and `subjectDid` are DIDs. Membership
 * rows are keyed on `identities.uuid`, a UUIDv5, so the old code compared a UUID
 * against a DID. `actor_is_admin` was false for every real admin, and true only
 * for `adminDids[0]` — the community's own DID, i.e. self-issuance. Every
 * `actor_is_admin: true` rule in the default policy therefore denied the admins
 * it was written for; the live VMC route never noticed because it is
 * single-issuer (the community signs its own VMCs, so issuer === governance).
 * `resolvePrimaryDids()` now maps each member to their primary DID before the
 * facts are built; `test/services/governance-guard.test.ts` pins admin-allowed,
 * self-issuance, and non-admin-denied.
 *
 * ## P3 — the governance rules moved out of this file
 *
 * Three decisions that used to be imperative TypeScript here are now policy, held as
 * data in the atomic catalog rule templates applied via `community_policy_bindings`:
 *
 *  - `validateCrystallization`'s threshold comparison, and the two VTC minimums
 *    (>= 2 admins, threshold >= 2) → `crystallize_ceremony` rules in the baseline.
 *  - `validateParentVtnPolicy`'s `allowedChildKinds` check → `parent_accepts_child`.
 *
 * Two things deliberately remain in this class, and should: **Ed25519 verification**
 * (cryptographic — it cannot be expressed as a policy rule) and **database reads**
 * (assembling the facts a document asks for). Everything a community actually decides
 * is now a rule, so changing it does not require a code change or a redeploy.
 */

import type { DataSource } from '../db/data-source.js';
import * as governanceRepo from '../db/repositories/governance-repo.js';
import * as membershipsRepo from '../db/repositories/memberships-repo.js';
import { DidManager } from './did-manager.js';
import type {
  PolicyEngine, PolicyQuery, PolicyData, PolicyResult, JsonPolicy,
  PolicyDecision, PolicyConsentRequirement,
} from './policy-engine.js';
import { defaultPolicy } from './policy-engine.js';
import { resolveCommunityRules, resolveCommunityChildKinds } from './policy-bindings.js';
import { resolvePolicyEngineConfig } from './policy-engine-config.js';
import { findEd25519KeysByIdentity } from '../db/repositories/keys-repo.js';
import { verifyEd25519 } from '../crypto/primitives.js';
import type { CeremonyProposal, CeremonyApproval } from '../tx/ceremony-store.js';

export interface GovernanceResult {
  allowed: boolean;
  reason?: string;
  /**
   * The full decision, when the engine produced one. ADDITIVE — a caller that reads
   * only `allowed`/`reason` is unaffected.
   */
  decision?: PolicyDecision;
  /**
   * Convenience projection of `decision.requireConsent`.
   *
   * This is the interesting case for a caller: it means "not allowed YET, and here is
   * exactly what would make it allowed" — an approver set and a minimum count — rather
   * than a bare refusal. `validateCrystallization` returns it when a ceremony has too
   * few valid approvals.
   */
  requireConsent?: PolicyConsentRequirement;
  /**
   * Rule ids whose `require` list passed, when the decision came from a rule. The audit
   * trail — it answers "why was this allowed?" with the rules that said so.
   */
  matchedRules?: string[];
  /**
   * True when a check could not be decided because a fact had no value for this
   * request. The result is still `allowed: false` (fail-closed), but a caller can tell
   * "no" apart from "I could not tell".
   */
  indeterminate?: boolean;
}

/**
 * Which default-policy KIND (`vtc`/`vtn`) supplies a community's rule-document SHAPE
 * (default decision, appliesTo). The RULES themselves come from the bindings.
 *
 * The community's own `identities.role` is authoritative, because a VTN and a VTC
 * have genuinely different baselines: `defaultPolicy` grants a VTN `affiliate_vtc` /
 * `unaffiliate_vtc` and deliberately withholds both from a VTC (a VTC cannot
 * affiliate itself into a network — its parent decides). The previous code passed
 * `'vtc'` unconditionally, so a VTN with no stored document silently lost those two
 * rules.
 *
 * `fallback` is consulted only for a role that is neither — e.g. a `vta` identity
 * that somehow carries a governance row — and comes from `TSP_POLICY_ENGINE` via
 * `resolvePolicyEngineConfig().defaultPolicyKind`.
 *
 * Extracted as a pure function so the choice is testable without a database.
 */
export function resolveBaselineKind(
  role: string | null | undefined,
  fallback: 'vtc' | 'vtn',
): 'vtc' | 'vtn' {
  if (role === 'vtn') return 'vtn';
  if (role === 'vtc') return 'vtc';
  return fallback;
}

/** Options for `GovernanceGuard`. */
export interface GovernanceGuardOptions {
  /**
   * Baseline document kind used when the community's own `identities.role` is
   * neither `vtc` nor `vtn`. Defaults to the resolved PolicyEngine configuration
   * (`TSP_POLICY_ENGINE`).
   */
  defaultPolicyKind?: 'vtc' | 'vtn';
}

export class GovernanceGuard {
  private readonly appDb: DataSource;
  private readonly policyEngine: PolicyEngine;
  private readonly defaultPolicyKind: 'vtc' | 'vtn';

  constructor(appDb: DataSource, policyEngine: PolicyEngine, options: GovernanceGuardOptions = {}) {
    this.appDb = appDb;
    this.policyEngine = policyEngine;
    this.defaultPolicyKind = options.defaultPolicyKind ?? resolvePolicyEngineConfig().defaultPolicyKind;
  }

  // ═══════════════════════════════════════════════════════════════
  // Phase 3 — Ceremony Rules
  // ═══════════════════════════════════════════════════════════════

  /**
   * Validate that a ceremony proposal is ready for crystallization.
   *
   * Split by kind of check, which is the point of P3:
   *
   *  **Cryptographic — always enforced here, never delegable:** every approval's
   *  Ed25519 signature verifies over `proposalHash`, and every approver is in the
   *  proposal's admin set.
   *
   *  **Authorization — delegated to the policy engine:** whether the valid approval
   *  count satisfies the threshold, and the VTC minimums (>= 2 admins, threshold >= 2).
   *  Both were imperative TypeScript here; they are now `crystallize_ceremony` rules in
   *  the baseline document, so a community can change them without a code change.
   *
   * ## A signature-counting defect this closes
   *
   * The threshold used to be compared against `approvals.length` — BEFORE any signature
   * was verified — and duplicates were never deduplicated. N copies of one admin's
   * signature therefore satisfied an N-of-N threshold. `approval_count` is now the
   * number of **distinct approvers whose signature actually verified**.
   */
  async validateCrystallization(
    proposal: CeremonyProposal,
    approvals: CeremonyApproval[],
  ): Promise<GovernanceResult> {
    // ── 1. Cryptographic checks ────────────────────────────────────────────
    const proposalHashBytes = new TextEncoder().encode(proposal.proposalHash);
    const validApprovers = new Set<string>();

    for (const a of approvals) {
      if (!proposal.adminDids.includes(a.approverDid)) {
        return { allowed: false, reason: `unknown approver: ${a.approverDid}` };
      }
      const publicKeys = await this.resolvePublicKeys(a.approverDid);
      if (publicKeys.length === 0) {
        return { allowed: false, reason: `cannot resolve key for ${a.approverDid}` };
      }
      const sigBytes = Buffer.from(a.signature, 'base64');
      // Try EVERY registered Ed25519 key (see `resolvePublicKeys`): one identity may hold
      // several, so checking only the first rejects valid signatures.
      if (!publicKeys.some((k) => verifyEd25519(sigBytes, proposalHashBytes, k))) {
        return { allowed: false, reason: `invalid signature from ${a.approverDid}` };
      }
      // Distinct approvers only — a repeated signature must not count twice.
      validApprovers.add(a.approverDid);
    }

    // ── 2. Authorization — the policy decides ──────────────────────────────
    const doc = await this.resolvePolicyDocument(proposal.vtcDid, proposal.kind);

    const query: PolicyQuery = {
      action: 'crystallize_ceremony',
      communityDid: proposal.vtcDid,
      actorDid: proposal.proposerDid,
      params: { kind: proposal.kind },
    };

    const data: PolicyData = {
      policy: doc.policy,
      governance: {
        // The PROPOSAL's admin set is authoritative here: the community does not exist
        // yet, so there is no membership roster to read. Its own DID is included
        // because a community may always act on its own behalf.
        adminDids: [...new Set([proposal.vtcDid, ...proposal.adminDids])],
        thresholdM: proposal.threshold,
        thresholdN: proposal.adminDids.length,
      },
      memberships: [],
      subjectIsCommunityMember: false,
      // A fact-bag entry WINS over the derived value. That is what lets one document
      // express "the community's standing M" for issuance and "this proposal's M" for
      // crystallization, without a second document having to say so.
      // Binding-supplied parameter facts sit UNDER the explicit crystallize facts:
      // the proposal's own numbers always win where they overlap.
      facts: {
        ...doc.facts,
        threshold_m: proposal.threshold,
        threshold_n: proposal.adminDids.length,
        approval_count: validApprovers.size,
        // Overrides the derived `adminDids.length`, which includes the community DID.
        admin_count: proposal.adminDids.length,
      },
    };

    return this.toGovernanceResult(this.policyEngine.evaluate(query, data));
  }

  /**
   * Validate that a parent VTN's policy permits this child VTC.
   *
   * The `allowedChildKinds` check used to be hardwired here, with three hard-coded
   * `return { allowed: true }` paths. It is now a policy evaluation
   * (`parent_accepts_child`) against the parent's own document, with the answer
   * supplied as the `child_kind_allowed` fact.
   *
   * ## Two early returns are preserved, deliberately
   *
   *  - no parent DID at all → there is nothing to consult;
   *  - a parent DID that does not resolve to a VTN → there is no VTN policy to apply.
   *
   * Both mean "this question does not apply", not "the answer is yes". Turning either
   * into a deny would refuse every orphan community and every non-VTN parent — a
   * behaviour change with no basis in the governance model. The other two former
   * fail-opens (no stored document, unparseable document) are GONE: both now fall back
   * to the baseline document and are therefore decided by policy rather than by a
   * hard-coded allow.
   */
  async validateParentVtnPolicy(
    parentCommunityDid: string | null | undefined,
    childKind: string,
  ): Promise<GovernanceResult> {
    if (!parentCommunityDid) return { allowed: true };

    const parent = await this.appDb.get<{ uuid: string; role: string | null }>(
      `SELECT i.uuid, i.role FROM identities i JOIN did_documents d ON d.identity_uuid = i.uuid
        WHERE d.did = ? AND i.role = 'vtn'`, parentCommunityDid);
    if (!parent) return { allowed: true };

    const loaded = await this.loadCommunityPolicy(parent.uuid, parent.role, 'vtn');

    // The declared restriction, if any, is a param on the parent's `parent-accepts-child`
    // binding. `null` means the parent declares nothing, i.e. unrestricted.
    const allowedKinds: string[] | null = await resolveCommunityChildKinds(this.appDb, parent.uuid);

    const data: PolicyData = {
      policy: loaded.policy,
      governance: {
        adminDids: [parentCommunityDid],
        thresholdM: loaded.thresholdM,
        thresholdN: loaded.thresholdN,
      },
      memberships: [],
      subjectIsCommunityMember: false,
      facts: {
        ...loaded.facts,
        child_kind_allowed: allowedKinds === null || allowedKinds.includes(childKind),
        parent_allowed_child_kinds: allowedKinds ?? [],
      },
    };

    const query: PolicyQuery = {
      action: 'parent_accepts_child',
      communityDid: parentCommunityDid,
      actorDid: parentCommunityDid,
      params: { child_kind: childKind },
    };

    return this.toGovernanceResult(this.policyEngine.evaluate(query, data));
  }

  // ═══════════════════════════════════════════════════════════════
  // Credential Issuance Validation
  // ═══════════════════════════════════════════════════════════════

  /**
   * Validate that a credential can be issued under the given governance rules.
   *
   * Called by CredentialFactory.mint() for community-governed credentials.
   * Checks:
   *   - Issuer DID maps to a real identity with the claimed governance role
   *   - Governance DID maps to a valid community (VTC/VTN)
   *   - Admin signatures (if provided) are valid Ed25519 over the issuance payload
   *
   * Future enhancement: integrate OPA/Rego policy engine (see docs/01_PolicyEngine-design.md).
   */
  async validateCredentialIssuance(input: {
    kind: string;
    issuerDid: string;
    subjectDid: string;
    governanceDid: string;
    adminSignatures?: Array<{ signerDid: string; signature: Uint8Array }>;
  }): Promise<GovernanceResult> {
    // 1. Validate issuer DID resolves to a real identity
    const issuerRow = await this.appDb.get<{ uuid: string; role: string }>(
      `SELECT i.uuid, i.role FROM identities i JOIN did_documents d ON d.identity_uuid = i.uuid
        WHERE d.did = ?`, input.issuerDid);
    if (!issuerRow) {
      return { allowed: false, reason: `issuer DID ${input.issuerDid} not found` };
    }

    // 2. Validate governance DID maps to a community
    const govRow = await this.appDb.get<{ uuid: string; role: string; name: string | null }>(
      `SELECT i.uuid, i.role, i.name FROM identities i JOIN did_documents d ON d.identity_uuid = i.uuid
        WHERE d.did = ?`, input.governanceDid);
    if (!govRow) {
      return { allowed: false, reason: `governance DID ${input.governanceDid} not found` };
    }
    if (govRow.role !== 'vtc' && govRow.role !== 'vtn') {
      return { allowed: false, reason: `governance DID ${input.governanceDid} is not a VTC or VTN (role=${govRow.role})` };
    }

    // 3. If admin signatures are provided, verify them
    if (input.adminSignatures && input.adminSignatures.length > 0) {
      // Build canonical issuance payload for signature verification
      const payload = JSON.stringify({
        kind: input.kind,
        issuerDid: input.issuerDid,
        subjectDid: input.subjectDid,
        governanceDid: input.governanceDid,
      });
      const payloadBytes = new TextEncoder().encode(payload);

      for (const sig of input.adminSignatures) {
        const publicKeys = await this.resolvePublicKeys(sig.signerDid);
        if (publicKeys.length === 0) {
          return { allowed: false, reason: `cannot resolve key for admin ${sig.signerDid}` };
        }
        const valid = publicKeys.some((k) => verifyEd25519(sig.signature, payloadBytes, k));
        if (!valid) {
          return { allowed: false, reason: `invalid signature from admin ${sig.signerDid}` };
        }
      }
    }

    // 4. Authorization policy — the decision belongs to the PolicyEngine.
    //
    // F-012: this used to fall through to `return { allowed: true }` when no
    // engine was configured, i.e. a guard that could not evaluate policy allowed
    // everything. The engine is now required at construction (see the class doc),
    // so there is no unconfigured state to be lenient about.
    return this.evaluateAuthorization(input);
  }

  /**
   * Resolve identity UUIDs to their PRIMARY DID, in one query.
   *
   * PolicyData facts are DID-space (see `evaluateAuthorization`) while identity
   * keys are UUID-space, so every roster entry must cross that boundary.
   * Identities with no primary DID are simply absent from the result.
   */
  private async resolvePrimaryDids(identityUuids: string[]): Promise<Map<string, string>> {
    const byIdentity = new Map<string, string>();
    const unique = [...new Set(identityUuids)];
    if (unique.length === 0) return byIdentity;
    const placeholders = unique.map(() => '?').join(', ');
    const rows = await this.appDb.all<{ identity_uuid: string; did: string }>(
      `SELECT identity_uuid, did FROM did_documents
        WHERE is_primary = 1 AND identity_uuid IN (${placeholders})`,
      ...unique,
    );
    for (const row of rows) byIdentity.set(row.identity_uuid, row.did);
    return byIdentity;
  }
  /**
   * Load a community's policy document, or the baseline for its kind.
   *
   * The baseline used to be `defaultPolicy('vtc')` unconditionally, which governed a
   * VTN by a VTC baseline — and a VTC baseline deliberately omits
   * `affiliate_vtc`/`unaffiliate_vtc`. `identities.role` is authoritative; the
   * configured `defaultPolicyKind` applies only when the role is neither `vtc` nor
   * `vtn` (e.g. a `vta` identity that somehow carries a governance row).
   *
   * The baseline supplies only the document SHAPE; the RULES come from the
   * community's policy bindings, so a missing or misconfigured binding set yields the
   * default decision rather than taking the guard down.
   */
  private async loadCommunityPolicy(
    uuid: string,
    role: string | null,
    fallbackHint: 'vtc' | 'vtn',
  ): Promise<{
    policy: JsonPolicy;
    thresholdM: number | null;
    thresholdN: number | null;
    /** Parameter facts supplied by the community's policy bindings (Phase A). */
    facts: Record<string, unknown>;
  }> {
    const govRow = await governanceRepo.findForCommunity(this.appDb, uuid);
    const kind = resolveBaselineKind(role ?? fallbackHint, this.defaultPolicyKind);

    // Rules come ONLY from the community's atomic bindings. There is no stored
    // policy document and no fallback: a community with no bindings has no rules, so
    // the document default (`deny`) applies — fail-closed. `defaultPolicy(kind)`
    // supplies only the document SHAPE (default decision, appliesTo, description);
    // the rules themselves are always data.
    const baseline = defaultPolicy(kind);
    const resolved = await resolveCommunityRules(this.appDb, uuid);
    const policy: JsonPolicy = { ...baseline, rules: resolved.rules };

    return {
      policy,
      thresholdM: govRow?.adminThresholdM ?? null,
      thresholdN: govRow?.adminThresholdN ?? null,
      facts: resolved.facts,
    };
  }

  /**
   * Resolve a governance DID to its policy document.
   *
   * A community UNDER FORMATION has no `identities` row yet — crystallization decides
   * whether to create it — so a missing row is NOT an error here. It means "no document
   * of its own yet", and the baseline governs. `fallbackHint` is what the caller knows
   * the community is being built as, before the identity exists.
   */
  private async resolvePolicyDocument(
    governanceDid: string,
    fallbackHint: 'vtc' | 'vtn',
  ): Promise<{ policy: JsonPolicy; uuid: string | null; role: string | null; facts: Record<string, unknown> }> {
    const row = await this.appDb.get<{ uuid: string; role: string | null }>(
      `SELECT i.uuid, i.role FROM identities i JOIN did_documents d ON d.identity_uuid = i.uuid
        WHERE d.did = ?`, governanceDid);

    if (!row) {
      return { policy: defaultPolicy(fallbackHint), uuid: null, role: null, facts: {} };
    }
    const loaded = await this.loadCommunityPolicy(row.uuid, row.role, fallbackHint);
    return { policy: loaded.policy, uuid: row.uuid, role: row.role, facts: loaded.facts };
  }

  /**
   * Project a `PolicyResult` onto `GovernanceResult`.
   *
   * `allowed` is passed through unchanged. The decision and its `requireConsent` are
   * attached, and — because `reason` is what actually reaches an operator or agent —
   * the refusal is restated to say what WOULD satisfy it. "the M-of-N admin quorum has
   * not been reached" is a dead end; "… — needs 2 approvals from 'community-admins'"
   * is actionable.
   */
  private toGovernanceResult(result: PolicyResult): GovernanceResult {
    const requireConsent = result.decision?.requireConsent;

    let reason = result.reason;
    if (requireConsent) {
      const minimum =
        requireConsent.minApprovalsFromFact !== undefined
          ? `${requireConsent.minApprovalsFromFact}`
          : String(requireConsent.minApprovals ?? 'more');
      reason = `${reason ?? 'consent required'} — needs ${minimum} approval(s) from '${requireConsent.approverSet}'`;
    }

    return {
      allowed: result.allowed,
      ...(reason !== undefined ? { reason } : {}),
      ...(result.decision ? { decision: result.decision } : {}),
      ...(requireConsent ? { requireConsent } : {}),
      ...(result.matchedRules ? { matchedRules: result.matchedRules } : {}),
      ...(result.indeterminate ? { indeterminate: true } : {}),
    };
  }

  /**
   * Authorize ANY action for a community — the reusable gate.
   *
   * This is the one-liner a route author needs: resolve the community's facts, evaluate
   * its policy, get a decision. `validateCredentialIssuance` is just this with
   * `action: 'issue_credential'` and the issuer as the actor, and the P4 `/policy/*`
   * routes are this generalised to every action.
   *
   * Facts are assembled here and only here, because this class owns DB access — the
   * engine stays pure (see the plan's `03` §8 deviation 1).
   *
   * @param query       the admission request.
   * @param extraFacts  facts the caller knows and the database does not, keyed by fact
   *                    name. They WIN over derived values (see `resolveFact`), which is
   *                    how a caller supplies e.g. `approval_count` for a dry run.
   */
  async authorize(
    query: PolicyQuery,
    extraFacts?: Record<string, unknown>,
  ): Promise<GovernanceResult> {
    const didManager = new DidManager(this.appDb);

    // Resolve the community identity uuid.
    const communityRow = await this.appDb.get<{ uuid: string; role: string | null }>(
      `SELECT i.uuid, i.role FROM identities i JOIN did_documents d ON d.identity_uuid = i.uuid
        WHERE d.did = ?`, query.communityDid);
    if (!communityRow) {
      return { allowed: false, reason: `governance DID ${query.communityDid} not found` };
    }

    const loaded = await this.loadCommunityPolicy(
      communityRow.uuid, communityRow.role, this.defaultPolicyKind);

    // Resolve admin DIDs + membership roster from memberships.
    //
    // F-012: PolicyData is DID-space (see the class doc) — the engine evaluates
    // `adminDids.includes(query.actorDid)` and `m.did === subjectDid`, and both
    // of those are DIDs — while membership rows are keyed on `identities.uuid`, a
    // UUIDv5. Pushing `memberIdentityUuid` straight in compared a UUID against a
    // DID, which made `actor_is_admin` false for every real admin. Resolve each
    // member to their PRIMARY DID first.
    const memberships = await membershipsRepo.findForCommunity(this.appDb, communityRow.uuid);
    const memberDids = await this.resolvePrimaryDids(memberships.map((m) => m.memberIdentityUuid));

    // The community itself is always authorized to act on its own behalf,
    // so include its DID alongside the admin/founding_admin members'.
    const adminDids: string[] = [query.communityDid];
    const memberRows: Array<{ did: string; status: string }> = [];
    for (const m of memberships) {
      const memberDid = memberDids.get(m.memberIdentityUuid);
      if (!memberDid) continue; // no primary DID → cannot satisfy a DID-space fact
      if (m.role === 'admin' || m.role === 'founding_admin') {
        adminDids.push(memberDid);
      }
      memberRows.push({ did: memberDid, status: m.status });
    }

    // MD-8: whether the subject DID belongs to this community context. Only asked when
    // the query carries a subject — an action with no subject has no subject fact, and
    // asking would invent one.
    const subjectDid = query.params?.['subjectDid'];
    const subjectIsCommunityMember =
      typeof subjectDid === 'string' && subjectDid.length > 0
        ? await didManager.isCommunityMember(subjectDid, query.communityDid)
        : false;

    // Binding parameter facts first; caller-supplied `extraFacts` win over them.
    const facts: Record<string, unknown> = { ...loaded.facts, ...(extraFacts ?? {}) };
    const data: PolicyData = {
      policy: loaded.policy,
      governance: {
        adminDids,
        thresholdM: loaded.thresholdM,
        thresholdN: loaded.thresholdN,
      },
      memberships: memberRows,
      subjectIsCommunityMember,
      ...(Object.keys(facts).length > 0 ? { facts } : {}),
    };

    return this.toGovernanceResult(this.policyEngine.evaluate(query, data));
  }



  /**
   * Credential issuance is a thin specialisation of `authorize()`.
   *
   * Kept as a named method because `validateCredentialIssuance` reads better for it,
   * and because it fixes the action and the actor for that call. The fact assembly
   * lives in `authorize()` — there is exactly one implementation of it now.
   */
  private async evaluateAuthorization(input: {
    kind: string;
    issuerDid: string;
    subjectDid: string;
    governanceDid: string;
  }): Promise<GovernanceResult> {
    return this.authorize({
      action: 'issue_credential',
      communityDid: input.governanceDid,
      actorDid: input.issuerDid,
      params: { kind: input.kind, subjectDid: input.subjectDid },
    });
  }

  // ═══════════════════════════════════════════════════════════════
  // Crypto helpers
  // ═══════════════════════════════════════════════════════════════

  /** Resolve an Ed25519 public key for a given DID from the app DB. */
  /**
   * Every Ed25519 public key registered for the identity behind `did`.
   *
   * An identity can hold MORE THAN ONE — its authoritative `did:scid:vh` key AND the
   * `did:peer:4` relationship-handshake stub's, both at `rotation_version` 0 — while
   * `findByIdentityUuid` orders only by `(key_type, rotation_version)`. "The first Ed25519
   * key" is therefore arbitrary, and resolving to it silently rejects valid signatures.
   */
  private async resolvePublicKeys(did: string): Promise<Uint8Array[]> {
    // 1. Find identity by DID
    const idRow = await this.appDb.get<{ uuid: string }>(
      `SELECT i.uuid FROM identities i JOIN did_documents d ON d.identity_uuid = i.uuid
        WHERE d.did = ?`, did);
    if (!idRow) return [];
    // 2. Every Ed25519 key it holds
    return findEd25519KeysByIdentity(this.appDb, idRow.uuid);
  }
}
