/**
 * governance-change — Phase B core: the model for a community rule/threshold change
 * and the CONSENT it needs.
 *
 * A change is proposed by an admin and APPLIED only once enough of the community has
 * consented. "Enough" is the setting's **approval scope**:
 *
 *   - `admins`       — every active admin/founding_admin (the DEFAULT),
 *   - `all_members`  — every active member,
 *   - `members`      — any active members, at least `minApprovals`.
 *
 * Scope resolution lives here (pure, testable); the durable proposal lifecycle lives in
 * `src/tx/governance-change-store.ts`; the enforcement (Ed25519 verification + distinct
 * verified count) lives in the server participant. This module is the single home for
 * "who must agree", so no route or participant re-derives it.
 */

import { sha256 } from '../crypto/primitives.js';

/** Who must consent to a change (configurable per setting). */
export type ApprovalScope = 'admins' | 'members' | 'all_members';

/** The scope + (for `members`) the minimum count. */
export interface ApprovalScopeSpec {
  scope: ApprovalScope;
  minApprovals?: number;
}

/** A binding-level operation within a change. */
export interface BindingOp {
  op: 'add' | 'remove' | 'update';
  /** The catalog rule type the binding references. */
  ruleType: string;
  enabled?: boolean;
  params?: Record<string, unknown>;
}

/** The full set of changes a governance-change proposal applies on crystallization. */
export interface GovernanceChange {
  /** New admin quorum values (optional). */
  adminThresholdM?: number;
  adminThresholdN?: number;
  /** Binding operations (optional). */
  bindings?: BindingOp[];
}

/** The community roster the scope resolves against (active rows only). */
export interface ChangeScopeContext {
  /** Active `admin` / `founding_admin` member identity uuids. */
  adminUuids: string[];
  /** All active member identity uuids (superset of `adminUuids`). */
  memberUuids: string[];
}

/** The resolved approver requirement for a change. */
export interface ResolvedApprovers {
  scope: ApprovalScope;
  /** Distinct approvers required for crystallization. */
  requiredCount: number;
  /** The eligible approver set (identity uuids) captured at `begin` time. */
  eligibleUuids: string[];
}

/**
 * The proposal view the agent / Rules UI consumes — whether read from the utility
 * server (`gov_change_pending_for`) or from the local mirror the durable
 * `exchange:governance-proposal` fan-out maintains.
 */
export interface GovernanceChangeProposalView {
  proposalId: string;
  communityUuid: string;
  communityDid: string;
  scope: ApprovalScope;
  requiredApproverCount: number;
  /** Signatures RECORDED so far (server read only; absent on the offline local mirror). */
  approvalCount?: number;
  /**
   * How many of those actually VERIFY — the number that decides crystallization. Present
   * only on the server read: a recorded signature whose key this server cannot resolve never
   * reaches the quorum, and without this the UI can only say "awaiting others" forever.
   */
  verifiedApproverCount?: number;
  proposalHash: string;
  change: GovernanceChange;
  expiresAt: number;
}

/** Resolve `spec` against the community roster into a concrete approver requirement. */
export function resolveRequiredApprovers(
  spec: ApprovalScopeSpec,
  ctx: ChangeScopeContext,
): ResolvedApprovers {
  const admins = [...new Set(ctx.adminUuids)];
  const members = [...new Set(ctx.memberUuids)];

  switch (spec.scope) {
    case 'all_members':
      return { scope: 'all_members', requiredCount: members.length, eligibleUuids: members };
    case 'members': {
      const min = Math.max(1, Math.floor(spec.minApprovals ?? 1));
      return {
        scope: 'members',
        requiredCount: Math.min(min, members.length),
        eligibleUuids: members,
      };
    }
    case 'admins':
    default:
      return { scope: 'admins', requiredCount: admins.length, eligibleUuids: admins };
  }
}

/** Deterministic JSON (sorted top-level keys) so the hash is independent of key order. */
function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`;
}

/**
 * The proposal hash every approver signs — a commitment to the community, the proposer,
 * the exact change, the scope, the eligible set and the expiry. Changing any of these
 * changes the hash, so an approval can never be replayed onto a different proposal.
 */
export function computeChangeProposalHash(input: {
  proposalId: string;
  communityUuid: string;
  proposerUuid: string;
  change: GovernanceChange;
  scope: ApprovalScope;
  requiredApproverUuids: string[];
  expiresAt: number;
}): string {
  const canonical = canonicalize({
    proposalId: input.proposalId,
    communityUuid: input.communityUuid,
    proposerUuid: input.proposerUuid,
    change: input.change,
    scope: input.scope,
    requiredApproverUuids: [...input.requiredApproverUuids].sort(),
    expiresAt: input.expiresAt,
  });
  return Buffer.from(sha256(new TextEncoder().encode(canonical))).toString('base64');
}
