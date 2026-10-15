// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The trust-task CATALOG — the parsed shapes of a step and a ceremony, and the
 * CODE-side executor registry.
 *
 * Definitions live in the DB (`trust_task_templates` / `ceremony_templates`);
 * their EXECUTORS live here in code. A step is 'policy' (a gate whose decision is
 * itself a loggable step) or 'effect' (an action dispatched through the 2PC
 * coordinator). A ceremony steps through a shared `threadId`, stacking via
 * `{ ceremony }` and iterating via `repeat`.
 */

import type { PolicyAction, PolicyCheck, PolicyDecision } from '../policy-engine.js';

/**
 * What a step IS, and therefore how the driver treats it.
 *
 *  - `policy`      — a gate: the driver asks the authorizer and logs the decision.
 *  - `effect`      — work: the driver runs the registered executor.
 *  - `coordination`— a ceremony-lifecycle event (`ceremony_begin` / `ceremony_approve`)
 *                    RECORDED by its owner, never driven. It exists as a catalog row so
 *                    its display wording lives in the database with everything else; a
 *                    ceremony must never execute one (the driver refuses).
 */
export type StepKind = 'policy' | 'effect' | 'coordination';

/** Default change-approval scope for an atomic rule (a binding may override it). */
export interface RuleChangeApproval {
  /** 'admins' = all admin/founding_admin (default); 'members' = any N members;
   *  'all_members' = every active member. */
  scope: 'admins' | 'members' | 'all_members';
  /** Required only when `scope === 'members'`. */
  minApprovals?: number;
}

/** A parameter slot a binding may fill for an atomic rule. */
export interface RuleParamSpec {
  type: 'number' | 'string' | 'boolean';
  default?: unknown;
  description?: string;
}

/**
 * The parsed `template` JSON of a `trust_task_templates` row.
 *
 * A `family='rule'` row is an ATOMIC policy rule: it carries the full rule body
 * (`when`/`require`/`decision`) so the rule is definable, versioned and replicated
 * as a first-class catalog artifact rather than an element of a single per-community
 * settings record. `GovernanceGuard` evaluates these via the same
 * `LocalPolicyEngine`; `community_policy_bindings` records which rules apply to a
 * community and with which parameters.
 */
export interface TrustTaskStepTemplate {
  name: string;
  kind: StepKind;
  /**
   * The PolicyActions measure. For 'policy' steps it is what authorize() checks;
   * for 'effect' steps it is the audit action performed. */
  action: string;
  // ── Atomic rule body (policy rules only) ────────────────────────────────
  /** Selector: which (action, kind) this rule applies to. */
  when?: { action?: PolicyAction; kind?: string };
  /** Conditions, implicitly ANDed, over the policy fact catalogue. */
  require?: PolicyCheck[];
  /** The decision when the selector + conditions match. */
  decision?: PolicyDecision;
  /** Community kinds this rule applies to. Omitted = both 'vtc' and 'vtn'. */
  roles?: Array<'vtc' | 'vtn'>;
  /** Parameter slots a community binding may fill. */
  params?: Record<string, RuleParamSpec>;
  /** Default approval scope for changing THIS rule. */
  changeApproval?: RuleChangeApproval;
  // ── Effect steps ────────────────────────────────────────────────────────
  /** 'effect' only — the Operation.op dispatched to the participant. */
  operation?: string;
  /** 'effect' only — the participant pid that executes the operation. */
  participant?: string;
  /** Optional JSON-Schema-ish payload shape. */
  payloadSchema?: unknown;
}

/** One element of a ceremony's `steps` array. */
export interface CeremonyStepRef {
  /** Reference to a leaf step's `type`. */
  step?: string;
  /** Reference to a nested (stacked) ceremony's `name`. */
  ceremony?: string;
  /** Iteration directive: 'once' (default) | a static collection name |
   *  a `$<stepType>[#<dot.path>]` reference into an earlier step's output
   *  (e.g. `$task:p2pts:vtc:establish:0.1#foundingAdmins`). */
  repeat?: string;
}

/** The parsed `template` JSON of a `ceremony_templates` row. */
export interface CeremonyDefinition {
  steps: CeremonyStepRef[];
}

// ── Display wording: the `display` COLUMN, never the `template` ───────────────
//
// `template` is the trust-task DEFINITION and stays aligned with the trust-task
// structure, so presentation data lives in its own column instead. That keeps the two
// concerns separable: an interoperable document, and the words a reader sees.

/** A step's reader-facing wording, parsed from the `display` column. */
export interface StepDisplay {
  label?: string;
  request?: string;
  response?: string;
}

/** A ceremony's reader-facing wording, parsed from the `display` column. */
export interface CeremonyDisplay {
  label?: string;
  description?: string;
}

/**
 * Parse a step's `display` column; null when the row has no wording.
 *
 * `undefined` means the COLUMN IS MISSING — a database created before it existed, whose
 * `0019` has already been applied (the ledger keys on filename, so adding a column to an
 * applied migration does NOT reach it). Fail loudly and say what to do, rather than
 * letting `JSON.parse(undefined)` surface as an inscrutable parse error.
 */
export function parseStepDisplay(json: string | null | undefined): StepDisplay | null {
  if (json === undefined) throw new Error(MISSING_DISPLAY_COLUMN);
  return json === null ? null : (JSON.parse(json) as StepDisplay);
}

/** Parse a ceremony's `display` column; null when the row has no wording. */
export function parseCeremonyDisplay(json: string | null | undefined): CeremonyDisplay | null {
  if (json === undefined) throw new Error(MISSING_DISPLAY_COLUMN);
  return json === null ? null : (JSON.parse(json) as CeremonyDisplay);
}

const MISSING_DISPLAY_COLUMN =
  'the `display` column is missing from trust_task_templates / ceremony_templates — this ' +
  'database was created BEFORE that column existed, and an applied migration is never ' +
  're-run. There is no production data yet: recreate the database from the migrations.';

/** Parse a raw `template` JSON column into the typed step template. */
export function parseStepTemplate(json: string): TrustTaskStepTemplate {
  return JSON.parse(json) as TrustTaskStepTemplate;
}

/** Parse a raw `template` JSON column into the typed ceremony definition. */
export function parseCeremonyDefinition(json: string): CeremonyDefinition {
  return JSON.parse(json) as CeremonyDefinition;
}

/** An effect step's executor. Receives the thread/step context. */
export type StepExecutor = (context: Record<string, unknown>) => Promise<unknown>;

const executors = new Map<string, StepExecutor>();

/** Register the executor for a step `type`. Executors are code, never DB. */
export function registerExecutor(type: string, executor: StepExecutor): void {
  executors.set(type, executor);
}

/** Resolve the executor for a step `type`, or undefined when not registered. */
export function resolveExecutor(type: string): StepExecutor | undefined {
  return executors.get(type);
}
