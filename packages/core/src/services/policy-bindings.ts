/**
 * policy-bindings — Phase A of the modular policy model.
 *
 * Tier 2 of the two-tier model (see docs/10_ModularPolicy-catalog-plan.md): the
 * `community_policy_bindings` table records WHICH catalog rule templates
 * (`trust_task_templates`, `family='rule'`) apply to a community, with which
 * parameters and which change-approval scope. This module resolves those bindings
 * into the `PolicyRuleV2[]` the (unchanged) `LocalPolicyEngine` evaluates, plus the
 * parameter facts a rule body may reference via `valueFact`.
 *
 * The rule DEFINITION lives in the catalog (global, versioned, replicated); the
 * per-community APPLICATION lives in the bindings. `GovernanceGuard` evaluates the
 * binding-derived rules through the unchanged `LocalPolicyEngine` — there is no
 * stored policy document and no fallback source.
 */

import type { DataSource } from '../db/data-source.js';
import type { PolicyCheck, PolicyDecision, PolicyRuleV2 } from './policy-engine.js';
import { parseStepTemplate } from './trust-tasks/catalog.js';
import { generateUuid } from '../db/uuid-helpers.js';

/** The rules + parameter facts a community's bindings resolve to. */
export interface ResolvedCommunityPolicy {
  rules: PolicyRuleV2[];
  /** Merged parameter facts (template defaults overlaid by binding values). */
  facts: Record<string, unknown>;
}

interface BindingRow {
  rule_type: string;
  enabled: number;
  params: string | null;
  priority: number | null;
}

interface TemplateRow {
  type: string;
  template: string;
}

/**
 * Derive a stable rule id from its catalog type.
 * `task:p2pts:rule:update-governance:0.1` → `update-governance`. Falls back to the
 * whole type when it does not match the `rule` namespace shape.
 */
export function ruleIdFromType(ruleType: string): string {
  const m = /^task:p2pts:rule:(.+):[^:]+$/.exec(ruleType);
  return m ? m[1] : ruleType;
}

/** Parse a JSON object column; a non-object / unparseable value yields `{}`. */
function safeParseObject(json: string | null): Record<string, unknown> {
  if (!json) return {};
  try {
    const v = JSON.parse(json);
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/**
 * Resolve a community's policy bindings into rules + parameter facts.
 *
 * Always returns a set — rules come from the bindings alone. A community with no
 * bindings yields `{ rules: [], facts: {} }`, so the policy default applies
 * (fail-closed). There is no second rule source.
 *
 * A binding whose `rule_type` is absent from the catalog, not a `policy` rule, or
 * disabled contributes nothing (a dangling binding is ignored, never guessed).
 */
export async function resolveCommunityRules(
  db: DataSource,
  communityUuid: string,
): Promise<ResolvedCommunityPolicy> {
  const rows = await db.all<BindingRow>(
    `SELECT rule_type, enabled, params, priority
       FROM community_policy_bindings
      WHERE community_identity_uuid = ?
      ORDER BY (priority IS NULL), priority, rule_type`,
    communityUuid,
  );

  const rules: PolicyRuleV2[] = [];
  const facts: Record<string, unknown> = {};

  for (const row of rows) {
    if (!row.enabled) continue;

    const tplRow = await db.get<TemplateRow>(
      `SELECT type, template FROM trust_task_templates WHERE type = ? AND family = 'rule'`,
      row.rule_type,
    );
    if (!tplRow) continue;

    const tpl = parseStepTemplate(tplRow.template);
    if (tpl.kind !== 'policy' || !tpl.decision) continue;

    // Parameter facts: the template's declared defaults, overlaid by the binding's
    // own values. These reach the engine through `PolicyData.facts`.
    const defaults: Record<string, unknown> = {};
    if (tpl.params) {
      for (const [key, spec] of Object.entries(tpl.params)) {
        if (spec && typeof spec === 'object' && Object.prototype.hasOwnProperty.call(spec, 'default')) {
          defaults[key] = (spec as { default?: unknown }).default;
        }
      }
    }
    const bindingParams = safeParseObject(row.params);
    for (const [key, value] of Object.entries({ ...defaults, ...bindingParams })) {
      facts[key] = value;
    }

    rules.push({
      id: ruleIdFromType(row.rule_type),
      ...(tpl.when ? { when: tpl.when } : {}),
      ...(tpl.require ? { require: tpl.require as PolicyCheck[] } : {}),
      decision: tpl.decision as PolicyDecision,
      ...(row.priority !== null && row.priority !== undefined ? { priority: row.priority } : {}),
    });
  }

  return { rules, facts };
}

// ── Claim-type + child-kind readers (the "metadata as bindings" concern) ──────

/** The catalog type for a claim-type marker binding (params.claim_type). */
export const CLAIM_TYPE_ALLOW_TYPE = 'task:p2pts:rule:claim-type-allow:0.1';
/** The catalog type for the parent child-kind rule (its binding carries the kinds). */
export const PARENT_ACCEPTS_CHILD_TYPE = 'task:p2pts:rule:parent-accepts-child:0.1';

/**
 * The community's allowed claim types — the `claim_type` params of its
 * `claim-type-allow` bindings (one binding per permitted type, distinguished by a
 * `#<type>` suffix on the rule_type so the UNIQUE(community, rule_type) key holds).
 */
export async function resolveCommunityClaimTypes(
  db: DataSource,
  communityUuid: string,
): Promise<string[]> {
  const rows = await db.all<{ params: string | null }>(
    `SELECT params FROM community_policy_bindings
      WHERE community_identity_uuid = ? AND enabled = 1 AND rule_type LIKE ?`,
    communityUuid, `${CLAIM_TYPE_ALLOW_TYPE}#%`,
  );
  const types = new Set<string>();
  for (const r of rows) {
    const ct = safeParseObject(r.params).claim_type;
    if (typeof ct === 'string' && ct.length > 0) types.add(ct);
  }
  return [...types];
}

/**
 * The child kinds a parent VTN permits — the `allowed_child_kinds` param of its
 * `parent-accepts-child` binding. `null` means "declares nothing" (unrestricted).
 */
export async function resolveCommunityChildKinds(
  db: DataSource,
  communityUuid: string,
): Promise<string[] | null> {
  const row = await db.get<{ params: string | null }>(
    `SELECT params FROM community_policy_bindings
      WHERE community_identity_uuid = ? AND rule_type = ? AND enabled = 1`,
    communityUuid, PARENT_ACCEPTS_CHILD_TYPE,
  );
  if (!row) return null;
  const kinds = safeParseObject(row.params).allowed_child_kinds;
  if (!Array.isArray(kinds) || !kinds.every((k) => typeof k === 'string')) return null;
  // An empty list means "declares nothing" (unrestricted), not "allows no kind".
  return kinds.length > 0 ? (kinds as string[]) : null;
}

/**
 * Write the DEFAULT binding set for a newly created community: every baseline
 * catalog rule applicable to `kind`, plus one claim-type binding per permitted claim
 * type, plus (for a parent VTN) the declared child-kind restriction.
 */
export async function seedDefaultBindings(
  db: DataSource,
  communityUuid: string,
  kind: 'vtc' | 'vtn',
  opts: { allowedClaimTypes?: string[]; allowedChildKinds?: string[] } = {},
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const rules = await db.all<{ type: string; template: string }>(
    `SELECT type, template FROM trust_task_templates WHERE family = 'rule'`,
  );

  for (const r of rules) {
    // Claim-type markers are seeded per declared type below, never generically.
    if (r.type === CLAIM_TYPE_ALLOW_TYPE) continue;
    const tpl = parseStepTemplate(r.template);
    if (tpl.roles && !tpl.roles.includes(kind)) continue;

    const params = r.type === PARENT_ACCEPTS_CHILD_TYPE
      ? JSON.stringify({ allowed_child_kinds: opts.allowedChildKinds ?? [] })
      : null;

    await db.run(
      `INSERT INTO community_policy_bindings
         (uuid, community_identity_uuid, rule_type, enabled, params, updated_at)
       VALUES (?, ?, ?, 1, ?, ?)
       ON CONFLICT (community_identity_uuid, rule_type) DO NOTHING`,
      generateUuid(), communityUuid, r.type, params, now,
    );
  }

  for (const claimType of opts.allowedClaimTypes ?? []) {
    await db.run(
      `INSERT INTO community_policy_bindings
         (uuid, community_identity_uuid, rule_type, enabled, params, updated_at)
       VALUES (?, ?, ?, 1, ?, ?)`,
      generateUuid(), communityUuid, `${CLAIM_TYPE_ALLOW_TYPE}#${claimType}`,
      JSON.stringify({ claim_type: claimType }), now,
    );
  }
}
