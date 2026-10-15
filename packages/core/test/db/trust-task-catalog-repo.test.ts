// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import * as catalogRepo from '../../src/db/repositories/trust-task-catalog-repo.js';
import {
  parseStepTemplate,
  parseCeremonyDefinition,
  parseStepDisplay,
  parseCeremonyDisplay,
  registerExecutor,
  resolveExecutor,
} from '../../src/services/trust-tasks/catalog.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

function open() {
  const db = new SqliteDataSource(':memory:');
  runMigrations(db.getRawDb(), MIGRATIONS_DIR);
  return db;
}

test('the catalog seed lands: steps are queryable by type and parseable', async () => {
  const db = open();
  const steps = await catalogRepo.listSteps(db);
  // 9 ceremony steps + 2 coordination events (0019/0020/0022) + 17 atomic rule
  // templates (0021).
  assert.equal(steps.length, 28);
  assert.equal(steps.filter((s) => s.family === 'rule').length, 17);

  const effect = await catalogRepo.findStepByType(db, 'task:p2pts:vtc:establish:0.1');
  assert.ok(effect);
  const tpl = parseStepTemplate(effect.template);
  assert.equal(tpl.kind, 'effect');
  assert.equal(tpl.action, 'crystallize_ceremony');
  assert.equal(tpl.operation, 'ceremony_crystallize');

  const gate = await catalogRepo.findStepByType(db, 'task:p2pts:policy:membership-vmc-authorized:0.1');
  assert.equal(parseStepTemplate(gate!.template).kind, 'policy');
});

test('a ceremony resolves to its ordered steps, including the output-fed repeat directive', async () => {
  const db = open();
  const ceremony = await catalogRepo.findCeremonyByName(db, 'vtc-establish');
  assert.ok(ceremony);
  const def = parseCeremonyDefinition(ceremony.template);
  assert.equal(def.steps.length, 2);
  assert.equal(def.steps[0].step, 'task:p2pts:vtc:establish:0.1');
  assert.equal(def.steps[1].step, 'task:p2pts:credential:membership-vmc:0.1');
  assert.equal(def.steps[1].repeat, '$task:p2pts:vtc:establish:0.1#foundingAdmins');
});

test('the executor registry round-trips a code-side handler', () => {
  registerExecutor('task:p2pts:vtc:establish:0.1', async () => ({ ok: true }));
  assert.equal(typeof resolveExecutor('task:p2pts:vtc:establish:0.1'), 'function');
  assert.equal(resolveExecutor('task:p2pts:does-not-exist:0.1'), undefined);
});

test('the 0019 seed declares the member-onboarding and vrc-personhood ceremonies', async () => {
  const db = open();

  const names = (await catalogRepo.listCeremonies(db)).map((c) => c.name).sort();
  assert.deepEqual(
    names,
    ['governance-change', 'member-invitation', 'member-onboarding', 'vrc-personhood', 'vtc-establish'],
  );

  // member-onboarding: gate (issue_credential) → mint.
  const onboarding = parseCeremonyDefinition(
    (await catalogRepo.findCeremonyByName(db, 'member-onboarding'))!.template,
  );
  assert.deepEqual(
    onboarding.steps.map((s) => s.step),
    ['task:p2pts:policy:membership-vmc-authorized:0.1', 'task:p2pts:credential:onboarding-vmc:0.1'],
  );

  // vrc-personhood: effect-only (its gate is the mutual personhood ack).
  const personhood = parseCeremonyDefinition(
    (await catalogRepo.findCeremonyByName(db, 'vrc-personhood'))!.template,
  );
  assert.deepEqual(
    personhood.steps.map((s) => s.step),
    ['task:p2pts:credential:relationship-vrc:0.1'],
  );

  // The gate is a `policy` step whose action is the governing action.
  const gate = await catalogRepo.findStepByType(db, 'task:p2pts:policy:membership-vmc-authorized:0.1');
  const gateTpl = parseStepTemplate(gate!.template);
  assert.equal(gateTpl.kind, 'policy');
  assert.equal(gateTpl.action, 'issue_credential');

  // The two new effect steps exist and are effects.
  assert.equal(
    parseStepTemplate((await catalogRepo.findStepByType(db, 'task:p2pts:credential:onboarding-vmc:0.1'))!.template).kind,
    'effect',
  );
  assert.equal(
    parseStepTemplate((await catalogRepo.findStepByType(db, 'task:p2pts:credential:relationship-vrc:0.1'))!.template).kind,
    'effect',
  );
});

test('the 0019 seed declares the member-invitation ceremony (gate → mint the VIC)', async () => {
  const db = open();

  const invitation = parseCeremonyDefinition(
    (await catalogRepo.findCeremonyByName(db, 'member-invitation'))!.template,
  );
  assert.deepEqual(
    invitation.steps.map((s) => s.step),
    [
      'task:p2pts:policy:invitation-vic-authorized:0.1',
      'task:p2pts:credential:invitation-vic:0.1',
    ],
  );

  // The gate's action is the one the baseline `vic-issue` rule selects on, and the
  // effect step mints the credential.
  const gate = await catalogRepo.findStepByType(db, 'task:p2pts:policy:invitation-vic-authorized:0.1');
  const gateTpl = parseStepTemplate(gate!.template);
  assert.equal(gateTpl.kind, 'policy');
  assert.equal(gateTpl.action, 'issue_credential');

  const mint = await catalogRepo.findStepByType(db, 'task:p2pts:credential:invitation-vic:0.1');
  const mintTpl = parseStepTemplate(mint!.template);
  assert.equal(mintTpl.kind, 'effect');
  assert.equal(mintTpl.action, 'issue_credential');
  assert.equal(mintTpl.operation, 'mint_invitation_vic');
});

test('an atomic rule template carries its rule body (when/require/decision)', async () => {
  const db = open();
  const row = await catalogRepo.findStepByType(db, 'task:p2pts:rule:update-governance:0.1');
  assert.ok(row);
  assert.equal(row.family, 'rule');

  const tpl = parseStepTemplate(row.template);
  assert.equal(tpl.kind, 'policy');
  assert.equal(tpl.action, 'update_governance');
  assert.equal(tpl.when?.action, 'update_governance');
  assert.equal((tpl.require?.[0] as { fact?: string } | undefined)?.fact, 'actor_is_admin');
  assert.equal(tpl.decision?.decision, 'allow');
  assert.equal(tpl.changeApproval?.scope, 'admins');
});

test('a community_policy_bindings row (Phase A schema) references a rule type', async () => {
  const db = open();
  await db.run(
    `INSERT INTO community_policy_bindings
       (uuid, community_identity_uuid, rule_type, enabled, change_approval, updated_at)
     VALUES (?, ?, ?, 1, ?, 0)`,
    'b0000000-0000-4000-8000-000000000001',
    'c0000000-0000-4000-8000-000000000001',
    'task:p2pts:rule:update-governance:0.1',
    '{"scope":"all_members"}',
  );

  const row = await db.get<{ rule_type: string; enabled: number; change_approval: string }>(
    'SELECT rule_type, enabled, change_approval FROM community_policy_bindings WHERE community_identity_uuid = ?',
    'c0000000-0000-4000-8000-000000000001',
  );
  assert.ok(row);
  assert.equal(row.rule_type, 'task:p2pts:rule:update-governance:0.1');
  assert.equal(row.enabled, 1);
  assert.equal(JSON.parse(row.change_approval).scope, 'all_members');
});

/**
 * NOT every catalog row is a ceremony step, and it matters which is which.
 *
 *  - `family='rule'` rows are atomic policy-rule BODIES. They are applied by the policy
 *    guard (resolved from `community_policy_bindings` — see src/services/policy-bindings.ts)
 *    at decision time. They are never "run" by a ceremony.
 *  - `family='ceremony'` rows are ceremony COORDINATION events (`ceremony:propose`,
 *    `ceremony:co-sign`). The ceremony coordinator RECORDS them; the driver never runs
 *    one. They exist as catalog rows so their display wording lives in the database with
 *    everything else.
 *  - Every OTHER row IS a step, and must be reachable from some `ceremony_templates`
 *    entry. An unreferenced step is dead weight that makes the catalogue look like it
 *    governs more than it does.
 */
const NON_STEP_FAMILIES = ['rule', 'ceremony'];

test('every non-rule catalog template is reachable from a ceremony (no orphan steps)', async () => {
  const db = open();
  const steps = await catalogRepo.listSteps(db);
  const ceremonies = await catalogRepo.listCeremonies(db);

  // Expand every ceremony's step refs to the leaf types it runs, recording which
  // ceremonies reference each type.
  const usage: Record<string, string[]> = {};
  for (const ceremony of ceremonies) {
    for (const ref of parseCeremonyDefinition(ceremony.template).steps) {
      if (!ref.step) continue;
      (usage[ref.step] ??= []).push(ceremony.name);
    }
  }

  const orphans = steps
    .filter((s) => !NON_STEP_FAMILIES.includes(s.family))
    .filter((s) => !usage[s.type])
    .map((s) => s.type);
  assert.deepEqual(
    orphans,
    [],
    `catalog steps no ceremony references (wire them into a ceremony, or delete them): ${orphans.join(', ')}`,
  );

  // The exact ceremony → step map. Changing any ceremony MUST update this test.
  // NB: `vtc-establish` runs exactly TWO step types — there is no `policy:` gate
  // (the founding flow is validated inside the establish effect step), and the
  // `rule`/`governance` families are NOT involved in VTC creation.
  assert.deepEqual(usage, {
    'task:p2pts:vtc:establish:0.1': ['vtc-establish'],
    'task:p2pts:credential:membership-vmc:0.1': ['vtc-establish'],
    'task:p2pts:policy:membership-vmc-authorized:0.1': ['member-onboarding'],
    'task:p2pts:credential:onboarding-vmc:0.1': ['member-onboarding'],
    'task:p2pts:credential:relationship-vrc:0.1': ['vrc-personhood'],
    'task:p2pts:policy:governance-change-authorized:0.1': ['governance-change'],
    'task:p2pts:governance:apply-change:0.1': ['governance-change'],
    'task:p2pts:policy:invitation-vic-authorized:0.1': ['member-invitation'],
    'task:p2pts:credential:invitation-vic:0.1': ['member-invitation'],
  });

  // Six families, two of which (`rule`, `ceremony`) are not ceremony steps.
  assert.deepEqual(
    [...new Set(steps.map((s) => s.family))].sort(),
    ['ceremony', 'credential', 'governance', 'policy', 'rule', 'vtc'],
  );
});

/**
 * The UI has no label table: every piece of wording it shows comes from the catalog. This
 * pins that, so a future ceremony cannot ship with display text only in a web page.
 */
test('step and ceremony wording lives in the `display` COLUMN (the UI has no label table)', async () => {
  const db = open();

  // A step carries its label plus a sentence for each direction — in `display`…
  const inviteRow = (await catalogRepo.findStepByType(db, 'task:p2pts:credential:invitation-vic:0.1'))!;
  const invite = parseStepDisplay(inviteRow.display)!;
  assert.equal(invite.label, 'Issue the signed invitation (VIC)');
  assert.match(String(invite.request), /^Began issuing the signed invitation/);
  assert.match(String(invite.response), /Invitation credential issued/);

  // …and its `template` is a PURE trust-task document: presentation data must NOT leak
  // into it, because that column stays aligned with the trust-task structure.
  const inviteTemplate = parseStepTemplate(inviteRow.template);
  assert.equal(
    (inviteTemplate as Record<string, unknown>).label, undefined,
    'template must not carry presentation data',
  );
  assert.equal((inviteTemplate as Record<string, unknown>).response, undefined);
  assert.equal(inviteTemplate.kind, 'effect');

  // The coordination events carry wording too, and are steps of no ceremony at all.
  const proposeRow = (await catalogRepo.findStepByType(db, 'task:p2pts:ceremony:propose:0.1'))!;
  assert.equal(parseStepTemplate(proposeRow.template).kind, 'coordination');
  const propose = parseStepDisplay(proposeRow.display)!;
  assert.equal(propose.label, 'Propose the community');
  assert.match(String(propose.request), /\{name\}/, 'the sentence carries its placeholders');

  // A ceremony carries its own title + description.
  const foundingRow = (await catalogRepo.findCeremonyByName(db, 'vtc-establish'))!;
  const foundingDisplay = parseCeremonyDisplay(foundingRow.display)!;
  assert.equal(foundingDisplay.label, 'Found a community (VTC / VTN)');
  assert.ok(foundingDisplay.description);
  assert.deepEqual(
    Object.keys(parseCeremonyDefinition(foundingRow.template)),
    ['steps'],
    'a ceremony template holds its steps and nothing else',
  );

  // EVERY displayed row has wording. A gap here means the UI would fall back to a raw
  // `task:p2pts:…` identifier for that step.
  const missing = (await catalogRepo.listSteps(db))
    .filter((s) => s.family !== 'rule') // rule bodies are never displayed as steps
    .filter((s) => {
      const display = parseStepDisplay(s.display);
      return !display?.label || !display.request || !display.response;
    })
    .map((s) => s.type);
  assert.deepEqual(missing, [], `catalog rows with no display wording: ${missing.join(', ')}`);

  const ceremoniesMissing = (await catalogRepo.listCeremonies(db))
    .filter((c) => {
      const display = parseCeremonyDisplay(c.display);
      return !display?.label || !display.description;
    })
    .map((c) => c.name);
  assert.deepEqual(ceremoniesMissing, [], `ceremonies with no label/description: ${ceremoniesMissing.join(', ')}`);
});


