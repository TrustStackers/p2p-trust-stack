-- 0019_trust_task_catalog.sql
-- The authoritative catalog of trust-task STEP and CEREMONY definitions.
--
-- A STEP is one task type: `kind` = 'policy' (a gate that must ALLOW), 'effect' (an
-- executable action), or 'coordination' (a ceremony-lifecycle event that is RECORDED,
-- never driven). A CEREMONY is an ordered group of step references.
--
-- TWO COLUMNS, TWO PURPOSES — do not mix them:
--   template — the trust-task DEFINITION, in the interoperable trust-task shape. It is
--              the authoritative/executable document and stays aligned with the
--              trust-task structure. It carries NO presentation data.
--   display  — the reader-facing WORDING for the UI, as JSON: a step's
--              {label, request, response}; a ceremony's {label, description}. Both the
--              agent app and the utility UI render this, so adding a ceremony needs no
--              UI change. `{placeholder}` slots are filled from a step's recorded
--              payload by the presentation layer.
--
-- `type`/`family`/`version` (and `name` for ceremonies) are indexed columns for lookup.
-- Executors are registered in CODE (src/services/trust-tasks/catalog.ts), never here.
--
-- Seed rows are single-line idempotent INSERTs (ON CONFLICT … DO NOTHING) so a re-apply
-- is a no-op; identifiers match src/services/trust-tasks/type-uris.ts.
--
-- NOTE (there is no production database yet): every seed for these two tables lives in
-- THIS file, the migration that creates them. Do not add insert-only migrations.

CREATE TABLE IF NOT EXISTS trust_task_templates (
  uuid              TEXT PRIMARY KEY,
  type              TEXT UNIQUE NOT NULL,
  family            TEXT NOT NULL,
  version           TEXT NOT NULL,
  template          TEXT NOT NULL,   -- JSON: the trust-task definition
  display           TEXT,            -- JSON: {label, request, response} for the UI
  recorded_by_node  TEXT,
  replicated_at     INTEGER,
  created_at        INTEGER,
  updated_at        INTEGER
);

CREATE INDEX IF NOT EXISTS idx_trust_task_templates_family ON trust_task_templates(family);

CREATE TABLE IF NOT EXISTS ceremony_templates (
  uuid              TEXT PRIMARY KEY,
  name              TEXT UNIQUE NOT NULL,
  version           TEXT NOT NULL,
  template          TEXT NOT NULL,   -- JSON: {steps:[…]}
  display           TEXT,            -- JSON: {label, description} for the UI
  recorded_by_node  TEXT,
  replicated_at     INTEGER,
  created_at        INTEGER,
  updated_at        INTEGER
);

-- ── Steps: the founding ceremony ────────────────────────────────────────────
INSERT INTO trust_task_templates (uuid, type, family, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000002','task:p2pts:vtc:establish:0.1','vtc','0.1','{"name":"Establish VTC","kind":"effect","action":"crystallize_ceremony","operation":"ceremony_crystallize","participant":"server:us-1"}','{"label":"Create the community","request":"Began creating the community.","response":"Community created."}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000003','task:p2pts:policy:membership-vmc-authorized:0.1','policy','0.1','{"name":"Authorize membership VMC issuance","kind":"policy","action":"issue_credential"}','{"label":"Policy check — may this membership credential be issued?","request":"Asked the community policy whether this membership credential may be issued.","response":"Policy decision recorded."}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000004','task:p2pts:credential:membership-vmc:0.1','credential','0.1','{"name":"Issue membership VMC","kind":"effect","action":"issue_credential","operation":"mint_membership_vmc","participant":"server:us-1"}','{"label":"Record a founding membership credential","request":"Began recording the membership credential for this founding admin.","response":"Membership credential recorded."}','seed',0,0) ON CONFLICT (type) DO NOTHING;

-- ── Steps: member onboarding + peer personhood ──────────────────────────────
INSERT INTO trust_task_templates (uuid, type, family, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000005','task:p2pts:credential:onboarding-vmc:0.1','credential','0.1','{"name":"Issue onboarding VMC","kind":"effect","action":"issue_credential","operation":"mint_onboarding_vmc","participant":"server:us-1"}','{"label":"Issue the membership credential","request":"Began issuing the membership credential for this member.","response":"Membership credential issued."}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000006','task:p2pts:credential:relationship-vrc:0.1','credential','0.1','{"name":"Mint peer VRC","kind":"effect","action":"issue_credential","operation":"mint_peer_vrc","participant":"agent:vrc-ceremony"}','{"label":"Mint the mutual personhood credential","request":"Began minting the mutual personhood credential between two people.","response":"Personhood credential minted."}','seed',0,0) ON CONFLICT (type) DO NOTHING;

-- ── Steps: changing a community's governance ────────────────────────────────
INSERT INTO trust_task_templates (uuid, type, family, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000007','task:p2pts:policy:governance-change-authorized:0.1','policy','0.1','{"name":"Authorize a governance change","kind":"policy","action":"update_governance"}','{"label":"Policy check — may this governance change proceed?","request":"Asked the community policy whether this governance change is allowed.","response":"Policy decision recorded."}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000008','task:p2pts:governance:apply-change:0.1','governance','0.1','{"name":"Apply a governance change","kind":"effect","action":"update_governance","operation":"governance_change_apply","participant":"server:us-1"}','{"label":"Apply the governance change","request":"Began applying the approved governance change.","response":"Governance change applied."}','seed',0,0) ON CONFLICT (type) DO NOTHING;

-- ── Steps: the member-INVITATION ceremony (issuing a VIC) ────────────────────
-- An invitation is the community's authorization for ONE named prospective member to
-- onboard, so it is a ceremony rather than a side effect: a `policy` gate on the
-- community's `issue_credential` rule (the baseline `vic-issue` rule requires
-- `actor_is_admin`, which makes "only an admin may invite" a rule a community can change
-- rather than a hard-coded check), then an `effect` step that MINTS the signed credential
-- carrying the OOBI transport artifact. Executors stay in code
-- (utility-server/src/tx/ceremony-participant.ts).
INSERT INTO trust_task_templates (uuid, type, family, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000009','task:p2pts:policy:invitation-vic-authorized:0.1','policy','0.1','{"name":"Authorize issuing an invitation (VIC)","kind":"policy","action":"issue_credential"}','{"label":"Policy check — may this invitation be issued?","request":"Asked the community policy whether this person may be invited.","response":"Policy decision recorded."}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000010','task:p2pts:credential:invitation-vic:0.1','credential','0.1','{"name":"Issue a signed invitation (VIC)","kind":"effect","action":"issue_credential","operation":"mint_invitation_vic","participant":"server:us-1"}','{"label":"Issue the signed invitation (VIC)","request":"Began issuing the signed invitation for this person.","response":"Invitation credential issued — the person can now accept it."}','seed',0,0) ON CONFLICT (type) DO NOTHING;

-- ── Coordination events: RECORDED by the ceremony coordinator, never driven ──
-- They are not ceremony STEPS, but they appear in the task log beside the steps, so
-- their wording lives here with everything else. `kind: 'coordination'` is what tells
-- the driver it must never execute one.
INSERT INTO trust_task_templates (uuid, type, family, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000011','task:p2pts:ceremony:propose:0.1','ceremony','0.1','{"name":"Propose a community","kind":"coordination","action":"crystallize_ceremony"}','{"label":"Propose the community","request":"Proposed founding the community {name} ({kind}) with {adminCount} founding admin(s).","response":"Proposal recorded — waiting for {coSignaturesRequired} co-signature(s)."}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000012','task:p2pts:ceremony:co-sign:0.1','ceremony','0.1','{"name":"Co-sign a founding proposal","kind":"coordination","action":"crystallize_ceremony"}','{"label":"Accept being a founding admin (co-signature)","request":"Signed the proposal — accepting the role of founding admin.","response":"Co-signature verified — {coSignaturesReceived} of {coSignaturesRequired} admins have signed."}','seed',0,0) ON CONFLICT (type) DO NOTHING;

-- ── Ceremonies ──────────────────────────────────────────────────────────────
-- `vtc-establish` has NO `policy` gate: the founding flow is validated *inside* the
-- createVtc effect step (name uniqueness, human-VTA + endpoint + VRC + threshold), which
-- throws and rolls back the transaction. Its membership-vmc step fans out over what the
-- establish step produced (output-fed `$`-repeat), documenting each already-minted VMC.
INSERT INTO ceremony_templates (uuid, name, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000101','vtc-establish','0.1','{"steps":[{"step":"task:p2pts:vtc:establish:0.1"},{"step":"task:p2pts:credential:membership-vmc:0.1","repeat":"$task:p2pts:vtc:establish:0.1#foundingAdmins"}]}','{"label":"Found a community (VTC / VTN)","description":"A community exists only once every named founding admin has co-signed the proposal."}','seed',0,0) ON CONFLICT (name) DO NOTHING;
INSERT INTO ceremony_templates (uuid, name, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000102','member-onboarding','0.1','{"steps":[{"step":"task:p2pts:policy:membership-vmc-authorized:0.1"},{"step":"task:p2pts:credential:onboarding-vmc:0.1"}]}','{"label":"Onboard a member","description":"Issues a member membership credential once the community policy allows it."}','seed',0,0) ON CONFLICT (name) DO NOTHING;
INSERT INTO ceremony_templates (uuid, name, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000103','vrc-personhood','0.1','{"steps":[{"step":"task:p2pts:credential:relationship-vrc:0.1"}]}','{"label":"Establish personhood between two people (VRC)","description":"Mints the mutual personhood credential that two people each hold for the other."}','seed',0,0) ON CONFLICT (name) DO NOTHING;
INSERT INTO ceremony_templates (uuid, name, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000104','governance-change','0.1','{"steps":[{"step":"task:p2pts:policy:governance-change-authorized:0.1"},{"step":"task:p2pts:governance:apply-change:0.1"}]}','{"label":"Change community governance","description":"Applies an approved governance-rule change once the required admins have consented."}','seed',0,0) ON CONFLICT (name) DO NOTHING;
INSERT INTO ceremony_templates (uuid, name, version, template, display, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000105','member-invitation','0.1','{"steps":[{"step":"task:p2pts:policy:invitation-vic-authorized:0.1"},{"step":"task:p2pts:credential:invitation-vic:0.1"}]}','{"label":"Invite a person to join","description":"Issues a signed invitation (VIC) that authorizes one named person to onboard."}','seed',0,0) ON CONFLICT (name) DO NOTHING;

-- ── Atomic RULE templates (`family='rule'`) ──────────────────────────────────
-- A rule row is a rule BODY, not a step: it carries the whole rule (when/require/
-- decision), an optional `roles` gate and a default `changeApproval` scope, and it is
-- applied per community through `community_policy_bindings` (0020, which creates that
-- table). Rule DEFINITIONS live in the DB; the rule EVALUATOR stays in code
-- (`LocalPolicyEngine` via `GovernanceGuard`).
--
-- These live HERE, with `trust_task_templates`, because that is the table they are
-- inserted into. There is no production database yet, so every seed for a table lives in
-- the migration that creates it — never an insert-only migration.
-- ── Tier 1: baseline rule templates (one atomic rule per row) ───────────────
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000201','task:p2pts:rule:vmc-issue:0.1','rule','0.1','{"name":"Issue membership VMC","kind":"policy","action":"issue_credential","when":{"action":"issue_credential","kind":"MembershipCredential"},"require":[{"fact":"actor_is_admin","is":true},{"fact":"subject_is_active_member","is":false}],"decision":{"decision":"allow"},"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000202','task:p2pts:rule:vec-issue:0.1','rule','0.1','{"name":"Issue endorsement credential","kind":"policy","action":"issue_credential","when":{"action":"issue_credential","kind":"EndorsementCredential"},"require":[{"fact":"actor_is_admin","is":true}],"decision":{"decision":"allow"},"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000203','task:p2pts:rule:vwc-issue:0.1','rule','0.1','{"name":"Issue witness credential","kind":"policy","action":"issue_credential","when":{"action":"issue_credential","kind":"WitnessCredential"},"require":[{"fact":"actor_is_admin","is":true}],"decision":{"decision":"allow"},"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000204','task:p2pts:rule:vic-issue:0.1','rule','0.1','{"name":"Issue invitation credential","kind":"policy","action":"issue_credential","when":{"action":"issue_credential","kind":"InvitationCredential"},"require":[{"fact":"actor_is_admin","is":true}],"decision":{"decision":"allow"},"params":{"min_approvals":{"type":"number","default":1}},"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000205','task:p2pts:rule:approve-membership:0.1','rule','0.1','{"name":"Approve membership","kind":"policy","action":"approve_membership","when":{"action":"approve_membership"},"require":[{"fact":"actor_is_admin","is":true}],"decision":{"decision":"allow"},"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000206','task:p2pts:rule:revoke-membership:0.1','rule','0.1','{"name":"Revoke membership","kind":"policy","action":"revoke_membership","when":{"action":"revoke_membership"},"require":[{"fact":"actor_is_admin","is":true}],"decision":{"decision":"allow"},"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000207','task:p2pts:rule:add-admin:0.1','rule','0.1','{"name":"Add an admin","kind":"policy","action":"add_admin","when":{"action":"add_admin"},"require":[{"fact":"actor_is_admin","is":true}],"decision":{"decision":"allow"},"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000208','task:p2pts:rule:remove-admin:0.1','rule','0.1','{"name":"Remove an admin","kind":"policy","action":"remove_admin","when":{"action":"remove_admin"},"require":[{"fact":"actor_is_admin","is":true}],"decision":{"decision":"allow"},"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000209','task:p2pts:rule:update-governance:0.1','rule','0.1','{"name":"Update community governance","kind":"policy","action":"update_governance","when":{"action":"update_governance"},"require":[{"fact":"actor_is_admin","is":true}],"decision":{"decision":"allow"},"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000210','task:p2pts:rule:vtc-min-admins:0.1','rule','0.1','{"name":"VTC requires at least 1 admin","kind":"policy","action":"crystallize_ceremony","when":{"action":"crystallize_ceremony","kind":"vtc"},"require":[{"fact":"admin_count","op":"lt","value":1}],"decision":{"decision":"deny","explanation":"a VTC requires at least 1 admin"},"roles":["vtc"],"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000211','task:p2pts:rule:vtc-min-threshold:0.1','rule','0.1','{"name":"VTC threshold must be at least 1","kind":"policy","action":"crystallize_ceremony","when":{"action":"crystallize_ceremony","kind":"vtc"},"require":[{"fact":"threshold_m","op":"lt","value":1}],"decision":{"decision":"deny","explanation":"a VTC threshold must be >= 1"},"roles":["vtc"],"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000212','task:p2pts:rule:crystallize-quorum-met:0.1','rule','0.1','{"name":"Crystallize quorum met","kind":"policy","action":"crystallize_ceremony","when":{"action":"crystallize_ceremony"},"require":[{"fact":"approval_count","op":"gte","valueFact":"threshold_n"}],"decision":{"decision":"allow"},"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000213','task:p2pts:rule:crystallize-quorum-short:0.1','rule','0.1','{"name":"Crystallize quorum short","kind":"policy","action":"crystallize_ceremony","when":{"action":"crystallize_ceremony"},"require":[{"fact":"approval_count","op":"lt","valueFact":"threshold_n"}],"decision":{"decision":"requireConsent","explanation":"not every founding admin has co-signed the ceremony yet","requireConsent":{"approverSet":"community-admins","minApprovalsFromFact":"threshold_n","excludeRequester":true}},"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000214','task:p2pts:rule:affiliate-vtc:0.1','rule','0.1','{"name":"Affiliate a child VTC","kind":"policy","action":"affiliate_vtc","when":{"action":"affiliate_vtc"},"require":[{"fact":"actor_is_admin","is":true}],"decision":{"decision":"allow"},"roles":["vtn"],"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000215','task:p2pts:rule:unaffiliate-vtc:0.1','rule','0.1','{"name":"Unaffiliate a child VTC","kind":"policy","action":"unaffiliate_vtc","when":{"action":"unaffiliate_vtc"},"require":[{"fact":"actor_is_admin","is":true}],"decision":{"decision":"allow"},"roles":["vtn"],"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000216','task:p2pts:rule:parent-accepts-child:0.1','rule','0.1','{"name":"Parent VTN accepts child kind","kind":"policy","action":"parent_accepts_child","when":{"action":"parent_accepts_child"},"require":[{"fact":"child_kind_allowed","is":true}],"decision":{"decision":"allow"},"roles":["vtn"],"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;

-- A claim-type marker: one binding per permitted claim type carries
-- params.claim_type (the rule_type is suffixed `#<type>` to keep the UNIQUE key
-- meaningful). The rule gates issuance of a listed kind via the derived
-- `claim_type_allowed` fact; an unlisted kind falls through to the kind rules.
INSERT INTO trust_task_templates (uuid, type, family, version, template, recorded_by_node, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000217','task:p2pts:rule:claim-type-allow:0.1','rule','0.1','{"name":"Allow a claim type","kind":"policy","action":"issue_credential","when":{"action":"issue_credential"},"require":[{"fact":"claim_type_allowed","is":true}],"decision":{"decision":"allow"},"params":{"claim_type":{"type":"string"}},"changeApproval":{"scope":"admins"}}','seed',0,0) ON CONFLICT (type) DO NOTHING;

