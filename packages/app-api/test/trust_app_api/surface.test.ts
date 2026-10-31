// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `AgentHandle` contract snapshot — P0 guardrail for the trust-app-api refactor.
 *
 * WHY THIS EXISTS
 *
 * `AgentHandle` (`trust-app-api/runtime/handle.ts`) is the interface the TUI and web adapter nominally program to.
 * Its instability is the core problem the api-layer refactor fixes: it has grown to 100 members, **47 of
 * them optional**, so every caller must null-check capabilities and the "contract" never settles.
 *
 * The refactor touches this interface twice:
 *   - P1 relocated the file (agent-app/src/ → trust-app-api/runtime/) with no change to its shape — done;
 *   - P6 deletes it, once `trust-app-api` domains have replaced it.
 *
 * Both are contract events, so both need a before/after. This test freezes the shape today: P1 must not
 * change it at all (beyond the path constant), and P6 must remove it deliberately rather than by drift.
 *
 * The interface is a TypeScript type, so it cannot be enumerated at runtime — the members are parsed out
 * of the source with a brace-aware scan, which is why nested object-literal properties (e.g. the
 * `{ success, error?, reset? }` inside `resetPersonhoodCeremony`) are correctly NOT counted as members.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/trust_app_api/surface.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The interface moved here in P1 (`agent-app/src/` → `trust-app-api/runtime/`). */
const HANDLE_PATH = fileURLToPath(new URL('../../src/runtime/handle.ts', import.meta.url));

const INTERFACE_HEADER = 'export interface AgentHandle {';

/** Members of `AgentHandle`, in source order. */
const EXPECTED_MEMBERS: string[] = [
  'getVid', 'getDid', 'getName', 'getMeta', 'getMultiaddrs', 'getPeerId', 'getDbHandle', 'signMessage',
  'start', 'stop',
  'generateOobi',
  'connectToPeer', 'connectToDiscoveredPeer', 'reconnectPeer', 'listRelationships', 'getRelationship',
  'disconnectPeer',
  'sendMessage', 'sendConfidentialMessage',
  'onMessage', 'onRelationshipChange', 'onConnectionEvent', 'onNetworkChange',
  'refreshBootstrapPeers', 'isBootstrapConnected', 'getBootstrapRelayAddr', 'getDiscoveredPeers',
  // Added 2026-10-19: the VTN identity. `getNet` reports the VTN key this agent
  // registers as (`net`); `setNet` adopts a different one and re-registers. Both
  // optional so an agent implementation without VTN switching still satisfies the
  // contract, and the login flow null-checks them.
  'getNet', 'setNet',
  'reRegisterWithBootstrap',
  'getConnectivityStatus', 'getNetworkProfile', 'isNetworkChanged', 'getClientSourceAddr',
  'createProfile', 'listProfiles', 'updateProfile', 'removeProfile',
  'addProfileClaim', 'updateProfileClaim', 'removeProfileClaim', 'listProfileClaims', 'getProfileCard',
  'createVtn', 'listVtcs', 'affiliateVtc', 'unaffiliateVtc', 'getVtnHierarchy',
  'issueVrc', 'issueVrcForSelf', 'verifyVrc', 'listVtcGovernanceDocs', 'listVrcsForSelf',
  'listCommunities', 'getCommunityByDid',
  'listCommunitiesFromDb',
  // Added 2026-10-08: the community-ceremony lifecycle. All seven were already PUBLIC on the runtime but
  // absent from this contract, so the adapter reached for them through `deps.agent as any`; declaring them
  // is what took that counter to 0. (`upsertRemoteVtc` was deliberately left out — its only would-be caller
  // passed `result.vtcData`, a field the ceremony has never returned.)
  'createCommunityCeremony', 'approveCeremony', 'queryCeremony', 'listPendingCeremonies',
  'listCeremonyLog', 'getCeremonyLog', 'resetCeremony',
  'createDelegation', 'listDelegations',
  'rotate', 'getNextSigningKeyPair', 'listRotationLog',
  'registerName', 'resolveName', 'getProfileSyncStatus', 'revokeName', 'listNames',
  'getCredentialFactory',
  // Added 2026-10-09: the context registry (P4). All three were already public on the runtime but absent from
  // the contract — declaring them is what lets `domains/contexts.ts` reach them without a cast.
  'provisionApp', 'revokeApp', 'listProvisionedApps',
  'fetchRecoveryState', 'lookupIdentity',
  'isUtilityServerConnected', 'getUtilityServerDid', 'configureUtilityServer', 'pushIdentityToUtilityServer',
  // Added 2026-10-08: the single seam for agent→server TSP queries. Promoted from a private helper that the
  // adapter could not reach, so five routes hand-built their own transport — 20 `deps.agent as any` reaches.
  'queryUtilityServer',
  'acknowledgeRemotePeer', 'getCeremonyStatus', 'resetPersonhoodCeremony',
  'onCeremonyPrompt', 'onCeremonyComplete', 'onCeremonyFailed', 'onCeremonyExpired', 'onCeremonyAckChange',
  'onDuplicateConnectNotice', 'getDuplicateConnectNotice',
  // Added 2026-10-08 (P4/P5): the arrival signal for a delivered credential. Before it, nothing observed a
  // delivery, so `nav.js` polled `/api/invitations` every 5 s and `credentials.html` polled every 3 s.
  'onCredentialReceived',
  // Added 2026-10-09: the community + proposal arrival signals. `community.changed` and
  // `governance.proposal` were declared in the catalogue with payload types and emitted by NOTHING, so the
  // Communities and Rules pages could only poll. Both are optional observers.
  'onCommunityChanged', 'onGovernanceProposal',
  // Added 2026-10-09: the ceremony-progress nudge. A founding co-signature had NO signal at all (the
  // community does not exist until the ceremony crystallizes), so the Communities page polled its log.
  'onCeremonyEvent',
  'getVrcConnectedPeers',
  // Added 2026-10-09 (P3 rest): the live-connection view `relationships.debug()` needs, promoted from the
  // raw node the adapter used to reach into.
  'getPeerConnections',
  'proposeGovernanceChange', 'approveGovernanceChange', 'listPendingGovernanceChanges',
];

/**
 * The optional (`?`) subset — the 47 members whose absence every caller must null-check. This is the
 * number the refactor exists to shrink; freezing it makes any change to that count a deliberate act.
 */
const EXPECTED_OPTIONAL: string[] = [
  'getDbHandle',
  // Added 2026-10-19: the VTN identity (see the members list above). Optional for
  // the same reason as the other capability methods — a stack that cannot switch
  // VTN must still be usable, so every caller null-checks them.
  'getNet', 'setNet',
  'getConnectivityStatus',
  'createVtn', 'listVtcs', 'affiliateVtc', 'unaffiliateVtc', 'getVtnHierarchy',
  // Added 2026-10-09 (Group A): the single-admin issuance path. Optional because it is a CAPABILITY — a
  // capability-scoped stack omits it — which is why `credentials.issue()` null-checks it and reports
  // `not_implemented` rather than letting a missing capability look like an unknown community.
  'issueVrcForSelf',
  'listCommunitiesFromDb',
  'createCommunityCeremony', 'approveCeremony', 'queryCeremony', 'listPendingCeremonies',
  'listCeremonyLog', 'getCeremonyLog', 'resetCeremony',
  'createDelegation', 'listDelegations',
  'getProfileSyncStatus',
  // Added 2026-10-09: the context registry (P4) — optional, so a caller must null-check them.
  'provisionApp', 'revokeApp', 'listProvisionedApps',
  'fetchRecoveryState', 'lookupIdentity',
  'isUtilityServerConnected', 'getUtilityServerDid', 'configureUtilityServer', 'pushIdentityToUtilityServer',
  'queryUtilityServer',
  'acknowledgeRemotePeer', 'getCeremonyStatus', 'resetPersonhoodCeremony',
  'onCeremonyPrompt', 'onCeremonyComplete', 'onCeremonyFailed', 'onCeremonyExpired', 'onCeremonyAckChange',
  'onDuplicateConnectNotice', 'getDuplicateConnectNotice',
  'onCredentialReceived',
  'onCommunityChanged', 'onGovernanceProposal',
  'onCeremonyEvent',
  'getVrcConnectedPeers',
  // Added 2026-10-09 (P3 rest): the live-connection view `relationships.debug()` needs, promoted from the
  // raw node the adapter used to reach into.
  'getPeerConnections',
  'proposeGovernanceChange', 'approveGovernanceChange', 'listPendingGovernanceChanges',
];

/**
 * Parse the `AgentHandle` interface body, returning every member declared at brace-depth 0.
 *
 * Depth tracking is what makes this correct: `resetPersonhoodCeremony?()` returns
 * `Promise<{ success; error?; reset? }>`, and a naive line scan would report `error` and `reset` as
 * members of the interface. They are not.
 */
function parseAgentHandle(source: string): { members: string[]; optional: string[] } {
  const start = source.indexOf(INTERFACE_HEADER);
  assert.ok(start >= 0, `"${INTERFACE_HEADER}" not found — has the interface been renamed or deleted?`);
  const body = source.slice(start + INTERFACE_HEADER.length);

  const members: string[] = [];
  const optional: string[] = [];
  let depth = 0;      // brace depth
  let parenDepth = 0; // paren depth — see the multi-line-signature note below

  // Strip block comments across the WHOLE body before splitting: a `(` or `{` inside a docblock is prose, not
  // structure, and a multi-line docblock cannot be removed line-by-line.
  const stripped = body.replace(/\/\*[\s\S]*?\*\//g, '');

  for (const raw of stripped.split('\n')) {
    const line = raw.replace(/\/\/.*$/, ''); // strip line comments before matching
    // A member is only recognised at the interface's own depth AND outside any parameter list. The paren
    // guard matters because a signature whose parameters span lines without an inline `{...}` type (e.g.
    // `foo(\n  a: string,\n  b?: number,\n): void;`) would otherwise leak `a` and `b` in as fake members —
    // inflating the count the snapshot pins.
    if (depth === 0 && parenDepth === 0) {
      // `<` is in the terminator class so a GENERIC method (`foo<T>(...)`) is still counted. Without it the
      // guard silently ignored one, which defeats the point of pinning the contract.
      const m = line.match(/^\s*([a-zA-Z_$][\w$]*)(\?)?\s*[<:(]/);
      if (m) {
        members.push(m[1]);
        if (m[2]) optional.push(m[1]);
      }
    }
    for (const ch of line) {
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      else if (ch === '(') parenDepth++;
      else if (ch === ')') parenDepth--;
    }
    if (depth < 0) break; // the interface's closing brace
  }

  return { members, optional };
}

test('AgentHandle exists at the expected path', () => {
  assert.ok(existsSync(HANDLE_PATH), `${HANDLE_PATH} is missing`);
});

test('AgentHandle member list is unchanged (103 members, in order)', () => {
  const { members } = parseAgentHandle(readFileSync(HANDLE_PATH, 'utf8'));
  assert.deepEqual(
    members,
    EXPECTED_MEMBERS,
    'AgentHandle changed shape — a contract change, not a test fix',
  );
  assert.equal(members.length, 103);
});

test('AgentHandle optional-member count is unchanged (50 optional)', () => {
  const { optional } = parseAgentHandle(readFileSync(HANDLE_PATH, 'utf8'));
  assert.deepEqual(
    optional,
    EXPECTED_OPTIONAL,
    'the set of optional members changed — callers null-check exactly these',
  );
  assert.equal(optional.length, 50);
});


// ─────────────────────────────────────────────────────────────────────────────
// P2: the trust-app-api surface itself
// ─────────────────────────────────────────────────────────────────────────────

const AGENT_API = fileURLToPath(new URL('../../src/', import.meta.url));

function readDir(dir: string, ext = '.ts'): string[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith(ext))
    .map((f) => join(dir, f));
}

test('the barrel re-exports NO runtime value — only the types `Host` signatures require', () => {
  const barrel = readFileSync(join(AGENT_API, 'index.ts'), 'utf8');
  // Strip comments first: the docblock NAMES `runtime/handle.js` to explain the exception, and prose must not be
  // read as an export.
  const stripped = barrel
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n').map((l) => l.replace(/\/\/.*$/, '')).join('\n');

  // Multi-line-safe: an export statement is `export [type] { ... } from '<spec>'`.
  const statements = [...stripped.matchAll(/export\s+(type\s+)?\{[\s\S]*?\}\s*from\s+'([^']+)'/g)];
  const fromRuntime = statements.filter((m) => m[2].includes('runtime/'));

  // A VALUE re-export would let a consumer call runtime code directly — that is what "reachable around" means.
  const values = fromRuntime.filter((m) => !m[1]);
  assert.deepEqual(
    values.map((m) => m[2]),
    [],
    'trust-app-api/index.ts must not re-export a runtime VALUE — the layer would be reachable around',
  );

  // The TYPE exceptions are allowed because `Host`'s own public signatures reference them, so without them a host
  // author cannot name what the seam hands back. Pinned exactly, so the list cannot grow by accident.
  assert.deepEqual(
    [...new Set(fromRuntime.map((m) => m[2]))].sort(),
    ['./runtime/handle.js', './runtime/types.js'],
    'the type-only exceptions are exactly the two `Host` requires (AgentHandle, AgentConfig)',
  );
});

test('API tests import only the public barrel — no runtime internals (R7)', () => {
  const offenders: string[] = [];
  for (const file of readDir(fileURLToPath(new URL('.', import.meta.url)))) {
    if (!file.endsWith('.test.ts') && !file.endsWith('harness.ts')) continue;
    const src = readFileSync(file, 'utf8');
    for (const m of src.matchAll(/from\s+'([^']+)'/g)) {
      if (m[1].includes('runtime/')) offenders.push(`${file.split('/').pop()}: ${m[1]}`);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    'a test needing a runtime internal means the API surface is missing something — add the method, do not reach in',
  );
});

test('no DTO carries an index signature or an `any` (the tell that a DB row leaked)', () => {
  const offenders: string[] = [];
  for (const file of readDir(join(AGENT_API, 'dto'))) {
    const name = file.split('/').pop();
    let inBlock = false;
    readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
      let code = line;
      // Strip comments — including block comments, whose prose legitimately names the very patterns this
      // test forbids (the DTO docstring explains why an index signature is not allowed).
      if (inBlock) {
        const end = code.indexOf('*/');
        if (end === -1) return;
        code = code.slice(end + 2);
        inBlock = false;
      }
      code = code.replace(/\/\*[\s\S]*?\*\//g, '');
      const open = code.indexOf('/*');
      if (open !== -1) {
        code = code.slice(0, open);
        inBlock = true;
      }
      code = code.replace(/\/\/.*$/, '');

      if (/\[\s*\w+\s*:\s*string\s*\]/.test(code)) offenders.push(`${name}:${i + 1} index signature`);
      if (/:\s*any\b/.test(code)) offenders.push(`${name}:${i + 1} : any`);
      if (/\bany\[\]/.test(code)) offenders.push(`${name}:${i + 1} any[]`);
    });
  }
  assert.deepEqual(offenders, [], 'DTOs must list their fields explicitly');
});

test('the P2 TrustStack exposes the two implemented domains and a semver version', () => {
  const src = readFileSync(join(AGENT_API, 'client', 'trust-stack.ts'), 'utf8');

  assert.match(src, /readonly identity: IdentityApi/, 'identity domain on the root');
  assert.match(src, /readonly connectivity: ConnectivityApi/, 'connectivity domain on the root');

  const version = src.match(/export const API_VERSION = '([^']+)'/);
  assert.ok(version, 'API_VERSION is exported');
  assert.match(version![1], /^\d+\.\d+\.\d+$/, 'API_VERSION is semver');
});

test('the domains that are not implemented yet are absent, not stubbed to throw', () => {
  const src = readFileSync(join(AGENT_API, 'client', 'trust-stack.ts'), 'utf8');

  // Implemented so far — each must be declared.
  const IMPLEMENTED = [
    'identity', 'connectivity', 'messaging', 'relationships', 'names', 'profiles', 'credentials', 'communities',
    // P4: the context registry, plus the `asContext()` capability scope that reads it.
    'contexts',
  ];
  for (const done of IMPLEMENTED) {
    assert.ok(
      new RegExp(`readonly ${done}:`).test(src),
      `\`${done}\` is implemented and must be declared on the root`,
    );
  }

  // Not yet implemented — a declared-but-throwing domain would be a lie about the contract.
  const NOT_YET = ['sync'];
  for (const pending of NOT_YET) {
    assert.ok(
      !new RegExp(`readonly ${pending}:`).test(src),
      `\`${pending}\` must not be declared until it is implemented`,
    );
  }
});

