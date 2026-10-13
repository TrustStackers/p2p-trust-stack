/**
 * The relationship graph — the **populated** fixture `graph()`'s port was blocked on.
 *
 * ## Why this is seeded rather than two live agents
 *
 * The plan called for "2 agents + a connect". But `graph()` is not a transport feature: it is a set of
 * **rendering rules over four tables**, and every one of them is about how rows are *interpreted*, not about how
 * they got there. Seeding the rows directly exercises all of them deterministically and in isolation — the same
 * technique `messaging.test.ts` uses for the durable transcript. A live connect would additionally test the
 * RFI/RFA handshake, which is a different concern and a flakier one.
 *
 * The rules under test, each of which a naive port would have broken silently:
 *
 *   1. **Ephemeral-`did:peer:4` canonicalization.** A `did:peer:4` row and its real VTA share Ed25519 key bytes;
 *      they must render as ONE node, with edges re-pointed onto the real uuid.
 *   2. **VRC pair-collapse.** The self-minted VRC and the peer's mirrored copy are two rows for one mutual
 *      relationship; they must render as ONE edge, oriented issuer→subject on the locally-issued row.
 *   3. **Peer-edge suppression.** A bare `relationships` row for a pair that already has a credential edge must
 *      NOT draw a second line.
 *   4. **Delegation edges** are their own kind.
 *   5. **VTC membership attachment.** A `vtc` node carries its active members; a non-`vtc` node does not carry
 *      the key at all.
 *   6. **Self is always present**, even with zero edges.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/trust_app_api/graph.test.ts
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createAgentStack, type TrustStack } from '../../src/index.js';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';

const HOMES: string[] = [];
const STACKS: TrustStack[] = [];

const PASS = 'correct horse battery';
const AGENT = 'graph-host';

after(async () => {
  for (const s of STACKS) { try { await s.stop(); } catch { /* never started */ } }
  for (const h of HOMES) rmSync(h, { recursive: true, force: true });
});

/** A 32-byte Ed25519 public key. Two identities sharing one of these are the SAME agent. */
const keyBytes = (fill: number): Buffer => Buffer.alloc(32, fill);

/** uuids are just strings here — the graph treats them as opaque, which is the point. */
const SELF = 'self-0000';
const ALICE = 'alice-000';       // REMOTE-A, the real VTA
const ALICE_EPH = 'alice-eph';   // REMOTE-A's ephemeral did:peer:4 shadow
const BOB = 'bob-00000';         // REMOTE-B, no credential
const VTC = 'vtc-00000';         // a community

const KEY_ALICE = keyBytes(0xa1);
const KEY_BOB = keyBytes(0xb2);

/**
 * Distinct listen port per stack. Only the `debug()` test starts its agent, but a fixed port would make a stray
 * process from an interrupted run look like a test failure.
 */
let nextPort = 24060;

async function makeStack(): Promise<{ stack: TrustStack; ds: SqliteDataSource; selfUuid: string }> {
  const home = mkdtempSync(join(tmpdir(), 'api-graph-'));
  HOMES.push(home);
  const stack = await createAgentStack({ home, agent: { name: AGENT, passphrase: PASS, port: nextPort++ } });
  assert.equal(stack.host.home, home, 'the stack must be bound to the isolated home, not the real P2PTS_HOME');
  STACKS.push(stack);

  const ds = stack.host.storageFor(AGENT) as SqliteDataSource;
  // The real agent's own identity row — its uuid is what `selfUuid` resolves to, and every self-side edge is
  // asserted against it.
  const selfRow = await ds.get<{ uuid: string }>('SELECT uuid FROM identities WHERE name = ?', AGENT);
  assert.ok(selfRow, 'the agent must have its own identity row');
  return { stack, ds, selfUuid: selfRow!.uuid };
}

// ---------------------------------------------------------------------------
// Seeding — the four tables graph() reads, plus the identity/key rows that make
// canonicalization meaningful
// ---------------------------------------------------------------------------

interface SeedIdentity {
  uuid: string;
  name: string | null;
  role?: string;
  subjectKind?: string;
  /** Ed25519 public key bytes. Two identities sharing these are the same agent. */
  key?: Buffer;
  did?: string;
  /** `'scid-vh'` (a real VTA) or the ephemeral `'did:peer:4'` shadow. */
  method?: string;
  recordedByNode?: string | null;
  isPrimary?: number;
}

async function seedIdentity(ds: SqliteDataSource, id: SeedIdentity): Promise<void> {
  await ds.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES (?, ?, ?, 'local', ?, 1, 1)`,
    id.uuid, id.role ?? 'vta', id.subjectKind ?? 'human', id.name,
  );
  if (id.did) {
    await ds.run(
      `INSERT INTO did_documents (uuid, identity_uuid, did, method, document_json, is_primary, recorded_by_node, created_at, updated_at)
       VALUES (?, ?, ?, ?, '{}', ?, ?, 1, 1)`,
      `doc-${id.uuid}`, id.uuid, id.did, id.method ?? 'scid-vh', id.isPrimary ?? 1, id.recordedByNode ?? null,
    );
  }
  if (id.key) {
    await ds.run(
      `INSERT INTO keys (uuid, identity_uuid, key_type, public_key, rotation_version, created_at)
       VALUES (?, ?, 'ed25519', ?, 0, 1)`,
      `key-${id.uuid}`, id.uuid, id.key,
    );
  }
}

async function seedCredential(
  ds: SqliteDataSource,
  c: { uuid: string; vcType: string; issuer: string; subject: string; status?: string },
): Promise<void> {
  await ds.run(
    `INSERT INTO credentials (uuid, vc_type, issuer_identity_uuid, subject_identity_uuid, status, valid_from, created_at)
     VALUES (?, ?, ?, ?, ?, 1, 1)`,
    c.uuid, c.vcType, c.issuer, c.subject, c.status ?? 'issued',
  );
}

async function seedDelegation(
  ds: SqliteDataSource,
  d: { uuid: string; principal: string; dependent: string; relationshipType?: string },
): Promise<void> {
  // `relationship_type` is CHECK-constrained to ('operates','owns','represents','employs').
  await ds.run(
    `INSERT INTO delegations (uuid, principal_identity_uuid, dependent_identity_uuid, relationship_type, granted_at)
     VALUES (?, ?, ?, ?, 1)`,
    d.uuid, d.principal, d.dependent, d.relationshipType ?? 'operates',
  );
}

async function seedRelationship(
  ds: SqliteDataSource,
  r: { uuid: string; local: string; remote: string; direction?: string; status?: string; personhood?: string | null },
): Promise<void> {
  await ds.run(
    `INSERT INTO relationships (uuid, local_identity_uuid, remote_identity_uuid, direction, status, personhood_status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 1, 1)`,
    r.uuid, r.local, r.remote, r.direction ?? 'bidirectional', r.status ?? 'established', r.personhood ?? null,
  );
}

async function seedMembership(
  ds: SqliteDataSource,
  m: { uuid: string; member: string; community: string; role: string; status?: string },
): Promise<void> {
  await ds.run(
    `INSERT INTO memberships (uuid, member_identity_uuid, community_identity_uuid, role, status)
     VALUES (?, ?, ?, ?, ?)`,
    m.uuid, m.member, m.community, m.role, m.status ?? 'active',
  );
}


// ---------------------------------------------------------------------------
// 6. Self is always present
// ---------------------------------------------------------------------------

test('a fresh agent renders exactly its own node, with the seven keys the page reads', async () => {
  const { stack, ds, selfUuid } = await makeStack();
  try {
    const g = await stack.relationships.graph();
    assert.deepEqual(Object.keys(g).sort(), ['edges', 'nodes']);
    assert.equal(g.nodes.length, 1);
    assert.deepEqual(g.edges, []);

    const self = g.nodes[0];
    // Compare the JSON shape, because that is what the route actually returns and what the page reads.
    // `members` is present-but-`undefined` on a non-`vtc` node in BOTH the old adapter code and this port;
    // `JSON.stringify` drops it, which is why the HTTP safety net sees seven keys and this raw object has eight.
    const asSeen = JSON.parse(JSON.stringify(self)) as Record<string, unknown>;
    assert.deepEqual(
      Object.keys(asSeen).sort(),
      ['did', 'id', 'identityUuid', 'isSelf', 'label', 'role', 'subjectKind'],
      'the port must not have changed the node shape',
    );
    assert.equal(self.id, selfUuid);
    assert.equal(self.identityUuid, selfUuid);
    assert.equal(self.isSelf, true);
    assert.equal(self.label, AGENT);
    assert.equal(self.role, 'vta');
    assert.equal(self.subjectKind, 'human');
  } finally { await ds.close(); }
});

// ---------------------------------------------------------------------------
// 1 + 2 + 3. Canonicalization, VRC collapse, peer suppression — one peer pair
// ---------------------------------------------------------------------------

/**
 * Seed the Alice pair exactly as a real handshake leaves it:
 *
 *   - `ALICE`      the real VTA, DID `did:scid:vh:...`, primary
 *   - `ALICE_EPH`  the ephemeral `did:peer:4` shadow, SAME Ed25519 key, `tsp-bridge`, not primary
 *   - two VRC rows for the one mutual relationship (self-minted + the peer's mirrored copy)
 *   - a bare `relationships` row for the same pair
 */
async function seedAlicePair(ds: SqliteDataSource, selfUuid: string): Promise<void> {
  await seedIdentity(ds, { uuid: ALICE, name: 'alice', did: 'did:scid:vh:1:zalice', key: KEY_ALICE });
  await seedIdentity(ds, {
    uuid: ALICE_EPH, name: null, key: KEY_ALICE,
    did: 'did:peer:4:zalice-ephemeral', method: 'did:peer:4', recordedByNode: 'tsp-bridge', isPrimary: 0,
  });
  // The self-minted VRC (issuer = self) and the peer's mirrored copy (issuer = the ephemeral row).
  await seedCredential(ds, { uuid: 'vrc-self', vcType: 'vrc', issuer: selfUuid, subject: ALICE_EPH });
  await seedCredential(ds, { uuid: 'vrc-peer', vcType: 'vrc', issuer: ALICE_EPH, subject: selfUuid });
  await seedRelationship(ds, {
    uuid: 'rel-alice', local: selfUuid, remote: ALICE_EPH, personhood: 'acknowledged',
  });
}

test('canonicalization: the ephemeral did:peer:4 shadow is NOT a node — it renders as its real VTA', async () => {
  const { stack, ds, selfUuid } = await makeStack();
  try {
    await seedAlicePair(ds, selfUuid);
    const g = await stack.relationships.graph();

    const ids = g.nodes.map((n) => n.id).sort();
    assert.deepEqual(
      ids, [ALICE, selfUuid].sort(),
      'the throwaway did:peer:4 row must not appear as its own node',
    );
    assert.equal(
      g.nodes.some((n) => n.id === ALICE_EPH), false,
      'ALICE_EPH must have been canonicalized onto ALICE',
    );

    // Every edge endpoint is a canonical uuid — an ephemeral uuid leaking into an edge would draw an orphan.
    for (const e of g.edges) {
      assert.notEqual(e.source, ALICE_EPH, `edge ${e.id} still points at the ephemeral uuid`);
      assert.notEqual(e.target, ALICE_EPH, `edge ${e.id} still points at the ephemeral uuid`);
    }

    // The real VTA carries the metadata (name → label), which is the whole reason to canonicalize.
    const alice = g.nodes.find((n) => n.id === ALICE);
    assert.equal(alice!.label, 'alice');
    assert.equal(alice!.isSelf, false);
    assert.equal(alice!.did, 'did:scid:vh:1:zalice', 'the real DID, not the peer4 one');
  } finally { await ds.close(); }
});

test('VRC pair-collapse: two rows for one mutual relationship render as ONE edge, self-oriented', async () => {
  const { stack, ds, selfUuid } = await makeStack();
  try {
    await seedAlicePair(ds, selfUuid);
    const g = await stack.relationships.graph();

    const vrcEdges = g.edges.filter((e) => e.kind === 'credential' && e.vcType === 'vrc');
    assert.equal(vrcEdges.length, 1, 'the self-minted VRC and the mirrored copy must collapse to one edge');

    const [vrc] = vrcEdges;
    assert.equal(vrc.id, 'credential:vrc-self', 'the LOCALLY-issued row is preferred, so the id is stable');
    assert.equal(vrc.source, selfUuid, 'and it keeps its issuer→subject orientation');
    assert.equal(vrc.target, ALICE);
  } finally { await ds.close(); }
});

test('peer-edge suppression: a bare relationship row draws no line when a credential already connects the pair', async () => {
  const { stack, ds, selfUuid } = await makeStack();
  try {
    await seedAlicePair(ds, selfUuid);
    const g = await stack.relationships.graph();

    assert.equal(
      g.edges.filter((e) => e.kind === 'peer').length, 0,
      'the VRC edge is the meaningful one; a peer edge would double the line',
    );
    // …and the node it would have connected is still present, because the credential edge put it there.
    assert.ok(g.nodes.some((n) => n.id === ALICE));
  } finally { await ds.close(); }
});


// ---------------------------------------------------------------------------
// 3 (inverse) + 4. A peer with NO credential gets a peer edge; delegation is its own kind
// ---------------------------------------------------------------------------

test('a peer with no credential DOES get a peer edge, and a delegation is its own kind', async () => {
  const { stack, ds, selfUuid } = await makeStack();
  try {
    // Bob: a real VTA, no credential of any kind.
    await seedIdentity(ds, { uuid: BOB, name: 'bob', did: 'did:scid:vh:1:zbob', key: KEY_BOB });
    await seedRelationship(ds, {
      uuid: 'rel-bob', local: selfUuid, remote: BOB, direction: 'bidirectional',
      status: 'established', personhood: 'acknowledged',
    });
    await seedDelegation(ds, { uuid: 'del-bob', principal: selfUuid, dependent: BOB });

    const g = await stack.relationships.graph();

    // The inverse of the suppression rule: with no credential on the pair the peer edge IS drawn — otherwise
    // suppression would be indistinguishable from "peer edges never render".
    const peerEdges = g.edges.filter((e) => e.kind === 'peer');
    assert.equal(peerEdges.length, 1, 'a credential-free peer must still be connected');
    assert.equal(peerEdges[0].id, 'peer:rel-bob');
    assert.equal(peerEdges[0].source, selfUuid);
    assert.equal(peerEdges[0].target, BOB);
    assert.equal(peerEdges[0].label, 'peer');
    assert.equal(peerEdges[0].status, 'established');
    assert.equal(peerEdges[0].personhoodStatus, 'acknowledged');

    const delEdges = g.edges.filter((e) => e.kind === 'delegation');
    assert.equal(delEdges.length, 1, 'a delegation renders as its own kind, not as a peer edge');
    assert.equal(delEdges[0].id, 'delegation:del-bob');
    assert.equal(delEdges[0].relationshipType, 'operates');
    assert.equal(delEdges[0].source, selfUuid, 'principal → dependent');
    assert.equal(delEdges[0].target, BOB);

    assert.deepEqual(g.nodes.map((n) => n.id).sort(), [BOB, selfUuid].sort());
  } finally { await ds.close(); }
});

test('a revoked or expired credential draws no edge — the filter is on status, not presence', async () => {
  const { stack, ds, selfUuid } = await makeStack();
  try {
    await seedIdentity(ds, { uuid: BOB, name: 'bob', did: 'did:scid:vh:1:zbob', key: KEY_BOB });
    await seedCredential(ds, { uuid: 'vmc-revoked', vcType: 'vmc', issuer: selfUuid, subject: BOB, status: 'revoked' });
    await seedCredential(ds, { uuid: 'vmc-expired', vcType: 'vmc', issuer: selfUuid, subject: BOB, status: 'expired' });

    const g = await stack.relationships.graph();
    assert.equal(
      g.edges.filter((e) => e.kind === 'credential').length, 0,
      'revoked/expired rows must not render — they would otherwise show as live trust',
    );
    // With no live credential and no relationship row, Bob is not connected at all.
    assert.deepEqual(g.nodes.map((n) => n.id), [selfUuid]);
  } finally { await ds.close(); }
});

// ---------------------------------------------------------------------------
// 5. VTC membership attachment
// ---------------------------------------------------------------------------

test('a vtc node carries its active members; a non-vtc node carries no `members` key at all', async () => {
  const { stack, ds, selfUuid } = await makeStack();
  try {
    // The community must be reachable by an EDGE to become a node — the node set is built from edge endpoints
    // plus self, so a membership row alone would not put it in the graph.
    await seedIdentity(ds, { uuid: VTC, name: 'Springfield', role: 'vtc' });
    await seedIdentity(ds, { uuid: BOB, name: 'bob', did: 'did:scid:vh:1:zbob', key: KEY_BOB });
    await seedCredential(ds, { uuid: 'vmc-bob', vcType: 'vmc', issuer: VTC, subject: BOB });
    await seedMembership(ds, { uuid: 'mem-bob', member: BOB, community: VTC, role: 'member' });
    // A REVOKED membership must not appear in the member list.
    await seedIdentity(ds, { uuid: 'carol-000', name: 'carol' });
    await seedMembership(ds, {
      uuid: 'mem-carol', member: 'carol-000', community: VTC, role: 'member', status: 'revoked',
    });

    const g = await stack.relationships.graph();

    const vtc = g.nodes.find((n) => n.id === VTC);
    assert.ok(vtc, 'the community must be a node');
    assert.equal(vtc!.role, 'vtc');
    assert.equal(vtc!.label, 'Springfield');
    assert.deepEqual(
      vtc!.members,
      [{ uuid: BOB, label: 'bob', role: 'member' }],
      'only ACTIVE members, with a display label',
    );

    // `members` is vtc-only. It is present-but-undefined elsewhere, which JSON drops — so assert on the
    // serialized shape, exactly as the page sees it.
    const bob = JSON.parse(JSON.stringify(g.nodes.find((n) => n.id === BOB))) as Record<string, unknown>;
    assert.equal('members' in bob, false, 'a non-vtc node must not advertise members');
  } finally { await ds.close(); }
});

// ---------------------------------------------------------------------------
// `debug()` — the other P3-rest port
// ---------------------------------------------------------------------------

test('debug() returns null for an unknown peer, and a truncated transport view for a known one', async () => {
  const { stack, ds, selfUuid } = await makeStack();
  try {
    assert.equal(await stack.relationships.debug('did:scid:vh:1:znobody'), null, 'the route turns this into a 404');

    await seedIdentity(ds, { uuid: BOB, name: 'bob', did: 'did:scid:vh:1:zbob', key: KEY_BOB });
    await seedRelationship(ds, { uuid: 'rel-bob', local: selfUuid, remote: BOB });

    // `debug()` wraps `agent.getRelationship()`, which reads the runtime's relationship store — and that store
    // only exists once the agent is STARTED, with a DID resolver built from the rows present at start. So the
    // seed must happen first and the start after. This is a property of the capability, not of the port.
    await stack.start();

    const d = await stack.relationships.debug('did:scid:vh:1:zbob');
    assert.ok(d, 'a seeded relationship must be found once the runtime store exists');
    assert.deepEqual(
      Object.keys(d!).sort(),
      [
        'createdAt', 'direction', 'hasEd25519Key', 'hasX25519Key', 'libp2pConnected', 'libp2pConns',
        'remoteDid', 'status', 'transport', 'updatedAt',
      ],
      'the debug payload shape must not have changed in the port',
    );
    assert.equal(d!.direction, 'bidirectional');
    assert.equal(d!.status, 'established');
    // No transport was recorded on the seeded row, so there is no peerId to ask about and no connection — the
    // contract `getPeerConnections()` documents is a clean false/[] rather than an error.
    assert.equal(d!.transport, null);
    assert.equal(d!.libp2pConnected, false);
    assert.deepEqual(d!.libp2pConns, []);
  } finally { await ds.close(); }
});


