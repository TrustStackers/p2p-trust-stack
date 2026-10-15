// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The relationship-graph builder — `GET /api/graph`'s logic, ported out of the adapter.
 *
 * ## Why this is its own module
 *
 * `graph()` is not a query, it is a **set of rendering rules over four tables** (credentials, delegations,
 * relationships, memberships) plus a canonicalization pass. That is ~280 lines; folding it into
 * `relationships.ts` would have doubled that file and buried the domain's actual API. It is a sibling module
 * instead, and the domain calls one function from it.
 *
 * ## What the port changed, and what it deliberately did not
 *
 * **Changed:** every query goes through `DataSource` (`db.all` / `db.get`) instead of `DatabaseSync.prepare()`.
 * That is the entire point of moving it — six of the adapter's eight `.prepare(` calls lived here, and raw SQL
 * above the layer is what R5 forbids.
 *
 * **Not changed:** the output shape, key for key. `test/trust_app_api/adapter-delegation.test.ts` pins the empty
 * case (one self node, seven keys, zero edges) precisely so this port could be verified rather than hoped at.
 *
 * ## The canonicalization rule (unchanged, and the subtle part)
 *
 * Every RFI/RFA handshake creates an **ephemeral** `did:peer:4` identity row
 * (`did_documents.method = 'did:peer:4'`, `recorded_by_node = 'tsp-bridge'`, `is_primary = 0`) that is NOT the
 * remote party's real VTA. Both rows share the same Ed25519 public key bytes — that shared key material (never
 * an internal id) is the only reliable signal that they are the same agent. Without this pass a single peer
 * would appear twice: once as a throwaway `did:peer:4` node and once as its real VTA.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { cesrEncode } from '@p2p-trust-stack/core/crypto/cesr.js';
import { CESR_CODES } from '@p2p-trust-stack/core/crypto/codes.js';

// ---------------------------------------------------------------------------
// DTOs — the wire shape of `GET /api/graph`, unchanged by the port
// ---------------------------------------------------------------------------

/** One node in the relationship graph. */
export interface GraphNodeDto {
  id: string;
  label: string;
  role: string;
  subjectKind: string;
  isSelf: boolean;
  identityUuid: string;
  did: string | null;
  /** Active members, present only on a `vtc` node. */
  members?: Array<{ uuid: string; label: string; role: string }>;
}

/** One edge. `kind` is the discriminator; the remaining fields belong to that kind. */
export interface GraphEdgeDto {
  id: string;
  source: string;
  target: string;
  kind: 'credential' | 'delegation' | 'peer';
  label: string;
  vcType?: string;
  status?: string;
  relationshipType?: string;
  direction?: string;
  personhoodStatus?: string;
  claim?: string | null;
  validFrom?: number;
  validUntil?: number | null;
  thresholdRequired?: number | null;
}

export interface GraphDto {
  nodes: GraphNodeDto[];
  edges: GraphEdgeDto[];
}

/** A local identity's metadata, as the canonicalization pass needs it. */
interface LocalIdentityMetaRow {
  identity_uuid: string;
  name: string | null;
  registered_name: string | null;
  namespace: string | null;
  role: string;
  subject_kind: string | null;
  is_ephemeral_peer4: number;
  ed25519_hex: string | null;
  did: string | null;
}

interface LocalIdentityMeta {
  name: string | null;
  role: string;
  subjectKind: string;
  registeredName: string | null;
  namespace: string | null;
  vid: string | null;
  did: string | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Resolve an identity's stable uuid from a real DID (via did_documents). Falls back to the DID itself. */
async function resolveIdentityUuid(db: DataSource, did: string): Promise<string> {
  const row = await db.get<{ uuid: string }>(
    `SELECT i.uuid FROM identities i JOIN did_documents d ON d.identity_uuid = i.uuid WHERE d.did = ?`,
    did,
  );
  return row?.uuid ?? did;
}

/**
 * A friendly label for an identity when `identities.name` is empty.
 *
 * The agent's local database has NO name data for remote peers by default (unlike the utility server, which
 * receives every VTA's name via identity_push) — RFI/RFA processing never captures a display name, and
 * `buildCleanPeer4FromDocument()` strips `alsoKnownAs` when storing the remote peer's DID document. The only
 * locally-available name source is `name_registry`, populated only when the operator explicitly resolved a
 * `vta:<namespace>:<name>` URI for that identity.
 */
function friendlyLabel(
  meta: {
    name: string | null;
    registeredName: string | null;
    namespace: string | null;
    subjectKind: string;
    vid: string | null;
  },
  uuid: string,
): string {
  if (meta.name) return meta.name;
  if (meta.registeredName) return meta.namespace ? `${meta.registeredName} (${meta.namespace})` : meta.registeredName;
  if (meta.subjectKind === 'organization') return 'Utility Server';
  if (meta.subjectKind === 'ai_agent') return 'AI Agent';
  if (meta.subjectKind === 'object') return 'Object';
  // Fall back to a truncated VID (the CESR-encoded Ed25519 public key) — the actual public identifier the user
  // shared via OOBI — rather than a meaningless internal database UUID fragment.
  if (meta.vid) return meta.vid.slice(0, 16) + '…';
  return `Peer #${uuid.slice(0, 8)}`;
}

/** `canonicalize.get(uuid) ?? uuid` — an ephemeral row's uuid maps to its real identity's uuid. */
function resolveLocalUuid(canonicalize: Map<string, string>, uuid: string): string {
  return canonicalize.get(uuid) ?? uuid;
}

/**
 * Build the ephemeral-`did:peer:4` → real-VTA uuid map, plus per-identity display metadata.
 *
 * Mirrors the utility server's `GET /graph/edges?format=graph` canonicalization so both sides agree on which
 * node a peer *is*.
 */
async function buildLocalCanonicalizationMap(db: DataSource): Promise<{
  canonicalize: Map<string, string>;
  metaByUuid: Map<string, LocalIdentityMeta>;
}> {
  const rows = await db.all<LocalIdentityMetaRow>(`
    SELECT
      i.uuid AS identity_uuid,
      i.name AS name,
      i.role AS role,
      i.subject_kind AS subject_kind,
      nr.name AS registered_name,
      nr.namespace AS namespace,
      CASE WHEN NOT EXISTS (
        SELECT 1 FROM did_documents dd2
        WHERE dd2.identity_uuid = i.uuid
          AND NOT (dd2.method = 'did:peer:4' AND dd2.recorded_by_node = 'tsp-bridge' AND dd2.is_primary = 0)
      ) THEN 1 ELSE 0 END AS is_ephemeral_peer4,
      hex(k.public_key) AS ed25519_hex,
      (SELECT dd2.did FROM did_documents dd2
        WHERE dd2.identity_uuid = i.uuid
        ORDER BY dd2.is_primary DESC LIMIT 1) AS did
    FROM identities i
    LEFT JOIN keys k ON k.identity_uuid = i.uuid AND k.key_type = 'ed25519' AND k.rotation_version = 0
    LEFT JOIN name_registry nr ON nr.identity_uuid = i.uuid AND nr.revoked_at IS NULL
  `);

  // Group by shared Ed25519 public key: an ephemeral row and its real VTA publish the SAME key bytes.
  const byKey = new Map<string, LocalIdentityMetaRow[]>();
  for (const row of rows) {
    if (!row.ed25519_hex) continue;
    const group = byKey.get(row.ed25519_hex) ?? [];
    group.push(row);
    byKey.set(row.ed25519_hex, group);
  }

  const canonicalize = new Map<string, string>();
  const metaByUuid = new Map<string, LocalIdentityMeta>();

  for (const row of rows) {
    let vid: string | null = null;
    if (row.ed25519_hex) {
      try {
        vid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, Buffer.from(row.ed25519_hex, 'hex'));
      } catch { /* malformed key material — leave vid null */ }
    }
    metaByUuid.set(row.identity_uuid, {
      name: row.name,
      role: row.role,
      subjectKind: row.subject_kind ?? 'human',
      registeredName: row.registered_name,
      namespace: row.namespace,
      vid,
      did: row.did,
    });
  }

  // Only a group with BOTH a real row and at least one ephemeral row canonicalizes. A lone ephemeral (whose real
  // identity is not known locally) stays as itself rather than being dropped or merged with an unrelated node.
  for (const [, group] of byKey) {
    const real = group.find((r) => r.is_ephemeral_peer4 === 0);
    const ephemerals = group.filter((r) => r.is_ephemeral_peer4 === 1);
    if (real && ephemerals.length > 0) {
      for (const eph of ephemerals) canonicalize.set(eph.identity_uuid, real.identity_uuid);
    }
  }

  return { canonicalize, metaByUuid };
}

// ---------------------------------------------------------------------------
// The graph
// ---------------------------------------------------------------------------

/**
 * Build the relationship graph.
 *
 * @param db       the active agent's database.
 * @param selfDid  the active agent's DID — its node is always present, even with zero edges.
 * @param selfName the active agent's name, used as its own node label.
 */
export async function buildGraph(
  db: DataSource,
  opts: { selfDid: string; selfName: string | null },
): Promise<GraphDto> {
  const { canonicalize, metaByUuid } = await buildLocalCanonicalizationMap(db);
  const selfUuid = await resolveIdentityUuid(db, opts.selfDid);

  const nodeUuids = new Set<string>();
  const edges: GraphEdgeDto[] = [];

  // ── Credential edges (issuer -> subject), canonicalized ──
  // `credentials` is uuid-first (migration 0019) — no integer `id` column; `uuid` is the row key.
  //
  // A VRC (peer-relationship) credential is inherently mutual: after the personhood ceremony this agent holds
  // TWO rows for the same peer pair — its own self-minted VRC (issuer=self, written by mintPeerVrc) and the
  // peer's mirrored copy received via store_remote_vrc (issuer=peer, subject=self, written by
  // storeReceivedDtgVrc). Emitting both drew two parallel arrow lines between the same two nodes, so only one is
  // kept — a single edge already expresses the two-way relationship (graph.html draws arrowheads on both ends).
  // Only 'vrc' is collapsed: VMC/VEC rows for the same pair are distinct credentials.
  //
  // pairKey (unordered "a|b") -> index into `edges`.
  const vrcEdgeIndexByPair = new Map<string, number>();
  const credRows = await db.all<{
    uuid: string; issuer_identity_uuid: string; subject_identity_uuid: string;
    vc_type: string; status: string; claim: string | null;
    valid_from: number; valid_until: number | null; threshold_required: number | null;
  }>(`
    SELECT uuid, issuer_identity_uuid, subject_identity_uuid, vc_type, status,
           claim, valid_from, valid_until, threshold_required
    FROM credentials WHERE status NOT IN ('revoked', 'expired')
  `);

  for (const c of credRows) {
    const source = resolveLocalUuid(canonicalize, c.issuer_identity_uuid);
    const target = resolveLocalUuid(canonicalize, c.subject_identity_uuid);
    // A self-issued credential draws no edge (source === target), but the node still exists via `selfUuid` below.
    if (source === target) continue;
    nodeUuids.add(source);
    nodeUuids.add(target);
    const edge: GraphEdgeDto = {
      id: `credential:${c.uuid}`, source, target,
      kind: 'credential', label: c.vc_type, vcType: c.vc_type, status: c.status,
      claim: c.claim, validFrom: c.valid_from, validUntil: c.valid_until,
      thresholdRequired: c.threshold_required,
    };
    if (c.vc_type === 'vrc') {
      // Collapse the self-minted VRC and the peer's mirrored copy into ONE mutual edge per unordered pair.
      // Prefer the locally-issued row (issuer === self) so the edge keeps its issuer->subject orientation and a
      // stable id across reloads, whichever row is seen first.
      const pairKey = source < target ? `${source}|${target}` : `${target}|${source}`;
      const prevIndex = vrcEdgeIndexByPair.get(pairKey);
      if (prevIndex !== undefined) {
        if (edges[prevIndex].source !== selfUuid && source === selfUuid) {
          edges[prevIndex] = edge;
        }
        continue;
      }
      vrcEdgeIndexByPair.set(pairKey, edges.length);
    }
    edges.push(edge);
  }

  // ── Delegation edges (principal -> dependent), canonicalized ──
  // `delegations` is uuid-first (migration 0018) — `uuid` is the row key (mirrors the utility server's route).
  const delRows = await db.all<{
    uuid: string; principal_identity_uuid: string; dependent_identity_uuid: string; relationship_type: string;
  }>(`
    SELECT uuid, principal_identity_uuid, dependent_identity_uuid, relationship_type
    FROM delegations WHERE revoked_at IS NULL
  `);

  for (const d of delRows) {
    const source = resolveLocalUuid(canonicalize, d.principal_identity_uuid);
    const target = resolveLocalUuid(canonicalize, d.dependent_identity_uuid);
    if (source === target) continue;
    nodeUuids.add(source);
    nodeUuids.add(target);
    edges.push({
      id: `delegation:${d.uuid}`, source, target,
      kind: 'delegation', label: d.relationship_type, relationshipType: d.relationship_type,
    });
  }


  // ── Peer relationship edges (relationships table), canonicalized ──
  // Includes personhoodStatus so the UI can distinguish plain transport peers from ones that have completed the
  // mutual-acknowledgment ceremony.
  const relRows = await db.all<{
    uuid: string; local_identity_uuid: string; remote_identity_uuid: string;
    direction: string; status: string; personhood_status: string | null;
  }>(`
    SELECT uuid, local_identity_uuid, remote_identity_uuid, direction, status, personhood_status
    FROM relationships
  `);

  for (const r of relRows) {
    const source = resolveLocalUuid(canonicalize, r.local_identity_uuid);
    const target = resolveLocalUuid(canonicalize, r.remote_identity_uuid);
    if (source === target) continue;
    // Skip a bare peer edge when a credential edge already connects the same pair in EITHER direction — the VRC
    // edge is the meaningful one, and drawing both would double the line.
    const hasCredential = edges.some((e) =>
      e.kind === 'credential' &&
      ((e.source === source && e.target === target) || (e.source === target && e.target === source)),
    );
    if (hasCredential) { nodeUuids.add(source); nodeUuids.add(target); continue; }
    nodeUuids.add(source);
    nodeUuids.add(target);
    edges.push({
      id: `peer:${r.uuid}`, source, target,
      kind: 'peer', label: 'peer', status: r.status, direction: r.direction,
      personhoodStatus: r.personhood_status ?? undefined,
    });
  }

  // Ensure self is always present, even with zero edges.
  nodeUuids.add(selfUuid);

  // ── VTC membership ──
  // The active members of each community, so the frontend can list them when a VTC node is clicked.
  const memberRows = await db.all<{
    community_identity_uuid: string; member_identity_uuid: string; role: string;
  }>(`
    SELECT community_identity_uuid, member_identity_uuid, role
    FROM memberships WHERE status = 'active'
  `);

  const membersByCommunity = new Map<string, Array<{ uuid: string; label: string; role: string }>>();
  for (const m of memberRows) {
    const community = resolveLocalUuid(canonicalize, m.community_identity_uuid);
    const memberUuid = resolveLocalUuid(canonicalize, m.member_identity_uuid);
    if (community === memberUuid) continue;
    const memberMeta = metaByUuid.get(memberUuid);
    const list = membersByCommunity.get(community) ?? [];
    list.push({
      uuid: memberUuid,
      label: memberMeta?.name || `#${memberUuid.slice(0, 8)}`,
      role: m.role,
    });
    membersByCommunity.set(community, list);
  }

  const nodes: GraphNodeDto[] = [];
  for (const uuid of nodeUuids) {
    const meta = metaByUuid.get(uuid);
    const isSelf = uuid === selfUuid;
    const subjectKind = meta?.subjectKind ?? 'human';
    const role = meta?.role ?? 'vta';
    nodes.push({
      id: uuid,
      label: isSelf
        ? (opts.selfName || 'Me')
        : friendlyLabel(
            {
              name: meta?.name ?? null,
              registeredName: meta?.registeredName ?? null,
              namespace: meta?.namespace ?? null,
              subjectKind,
              vid: meta?.vid ?? null,
            },
            uuid,
          ),
      role,
      subjectKind,
      isSelf,
      identityUuid: uuid,
      did: isSelf ? opts.selfDid : (meta?.did ?? null),
      // `members` is set only on a VTC node — and to an ARRAY even when empty, matching the adapter's shape
      // (the key's presence is what the page keys off).
      members: role === 'vtc' ? (membersByCommunity.get(uuid) ?? []) : undefined,
    });
  }

  return { nodes, edges };
}
