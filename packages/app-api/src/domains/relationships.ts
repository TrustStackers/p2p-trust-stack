// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `relationships` domain — OOBI, connect, list/get, ceremony, and the VRC checks.
 *
 * Wraps the runtime's relationship surface. Two things are deliberate:
 *
 * 1. **No raw SQL.** `verify()` and `dtgVrc()` in the adapter resolve identity uuids with inline `SELECT ...
 *    JOIN` through `getActiveDb()`. Here they go through `identities-repo` on the agent's own database, which
 *    is the coupling this layer exists to remove.
 * 2. **`graph()` and `debug()` ARE here** (P3 rest, 2026-10-09). `GET /api/graph` was ~150 lines of raw SQL
 *    plus ephemeral-`did:peer:4` canonicalization; `GET /api/relationships/:id/debug` reached into the
 *    adapter's `libp2pNode`. Both are now domain methods — the SQL moved behind `DataSource` and the libp2p
 *    reach became the declared `AgentHandle.getPeerConnections()`. The graph's rendering rules live in
 *    `relationships-graph.ts`; read that before changing anything about them.
 */
import { requireAgent, type DomainContext } from './context.js';
import { StackError } from '../errors.js';
import { resolvePeerAgentName } from '../runtime/peer-name.js';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { loadP2ptsConfig } from '@p2p-trust-stack/core/platform/p2pts-home.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { generatePersonhoodChallenge } from '@p2p-trust-stack/core/services/verified-channel.js';
import { getDtgRelationshipCredentials, isDtgVerifiedChannel } from '@p2p-trust-stack/core/services/verified-channel.js';
import type { RelationshipRecord } from '@p2p-trust-stack/core/relationship/types.js';
import type { TransportAddress } from '@p2p-trust-stack/core/transport/types.js';
import type { DiscoveredPeerDto } from '../dto/connectivity.js';
import { buildGraph, type GraphDto } from './relationships-graph.js';

export type { GraphDto, GraphNodeDto, GraphEdgeDto } from './relationships-graph.js';

/**
 * Diagnostics for one peer — the `/api/relationships/:id/debug` payload.
 *
 * Deliberately truncated, not raw: `remoteDid` is sliced and the transport keys are reduced to booleans, because
 * this is a debug view meant to be read, not a data export.
 */
export interface PeerDebugDto {
  remoteDid: string;
  direction: string;
  status: string;
  hasEd25519Key: boolean;
  hasX25519Key: boolean;
  transport: { peerId: string; multiaddrs: string[] } | null;
  libp2pConnected: boolean;
  libp2pConns: Array<{ remoteAddr: string | null; direction: string | null; status: string | null }>;
  createdAt: number;
  updatedAt: number;
}

/** A relationship as the API presents it — the runtime record, plus the ceremony ack view when available. */
export interface RelationshipDto {
  remoteDid: string;
  localDid: string;
  direction: string;
  status: string;
  personhoodStatus?: string;
  remoteSubjectKind?: string | null;
  /**
   * Where the peer can be reached, as the relationship recorded it.
   *
   * Was `{ peerId?: string }` — an under-declaration of what the runtime actually stores
   * (`TransportAddress`, whose `multiaddrs` are optional but whose `peerId` is required). A consumer that needed
   * the addresses (the TUI's connection-state label does) had to cast to reach them.
   */
  remoteTransport?: TransportAddress | null;
  /**
   * The peer's agent login name, or null when they never registered one.
   *
   * Resolved here rather than in the adapter: the chat UI renders it as the primary label, and resolving it
   * needs the peer's Ed25519 key (the reliable identifier when a peer's name landed on an ephemeral
   * `did:peer:4` sibling row) — which is relationship data, not presentation data.
   */
  remoteName?: string | null;
  /** Ceremony acknowledgement view, attached for an established-but-unverified relationship. */
  ack?: unknown;
}

/**
 * A pending duplicate-connect notice — a peer presented an OOBI already bound to a different identity.
 *
 * Carries no DIDs: the caller already has the peer it asked about, and the notice's only job is to say WHO the
 * other identity claims to be and WHEN the collision was seen.
 */
export interface DuplicateNoticeDto {
  /** The name the other identity claims, or null when it never registered one. */
  remoteName: string | null;
  /** Unix milliseconds when the collision was recorded. */
  at: number;
}

export interface ConnectResultDto {
  ok: true;
  message: string;
}

export interface OobiDto {
  oobi: string;
}

export interface CeremonyStatusDto {
  remoteDid: string;
  personhoodStatus: string | null;
  direction: string | null;
  status: string | null;
  ceremony: Record<string, unknown> | null;
}

export interface ResetCeremonyDto {
  success: boolean;
  error?: string;
  reset?: boolean;
}

export interface VerifyResultDto {
  ok: true;
  /** A truncated challenge nonce, for display. */
  nonce: string;
  message: string;
}

export interface VrcStatusDto {
  verified: boolean;
  vrcs: unknown[];
}

export interface DtgVrcStatusDto {
  verified: boolean;
  dtgVrcs: unknown[];
}

export interface RelationshipsApi {
  /** This agent's OOBI, for a peer to connect to. */
  oobi(): Promise<OobiDto>;
  /** Initiate a connection from a pasted OOBI. Emits `relationship.changed`. */
  connect(oobi: string): Promise<ConnectResultDto>;
  /**
   * Connect to a peer **discovered through the bootstrap server**.
   *
   * Distinct from `connect(oobi)`: the caller holds a discovery RECORD, not an OOBI, and turning one into the
   * other is a protocol detail — a strict 4-item OOBI needs the peer's DID, peer id and multiaddrs in a fixed
   * frame. A caller forced to build that would be reimplementing the OOBI codec, which is exactly what the web
   * adapter does today. `DiscoveredPeerDto` is already public (it aliases the transport's discovery result), so
   * this needs no new type.
   */
  connectDiscovered(peer: DiscoveredPeerDto): Promise<ConnectResultDto>;
  /**
   * Re-dial an existing peer whose connection has gone quiet.
   *
   * Distinct from `connect(oobi)`: this addresses a peer we already have a relationship with, by DID, and asks
   * the runtime to refresh bootstrap peers and dial directly. It is the recovery action a UI offers when a send
   * fails — "ask the other side to re-connect" is the fallback, and this is the half we can do ourselves.
   *
   * Refuses with `not_found` when there is no such relationship, so a typo cannot look like a successful dial.
   */
  reconnect(peerDid: string): Promise<{ ok: true }>;
  /**
   * A pending **duplicate-connect notice** for a peer, or null.
   *
   * When someone presents an OOBI that is already bound to a different identity, the runtime records a
   * one-shot notice. `duplicate.connect.notice` pushes it; this reads it back, which is what lets a UI that was
   * CLOSED when it arrived still surface it. Reading consumes it, so a caller must not poll this in a loop — the
   * event is the push path and this is the catch-up path.
   */
  duplicateNotice(peerDid: string): Promise<DuplicateNoticeDto | null>;
  /** Chat-eligible relationships (organization and self-referencing rows filtered out). */
  list(): Promise<RelationshipDto[]>;
  /** One relationship, or null. */
  get(peerDid: string): Promise<RelationshipDto | null>;
  /** Tear down a relationship. Emits `relationship.changed`. */
  disconnect(peerDid: string): Promise<{ ok: true }>;
  /** Acknowledge the personhood ceremony for a peer. Emits `relationship.ceremony`. */
  acknowledge(peerDid: string): Promise<{ ok: true; message: string; personhoodStatus: string }>;
  /** Durable ceremony-saga state for a peer. */
  ceremonyStatus(peerDid: string): Promise<CeremonyStatusDto>;
  /** Reset a stuck ceremony so a fresh OOBI exchange can be attempted. Emits `relationship.ceremony`. */
  resetCeremony(peerDid: string): Promise<ResetCeremonyDto>;
  /** Send a personhood challenge to a peer. */
  verify(peerDid: string): Promise<VerifyResultDto>;
  /** Whether a live VRC covers this peer. */
  vrc(peerDid: string): Promise<VrcStatusDto>;
  /** Whether a DTG relationship credential covers this peer. */
  dtgVrc(peerDid: string): Promise<DtgVrcStatusDto>;
  /**
   * The relationship graph — every identity this agent knows about, and the edges between them.
   *
   * Ported from the adapter's `GET /api/graph` (P3 rest). The shape is unchanged; the SQL is not (it now runs
   * through `DataSource` rather than the adapter's raw `DatabaseSync` handle). See `relationships-graph.ts` for
   * the rendering rules — ephemeral-`did:peer:4` canonicalization, VRC pair-collapsing, and peer-edge
   * suppression are the parts worth reading before changing anything here.
   */
  graph(): Promise<GraphDto>;
  /**
   * Diagnostics for one peer: identity, transport, and live libp2p connection state.
   *
   * Returns `null` when there is no relationship record for that peer — the route turns that into its 404.
   */
  debug(peerDid: string): Promise<PeerDebugDto | null>;
}

/** Build the `relationships` domain. */
export function createRelationshipsApi(ctx: DomainContext): RelationshipsApi {
  /** Project a runtime relationship record onto the contract. */
  function toDto(r: RelationshipRecord): RelationshipDto {
    const rec = r as RelationshipRecord & {
      remoteSubjectKind?: string | null;
      remoteTransport?: TransportAddress | null;
    };
    return {
      remoteDid: rec.remoteDid,
      localDid: rec.localDid,
      direction: rec.direction,
      status: rec.status,
      personhoodStatus: rec.personhoodStatus,
      remoteSubjectKind: rec.remoteSubjectKind ?? null,
      remoteTransport: rec.remoteTransport ?? null,
    };
  }

  /** Resolve an identity uuid from a DID out of the agent's own database, via the repository. */
  async function identityUuidFor(agentName: string, did: string): Promise<string | null> {
    let ds: SqliteDataSource | null = null;
    try {
      ds = ctx.host.storageFor(agentName) as SqliteDataSource;
      const row = await identitiesRepo.findByRealDid(ds, did);
      return row?.uuid ?? null;
    } catch {
      return null;
    } finally {
      if (ds) await ds.close();
    }
  }

  return {
    async oobi(): Promise<OobiDto> {
      const agent = requireAgent(ctx, 'generate an OOBI');
      return { oobi: agent.generateOobi() };
    },

    async connect(oobi: string): Promise<ConnectResultDto> {
      const agent = requireAgent(ctx, 'connect to a peer');
      const cleaned = String(oobi ?? '').replace(/\s+/g, '');
      if (!cleaned) throw new Error('oobi is required');
      // A duplicate OOBI connect throws a relationship-exists error carrying a stable `code`; it is not
      // swallowed here — the adapter maps it to 409 and the caller can branch on `code`.
      await agent.connectToPeer(cleaned);
      ctx.bus.emit('relationship.changed', {
        peerDid: cleaned.slice(0, 64),
        status: 'initiated',
        at: Date.now(),
      });
      return { ok: true, message: 'Connection initiated' };
    },

    async connectDiscovered(peer: DiscoveredPeerDto): Promise<ConnectResultDto> {
      const agent = requireAgent(ctx, 'connect to a discovered peer');
      if (!peer?.peerId) throw new StackError('invalid_input', 'peerId is required');
      // The runtime owns the OOBI construction from a discovery record — see the interface note.
      await agent.connectToDiscoveredPeer(peer);
      ctx.bus.emit('relationship.changed', {
        peerDid: peer.did ?? peer.peerId,
        status: 'initiated',
        at: Date.now(),
      });
      return { ok: true, message: 'Connection initiated' };
    },

    async list(): Promise<RelationshipDto[]> {
      const agent = requireAgent(ctx, 'list relationships');
      const rels = agent.listRelationships();

      // Only human-to-human relationships are chat-eligible: the utility server is tagged
      // subject_kind='organization' (infrastructure, not a chat peer), and a self-referencing row left by a
      // pre-guard self-connect must never render as a pending line.
      const human = rels.filter(
        (r) =>
          ((r as { remoteSubjectKind?: string }).remoteSubjectKind ?? 'human') !== 'organization' &&
          r.remoteDid !== r.localDid,
      );

      // One DataSource for the whole listing — name resolution runs per row, and opening a connection per row
      // would be the wrong shape for a route the dashboard polls.
      let ds: SqliteDataSource | null = null;
      try {
        ds = ctx.host.storageFor(agent.getName()) as SqliteDataSource;
      } catch {
        ds = null; // names degrade to null; the relationship listing still works
      }

      const out: RelationshipDto[] = [];
      try {
        for (const r of human) {
          const dto = toDto(r);
          if (ds) {
            try {
              dto.remoteName = resolvePeerAgentName(ds.getRawDb(), {
                remoteDid: r.remoteDid,
                remoteEd25519Key: r.remoteEd25519Key ?? null,
              });
            } catch {
              dto.remoteName = null;
            }
          }
          // Attach the ceremony ack view for an established-but-unverified peer, so the dashboard renders the
          // real ack state rather than guessing. Non-fatal: the per-peer ceremony-status call is the fallback.
          if (r.direction === 'bidirectional' && r.status === 'established' && r.personhoodStatus !== 'verified') {
            try {
              const cs = await agent.getCeremonyStatus?.(r.remoteDid);
              if (cs?.ack) dto.ack = cs.ack;
            } catch {
              /* leave `ack` absent */
            }
          }
          out.push(dto);
        }
      } finally {
        if (ds) await ds.close();
      }
      return out;
    },

    async get(peerDid: string): Promise<RelationshipDto | null> {
      const agent = requireAgent(ctx, 'read a relationship');
      const record = agent.getRelationship(peerDid);
      return record ? toDto(record) : null;
    },

    async disconnect(peerDid: string): Promise<{ ok: true }> {
      const agent = requireAgent(ctx, 'disconnect a peer');
      await agent.disconnectPeer(peerDid);
      ctx.bus.emit('relationship.changed', { peerDid, status: 'disconnected', at: Date.now() });
      return { ok: true };
    },

    async reconnect(peerDid: string): Promise<{ ok: true }> {
      const agent = requireAgent(ctx, 'reconnect to a peer');
      if (!peerDid) throw new StackError('invalid_input', 'peerDid is required');
      // Guard on a KNOWN relationship first: the runtime's dial is happy to attempt an unknown DID, so without
      // this a typo would report a successful reconnect that could never have worked.
      if (!agent.getRelationship(peerDid)) {
        throw new StackError('not_found', `No relationship with '${peerDid}'.`);
      }
      await agent.reconnectPeer(peerDid);
      ctx.bus.emit('relationship.changed', { peerDid, status: 'reconnected', at: Date.now() });
      return { ok: true };
    },

    async duplicateNotice(peerDid: string): Promise<DuplicateNoticeDto | null> {
      requireAgent(ctx, 'read a duplicate-connect notice');
      if (!peerDid) throw new StackError('invalid_input', 'peerDid is required');
      // Optional on the handle: an implementation that does not track duplicate connects has none to report,
      // which is a null rather than an error.
      const notice = ctx.getAgent()?.getDuplicateConnectNotice?.(peerDid);
      return notice ? { remoteName: notice.remoteName, at: notice.at } : null;
    },

    async acknowledge(peerDid: string) {
      const agent = requireAgent(ctx, 'acknowledge a ceremony');
      if (!peerDid) throw new Error('peerDid is required');
      agent.acknowledgeRemotePeer?.(peerDid);
      const record = agent.getRelationship(peerDid);
      ctx.bus.emit('relationship.ceremony', { peerDid, step: 'acknowledged', at: Date.now() });
      return {
        ok: true as const,
        message: 'Acknowledgment sent',
        personhoodStatus: record?.personhoodStatus ?? 'acknowledged',
      };
    },

    async ceremonyStatus(peerDid: string): Promise<CeremonyStatusDto> {
      const agent = requireAgent(ctx, 'read ceremony status');
      const record = agent.getRelationship(peerDid);
      let ceremony: Record<string, unknown> | null = null;
      try {
        ceremony = ((await agent.getCeremonyStatus?.(peerDid)) as Record<string, unknown> | undefined) ?? null;
      } catch {
        /* the durable saga state is best-effort */
      }
      return {
        remoteDid: peerDid,
        personhoodStatus: record?.personhoodStatus ?? null,
        direction: record?.direction ?? null,
        status: record?.status ?? null,
        ceremony,
      };
    },

    async resetCeremony(peerDid: string): Promise<ResetCeremonyDto> {
      const agent = requireAgent(ctx, 'reset a ceremony');
      if (!peerDid) throw new Error('peerDid is required');
      if (!agent.resetPersonhoodCeremony) {
        return { success: false, error: 'ceremony reset is not supported by this agent' };
      }
      const result = await agent.resetPersonhoodCeremony(peerDid);
      if (result.success) {
        ctx.bus.emit('relationship.ceremony', { peerDid, step: 'reset', at: Date.now() });
      }
      return result;
    },

    async verify(peerDid: string): Promise<VerifyResultDto> {
      const agent = requireAgent(ctx, 'send a personhood challenge');
      if (!peerDid) throw new Error('peerDid is required');

      const selfUuid = await identityUuidFor(agent.getName(), agent.getDid());
      if (!selfUuid) throw new Error('local identity not found');

      const ds = ctx.host.storageFor(agent.getName());
      try {
        const challenge = await generatePersonhoodChallenge(ds, selfUuid);
        const payload = new TextEncoder().encode(JSON.stringify(challenge));
        // Reconnect first: a NAT'd peer may have no live libp2p connection after the handshake.
        try {
          await agent.reRegisterWithBootstrap();
          await agent.reconnectPeer(peerDid);
        } catch {
          /* best effort — sendMessage will attempt its own dial */
        }
        await agent.sendMessage(peerDid, payload);
        return { ok: true, nonce: challenge.nonce.slice(0, 16) + '…', message: 'Challenge sent' };
      } finally {
        await ds.close();
      }
    },

    async vrc(peerDid: string): Promise<VrcStatusDto> {
      const agent = requireAgent(ctx, 'read VRC status');
      if (!peerDid) throw new Error('peerDid is required');
      const vrcs = agent.listVrcsForSelf();
      const related = vrcs.filter((vrc) => {
        const v = vrc as { issuer?: string; subject?: string; status?: string };
        return (v.issuer === peerDid || v.subject === peerDid) && v.status === 'issued';
      });
      return { verified: related.length > 0, vrcs: related };
    },

    async dtgVrc(peerDid: string): Promise<DtgVrcStatusDto> {
      const agent = requireAgent(ctx, 'read DTG VRC status');
      if (!peerDid) throw new Error('peerDid is required');

      const selfUuid = await identityUuidFor(agent.getName(), agent.getDid());
      const remoteUuid = await identityUuidFor(agent.getName(), peerDid);
      if (!selfUuid || !remoteUuid) return { verified: false, dtgVrcs: [] };

      const ds = ctx.host.storageFor(agent.getName());
      try {
        const dtgVrcs = await getDtgRelationshipCredentials(ds, selfUuid, remoteUuid);
        const verified = await isDtgVerifiedChannel(ds, selfUuid, remoteUuid);
        return { verified, dtgVrcs };
      } finally {
        await ds.close();
      }
    },

    async graph(): Promise<GraphDto> {
      const agent = requireAgent(ctx, 'read the relationship graph');
      const ds = ctx.host.storageFor(agent.getName()) as SqliteDataSource;
      try {
        // The VTN this agent joined — `config.yaml`'s `vtn:` key, which is what
        // `bootstrapConfig.recordVtn()` writes when the user picks a network and
        // what the bootstrap registers. `buildGraph` appends it to the
        // utility-server/VTN node labels so the graph names the network it is
        // connected to. Absent when no VTN was chosen: the labels stay plain.
        const vtnKey = loadP2ptsConfig(ctx.host.home).vtn.trim() || undefined;
        return await buildGraph(ds, {
          selfDid: agent.getDid(),
          selfName: agent.getName(),
          vtnKey,
        });
      } finally {
        await ds.close();
      }
    },

    async debug(peerDid: string): Promise<PeerDebugDto | null> {
      const agent = requireAgent(ctx, 'read peer diagnostics');
      const record = agent.getRelationship(peerDid) as
        | (RelationshipRecord & { remoteTransport?: { peerId: string; multiaddrs: string[] } | null })
        | undefined;
      if (!record) return null;

      // Live connection state comes from the runtime, not from a raw node handle: the adapter used to reach into
      // `deps.libp2pNode as any` here, which is a dependency this layer deliberately does not own.
      const peerId = record.remoteTransport?.peerId;
      const conns = peerId ? (agent.getPeerConnections?.(peerId) ?? []) : [];

      return {
        remoteDid: record.remoteDid.slice(0, 24) + '...',
        direction: record.direction,
        status: record.status,
        hasEd25519Key: !!record.remoteEd25519Key,
        hasX25519Key: !!record.remoteX25519Key,
        transport: record.remoteTransport
          ? {
              peerId: record.remoteTransport.peerId.slice(0, 12) + '...',
              multiaddrs: record.remoteTransport.multiaddrs,
            }
          : null,
        libp2pConnected: conns.length > 0,
        libp2pConns: conns,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
      };
    },
  };
}

