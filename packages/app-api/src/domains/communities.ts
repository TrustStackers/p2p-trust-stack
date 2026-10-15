// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `communities` domain — the community list, its detail view, and the founding/invitation ceremonies.
 *
 * ## SQL-free by construction
 *
 * Every read here goes through a repository (`identities-repo`, `governance-repo`, `memberships-repo`,
 * `did-documents-repo`) or through a service that owns the concern (`resolveCommunityClaimTypes`). This domain
 * assembles; it does not query. The three `.prepare(` statements the detail route used to hold — a
 * three-table join for the community, a roster join, and a policy-binding scan — are gone.
 *
 * ## What it does NOT own
 *
 * The **ceremony machinery** stays where it is. This domain *asks* for a ceremony
 * (`createCommunityCeremony` / `approveCeremony` / `resetCeremony`), and the utility server drives the
 * catalogued `vtc-establish` ceremony through the shared trust-task driver inside a 2PC transaction. Nothing
 * here re-implements, shortcuts or reorders that. The read-only ceremony queries
 * (`ceremony_log_*`, `ceremony_pending_for`) go through `AgentHandle.queryUtilityServer`, which is a bare
 * request/response — correct for reads, and never used for a mutation.
 */
import { requireAgent, type DomainContext } from './context.js';
import { StackError } from '../errors.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import { resolveCommunityClaimTypes } from '@p2p-trust-stack/core/services/policy-bindings.js';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type {
  AdminCandidateDto,
  CeremonyLogStepDto,
  CeremonyLogThreadDto,
  CeremonyStatusDto,
  CommunityDetailDto,
  CommunityDto,
  CommunityInviteDto,
  CommunityMemberDto,
  CommunityNameCheckDto,
  CreateCommunityResultDto,
  GovernanceChangeResultDto,
  GovernanceDocDto,
  GovernanceProposalDto,
  ParentVtnDto,
  PendingCeremonyDto,
} from '../dto/communities.js';

export interface CommunitiesDeps {
  /** The active agent's database, or null before activation. */
  dataSource(): DataSource | null;
}

/** Raised when a community cannot be resolved from the identifier given. */
export class CommunityNotFoundError extends StackError {
  constructor(identifier: string) {
    super('community_not_found', `No community matches '${identifier}'.`);
  }
}

/** Roles that denote a community rather than a person or this agent itself. */
const COMMUNITY_ROLES = new Set(['vtc', 'vtn']);

function requireDb(deps: CommunitiesDeps): DataSource {
  const db = deps.dataSource();
  if (!db) throw new StackError('no_database', 'The active agent has no database.');
  return db;
}

/**
 * Resolve a community identity from EITHER its stable uuid OR its real DID.
 *
 * Both are accepted because `listCommunitiesFromDb()` projects `COALESCE(dd.did, uuid)` as the row's `did`, so
 * a caller can legitimately hand back either form. Returns null when nothing matches or the identity is not a
 * community — the two cases are one answer for every caller here.
 */
async function resolveCommunity(db: DataSource, identifier: string) {
  const byUuid = await identitiesRepo.findByUuid(db, identifier);
  if (byUuid && COMMUNITY_ROLES.has(byUuid.role)) return byUuid;
  const byDid = await identitiesRepo.findByRealDid(db, identifier);
  if (byDid && COMMUNITY_ROLES.has(byDid.role)) return byDid;
  return null;
}

export interface CommunitiesApi {
  /** Communities this agent knows about, with the caller's own membership role. */
  list(): Promise<CommunityDto[]>;
  /**
   * Every community's **signed governance document, projected** — name, kind, threshold, allowed claim types
   * and an admin count.
   *
   * The projection is the point. The raw `VtcGovernanceDoc` carries `adminVids` (CESR public keys), a `digest`
   * and the founding `signatures`; this method publishes none of them. It exists so a client never has to reach
   * the runtime for `listVtcGovernanceDocs()`, which is what `GET /api/vtcs` used to do.
   */
  governanceDocs(): Promise<GovernanceDocDto[]>;
  /** One community's roster and governance. */
  detail(did: string): Promise<CommunityDetailDto>;
  /** Pre-flight name availability, answered by the utility server (the system of record). */
  checkName(name: string): Promise<CommunityNameCheckDto>;
  /** Candidate parent VTNs for the create-community picker. */
  parents(): Promise<ParentVtnDto[]>;
  /** Founding-admin candidates: this agent plus its VRC-connected peers. */
  adminCandidates(): Promise<AdminCandidateDto[]>;
  /** Invite a person to a community (server-mediated VIC mint). */
  invite(did: string, body: {
    subjectDid?: string;
    subjectName?: string;
    subjectIdentityUuid?: string;
    taskContext?: string;
  }): Promise<CommunityInviteDto>;
  /** Begin a community-founding ceremony. */
  create(params: {
    name: string;
    kind?: 'vtc' | 'vtn';
    threshold?: number;
    adminUuids: string[];
    parentCommunityUuid?: string;
  }): Promise<CreateCommunityResultDto>;
  /** Pending governance-change proposals this agent may approve. */
  governanceProposals(): Promise<GovernanceProposalDto[]>;
  /** Propose a community rule/threshold change. */
  propose(params: {
    communityUuid: string;
    change: unknown;
    scope?: 'admins' | 'members' | 'all_members';
    minApprovals?: number;
  }): Promise<GovernanceChangeResultDto>;
  /** Co-sign a pending governance-change proposal. */
  approve(proposalId: string): Promise<GovernanceChangeResultDto>;
  /** What the server's ceremonies did, newest first. */
  ceremonyLog(): Promise<CeremonyLogThreadDto[]>;
  /** One ceremony run's recorded steps, in order. */
  ceremonyLogThread(threadId: string): Promise<CeremonyLogStepDto[]>;
  /** Ceremonies awaiting THIS agent's co-signature. */
  pendingCeremonies(): Promise<PendingCeremonyDto[]>;
  /** Co-sign a pending ceremony. */
  approveCeremony(ceremonyId: string): Promise<{ success: boolean; status?: string; error?: string }>;
  /** Read a founding ceremony's current state. */
  ceremony(ceremonyId: string): Promise<CeremonyStatusDto>;
  /** Abandon a ceremony so it can be started again. */
  resetCeremony(ceremonyId: string): Promise<{ success: boolean; error?: string }>;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export function createCommunitiesApi(ctx: DomainContext, deps: CommunitiesDeps): CommunitiesApi {
  return {
    async list(): Promise<CommunityDto[]> {
      const agent = requireAgent(ctx, 'list communities');
      // The runtime already projects this list (it drives the list from `governance`, not from a role tag, so
      // a community shows regardless of how its identity row was tagged). Re-deriving it here would duplicate
      // that rule and risk the two drifting.
      const rows = agent.listCommunitiesFromDb?.() ?? [];
      return rows as CommunityDto[];
    },

    async governanceDocs(): Promise<GovernanceDocDto[]> {
      const agent = requireAgent(ctx, 'list community governance documents');
      const db = requireDb(deps);
      const docs = agent.listVtcGovernanceDocs();

      // `kind` comes from the local `identities.role`, resolved in ONE query rather than per document. It is a
      // local classification, not part of the signed governance doc, so it is resolved here instead of being
      // added to `VtcGovernanceDoc` — which would imply the admins signed it.
      //
      // Keyed by DID, which means joining `did_documents`: `identities` has no `did` column, and a first cut of
      // this method keyed the map by uuid while looking it up by DID, so every lookup missed.
      const roleByDid = new Map<string, string>();
      const roleRows = await db.all<{ did: string; role: string }>(
        `SELECT d.did AS did, i.role AS role
           FROM identities i
           JOIN did_documents d ON d.identity_uuid = i.uuid AND d.is_primary = 1`,
      );
      for (const row of roleRows) roleByDid.set(row.did, row.role);

      return docs.map((doc) => {
        // `vtcDid` is the DID the store resolved, and `vtcVid` is a DID too for a store-loaded doc (see
        // `governanceRowToDoc`) — so this is a preference order, not a conversion.
        const did = doc.vtcDid || doc.vtcVid;
        return {
          did,
          name: doc.name || '',
          // An unresolvable role falls back to `'vtc'`, which is what the old page rendered for everything
          // anyway — but now it is a stated fallback rather than a field that never existed.
          kind: roleByDid.get(did) ?? 'vtc',
          threshold: doc.threshold,
          allowedClaimTypes: doc.allowedClaimTypes,
          // A COUNT, never the list: `adminVids` are CESR public keys and `adminDids` are identity DIDs, and
          // neither belongs on the wire.
          adminCount: doc.adminVids.length,
          createdAt: doc.createdAt,
        };
      });
    },

    async detail(did: string): Promise<CommunityDetailDto> {
      requireAgent(ctx, 'read a community');
      const db = requireDb(deps);

      const comm = await resolveCommunity(db, did);
      if (!comm) throw new CommunityNotFoundError(did);

      // Governance is a separate table keyed by community uuid; a community without a row simply has no
      // thresholds yet, which is what the LEFT JOIN used to express as nulls.
      const governance = await governanceRepo.findForCommunity(db, comm.uuid);

      // Roster: the membership rows carry role/status/personhood, the identities carry the display name and
      // DID. Two queries total — `Identity` already resolves the primary DID, so there is no per-member hop.
      const memberships = await membershipsRepo.findForCommunity(db, comm.uuid);
      const identities = await identitiesRepo.list(db);
      const byUuid = new Map(identities.map((i) => [i.uuid, i]));
      const members: CommunityMemberDto[] = memberships.map((m) => {
        const identity = byUuid.get(m.memberIdentityUuid);
        return {
          name: identity?.name || '(unnamed)',
          did: identity?.did ?? null,
          role: m.role,
          status: m.status,
          personhoodAsserted: m.personhoodAsserted,
        };
      });

      // Allowed claim types live in claim-type bindings (there is no policy blob). The service owns that
      // convention — including the `#<claimType>` rule_type suffix — so this domain does not encode it.
      const allowedClaimTypes = await resolveCommunityClaimTypes(db, comm.uuid);

      return {
        name: comm.name || '(unnamed)',
        did: comm.did ?? comm.uuid,
        role: comm.role,
        uuid: comm.uuid,
        governance: {
          adminThresholdM: governance?.adminThresholdM ?? null,
          adminThresholdN: governance?.adminThresholdN ?? null,
          allowedClaimTypes,
          parentCommunityUuid: governance?.parentCommunityUuid ?? null,
        },
        members,
      };
    },

    async checkName(name: string): Promise<CommunityNameCheckDto> {
      const agent = requireAgent(ctx, 'check a community name');
      const trimmed = name.trim();
      if (!trimmed) return { available: false, message: 'name is required' };
      // The utility server is the system of record for names, so this asks it. A missing server link throws
      // `utility_server_unavailable`, which the route turns into a 503 — the caller can retry.
      const result = await agent.queryUtilityServer?.<CommunityNameCheckDto>('name_check', { name: trimmed });
      if (!result || typeof result.available !== 'boolean') {
        throw new StackError('name_check_failed', 'Name check returned an unexpected result.');
      }
      return result;
    },


    async parents(): Promise<ParentVtnDto[]> {
      const agent = requireAgent(ctx, 'list parent VTNs');
      const found: ParentVtnDto[] = [];

      // (a) VTNs this agent already knows locally — the communities it is a member of.
      try {
        for (const c of await this.list()) {
          if (c.role === 'vtn' && c.uuid) {
            found.push({ uuid: c.uuid, name: c.name ?? null, did: c.did ?? null, namespace: null });
          }
        }
      } catch { /* the local list is best-effort; the server answer below still counts */ }

      // (b) The namespace VTN this agent's server serves. The namespace VTN is a SERVER-side identity and an
      // agent only receives records for communities it is a MEMBER of, so an agent that joined a VTC but not
      // the namespace VTN has no local row — which is exactly why this leg exists. Degrades to (a) offline.
      try {
        const info = await agent.queryUtilityServer?.<{
          configured?: boolean; namespace?: string | null;
          vtnUuid?: string | null; vtnName?: string | null; vtnDid?: string | null;
        }>('namespace_info', {});
        if (info?.configured && info.vtnUuid) {
          found.push({
            uuid: info.vtnUuid,
            name: info.vtnName ?? null,
            did: info.vtnDid ?? null,
            namespace: info.namespace ?? null,
          });
        }
      } catch { /* the server is optional here — the picker still offers the local entries */ }

      // Dedupe by uuid, preferring the entry that carries a namespace: it is the more informative label, and
      // the value the picker submits is identical either way.
      const byUuid = new Map<string, ParentVtnDto>();
      for (const v of found) {
        const existing = byUuid.get(v.uuid);
        if (!existing || (!existing.namespace && v.namespace)) byUuid.set(v.uuid, v);
      }
      return [...byUuid.values()];
    },

    async adminCandidates(): Promise<AdminCandidateDto[]> {
      const agent = requireAgent(ctx, 'list admin candidates');
      const db = requireDb(deps);
      const myDid = agent.getDid();

      // The local store is the source of truth here. A co-admin must be DELIVERABLE (relationship transport +
      // Ed25519 key), and the utility server cannot vouch for that — so its own candidate entries are never
      // merged in, because the create ceremony strictly requires local deliverability.
      const self = (await identitiesRepo.findByRealDid(db, myDid))
        ?? (await identitiesRepo.findByUuid(db, myDid));

      const peers = typeof agent.getVrcConnectedPeers === 'function' ? agent.getVrcConnectedPeers() : [];
      return [
        { uuid: self?.uuid ?? myDid, name: agent.getName() || '(you)', did: myDid, isCreator: true },
        ...peers.map((p) => ({ uuid: p.uuid, name: p.name, did: p.did, isCreator: false })),
      ];
    },

    async invite(did, body): Promise<CommunityInviteDto> {
      const agent = requireAgent(ctx, 'invite a member');
      const db = requireDb(deps);
      const comm = await resolveCommunity(db, did);
      if (!comm) throw new CommunityNotFoundError(did);

      // The server needs the community's STABLE uuid (the cross-node anchor), because the local `did` may be
      // either the real did:peer:4 or the UUIDv5 fallback. The server mints the VIC with the community signing
      // key, so the agent never needs that key (Model A custody).
      const result = await agent.queryUtilityServer?.<CommunityInviteDto>('vtc_invite', {
        communityUuid: comm.uuid,
        inviterDid: agent.getDid(),
        subjectDid: body.subjectDid,
        subjectName: body.subjectName,
        subjectIdentityUuid: body.subjectIdentityUuid,
        taskContext: body.taskContext,
      });
      // The SENDER half of an invitation. `invitation.received` fires on the INVITEE's agent when the VIC is
      // delivered; without this, the inviter's own UI could only learn that an invite went out by re-reading the
      // community — the server-minted VIC never passes through this agent's credential store, so no local signal
      // exists.
      //
      // Emitted only on SUCCESS. A refusal (`result.error`) mints nothing, and announcing a uuid that does not
      // exist would be worse than staying quiet.
      if (result?.invitationUuid) {
        ctx.bus.emit('invitation.sent', {
          uuid: result.invitationUuid,
          communityUuid: comm.uuid,
          at: Date.now(),
        });
      }
      return result ?? {};
    },

    async create(params): Promise<CreateCommunityResultDto> {
      const agent = requireAgent(ctx, 'create a community');
      // The agent generates the ceremony id, so it can query and approve the ceremony afterwards. The server's
      // CeremonyCoordinatorParticipant records the proposal and, on crystallization, drives the catalogued
      // `vtc-establish` ceremony. This domain only asks — it does not run the ceremony.
      const result = await agent.createCommunityCeremony?.({
        name: params.name,
        kind: params.kind ?? 'vtc',
        threshold: params.threshold ?? 1,
        coadminUuids: params.adminUuids,
        parentCommunityUuid: params.parentCommunityUuid,
      });
      return result ?? { success: false, error: 'Community creation is not supported in this deployment mode.' };
    },


    async governanceProposals(): Promise<GovernanceProposalDto[]> {
      const agent = requireAgent(ctx, 'list governance proposals');
      // Typed handle member. An implementation without the capability has no proposals — an empty list, not a
      // throw, because "this deployment has no governance" is a legitimate, renderable state.
      return await (agent.listPendingGovernanceChanges?.() ?? []);
    },

    async propose(params): Promise<GovernanceChangeResultDto> {
      const agent = requireAgent(ctx, 'propose a governance change');
      if (typeof agent.proposeGovernanceChange !== 'function') {
        throw new StackError('not_supported', 'Governance changes are not supported in this deployment mode.');
      }
      // The server resolves the approval scope from the community's own bindings, hashes the proposal, and
      // durably fans it out to every required approver. This domain does not decide scope.
      const result = await agent.proposeGovernanceChange({
        communityUuid: params.communityUuid,
        change: params.change as Parameters<typeof agent.proposeGovernanceChange>[0]['change'],
        scope: params.scope,
        minApprovals: params.minApprovals,
      });
      return result ?? { success: false, error: 'The proposal was not accepted.' };
    },

    async approve(proposalId: string): Promise<GovernanceChangeResultDto> {
      const agent = requireAgent(ctx, 'approve a governance change');
      if (typeof agent.approveGovernanceChange !== 'function') {
        throw new StackError('not_supported', 'Governance changes are not supported in this deployment mode.');
      }
      // The co-signature is a real Ed25519 signature over the proposal hash, verified by the server before
      // crystallization — the same rule the founding ceremony uses.
      const result = await agent.approveGovernanceChange(proposalId);
      return result ?? { success: false, error: 'The approval was not accepted.' };
    },

    async ceremonyLog(): Promise<CeremonyLogThreadDto[]> {
      const agent = requireAgent(ctx, 'read the ceremony log');
      // Read-only, and deliberately on the bare query seam: a log read has nothing to commit, and it must
      // degrade to an empty list rather than throw into a page when the server is down.
      const rows = await (agent.listCeremonyLog?.() ?? []);
      return rows as CeremonyLogThreadDto[];
    },

    async ceremonyLogThread(threadId: string): Promise<CeremonyLogStepDto[]> {
      const agent = requireAgent(ctx, 'read a ceremony run');
      const rows = await (agent.getCeremonyLog?.(threadId) ?? []);
      return rows as CeremonyLogStepDto[];
    },

    async pendingCeremonies(): Promise<PendingCeremonyDto[]> {
      const agent = requireAgent(ctx, 'list pending ceremonies');
      const rows = await (agent.listPendingCeremonies?.() ?? []);
      return rows as PendingCeremonyDto[];
    },

    async approveCeremony(ceremonyId: string): Promise<{ success: boolean; status?: string; error?: string }> {
      const agent = requireAgent(ctx, 'approve a ceremony');
      // A MUTATION: this co-signs with a real Ed25519 key and is submitted through the 2PC coordinator inside
      // the runtime. It must never be routed through the bare query seam — that would lose the transaction.
      return await (agent.approveCeremony?.(ceremonyId)
        ?? { success: false, error: 'Ceremony approval is not supported in this deployment mode.' });
    },

    async ceremony(ceremonyId: string): Promise<CeremonyStatusDto> {
      const agent = requireAgent(ctx, 'check the ceremony status');
      // A read that reports failure in-band (`{ error }`) rather than returning null, so the caller can tell
      // "no such ceremony" from "the server could not be reached".
      return await (agent.queryCeremony?.(ceremonyId)
        ?? { error: 'Ceremony status is not supported in this deployment mode.' });
    },

    async resetCeremony(ceremonyId: string): Promise<{ success: boolean; error?: string }> {
      const agent = requireAgent(ctx, 'reset a ceremony');
      // Also a mutation, through the same 2PC path as `approveCeremony`.
      return await (agent.resetCeremony?.(ceremonyId)
        ?? { success: false, error: 'Ceremony reset is not supported in this deployment mode.' });
    },
  };
}
