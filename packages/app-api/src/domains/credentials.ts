/**
 * `credentials` domain — VRCs, credential signatures, and community invitations.
 *
 * Every read here goes through a repository (`credentials-repo`, `credential-signatures-repo`,
 * `memberships-repo`, `identities-repo`), so this domain contains no SQL of its own.
 *
 * ## What this domain deliberately does NOT do yet
 *
 * Three credential operations are absent from the adapter, and re-adding them is a **contract decision**, not a
 * port. They are listed here so the next reader does not mistake the gap for an oversight:
 *
 *  - **issue** (`POST /api/vrcs`) — deleted from the adapter in `86eb1e8`. The credentials page still posts
 *    `{ vtcVid, subjectVid, claim, signers: [] }`, while `AgentHandle.issueVrc` takes
 *    `{ vtcDid, subjectVid, claim, signers: [{ vid, signingKeyPair }] }`. Deciding the contract means answering
 *    "is the VTC a DID or a CESR VID, and who holds the signing keys?" — and the page sends no keys at all.
 *  - **verify** (`POST /api/vrcs/:id/verify`) — also deleted in `86eb1e8`; its body was pasted over
 *    `GET /api/vrcs`, which is why that route answered `400 id must be an integer` for every request. It
 *    addressed a VRC by numeric `id`, but `AgentHandle.listVrcsForSelf()` returns `Vrc[]` with **no `id`** (the
 *    store drops the rowid), so its lookup could never match. It needs the same identity decision as `issue`.
 *  - **acceptInvitation** (`POST /api/invitations/:uuid/accept`) — **DONE** (2026-10-09). It was blocked on
 *    `_txBootstrap`, `tspBridge` and `tspClient`, none of which are on `AgentHandle`; rather than expose those,
 *    the handle gained ONE seam — `queryUtilityServer(protocol, payload)` — which owns the transport. With the
 *    seam in place the only piece left was this domain's own `UPDATE` that marks the VIC spent, and that is now
 *    `acceptInvitation()`.
 */
import { requireAgent, type DomainContext } from './context.js';
import { NotImplementedError, StackError, UtilityServerUnavailableError } from '../errors.js';
import * as credentialsRepo from '@p2p-trust-stack/core/db/repositories/credentials-repo.js';
import * as signatureRepo from '@p2p-trust-stack/core/db/repositories/credential-signatures-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { CesrVid } from '@p2p-trust-stack/core/tsp/v3/types.js';
import { asCesrVid } from '@p2p-trust-stack/core/vtc/codec.js';
import type { CredentialRow } from '@p2p-trust-stack/core/db/repositories/credentials-repo.js';
import type {
  CredentialKind,
  CredentialScenario,
  CredentialViewModel,
} from '@p2p-trust-stack/core/services/credential-factory/types.js';
import type {
  AcceptInvitationDto,
  CredentialAckDto,
  CredentialDto,
  CredentialSignatureDto,
  CredentialViewModelsDto,
  InvitationDto,
  IssuedCredentialDto,
  IssueVrcInput,
  StoredCredentialDto,
  VerifyVrcInput,
  VrcVerificationDto,
  VtcCredentialDto,
} from '../dto/credentials.js';

export interface CredentialsDeps {
  /** The active agent's database, or null before activation. */
  dataSource(): DataSource | null;
}

/** Filters for the credentials page's read model. Mirrors the factory's own filter shape. */
export interface CredentialViewFilters {
  kind?: CredentialKind;
  scenario?: CredentialScenario;
  status?: 'issued' | 'pending_signatures' | 'revoked' | 'expired';
}

export interface CredentialsApi {
  /** Every credential held for the active identity, from **both** stores. */
  list(): Promise<CredentialDto[]>;
  /**
   * Issue a community credential, signed by the active identity.
   *
   * The subject defaults to the caller (self-issue). Refusals are typed so the page can say which rule was hit:
   * `invalid_input` · `not_found` (no such VTC) · `not_admin` · `claim_not_allowed` · `threshold_not_met`
   * (community needs M>1 signatures; a self-signed credential supplies one) · `unknown_subject`.
   *
   * Emits `credential.issued`.
   */
  issue(input: IssueVrcInput): Promise<IssuedCredentialDto>;
  /**
   * Verify a stored credential against its issuer's locally-known governance doc.
   *
   * Addressed by the VTC store's own composite key — see `VerifyVrcInput` for why neither a rowid nor a UUID
   * works here. Throws `not_found` when no such credential (or no governance doc for its issuer) is known.
   */
  verify(input: VerifyVrcInput): Promise<VrcVerificationDto>;
  /** The co-signatures over one credential, addressed by its **uuid**. `null` when there is no such credential. */
  signatures(uuid: string): Promise<CredentialSignatureDto[] | null>;
  /**
   * Revoke one credential by **uuid**. Emits `credential.changed` and `credential.revoked`.
   * `null` when there is no such credential.
   *
   * Addressed by uuid, like every other credential operation. It took a numeric rowid until 2026-10-10 — a
   * storage detail that no DTO published, which made the method unreachable from any consumer (the web UI's
   * Revoke button was disabled with "no usable id to address").
   */
  revoke(uuid: string): Promise<StoredCredentialDto | null>;
  /** Community invitations addressed to the active identity and not yet consumed. */
  invitations(): Promise<InvitationDto[]>;
  /** Decline an invitation. Emits `invitation.changed`. Idempotent. */
  declineInvitation(uuid: string): Promise<CredentialAckDto>;
  /**
   * Accept a community invitation.
   *
   * Reads the VIC, resolves the community DID from it, asks the utility server to create the membership through
   * the `queryUtilityServer` seam, then **consumes the VIC locally** — once the membership exists the invitation
   * is spent.
   *
   * Emits `invitation.changed`. The route this replaces did NOT announce the consumption, so an accepted
   * invitation stayed in the pending list until a reload; with pushes replacing polls there is nothing to
   * refresh it, so the announcement is part of the port rather than an extra.
   *
   * Throws `not_found` when there is no such VIC, `invalid_invitation` when the community cannot be determined
   * from it, and `utility_server_unavailable` when the server is unreachable (retryable, and the adapter turns
   * that code into a 503 with a layer-aware message).
   */
  acceptInvitation(uuid: string): Promise<AcceptInvitationDto>;
  /** The credentials page's read model: view models, their scenario groupings, and form introspection. */
  viewModels(filters?: CredentialViewFilters): Promise<CredentialViewModelsDto>;
}

/** The active agent's database, or a typed error — a domain never reaches for a DB handle itself. */
function requireDs(deps: CredentialsDeps, operation: string): DataSource {
  const ds = deps.dataSource();
  if (!ds) throw new StackError('no_database', `Cannot ${operation}: no active database.`);
  return ds;
}

/** `:id` arrives as a string from the route; a non-integer is a caller error, not a missing credential. */
/**
 * Validate a credential uuid.
 *
 * UUIDs are the trust stack's identifier standard: memberships, invitations, governance, signatures and
 * credentials are all addressed by uuid, and the uuid is what every published DTO carries. A numeric row id was
 * the one place a storage detail leaked into the contract — and it made `revoke()` and `signatures()`
 * **unaddressable from any consumer**, because no DTO ever published a row id. The web UI worked around it by
 * disabling its Revoke button outright.
 */
function requireUuid(uuid: string): string {
  const v = String(uuid ?? '').trim();
  if (!v) throw new StackError('invalid_input', 'uuid is required');
  return v;
}

/** Project a repository row onto the contract, dropping replication bookkeeping. */
function toStoredDto(row: CredentialRow): StoredCredentialDto {
  return {
    source: 'dtg',
    uuid: row.uuid,
    vcType: row.vcType,
    issuerIdentityUuid: row.issuerIdentityUuid,
    subjectIdentityUuid: row.subjectIdentityUuid,
    claim: row.claim,
    status: row.status,
    w3cVcJson: row.w3cVcJson,
    createdAt: row.createdAt,
  };
}

/** Read the two display fields out of a VIC's claim, tolerating a malformed or absent one. */
function parseClaim(claim: string | null): { communityName: string | null; communityDid: string | null } {
  try {
    const parsed = JSON.parse(claim ?? '{}') as { communityName?: unknown; oobi?: { did?: unknown } };
    return {
      communityName: typeof parsed.communityName === 'string' ? parsed.communityName : null,
      communityDid: typeof parsed.oobi?.did === 'string' ? parsed.oobi.did : null,
    };
  } catch {
    return { communityName: null, communityDid: null };
  }
}

/**
 * The issuer DID out of a VIC's W3C VC JSON — the fallback for an invitation whose claim carries no OOBI.
 *
 * Tolerates a malformed or absent document, like `parseClaim`: an invitation that cannot be parsed is a 400, not
 * a crash.
 */
function parseW3cIssuer(w3cVcJson: string | null): string | null {
  try {
    const parsed = JSON.parse(w3cVcJson ?? '{}') as { issuer?: unknown };
    return typeof parsed.issuer === 'string' ? parsed.issuer : null;
  } catch {
    return null;
  }
}

/** Build the `credentials` domain. */
export function createCredentialsApi(ctx: DomainContext, deps: CredentialsDeps): CredentialsApi {
  return {
    async list(): Promise<CredentialDto[]> {
      const agent = requireAgent(ctx, 'list credentials');
      const ds = requireDs(deps, 'list credentials');

      // The in-process VTC store first, preserving the order the pre-regression route returned.
      const vtc: VtcCredentialDto[] = agent.listVrcsForSelf().map((v) => ({
        source: 'vtc',
        subjectVid: String(v.subjectVid),
        issuerVid: String(v.issuerVid),
        claimType: v.claim?.type ?? '',
        issuedAt: v.issuedAt,
        expiresAt: v.expiresAt ?? null,
        signatureCount: v.signatures?.length ?? 0,
      }));

      // Then the DTG rows this identity issued or was issued.
      const me = await identitiesRepo.findByRealDid(ds, agent.getDid());
      if (!me) return vtc;
      const rows = await credentialsRepo.list(ds, { vcType: 'vrc' });
      const dtg = rows
        .filter((r) => r.status === 'issued'
          && (r.issuerIdentityUuid === me.uuid || r.subjectIdentityUuid === me.uuid))
        .map(toStoredDto);
      return [...vtc, ...dtg];
    },

    /**
     * Issue a credential, signed by the active identity.
     *
     * The runtime's `issueVrc` enforces the same three rules checked here — claim type allowed, signer on the
     * admin list, signer count at threshold — but it throws bare `Error`s distinguishable only by their message
     * text. Pre-checking against the governance doc (which this domain already holds) is what turns those into
     * codes a caller can branch on, and what lets the page say "you are not an admin of this community" rather
     * than relaying an internal sentence.
     */
    async issue(input: IssueVrcInput): Promise<IssuedCredentialDto> {
      const agent = requireAgent(ctx, 'issue a credential');
      const ds = requireDs(deps, 'issue a credential');

      const vtcDid = input?.vtcDid;
      if (!vtcDid) throw new StackError('invalid_input', 'vtcDid is required');
      const claimType = input?.claim?.type;
      if (!claimType) throw new StackError('invalid_input', 'claim.type is required');

      // Self-signing is a capability, not a given — a capability-scoped stack omits it.
      const issueForSelf = agent.issueVrcForSelf?.bind(agent);
      if (typeof issueForSelf !== 'function') {
        throw new NotImplementedError('self-signed credential issuance', 'P4');
      }

      // Authorization comes from the signed governance doc, which names its admins — never from the caller's
      // own claim about itself.
      const doc = agent.getCommunityByDid(vtcDid);
      if (!doc) {
        throw new StackError('not_found', `No community known locally for ${vtcDid.slice(0, 16)}…`);
      }
      // Checked against `adminVids` (CESR keys) because that is the exact list the runtime validates the SIGNER
      // against — and here the signer is always this identity (`issueVrcForSelf`). Using the same list means this
      // pre-check cannot disagree with the runtime it is fronting. `adminVids` is required on the doc;
      // `adminDids` is optional, so it would fail closed for every store-loaded doc that predates the field.
      if (!doc.adminVids.includes(agent.getVid())) {
        throw new StackError('not_admin', 'Only an admin of the issuing community can issue its credentials.');
      }
      if (!doc.allowedClaimTypes.includes(claimType)) {
        throw new StackError(
          'claim_not_allowed',
          `This community does not allow claim type "${claimType}". Allowed: ${doc.allowedClaimTypes.join(', ') || '(none)'}.`,
        );
      }
      // A self-signed credential carries exactly one signature, so a community with threshold > 1 cannot be
      // satisfied from here. Refused rather than recorded as `pending_signatures`: `graph()` filters only
      // revoked/expired, so a below-threshold row would render as a LIVE trust edge — recording one means
      // teaching the graph and every verifier to treat it as unproven first, which is a second design.
      if (doc.threshold > 1) {
        throw new StackError(
          'threshold_not_met',
          `This community requires ${doc.threshold} admin signatures; a self-signed credential provides 1.`,
        );
      }

      // The subject. Omitted means self-issue, which is always resolvable. Anything else must be a VID this node
      // already knows: `VtcStore.saveVrc` calls `resolveRemoteIdentity`, which FABRICATES a placeholder for an
      // unknown VID — so without this check a typo would mint a phantom identity AND a credential that no later
      // read can match.
      const rawSubject = input.subjectVid?.trim();
      let subjectVid: CesrVid | undefined;
      if (rawSubject) {
        try {
          subjectVid = asCesrVid(rawSubject, 'subjectVid', 'credentials.issue');
        } catch (err) {
          // A DID or UUID where a CESR key belongs is a caller error, and the codec's message already names the
          // offending field — so it is relayed rather than replaced.
          throw new StackError('invalid_input', (err as Error).message);
        }
        if (subjectVid !== agent.getVid()) {
          const known = await identitiesRepo.list(ds, { vid: subjectVid });
          if (known.length === 0) {
            throw new StackError('unknown_subject', `No identity known locally for subject ${subjectVid.slice(0, 16)}…`);
          }
        }
      }

      const vrc = issueForSelf({
        vtcDid,
        ...(subjectVid ? { subjectVid } : {}),
        claim: input.claim,
        ...(input.expiresAt !== undefined ? { expiresAt: input.expiresAt } : {}),
      });

      // Announce on the bus — P5 retired the polls, so this is what refreshes another client's list. The store
      // assigns the row's uuid inside `saveVrc` and the returned `Vrc` does not carry it back, so it is recovered
      // through the digest the store persisted (`credential_digest = base64(vrc.digest)`).
      const row = await credentialsRepo.findByDigest(ds, Buffer.from(vrc.digest).toString('base64'));
      if (row) ctx.bus.emit('credential.issued', { uuid: row.uuid, vcType: 'vrc', at: Date.now() });

      return {
        subjectVid: String(vrc.subjectVid),
        issuerVid: String(vrc.issuerVid),
        claimType: vrc.claim?.type ?? '',
        issuedAt: vrc.issuedAt,
        expiresAt: vrc.expiresAt ?? null,
        signatureCount: vrc.signatures?.length ?? 0,
      };
    },

    /**
     * Verify a stored credential against its issuer's governance doc.
     *
     * Looked up in `listVrcsForSelf()` rather than fetched by key, because that is the same projection `list()`
     * renders — so what the page offers to verify is exactly what this resolves. A credential whose issuer has
     * no locally-known governance doc is `not_found`, not a failed verification: "I cannot check this" and "this
     * did not check out" are different answers, and only the second is evidence against the credential.
     */
    async verify(input: VerifyVrcInput): Promise<VrcVerificationDto> {
      const agent = requireAgent(ctx, 'verify a credential');

      const subjectVid = input?.subjectVid;
      const issuerVid = input?.issuerVid;
      const claimType = input?.claimType;
      if (!subjectVid) throw new StackError('invalid_input', 'subjectVid is required');
      if (!issuerVid) throw new StackError('invalid_input', 'issuerVid is required');
      if (!claimType) throw new StackError('invalid_input', 'claimType is required');

      const match = agent.listVrcsForSelf().find((v) =>
        String(v.subjectVid) === subjectVid
        && String(v.issuerVid) === issuerVid
        && (v.claim?.type ?? '') === claimType,
      );
      if (!match) {
        throw new StackError('not_found', 'No such credential is held for this identity.');
      }
      if (!agent.getCommunityByDid(issuerVid)) {
        throw new StackError('not_found', `No governance document known locally for issuer ${issuerVid.slice(0, 16)}…`);
      }

      const result = agent.verifyVrc(match);
      return {
        valid: result.valid,
        validSignatureCount: result.validSignatureCount,
        ...(result.reason !== undefined ? { reason: result.reason } : {}),
      };
    },

    async signatures(uuid: string): Promise<CredentialSignatureDto[] | null> {
      requireAgent(ctx, 'list credential signatures');
      const ds = requireDs(deps, 'list credential signatures');
      const cred = await credentialsRepo.findByUuid(ds, requireUuid(uuid));
      if (!cred) return null;
      const rows = await signatureRepo.findForCredential(ds, cred.uuid);
      // Explicit projection: `signature` is the raw Ed25519 bytes and has no business on the wire.
      return rows.map((s) => ({
        uuid: s.uuid,
        credentialUuid: s.credentialUuid,
        signerIdentityUuid: s.signerIdentityUuid,
        signedAt: s.signedAt,
      }));
    },

    async revoke(uuid: string): Promise<StoredCredentialDto | null> {
      requireAgent(ctx, 'revoke a credential');
      const ds = requireDs(deps, 'revoke a credential');
      const cred = await credentialsRepo.findByUuid(ds, requireUuid(uuid));
      if (!cred) return null;
      await credentialsRepo.updateStatus(ds, cred.uuid, 'revoked');
      const at = Date.now();
      // Two events, deliberately. `credential.changed` is the generic "this row moved, repaint" signal that every
      // credential mutation emits; `credential.revoked` says WHY, and carries the `vcType` a subscriber needs to
      // react without re-reading the row — a revoked VIC should invalidate a community-membership view, a revoked
      // VMC should not.
      ctx.bus.emit('credential.changed', { uuid: cred.uuid, status: 'revoked', at });
      ctx.bus.emit('credential.revoked', { uuid: cred.uuid, vcType: cred.vcType, at });
      return toStoredDto({ ...cred, status: 'revoked' });
    },

    async invitations(): Promise<InvitationDto[]> {
      const agent = requireAgent(ctx, 'list invitations');
      const ds = requireDs(deps, 'list invitations');
      const me = await identitiesRepo.findByRealDid(ds, agent.getDid());
      if (!me) return [];

      const rows = await credentialsRepo.list(ds, { vcType: 'vic', subjectUuid: me.uuid });
      const out: InvitationDto[] = [];
      for (const row of rows) {
        if (row.status !== 'issued') continue;
        // An invitation to a community this identity already belongs to is spent: the membership is the record.
        const membership = await membershipsRepo.findByPair(ds, me.uuid, row.issuerIdentityUuid);
        if (membership) continue;
        const claim = parseClaim(row.claim);
        out.push({
          uuid: row.uuid,
          communityUuid: row.issuerIdentityUuid,
          communityName: claim.communityName ?? row.issuerIdentityUuid,
          communityDid: claim.communityDid,
          createdAt: row.createdAt,
        });
      }
      return out;
    },

    async declineInvitation(uuid: string): Promise<CredentialAckDto> {
      requireAgent(ctx, 'decline an invitation');
      const ds = requireDs(deps, 'decline an invitation');
      if (!uuid) throw new StackError('invalid_input', 'uuid is required');
      const row = await credentialsRepo.findByUuid(ds, uuid);
      // Idempotent: declining an invitation that is already spent is not something a caller can act on.
      if (row && row.vcType === 'vic' && row.status !== 'revoked') {
        await credentialsRepo.updateStatus(ds, uuid, 'revoked');
        ctx.bus.emit('invitation.changed', { uuid, status: 'revoked', at: Date.now() });
      }
      return { ok: true };
    },

    async acceptInvitation(uuid: string): Promise<AcceptInvitationDto> {
      const agent = requireAgent(ctx, 'accept an invitation');
      const ds = requireDs(deps, 'accept an invitation');
      if (!uuid) throw new StackError('invalid_input', 'uuid is required');

      const row = await credentialsRepo.findByUuid(ds, uuid);
      if (!row || row.vcType !== 'vic') {
        throw new StackError('not_found', 'invitation not found');
      }

      // Where this membership is being accepted into. The claim's OOBI is the primary source; the W3C VC issuer
      // is the fallback for an invitation whose claim predates the OOBI field.
      const communityDid = parseClaim(row.claim).communityDid ?? parseW3cIssuer(row.w3cVcJson);
      if (!communityDid) {
        throw new StackError('invalid_invitation', 'cannot determine community from invitation');
      }

      // The runtime seam. This route is WHY `queryUtilityServer` exists: it used to assemble its own participant
      // transport out of the agent's private transaction/transport state. The seam owns that and rejects with a
      // typed `utility_server_unavailable` rather than letting a missing transport look like a server failure.
      const query = agent.queryUtilityServer?.bind(agent);
      if (typeof query !== 'function') {
        throw new UtilityServerUnavailableError('accept the invitation');
      }
      const membership = await query<unknown>('vtc_accept', { communityDid, memberDid: agent.getDid() });
      if (!membership) {
        // A reachable server that answers nothing is still not an acceptance — treat it as unavailable rather
        // than consuming the invitation against a membership that was never created.
        throw new UtilityServerUnavailableError('accept the invitation');
      }

      // Consume the invitation locally — the membership now exists, so the VIC is spent. Ordering matters: this
      // runs only AFTER the server confirms, so a failed accept leaves the invitation retryable.
      await credentialsRepo.updateStatus(ds, uuid, 'revoked');
      ctx.bus.emit('invitation.changed', { uuid, status: 'accepted', at: Date.now() });
      return { ok: true, message: 'You are now a member of this community.', membership };
    },

    async viewModels(filters: CredentialViewFilters = {}): Promise<CredentialViewModelsDto> {
      const agent = requireAgent(ctx, 'list credential view models');
      const factory = agent.getCredentialFactory();
      const viewModels = await factory.listViewModels(filters);

      const groups: Record<string, CredentialViewModel[]> = {};
      for (const vm of viewModels) (groups[vm.scenario] ??= []).push(vm);

      const stats: Record<string, number> = {};
      for (const [scenario, list] of Object.entries(groups)) stats[scenario] = list.length;

      // Introspection for the issue form's dropdowns. Derived from the view models actually present rather than
      // from the registry, so an empty credential list yields no dropdown entries instead of a misleading one.
      const scenarios = [...new Set(viewModels.map((v) => v.scenario))].map((scenario) => ({
        scenario,
        kinds: factory.kindsForScenario(scenario) as string[],
      }));

      return { viewModels, groups, stats, scenarios };
    },
  };
}
