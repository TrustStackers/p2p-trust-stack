/**
 * `delegations` domain — the standing accountability/custody links between identities.
 *
 * This domain is built directly on `delegations-repo` rather than on the runtime, because the runtime has
 * **no delegation methods at all**. `AgentHandle` declares `createDelegation?`/`listDelegations?` as optional
 * members, and nothing anywhere implements them — so the TUI's Delegations screen, which programmed to those
 * two, had a list that was permanently empty, a create that never ran, and a `[r] Revoke` key that printed
 * "Delegation revoked." while doing nothing. The repository (`create` / `list` / `revoke`) is complete, so the
 * layer is built on that and the screen is pointed at this instead.
 *
 * ## No event is emitted
 *
 * The catalogue is deliberately closed (30 names) and holds no delegation event, so adding one is a contract
 * decision rather than a detail of this port. The consequence is stated rather than hidden: another client
 * changing a delegation will not push to this one. Revoke/create still return the new state, so the acting
 * client needs no refetch.
 */
import { requireAgent, type DomainContext } from './context.js';
import { StackError } from '../errors.js';
import * as delegationsRepo from '@p2p-trust-stack/core/db/repositories/delegations-repo.js';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { DelegationRow } from '@p2p-trust-stack/core/db/repositories/delegations-repo.js';
import type { CreateDelegationInput, DelegationDto } from '../dto/delegations.js';

export interface DelegationsDeps {
  /** The active agent's database, or null before activation. */
  dataSource(): DataSource | null;
}

export interface DelegationsApi {
  /**
   * Every delegation the active identity is party to, as **principal or dependent**.
   *
   * Both sides are included on purpose: a delegation is one link seen from two ends, and a screen showing only
   * the principal's view would hide "who acts for me".
   */
  list(): Promise<DelegationDto[]>;
  /**
   * Create a delegation. Refusals are typed: `invalid_input` (missing side or bad type) · `not_found`
   * (a side is not a known identity) · `self_delegation`.
   */
  create(input: CreateDelegationInput): Promise<DelegationDto>;
  /** Revoke a delegation by uuid. Idempotent — revoking an already-revoked link is not an error. */
  revoke(uuid: string): Promise<DelegationDto>;
}

/** The active agent's database, or a typed error — a domain never reaches for a DB handle itself. */
function requireDs(deps: DelegationsDeps, operation: string): DataSource {
  const ds = deps.dataSource();
  if (!ds) throw new StackError('no_database', `Cannot ${operation}: no active database.`);
  return ds;
}

const RELATIONSHIP_TYPES = ['operates', 'owns', 'represents', 'employs'] as const;

/** Project a repository row onto the contract, dropping replication bookkeeping. */
function toDto(row: DelegationRow): DelegationDto {
  return {
    uuid: row.uuid,
    principalIdentityUuid: row.principalIdentityUuid,
    dependentIdentityUuid: row.dependentIdentityUuid,
    relationshipType: row.relationshipType,
    scope: row.scope,
    grantedAt: row.grantedAt,
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt,
  };
}

/** Build the `delegations` domain. */
export function createDelegationsApi(ctx: DomainContext, deps: DelegationsDeps): DelegationsApi {
  return {
    async list(): Promise<DelegationDto[]> {
      const agent = requireAgent(ctx, 'list delegations');
      const ds = requireDs(deps, 'list delegations');

      const me = await ds.get<{ uuid: string }>(
        // The DID is not a column on `identities` — it lives on the primary `did_documents` row. This is the
        // same join `IdentityResolver.lookupByDid` uses; the first version of this query asked `identities` for
        // a `did` column and failed with `no such column: did`.
        `SELECT i.uuid FROM identities i
           JOIN did_documents d ON d.identity_uuid = i.uuid
          WHERE d.did = ?`,
        agent.getDid(),
      );
      // An agent with no identities row has no delegations, and that is an empty list rather than an error.
      if (!me) return [];

      // Both directions. A delegation where this identity is BOTH sides is impossible (`self_delegation` is
      // refused), so the two lists cannot overlap and no de-duplication is needed.
      const asPrincipal = await delegationsRepo.list(ds, { principalIdentityUuid: me.uuid });
      const asDependent = await delegationsRepo.list(ds, { dependentIdentityUuid: me.uuid });
      return [...asPrincipal, ...asDependent].map(toDto);
    },

    async create(input: CreateDelegationInput): Promise<DelegationDto> {
      requireAgent(ctx, 'create a delegation');
      const ds = requireDs(deps, 'create a delegation');

      const principal = input?.principalIdentityUuid?.trim();
      const dependent = input?.dependentIdentityUuid?.trim();
      if (!principal) throw new StackError('invalid_input', 'principalIdentityUuid is required');
      if (!dependent) throw new StackError('invalid_input', 'dependentIdentityUuid is required');
      if (!input?.relationshipType) throw new StackError('invalid_input', 'relationshipType is required');
      if (!RELATIONSHIP_TYPES.includes(input.relationshipType)) {
        throw new StackError(
          'invalid_input',
          `relationshipType must be one of: ${RELATIONSHIP_TYPES.join(', ')}.`,
        );
      }
      // A link from an identity to itself is not a delegation, and the table cannot express one usefully.
      if (principal === dependent) {
        throw new StackError('self_delegation', 'An identity cannot delegate to itself.');
      }

      // Both sides must be identities this node knows, so a typo cannot mint a link to nobody — the same
      // reasoning as `credentials.issue`'s `unknown_subject` guard.
      for (const [side, uuid] of [['principal', principal], ['dependent', dependent]] as const) {
        const known = await ds.get('SELECT uuid FROM identities WHERE uuid = ?', uuid);
        if (!known) {
          throw new StackError('not_found', `No identity known locally for the ${side} (${uuid.slice(0, 16)}…).`);
        }
      }

      const uuid = await delegationsRepo.create(ds, {
        principalIdentityUuid: principal,
        dependentIdentityUuid: dependent,
        relationshipType: input.relationshipType,
        ...(input.scope !== undefined ? { scope: input.scope } : {}),
        ...(input.expiresAt !== undefined ? { expiresAt: input.expiresAt } : {}),
      });

      const row = await delegationsRepo.findByUuid(ds, uuid);
      if (!row) throw new StackError('not_found', 'The delegation could not be read back after creation.');
      return toDto(row);
    },

    async revoke(uuid: string): Promise<DelegationDto> {
      requireAgent(ctx, 'revoke a delegation');
      const ds = requireDs(deps, 'revoke a delegation');
      if (!uuid) throw new StackError('invalid_input', 'uuid is required');

      const row = await delegationsRepo.findByUuid(ds, uuid);
      if (!row) throw new StackError('not_found', `No delegation matches '${uuid}'.`);

      // Idempotent, and the FIRST timestamp is kept: a repeat click must not rewrite when the link lapsed.
      if (row.revokedAt) return toDto(row);

      await delegationsRepo.revoke(ds, uuid);
      const updated = await delegationsRepo.findByUuid(ds, uuid);
      if (!updated) throw new StackError('not_found', `No delegation matches '${uuid}'.`);
      return toDto(updated);
    },
  };
}

