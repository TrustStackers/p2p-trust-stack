/**
 * `delegations` DTOs — accountability/custody links between identities.
 *
 * A delegation is a standing relationship ("this agent operates that asset", "this org employs that agent"),
 * distinct from a credential: it is the *link*, and a credential may optionally back it.
 *
 * Two deliberate omissions:
 *
 *  - `recordedByNode` / `replicatedAt` — replication bookkeeping, i.e. how THIS node learned of the row rather
 *    than anything about the delegation.
 *  - `credentialUuid` — the credential that backs the link is reachable through `credentials.list()`; carrying
 *    a foreign key here would publish a join rather than a fact.
 */

/** The kinds of standing relationship a delegation can express. Mirrors the table's CHECK constraint. */
export type DelegationRelationshipType = 'operates' | 'owns' | 'represents' | 'employs';

/** One delegation link. */
export interface DelegationDto {
  uuid: string;
  /** The delegating identity. */
  principalIdentityUuid: string;
  /** The identity acting on the principal's behalf. */
  dependentIdentityUuid: string;
  relationshipType: DelegationRelationshipType;
  /** Optional free-form scope, e.g. a JSON document describing what is delegated. */
  scope: string | null;
  grantedAt: number | null;
  expiresAt: number | null;
  /** Set once revoked. A revoked delegation is retained, not deleted — the record is the point. */
  revokedAt: number | null;
}

/**
 * Input for creating a delegation.
 *
 * Both sides are named by **identity uuid**, not a numeric id: the table keys on
 * `principal_identity_uuid`/`dependent_identity_uuid`, and the TUI's original form asked for "Principal ID" /
 * "Dependent ID" as numbers that exist nowhere in the model.
 */
export interface CreateDelegationInput {
  principalIdentityUuid: string;
  dependentIdentityUuid: string;
  relationshipType: DelegationRelationshipType;
  scope?: string;
  /** Unix seconds after which the link lapses. */
  expiresAt?: number;
}
