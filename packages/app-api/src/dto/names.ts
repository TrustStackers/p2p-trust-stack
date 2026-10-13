/**
 * Name-registration DTOs.
 *
 * Explicit fields, no index signature (see `dto/identity.ts` for why).
 */

/** Result of registering or revoking a name. */
export interface RegisterResultDto {
  success: boolean;
  reason?: string;
}

/** A resolved name — where it points and how the binding was made. */
export interface ResolvedNameDto {
  peerId: string;
  did: string;
  multiaddrs: string[];
  /** The peer's profile card, when the resolver returned one. */
  rCard?: unknown;
}

/** One of this identity's registered names. */
export interface NameEntryDto {
  nameUri: string;
  namespace: string;
  name: string;
  did: string;
  bindingType: 'alsoKnownAs' | 'vrc' | 'utility_managed';
}
