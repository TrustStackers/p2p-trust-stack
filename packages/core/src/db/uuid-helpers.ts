/**
 * UUID helpers for distributed identity and replication.
 *
 * didToUuid() derives a deterministic UUIDv5 from a real DID string —
 * used for DID-keyed non-identity records (e.g. VRC ceremony sessions, governance row keys).
 *
 * All other entity tables use UUIDv7 (time-ordered, no central coordination needed).
 */

import { v5, v7 } from 'uuid';

/** DNS namespace UUID from RFC 4122, Appendix C. */
const DID_NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';

/**
 * Derive a deterministic UUIDv5 from a real DID string.
 * Used for DID-keyed non-identity records (e.g. VRC ceremony sessions, governance row keys).
 */
export function didToUuid(realDid: string): string {
  return v5(realDid, DID_NAMESPACE);
}

/**
 * Generate a UUIDv7 (time-ordered, unique).
 * Used for all non-identity entity rows that are replicated across nodes.
 */
export function generateUuid(): string {
  return v7();
}