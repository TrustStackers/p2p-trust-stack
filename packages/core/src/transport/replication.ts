/**
 * Pubsub Replication Protocol — /p2pts/replication/1.0.0
 *
 * Distributed trust graph synchronization between utility-server nodes.
 * Uses libp2p pubsub for broadcast of public data. Private/secure data
 * (messages, nonces, encrypted secret keys) is never replicated.
 *
 * ## Topic
 * /p2pts/replication/1.0.0
 *
 * ## Replication categories
 * | Data                              | Replicated | Via    |
 * |-----------------------------------|-----------|--------|
 * | identities (public fields)        | Yes       | pubsub |
 * | did_documents                     | Yes       | pubsub |
 * | keys.public_key                   | Yes       | pubsub |
 * | keys.encrypted_secret_key         | No        | —      |
 * | credentials (public fields)       | Yes       | pubsub |
 * | credential_signatures             | Yes       | pubsub |
 * | governance                        | Yes       | pubsub |
 * | memberships (public fields)       | Yes       | pubsub |
 * | personhood_events                 | Yes       | pubsub |
 * | rotation_log                      | Yes       | pubsub |
 * | witness_attestations              | Yes       | pubsub |
 * | profiles (visibility='public')    | Yes       | pubsub |
 * | profile_claims (disclosure='always') | Yes   | pubsub |
 * | status_lists                      | Yes       | pubsub |
 * | status_list_flips                 | Yes       | pubsub |
 * | delegations (public fields)       | Yes       | pubsub |
 * | grants                            | Yes       | pubsub |
 * | relationships                     | Yes       | pubsub |
 * | messages                          | No        | TSP p2p |
 * | nonces                            | No        | local   |
 */

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

export const REPLICATION_TOPIC = '/p2pts/replication/1.0.0';

/** Tables that are replicated via pubsub. */
export const REPLICATED_TABLES = [
  'identities',
  'did_documents',
  'keys',
  'peer_endpoints',
  'rotation_log',
  'witness_attestations',
  'relationships',
  'memberships',
  'personhood_events',
  'governance',
  'delegations',
  'grants',
  'credentials',
  'credential_signatures',
  'status_lists',
  'status_list_flips',
  'profiles',
  'profile_claims',
] as const;

export type ReplicatedTable = typeof REPLICATED_TABLES[number];

// ---------------------------------------------------------------------------
// Replication event types
// ---------------------------------------------------------------------------

export type ReplicationEventType = 'create' | 'update' | 'delete';

export interface ReplicationEvent {
  /** UUIDv7 of this event — used for dedup on the receiving side. */
  eventUuid: string;
  /** What kind of change this represents. */
  eventType: ReplicationEventType;
  /** Which table the row belongs to. */
  table: ReplicatedTable;
  /** UUID of the affected row (the `uuid` column in the table). */
  rowUuid: string;
  /** The row data — for 'create' and 'update', the full row (public fields only).
   *  For 'delete', null or { uuid, status: 'revoked' }. */
  payload: Record<string, unknown> | null;
  /** Which utility-server node published this event. */
  nodeId: string;
  /** Unix epoch milliseconds timestamp. */
  timestamp: number;
  /** Ed25519 signature over (eventUuid || table || rowUuid || JSON.stringify(payload) || nodeId || timestamp). */
  signature?: string;
}

/**
 * Tables that bootstrap nodes filter for identity↔peer mapping only.
 * Bootstrap nodes subscribe to the replication topic but only persist
 * events matching these tables.
 */
export const BOOTSTRAP_REPLICATED_TABLES: ReplicatedTable[] = [
  'identities',
  'did_documents',
  'keys',
  'relationships',
];

/**
 * Check if a replication event should be processed by a bootstrap node.
 */
export function isBootstrapRelevant(table: ReplicatedTable): boolean {
  return BOOTSTRAP_REPLICATED_TABLES.includes(table);
}

/**
 * Build the data to sign for a replication event.
 * Used by the publisher to sign and the subscriber to verify.
 */
export function replicationEventSigningPayload(event: ReplicationEvent): Uint8Array {
  const parts = [
    event.eventUuid,
    event.table,
    event.rowUuid,
    JSON.stringify(event.payload ?? {}),
    event.nodeId,
    String(event.timestamp),
  ];
  return new TextEncoder().encode(parts.join('|'));
}