/**
 * Computed Record Exchange (CRE) — domain types.
 *
 * The CRE is a declarative, data-driven synchronization & sharing layer. Every
 * exchangeable set of records is described once as a `RecordSetDef` (the query
 * that materializes it at send time, the ACL/projection, the delivery
 * mechanism, the resync policy, and the ownership/custody rules). All existing
 * ceremonies and transports (2PC, secure RPC, durable outbox/inbox, pubsub
 * replication, agent delivery queue) become pluggable transports beneath a
 * single ExchangeEngine.
 *
 * Design reference: docs/05_CRE-SystemDesign.md §5.
 */

import type { DataSource } from '../db/data-source.js';
import type { ParticipantTransport } from '../tx/participant.js';

export type RecordSetName =
  | 'identity'
  | 'rcard'
  | 'vtc-membership'
  | 'governance'
  | 'governance-proposal'
  | 'governance-events'
  | 'ceremony-event'
  | 'credential'
  | 'registry'
  | 'recovery'
  | 'identity-lookup'
  | 'witness-endorsement';

export type RecordSetTarget = 'peer' | 'server' | 'utilities';
export type DeliveryType = 'pull' | 'push-event' | 'queue-row' | 'pubsub';
export type ResyncPolicy = 'on-write' | 'on-connect' | `periodic(${number})` | 'on-demand';
export type DisclosureGate = 'always' | 'discretionary' | 'zkp_only' | 'never';
export type ExchangeHandlerKind =
  | 'ExchangeQueryParticipant'
  | 'ExchangePushParticipant'
  | 'AgentDeliveryQueue'
  | 'ExchangePubsubParticipant';

/** A principal identity (requester or recipient). */
export interface ExchangeIdentity {
  realDid: string;
  uuid: string;
  role: string;
}

/**
 * Serializable request carried on the wire. Deliberately excludes the runtime
 * transport handle so it can cross the coordinator query path.
 */
export interface ExchangeRequest {
  requester?: ExchangeIdentity;
  recipient?: ExchangeIdentity;
  /** Request-scoped filters (e.g. requestedKeys for R-Card selective disclosure). */
  filters?: Record<string, unknown>;
}

/** Runtime context: request + the live transport handle (not serialized). */
export interface ExchangeContext extends ExchangeRequest {
  transport?: ParticipantTransport;
}

export interface RecordSetAcl {
  /** Which roles may request/receive this set. Deny by default. */
  roles: string[];
  /** Columns/fields to include in the projection. */
  include: string[];
  /** Columns/fields to exclude even if present. */
  exclude: string[];
  /** Optional disclosure gate (e.g. claim disclosure level). */
  disclosureGate?: DisclosureGate;
  /**
   * Optional policy hook — e.g. filter claims by
   * resolveEffectivePolicy().effectiveAllowedClaimTypes (wired in Phase 6).
   */
  policyFilter?: (ctx: ExchangeContext) => Promise<string[] | null>;
}

export interface RecordSetOwnership {
  /** This node is the authoritative writer for the set. */
  localCustody?: boolean;
  /** Recipient may only write with custody='remote'. */
  remoteCustody?: boolean;
  /** Provenance label to stamp (e.g. 'agent-push'). */
  recordedBy?: string;
}

export interface RecordSetDef {
  /** Canonical name — the wire `exchange:<name>` discriminator. */
  name: RecordSetName;
  /** Who is the target of this set. */
  target: RecordSetTarget;
  /**
   * Materialize the record set AT SEND TIME from the DB. Never store a
   * snapshot; always compute the freshest projection for this target + context.
   */
  materialize(db: DataSource, ctx: ExchangeContext): Promise<Record<string, unknown>[]>;
  /** Delivery mechanism + wire bridge (see design §7). */
  transport: {
    delivery: DeliveryType;
    /** Wire op this recordset crosses the coordinator under (`exchange:<name>`). */
    wireOp?: string;
    /** Server participant that handles the inbound side. */
    handler?: ExchangeHandlerKind;
    /** Pubsub topic for `delivery: 'pubsub'` broadcast recordsets. */
    topic?: string;
  };
  /** Privacy / capability projection. */
  acl: RecordSetAcl;
  /** Resync policy (see design §8). */
  resync: ResyncPolicy;
  /** Idempotency key derivation for a row (replay-safe). */
  idempotencyKey(row: Record<string, unknown>): string;
  /** Ownership / custody semantics (see design §9). */
  ownership: RecordSetOwnership;
}

export type ExchangeErrorCode =
  | 'not_found'
  | 'denied'
  | 'transient'
  | 'permanent'
  | 'invalid_projection'
  | 'not_wired';

/** Typed error carrying a machine-readable code for retry/observability (N5). */
export class ExchangeError extends Error {
  readonly code: ExchangeErrorCode;
  constructor(code: ExchangeErrorCode, message: string) {
    super(message);
    this.name = 'ExchangeError';
    this.code = code;
  }
}

/** Success/failure wrapper for pull responses (serializable over the wire). */
export type ExchangeResult<T = unknown> =
  | { ok: true; data: T }
  | { ok: false; error: { code: ExchangeErrorCode; message: string } };

// ---------------------------------------------------------------------------
// Phase E — semantic exchange events (post-commit fan-out / pubsub)
// ---------------------------------------------------------------------------

/** The kind of change a semantic ExchangeEvent represents. */
export type ExchangeEventType = 'create' | 'update' | 'delete' | 'change';

/**
 * A semantic, recordset-scoped change event emitted AFTER a ceremony/commit —
 * the RFC §9 "ceremonies as agree state; exchange as computed result" carrier.
 * This is deliberately recordset-granular (not table-row-granular like the
 * legacy ReplicationEvent), so receivers can apply via the recordset's own
 * materializer/upsert rather than raw table writes.
 */
export interface ExchangeEvent {
  /** UUIDv7 — the receiver dedups on this (eventUuid). */
  eventUuid: string;
  /** Which recordset this event belongs to (wire `exchange:<recordSet>`). */
  recordSet: RecordSetName;
  /** The change kind. */
  eventType: ExchangeEventType;
  /** Canonical row/entity id this event is about (e.g. a community/credential uuid). */
  rowUuid: string;
  /** Unix epoch ms when the change was emitted. */
  timestamp: number;
  /** Publishing node id (for provenance / server↔server). */
  nodeId?: string;
}

/**
 * Minimal pubsub transport abstraction for `delivery: 'pubsub'` recordsets.
 * The server's ExchangePubsubParticipant bridges this to the libp2p
 * `/p2pts/replication/1.0.0` topic; tests inject a fake. Kept out of the wire
 * path so the engine has no hard libp2p dependency.
 */
export interface ExchangePubsubTransport {
  publish(topic: string, data: Uint8Array): Promise<void>;
  subscribe(topic: string, handler: (data: Uint8Array) => void | Promise<void>): Promise<void>;
}

// ---------------------------------------------------------------------------
// Server-side fan-out (queue-row) — the engine's pluggable durable queue store
// ---------------------------------------------------------------------------

/**
 * The queue-row transport the server-side ExchangeEngine fans out through.
 *
 * Narrow interface (mirrors the `outbox`/`pubsub` dep pattern): the engine
 * resolves target members + derives idempotency keys THROUGH this store, so
 * `src/exchange` never imports utility-server repos directly. `AgentDeliveryQueue`
 * implements this on the utility server (`pending_agent_deliveries`).
 *
 * The payload passed to `enqueue` is the REF (communityUuid / credentialUuid);
 * the full recordset is re-materialized at SEND time by `deliverOne` via the
 * catalog — never stored as a snapshot (CRE invariant 1).
 */
export interface ExchangeFanoutStore {
  /** Resolve the recipient member identity uuids for a recordset fan-out ref. */
  targets(name: RecordSetName, ref: Record<string, unknown>): Promise<string[]>;
  /** Derive a durable idempotency key for a (recordset, ref, member) row. */
  idempotencyKey(name: RecordSetName, ref: Record<string, unknown>, memberUuid: string): Promise<string>;
  /** Insert one durable pending row (op_type `exchange:<name>`, params = the REF). */
  enqueue(name: RecordSetName, memberUuid: string, ref: Record<string, unknown>, idempotencyKey: string): Promise<void>;
}
