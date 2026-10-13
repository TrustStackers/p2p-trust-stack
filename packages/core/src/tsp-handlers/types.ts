/**
 * TSP Protocol Handler Types — shared between agent and utility server.
 *
 * Defines the ProtocolMessage envelope carried as a TSP_GEN body with a
 * structured JSON body that includes a `protocol` discriminator field.
 *
 * ## Protocol message format (TSP_GEN body)
 *
 * All protocol messages are JSON-encoded Uint8Array within TSP_GEN:
 * ```json
 * {
 *   "protocol": "tx_prepare",
 *   "correlation_id": "uuid-for-req-res-pairing",
 *   "payload": { ... coordinator op ... }
 * }
 * ```
 *
 * ## Request/Response pattern
 *
 * Protocols that require a response include a `correlation_id`; the receiver
 * sends a TSP_GEN response with the same `correlation_id`. Fire-and-forget
 * protocols omit it.
 *
 * As of Phases C–G the only live wire traffic rides the transaction
 * coordinator ops (`tx_*` / `exchange:*`); the historical raw-TSP protocol
 * constants and payload definitions (identity_push, name_register,
 * name_resolve, name_revoke, identity_lookup, network_health) have been
 * removed — the envelope below is a pure carrier.
 */

// ---------------------------------------------------------------------------
// Protocol message envelope
// ---------------------------------------------------------------------------

export interface ProtocolMessage {
  /** Protocol identifier string. */
  protocol: string;
  /** Optional correlation ID for request/response pairing. */
  correlationId?: string;
  /** Protocol-specific payload (JSON-serializable). */
  payload: unknown;
}

// ---------------------------------------------------------------------------
// Protocol-specific payload types
// ---------------------------------------------------------------------------

import type { RotationEntryJson } from '../did/rotation-entry-codec.js';

/** identity_push payload — fire and forget. */
export interface IdentityPushPayload {
  realDid: string;
  /**
   * The identity's canonical `identities.uuid` (UUIDv5 of `realDid`).
   * Carried verbatim so the utility server's copy of this identity uses the
   * SAME identity key the agent reports back in ceremonies (adminUuids /
   * ceremony_begin). Without it, the server would derive a divergent key and
   * VTC/VRC flows fail with "admin UUID ... not found".
   */
  identityUuid?: string;
  name?: string;
  subjectKind: string;
  didDocument: object;
  publicKeys: { ed25519: string; x25519: string };
  peerId?: string;
  /**
   * The identity's full `did:scid:vh` rotation log, in wire JSON form
   * (`rotationEntryToJson`).
   *
   * WHY: the server otherwise holds only a cached DID document for a pushed
   * identity, so a third party resolving that DID gets `source: 'cache'` (not
   * chain-verified). Carrying the log lets the server persist it and serve a
   * VERIFIED resolution.
   *
   * Additive and optional: an agent that omits it leaves whatever log the server
   * already holds untouched. The WHOLE log is re-sent on every push, and the
   * server writes it insert-if-absent per version, so re-sends are no-ops.
   */
  rotationLog?: RotationEntryJson[];
  /**
   * The pushing node's CURRENT dialable multiaddrs, as advertised by its own
   * libp2p node (`node.getMultiaddrs()`).
   *
   * WHY: `peer_endpoints.multiaddrs` is what the utility server's
   * ConnectivitySupervisor dials to (re)reach a member (`listMemberEndpoints`).
   * The push used to carry only `peerId`, so every agent endpoint row was
   * written with `multiaddrs = NULL` — the supervisor then had exactly ONE
   * candidate (the bootstrap relay address) and logged
   * `reconnect to agent 12D3Koo… failed (all 1 address(es) failed) — retrying
   * in 120s` forever whenever that relay path was unavailable (e.g. both peers
   * on the same LAN, or a lapsed reservation). Carrying the addresses here makes
   * the direct path available to the server again.
   *
   * Additive and optional: a push from an older agent omits it (the receiver
   * then behaves exactly as before).
   */
  multiaddrs?: string[];
  bootstrapPeerId?: string;
  /** Profile data to sync to the utility server for R-Card resolution. */
  profiles?: Array<{
    label: string;
    purpose?: string;
    visibility: string;
    claims: Array<{ claimKey: string; claimValue: string | null; valueType: string; disclosure: string }>;
  }>;
  /** Credentials issued by or for this agent (public verifiable credentials). */
  credentials?: Array<{
    uuid: string;
    vcType: string;
    issuerIdentityUuid: string;
    subjectIdentityUuid: string;
    w3cVcJson: string | null;
    claim: string | null;
    status: string;
    thresholdRequired: number | null;
    validFrom: number;
    validUntil: number | null;
    credentialDigest: string | null;
    createdAt: number | null;
  }>;
  /** Signatures for the above credentials. */
  credentialSignatures?: Array<{
    credentialUuid: string;
    signerIdentityUuid: string;
    signature: string; // base64-encoded
    signedAt: number | null;
  }>;
  /**
   * A single established bidirectional peer relationship (VRC pair) to persist
   * in the utility server's `relationships` table. Carried by the VRC
   * ceremony's server-archive leg so YB reflects the VRC as a real relationship
   * row (not just a credential) — `createVtc`'s governance checks
   * (`hasEstablishedVrcBetween`) depend on this existing in the app DB.
   *
   * `localUuid` is the identity being pushed; `remoteUuid` is the VRC peer.
   */
  relationship?: {
    localUuid: string;
    remoteUuid: string;
    remotePeerId?: string;
    remoteTransport?: string;
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/** Encode a ProtocolMessage into Uint8Array for TSP_GEN body. */
export function encodeProtocolMessage(msg: ProtocolMessage): Uint8Array {
  return textEncoder.encode(JSON.stringify(msg));
}

/** Decode a TSP_GEN body (Uint8Array) into a ProtocolMessage. */
export function decodeProtocolMessage(body: Uint8Array): ProtocolMessage {
  return JSON.parse(textDecoder.decode(body)) as ProtocolMessage;
}