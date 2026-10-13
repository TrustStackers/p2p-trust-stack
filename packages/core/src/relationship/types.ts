/**
 * Relationship module types — Step 4.
 *
 * Defines the types for OOBI payloads, relationship records, and the local
 * identity structure used by RelationshipManager.
 *
 * Reference: docs/implementation-plan-step4.md
 */

import type { DidDocument } from '../did/types.js';
import type { TransportAddress } from '../transport/types.js';
import type { Vid } from '../tsp/v3/types.js';

// ---------------------------------------------------------------------------
// OOBI (Out-of-Band Introduction)
// ---------------------------------------------------------------------------

/**
 * An OOBI (Out-of-Band Introduction) payload.
 *
 * Shared out-of-band (QR code, link, copy-paste) so one endpoint can learn
 * another's VID, real DID, and transport address before any TSP message is sent.
 *
 * Wire format: CESR group frame with EXACTLY 4 items (strict; no legacy fallback):
 *   -TAC<vid (ED25519_PUBLIC_KEY)><peerId (VARIABLE_BYTES)><multiaddrsJson (VARIABLE_BYTES)><did (VARIABLE_BYTES)>
 *
 * The sender's real DID is REQUIRED so the receiver can key the identity stub by
 * its stable DID/UUID instead of the ephemeral VID. `decodeOobi` requires all 4.
 */
export interface OobiPayload {
  /**
   * CESR-encoded Ed25519 public key of the introducer — the OOBI's FIRST item.
   *
   * A KEY, not a DID (in Rev 3 the identity reference is `did`, the fourth item).
   * The name is `cesrVid` so it cannot be confused with `did`; the wire bytes are
   * unchanged (the CESR group items are positional).
   */
  cesrVid: Vid;
  /** libp2p PeerID string. */
  peerId: string;
  /** libp2p multiaddrs (may be empty). */
  multiaddrs: string[];
  /** The sender's real DID string (required). */
  did: string;
  /**
   * Optional ML-DSA-65 signature over this introduction (raw 3309 bytes), as
   * produced by `signOobi`.
   *
   * An OOBI is the canonical OUT-OF-BAND INTRODUCTION: it is copied by hand
   * between parties and is the artifact that establishes who a peer is before any
   * TSP message flows — so it is exactly the kind of high-value, long-lived,
   * asynchronous statement the PQ root of trust is for. A 5th CESR item carries
   * it; the 4-item form remains valid (unsigned) for backward compatibility.
   */
  mlDsa65Signature?: Uint8Array;
}

// ---------------------------------------------------------------------------
// Relationship record
// ---------------------------------------------------------------------------

/** Direction of a relationship from the local endpoint's perspective. */
export type RelationshipDirection = 'outbound' | 'inbound' | 'bidirectional';

/** Status of a relationship. */
export type RelationshipStatus = 'pending' | 'established' | 'rejected';

/**
 * A relationship record stored in the relationship table.
 *
 * Represents the state of a relationship between the local VID and a remote VID.
 * Created when an RFI is sent (outbound) or received (inbound), and updated
 * to 'bidirectional' when the RFA completes the handshake.
 */
export interface RelationshipRecord {
  /** DID string from did_documents.did (e.g., \"did:peer:4:...\"). */
  localDid: Vid;
  /** DID string from did_documents.did (e.g., \"did:peer:4:...\"). */
  remoteDid: Vid;
  /** Direction of the relationship from the local endpoint's perspective. */
  direction: RelationshipDirection;
  /** Status of the relationship. */
  status: RelationshipStatus;
  /** Self-addressing digest of the winning RFI payload. */
  rfiDigest?: Uint8Array;
  /** Self-addressing digest of the RFA payload (set when bidirectional). */
  rfaReplyDigest?: Uint8Array;
  /** Remote endpoint's Ed25519 signing key (32 bytes, from inlined didDocument). */
  remoteEd25519Key?: Uint8Array;
  /** Remote endpoint's X25519 agreement key (32 bytes, from inlined didDocument). */
  remoteX25519Key?: Uint8Array;
  /**
   * The peer's ML-DSA-65 root-of-trust public key, as published in its document's
   * `#key-mldsa`.
   *
   * Why the store carries it: the OOBI introduction check has to verify a
   * signature against the key of the identity the OOBI names, and it resolves
   * that key from `oobi.did`. For a long-form `did:peer:4` the document travels
   * inside the DID (self-contained); for a `did:scid:vh` peer there is nothing to
   * resolve locally — `DidPeer4Method.resolve()` handles only peer4 and
   * `ScidVhMethod.resolve()` needs THAT did's rotation log. This stored key is
   * the second source, and it is a TOFU pin: it came from the document the peer
   * presented in a handshake (or an identity push) we already accepted, so a
   * receiver can still integrity-check an introduction from a KNOWN scvh peer.
   */
  remoteMlDsa65Key?: Uint8Array;
  /**
   * The peer's MLKEM768-X25519 (post-quantum) agreement public key, when it
   * publishes one as `#key-kem` in its DID document.
   *
   * Present ⇒ confidential messages to this peer are sealed under the HYBRID KEM
   * (`hpkeHybridSeal`, enc = 1120 bytes); absent ⇒ classical DHKEM(X25519)
   * (enc = 32). The receiver mirrors this rule, and ultimately the AEAD tag
   * decides which KEM a given message used (see the confidential branch of
   * `RelationshipManager.processGen`).
   */
  remoteHybridKemKey?: Uint8Array;
  /** Remote endpoint's transport address (PeerID + multiaddrs). */
  remoteTransport?: TransportAddress;
  /** Full inlined DID document from the remote endpoint's RFI or RFA. */
  remoteDidDocument?: DidDocument;
  /** Remote endpoint's subject kind ('human' | 'organization' | null). */
  remoteSubjectKind?: string | null;
  /** Unix timestamp (seconds) when the record was created. */
  createdAt: number;
  /** Unix timestamp (seconds) when the record was last updated. */
  updatedAt: number;
  /** Personhood ceremony status: 'acknowledged' (local ack'd) | 'verified' (mutual) | undefined (not started). */
  personhoodStatus?: 'acknowledged' | 'verified';
}

// ---------------------------------------------------------------------------
// Local identity
// ---------------------------------------------------------------------------

/**
 * The local identity used by RelationshipManager.
 *
 * Holds all the keys and DID information needed to build and sign RFI/RFA
 * messages and to verify incoming messages.
 */
export interface LocalIdentity {
  /**
   * CESR-encoded Ed25519 public key — the identity's VID **in its legacy
   * key-string sense** (the keystore's key, the first OOBI item, and the value
   * carried in `identities.vid`).
   *
   * Named `cesrVid` rather than `vid` deliberately: in Rev 3 the identity
   * *reference* is `did` (below), and this field is a KEY, not a DID. The
   * remaining consumers (keystore key, OOBI first item, `identities.vid`,
   * bootstrap registration) and what removing each would take are catalogued in
   * `docs/vid-to-did-migration.md`.
   */
  cesrVid: Vid;
  /**
   * Full did:peer:4 DID string (used for verifyDidPeer4 and stored in
   * relationship records). e.g., "did:peer:4:z..."
   */
  did: string;
  /**
   * Full DID document (inlined in RFI/RFA payloads per task 4.7).
   * This is the resolved document (with the `id` field populated).
   */
  didDocument: DidDocument;
  /** Ed25519 signing key pair. */
  signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array };
  /** X25519 key agreement key pair. */
  agreementKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array };
  /**
   * ML-DSA-65 ROOT-OF-TRUST signing key pair (post-quantum).
   *
   * Present only for identities provisioned with PQ keys (G7e). Used for
   * high-value, long-lived, ASYNCHRONOUS statements — key rotation and
   * out-of-band introductions — never for ordinary TSP messages, which stay
   * Ed25519 because they are ephemeral.
   */
  mlDsa65KeyPair?: { secretKey: Uint8Array; publicKey: Uint8Array };
  /**
   * MLKEM768-X25519 hybrid KEM key pair (post-quantum key agreement), used for
   * confidential payloads; the classical X25519 `#key-2` counterpart stays
   * available as the fallback.
   */
  hybridKemKeyPair?: { secretKey: Uint8Array; publicKey: Uint8Array };
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Thrown by `Agent.connectToPeer` when the pasted OOBI resolves to an
 * already-established relationship whose personhood ceremony has COMPLETED
 * (both VRCs minted and exchanged — `personhood_status = 'verified'`).
 *
 * Re-running an OOBI exchange + connect for a relationship the agent already
 * has must NOT send a duplicate RFI. The UI surfaces this as an
 * acknowledgment-required error and returns to the pre-paste state.
 *
 * Distinguishable by the stable `code` ('RELATIONSHIP_EXISTS') and the HTTP
 * status the web API maps it to (`statusCode` = 409 Conflict).
 */
export class RelationshipAlreadyExistsError extends Error {
  /** Stable machine-readable code for UI/API dispatch. */
  readonly code = 'RELATIONSHIP_EXISTS';
  /** HTTP status the web API maps this error to (409 Conflict). */
  readonly statusCode = 409;
  /** The existing relationship record. */
  readonly record: RelationshipRecord;
  /** Display name of the remote agent (fallback: null → UI uses the DID). */
  readonly remoteName: string | null;

  constructor(record: RelationshipRecord, remoteName?: string | null) {
    const remoteDid = record.remoteDid ?? '';
    const who = remoteName && remoteName.trim()
      ? remoteName.trim()
      : (remoteDid.length > 32 ? `${remoteDid.slice(0, 32)}…` : remoteDid);
    super(`You already have a relationship with ${who}.`);
    this.name = 'RelationshipAlreadyExistsError';
    this.record = record;
    this.remoteName = remoteName ?? null;
  }
}

