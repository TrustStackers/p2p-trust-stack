// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * TSP v3 (Rev 3) message types.
 *
 * In Rev 3 a `Vid` is a DID/URN **string** (e.g. `did:peer:4…`), carried on the
 * wire as a variable-length VID_String (`4B##…`). It is NOT a bare key.
 */

import type { DidDocument } from '../../did/types.js';

/** A verifiable identifier — a DID or URN string. */
export type Vid = string;

/**
 * A VID in its CESR **encoded** form — a base64url-encoded Ed25519 public key
 * (`D…`, 44 chars), NOT a DID.
 *
 * This is the form the VTC/VRC binary codec (`src/vtc/codec.ts`) writes for every
 * VID it embeds, and the form the pre-Rev-3 wire fields carried. In Rev 3 the
 * *identity reference* is a DID (`Vid`), so the two coexist — and because both
 * are `string`s at runtime, a DID or a UUID could silently be passed where a key
 * string was expected, surfacing only as a bare runtime `TypeError` deep inside
 * `cesrDecode`.
 *
 * The brand makes that a **compile** error: a plain `string` is not assignable to
 * `CesrVid`, so a value must be explicitly converted with `asCesrVid()` (which
 * validates the CESR code and throws a named error). Assignment runs one way
 * only — a `CesrVid` IS a `string`, so encoded values still flow into
 * `Vid`-typed code (e.g. digest computation) without ceremony.
 */
export type CesrVid = string & { readonly __cesrVidBrand: unique symbol };

/** General application message (carried as `XSCS` upper-layer payload). */
export interface TspGenPayload {
  type: 'TSP_GEN';
  /** Application-level message body (opaque bytes; JSON ProtocolMessage, etc.). */
  body: Uint8Array;
}

/** Relationship-forming invite (`XRFI`). */
export interface TspRfiPayload {
  type: 'TSP_RFI';
  /** 16-byte (128-bit) random nonce. */
  nonce: Uint8Array;
  /**
   * 32-byte self-addressing digest of this invite. Derived by `tspSeal` (never
   * trusted from the caller); present on any decoded envelope.
   */
  digest?: Uint8Array;
  /**
   * Optional sender DID document (codebase extension). The Rev 3 spec resolves
   * the VID (DID) via a Support System; this single-stack codebase exchanges
   * the DID document inline as a trailing field so the receiver can recover
   * the sender's Ed25519/X25519 keys on first contact.
   */
  didDocument?: DidDocument;
}

/** Relationship-forming accept (`XRFA`). */
export interface TspRfaPayload {
  type: 'TSP_RFA';
  /** Digest of the `XRFI` being accepted (copied verbatim). */
  digest: Uint8Array;
  /**
   * 32-byte self-addressing digest of this accept. Derived by `tspSeal` (never
   * trusted from the caller); present on any decoded envelope.
   */
  replyDigest?: Uint8Array;
  /** Optional sender DID document (codebase extension, see TspRfiPayload). */
  didDocument?: DidDocument;
}

/** Relationship-forming decline (`XRFD`, new in Rev 3). */
export interface TspRfdPayload {
  type: 'TSP_RFD';
  /** Digest of the `XRFI`/`XRFA` being declined. */
  digest: Uint8Array;
}

/** Confidential application message (HPKE-Base; implemented in Phase 4). */
export interface TspGenConfidentialPayload {
  type: 'TSP_GEN_CONFIDENTIAL';
  /** HPKE encapsulated key. */
  enc: Uint8Array;
  /** HPKE ciphertext. */
  ciphertext: Uint8Array;
}

export type TspPayload =
  | TspGenPayload
  | TspRfiPayload
  | TspRfaPayload
  | TspRfdPayload
  | TspGenConfidentialPayload;

/** A decoded TSP message (signature already verified). */
export interface TspEnvelope {
  /** Version string, e.g. `YTSP-AAC`. */
  version: string;
  /** Sender VID (DID/URN string). */
  vidSender: Vid;
  /** Receiver VID, or null for the NULL VID. */
  vidReceiver: Vid | null;
  payload: TspPayload;
}

export interface TspSealParams {
  vidSender: Vid;
  vidReceiver: Vid | null;
  payload: TspPayload;
  /** Ed25519 secret key (32 bytes). */
  signingSecretKey: Uint8Array;
}

export interface TspOpenParams {
  /** Raw CESR-encoded TSP message bytes (as produced by tspSeal). */
  message: Uint8Array;
  /**
   * Ed25519 public key (32 bytes) of the sender. The caller resolves the
   * sender VID (DID) to this key before opening; tspOpen verifies the
   * signature with it.
   */
  senderPublicKey: Uint8Array;
  /**
   * Encapsulated-key size of the KEM used for a `TSP_GEN_CONFIDENTIAL` payload.
   * Defaults to `X25519_ENC_SIZE` (32, DHKEM(X25519)) — the KEM this deployment
   * seals with. Pass `MLKEM768_X25519_ENC_BYTES` (1120) for a hybrid-KEM message:
   * the CESR HPKE-Base cipher carries no KEM identifier, so the split point has
   * to be supplied by the receiver rather than guessed from the bytes.
   */
  hpkeEncSize?: number;
}
