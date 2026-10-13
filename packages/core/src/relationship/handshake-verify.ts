/**
 * Shared RFI/RFA self-addressing digest verification — TSP Rev 3 §7.2.1.
 *
 * The digest a peer computes over `TSP_Version + VID_sndr + VID_rcvr + payload`
 * (with the digest's own slot dummy-filled) MUST be re-derived on receipt: it is
 * what the relationship record keys on, so accepting a wrong one silently binds
 * the wrong invite.
 *
 * Two independent implementations of the handshake responder exist — the agent's
 * `RelationshipManager` and the utility server's `tsp-bridge` — and they had
 * DIVERGED: only the agent verified anything, while the server verified nothing
 * at all (despite its comment claiming to mirror the manager). Both now call
 * this module, so the rule cannot change on one side only.
 *
 * ## Why the result is returned, not thrown
 *
 * The previous agent-side behaviour on mismatch was a bare `return`: the invite
 * was dropped with no wire signal, so the initiator polled for a relationship
 * that would never form and timed out after 30 s with no reason anywhere. The
 * callers are expected to (a) decline with an `XRFD` carrying the offending
 * digest so the initiator fails immediately, and (b) log `reason` verbatim.
 */

import { computeSaidDigest } from '../tsp/v3/message.js';
import type { Vid } from '../tsp/v3/types.js';
import { cesrEncode, CESR_CODES } from '../crypto/cesr.js';
import { extractEd25519PublicKey } from './key-extract.js';
import type { DidDocument } from '../did/types.js';

/** Machine-readable reason a handshake message was rejected. */
export type HandshakeRejectReason =
  | 'rfi_addressed_elsewhere'
  | 'rfi_digest_mismatch'
  | 'rfa_addressed_elsewhere'
  | 'rfa_digest_mismatch'
  | 'rfa_reply_digest_mismatch'
  | 'sender_document_missing_id'
  | 'sender_document_mismatch';

/** Verification outcome. `detail` is safe to log (hex prefixes only). */
export type HandshakeVerification =
  | { ok: true }
  | { ok: false; reason: HandshakeRejectReason; detail: string };

/** Short hex prefix of a digest, for correlating two logs. */
function hex8(bytes: Uint8Array | undefined): string {
  if (!bytes || bytes.length === 0) return 'none';
  return Buffer.from(bytes.subarray(0, 8)).toString('hex');
}

/** Short, log-safe rendering of a DID/VID. */
function short(vid: string | null | undefined): string {
  if (!vid) return 'none';
  return vid.length > 32 ? `${vid.slice(0, 32)}…` : vid;
}

/**
 * Verify that the inline DID document identifies the SAME party as the
 * signature-verified envelope's sender VID — i.e. that the document we are about
 * to trust for keys is the document of the identity we believe we are talking to.
 *
 * ## Why this exists (H1)
 *
 * The RFI/RFA self-addressing digest covers `TSP_Version + VID_sndr + VID_rcvr +
 * payload fields` (spec 7.2.1) and NOT the inlined DID document — and the inline
 * document is the only source of the sender's Ed25519 key, which is what
 * verifies the message's signature in the first place. Nothing used to check that
 * the two agreed, so a peer could put identity A in the envelope's sender slot
 * (which the digest covers, and which several paths treat as the peer's identity:
 * the relationship-record lookup for TSP_GEN, `markRejected`, the ceremony trace)
 * while supplying identity B's document (whose keys the receiver then trusts).
 *
 * This check makes the document and the claimed sender the same identity, so the
 * two can no longer be played off against each other. It does NOT change the wire
 * format and does not touch the SAID: binding the document into the digest would
 * not close this on its own, because an active attacker re-derives the digest
 * over whatever document they supplied.
 *
 * ## Accepted forms
 *
 *  - `document.id === vidSender` — how BOTH runtimes in this codebase build
 *    handshake messages: `vidSender` carries the sender's real DID.
 *  - `cesrEncode(ED25519_PUBLIC_KEY, document's Ed25519 key) === vidSender` — the
 *    spec-conformant CESR-key VID form, accepted for producers that put a VID
 *    (rather than a DID) in that slot. This is the *key* that will verify the
 *    signature, so the claimed identity is still derived from the document.
 *
 * A document with no `id` is rejected outright: the handshake keys the remote
 * identity by `document.id`, and today a missing id would be written through as
 * `undefined`.
 */
export function verifySenderDocumentBinding(params: {
  /** Sender VID/DID from the SIGNATURE-VERIFIED envelope. */
  vidSender: Vid;
  /** The inline document from the same message. */
  document: DidDocument | undefined;
}): HandshakeVerification {
  const docId = params.document?.id ?? '';
  if (!docId) {
    return {
      ok: false,
      reason: 'sender_document_missing_id',
      detail: `the inline document has no id; envelope sender=${short(params.vidSender)}`,
    };
  }

  if (docId === params.vidSender) return { ok: true };

  // CESR-key VID form: the claimed sender must still be derived from the
  // document's signing key.
  let documentKeyVid: string | undefined;
  try {
    documentKeyVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, extractEd25519PublicKey(params.document!));
  } catch {
    documentKeyVid = undefined;
  }
  if (documentKeyVid && documentKeyVid === params.vidSender) return { ok: true };

  return {
    ok: false,
    reason: 'sender_document_mismatch',
    detail:
      `envelope sender=${short(params.vidSender)} doc.id=${short(docId)} ` +
      `docKey=${documentKeyVid ? short(documentKeyVid) : 'none'}`,
  };
}

/** Constant-time-ish equality; a missing digest is never equal. */
function same(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Verify an inbound invite's self-addressing digest.
 *
 * `localDid` is the DID the invite was ADDRESSED to — i.e. our own identity DID
 * (`identity.did` on an agent, `serverIdentity.realDid` on the utility server).
 * A peer that addressed a different DID produces a digest that cannot match, so
 * a mismatch here means the sender used a stale/mismatched OOBI `did`.
 */
export function verifyRfiDigest(params: {
  vidSender: Vid;
  localDid: Vid;
  nonce: Uint8Array;
  digest: Uint8Array | undefined;
  /**
   * The receiver VID from the SIGNATURE-VERIFIED envelope. When provided, an
   * invite addressed to a different DID is reported as `rfi_addressed_elsewhere`
   * — the precise symptom of a stale/mismatched OOBI — instead of being lumped
   * in with a digest mismatch.
   */
  receiverVid?: Vid | null;
}): HandshakeVerification {
  if (params.receiverVid !== undefined && params.receiverVid !== params.localDid) {
    return {
      ok: false,
      reason: 'rfi_addressed_elsewhere',
      detail: `addressed=${short(params.receiverVid)} ours=${short(params.localDid)}`,
    };
  }
  const expected = computeSaidDigest('RFI', params.vidSender, params.localDid, { nonce: params.nonce });
  if (!same(params.digest, expected)) {
    return {
      ok: false,
      reason: 'rfi_digest_mismatch',
      detail: `expected=${hex8(expected)} actual=${hex8(params.digest)}`,
    };
  }
  return { ok: true };
}

/**
 * Verify an inbound accept.
 *
 * Two independent checks:
 *  - `digest` must equal the digest of the RFI we sent (only checkable by the
 *    initiator, which passes `expectedRfiDigest` from its stored record);
 *  - `replyDigest` must be the self-addressing digest of THIS accept, over the
 *    echoed request digest. Checkable on both sides — the RFA's own SAID uses
 *    the DID the accept was addressed to, which is always us.
 */
export function verifyRfaDigests(params: {
  vidSender: Vid;
  localDid: Vid;
  digest: Uint8Array | undefined;
  replyDigest: Uint8Array | undefined;
  /** Digest of the RFI we sent; omit when we did not initiate (server side). */
  expectedRfiDigest?: Uint8Array;
  /** Receiver VID from the signature-verified envelope (see verifyRfiDigest). */
  receiverVid?: Vid | null;
}): HandshakeVerification {
  if (params.receiverVid !== undefined && params.receiverVid !== params.localDid) {
    return {
      ok: false,
      reason: 'rfa_addressed_elsewhere',
      detail: `addressed=${short(params.receiverVid)} ours=${short(params.localDid)}`,
    };
  }
  if (params.expectedRfiDigest && !same(params.digest, params.expectedRfiDigest)) {
    return {
      ok: false,
      reason: 'rfa_digest_mismatch',
      detail: `expected=${hex8(params.expectedRfiDigest)} actual=${hex8(params.digest)}`,
    };
  }
  if (!params.digest) {
    return { ok: false, reason: 'rfa_digest_mismatch', detail: 'missing echoed request digest' };
  }
  const expectedReply = computeSaidDigest('RFA', params.vidSender, params.localDid, {
    requestDigest: params.digest,
  });
  if (!same(params.replyDigest, expectedReply)) {
    return {
      ok: false,
      reason: 'rfa_reply_digest_mismatch',
      detail: `expected=${hex8(expectedReply)} actual=${hex8(params.replyDigest)}`,
    };
  }
  return { ok: true };
}
