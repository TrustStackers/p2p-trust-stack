// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * VTC invitation artifacts — ONE builder shared by both invite producers.
 *
 * ## Why this module exists
 *
 * Two independent producers built the invite by hand with identical code:
 * `utility-server/src/tx/vtc-participant.ts` (the `vtc_invite` coordinator op the
 * agent UI calls) and `utility-server/src/routes/layer5-applications/vtc-invite.ts`
 * (the operator REST route). They also built it *wrong* in two ways:
 *
 * 1. **The `peerId` slot was packed** as `"<communityDid>|<peerId>"`. A libp2p
 *    peerId can never contain `|`, so the artifact was NOT dialable: any caller
 *    that handed it to `RelationshipManager.sendRfi()` (which dials
 *    `oobi.peerId`) got an opaque dial failure.
 * 2. **The `did` slot held the community DID** — but the community is an
 *    `identities` row on the server, not a libp2p node. The node the `peerId`
 *    actually reaches is the **utility server**, so an invite-derived RFI was
 *    addressed to a DID that cannot answer it. Since the rev-3 handshake verifies
 *    that an invite was addressed to *us*, such an RFI is now refused
 *    (`rfi_addressed_elsewhere`) instead of being silently mis-keyed.
 *
 * The fix is additive and backward compatible: the legacy packed token is still
 * produced verbatim as `invite` (the operator `/vtcs/:uuid/join` route unpacks it
 * to sanity-check "is this the right community's invite?"), and a NEW
 * `connectionOobi` carries the same transport data addressed to the **server's**
 * DID, so it is a valid, dialable, rev-3-conformant OOBI. The signed VIC already
 * carries the community reference in its claim (`oobi` + `communityName`), so
 * nothing is lost by not putting it in the connection artifact.
 *
 * Consumers: mint via `buildVtcInvite`, read a pasted token via `parseVtcInvite`.
 */

import { encodeOobi, decodeOobi } from './oobi.js';
import { getOobiSignerFor, maybeSignOobi } from './oobi-signer.js';

export interface BuildVtcInviteParams {
  /** The community (VTC/VTN) the invitation is for. */
  communityDid: string;
  /**
   * DID of the node the `peerId` actually reaches — the utility server hosting
   * the community. When omitted/null the connection OOBI falls back to
   * `communityDid` (legacy behaviour) and a warning is logged.
   */
  serverDid?: string | null;
  /** CESR-encoded Ed25519 VID for the OOBI's display slot (the community signing VID). */
  vid: string;
  /** The server's REAL libp2p peerId (no packing — this must stay dialable). */
  peerId: string;
  multiaddrs: string[];
}

export interface VtcInviteArtifact {
  /**
   * The legacy shareable invite token: `<communityDid>|<peerId>` packed into the
   * `peerId` slot. Kept byte-for-byte for compatibility with already-issued
   * invites and the operator `/join` route. **Do not pass this to `sendRfi()`** —
   * use `connectionOobi`.
   */
  invite: string;
  /**
   * A valid OOBI for *connecting* to the server that hosts the community: plain
   * peerId + multiaddrs, addressed to the server's DID. Safe for `sendRfi()`.
   */
  connectionOobi: string;
  communityDid: string;
  peerId: string;
  /** The DID `connectionOobi` is addressed to (`null` when the server DID is unknown). */
  connectionDid: string | null;
}

/** Pack the community DID and the peerId into the legacy invite's peer slot. */
export function packInvitePeerField(communityDid: string, peerId: string): string {
  return `${communityDid}|${peerId}`;
}

/**
 * Build both invitation artifacts from one set of inputs.
 *
 * @throws if `peerId` is empty or already contains the pack separator (a
 *         pre-packed peerId would produce an un-dialable OOBI again).
 */
export function buildVtcInvite(params: BuildVtcInviteParams): VtcInviteArtifact {
  const { communityDid, vid, peerId, multiaddrs } = params;
  if (!peerId) {
    throw new Error('buildVtcInvite: peerId is required (the invite must be dialable)');
  }
  if (peerId.includes('|')) {
    throw new Error('buildVtcInvite: peerId must be a plain libp2p peerId (got a packed value)');
  }

  const connectionDid = params.serverDid && params.serverDid.length > 0 ? params.serverDid : null;
  if (!connectionDid) {
    console.warn(
      '[vtc-invite] server DID unknown — the connection OOBI falls back to the community DID, ' +
      'which cannot answer a dial. Set it via setServerNodeDid() at startup.',
    );
  }

  // The dialable connection OOBI is ML-DSA-65-signed when this process holds a
  // PQ key (H2 prerequisite #2). The legacy `invite` token below is deliberately
  // NOT signed: its bytes are a compatibility contract (an already-issued token
  // must stay valid and byte-identical), and it is not the artifact agents dial.
  const signerFor = getOobiSignerFor(connectionDid ?? communityDid);
  const connectionOobi = encodeOobi(maybeSignOobi({
    cesrVid: vid,
    peerId,
    multiaddrs,
    did: connectionDid ?? communityDid,
  }));
  if (!signerFor) {
    console.log(
      '[vtc-invite] connection OOBI is UNSIGNED (this process is not the ML-DSA-65 authority ' +
      `for ${(connectionDid ?? communityDid).slice(0, 24)}…) — an OOBI taken from this invite ` +
      'cannot pass an "enforce" integrity policy',
    );
  }

  return {
    invite: encodeOobi({
      cesrVid: vid,
      peerId: packInvitePeerField(communityDid, peerId),
      multiaddrs,
      did: communityDid,
    }),
    connectionOobi,
    communityDid,
    peerId,
    connectionDid,
  };
}

export interface ParsedVtcInvite {
  /**
   * The community the invite names. `null` for the modern connection-only OOBI
   * (or any plain OOBI), which carries no community reference.
   */
  communityDid: string | null;
  /** Plain libp2p peerId (unpacked when the token used the legacy packed form). */
  peerId: string;
  multiaddrs: string[];
  /** The DID the token is addressed to. */
  did: string;
}

/**
 * Read a pasted invite token. Accepts BOTH the legacy packed form
 * (`"<communityDid>|<peerId>"` in the peer slot) and a plain OOBI whose peerId is
 * already unpacked, so changing the producer can never strand an old token.
 *
 * @throws SyntaxError when the token is not a decodable OOBI.
 */
export function parseVtcInvite(token: string): ParsedVtcInvite {
  const oobi = decodeOobi(token);
  const sep = oobi.peerId.indexOf('|');
  if (sep === -1) {
    return { communityDid: null, peerId: oobi.peerId, multiaddrs: oobi.multiaddrs, did: oobi.did };
  }
  return {
    communityDid: oobi.peerId.slice(0, sep),
    peerId: oobi.peerId.slice(sep + 1),
    multiaddrs: oobi.multiaddrs,
    did: oobi.did,
  };
}
