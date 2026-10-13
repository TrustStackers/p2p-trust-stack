/**
 * RelationshipManager — stateful RFI/RFA orchestrator — Step 4, Tasks 4.2–4.5.
 * Extended in Step 6 with TSP_GEN application-message send/receive.
 *
 * Owns a TspTransport, RelationshipStore, and local identity. Registers the
 * single onMessage handler on the transport and dispatches by payload type:
 *   - TSP_RFI → processRfi() (verify, store, send RFA)
 *   - TSP_RFA → processRfa() (verify, confirm bidirectional)
 *   - TSP_GEN → processGen() (verify against relationship table, invoke onGenMessage handler)
 *
 * ## Usage
 *
 * ```typescript
 * const manager = new RelationshipManager({ transport, store, identity });
 * manager.start();  // registers onMessage handler
 *
 * // Initiate a relationship with a remote peer:
 * await manager.sendRfi(encodedOobi);
 *
 * // After the handshake completes:
 * const record = manager.getRelationship(remoteDid);
 * // record.direction === 'bidirectional'
 *
 * // Register a handler for incoming application messages:
 * manager.onGenMessage((remoteDid, body) => {
 *   console.log('Received from', remoteDid, ':', new TextDecoder().decode(body));
 * });
 *
 * // Send an application message to an established peer:
 * await manager.sendMessage(remoteDid, new TextEncoder().encode('Hello!'));
 * ```
 *
 * Reference: docs/implementation-plan-step4.md, docs/implementation-plan-step6.md
 */

import {
  tspSeal,
  tspOpen,
  peekEnvelope,
  encodeAad,
  computeSaidDigest,
  TSP_HPKE_INFO,
} from '../tsp/v3/message.js';
import {
  hpkeBaseSeal,
  importHpkePublicKey,
} from '../crypto/primitives.js';
import { hpkeHybridSeal } from '../crypto/ml-kem-x25519.js';
import { DidPeer4Method } from '../did/did-peer4-method.js';
import type { DidMethod } from '../did/did-method.js';

import type { TspTransport, TransportAddress } from '../transport/types.js';
import type { DidDocument } from '../did/types.js';
import type { TspRfiPayload, TspRfaPayload, Vid } from '../tsp/v3/types.js';
import { ceremonyTrace } from './ceremony-trace.js';
import { verifyRfiDigest, verifyRfaDigests, verifySenderDocumentBinding } from './handshake-verify.js';
import { openConfidentialBody } from './confidential-open.js';
import { decodeOobi, verifyOobiSignature } from './oobi.js';
import { RelationshipStore } from './store.js';
import type { LocalIdentity, OobiPayload, RelationshipRecord } from './types.js';
import { extractEd25519PublicKey, extractMlDsa65PublicKey } from './key-extract.js';


// ---------------------------------------------------------------------------
// RelationshipManager
// ---------------------------------------------------------------------------

/**
 * What to do when an inbound OOBI's ML-DSA-65 introduction signature does not
 * check out (H2, decision D-2).
 *
 *  - `off`     — do not check at all (no verification, no logging).
 *  - `warn`    — check and report; never abort. The DEFAULT, because an OOBI that
 *                predates PQ provisioning (or a peer whose PQ key rotated without
 *                re-issuing it) is a *legitimate* introduction that enforcing
 *                would refuse — and refusing it means you cannot connect.
 *  - `enforce` — refuse the introduction (throw) when it is unsigned, publishes
 *                no ML-DSA key, or carries a signature that does not verify.
 *
 * ## What `enforce` is, and is not
 *
 * It is an INTEGRITY control: it detects a stripped, truncated or altered
 * introduction. It is **not** an authentication control against an active
 * attacker, because the key it verifies against is resolved from the OOBI's own
 * `did` — and for a long-form `did:peer:4` that document travels *inside* the
 * same artifact, so an attacker who can rewrite the OOBI can rewrite the DID,
 * substitute their own ML-DSA key and re-sign. It becomes a real authentication
 * control only where `did` resolution is anchored outside the artifact
 * (e.g. a did:scid:vh resolved from a log the attacker cannot rewrite).
 *
 * ## Prerequisites before defaulting a deployment to `enforce`
 *
 *  1. every peer is PQ-provisioned (otherwise every pre-G7e peer is refused);
 *  2. the utility server signs its own OOBI (today it does not — see
 *     `routes/layer2-spanning/relationships.ts`), or no agent can connect to it;
 *  3. a rotation-aware OOBI re-issue flow exists, so an honest peer that rotated
 *     its ML-DSA key is not locked out.
 */
export type OobiSignaturePolicy = 'off' | 'warn' | 'enforce';

/** The environment variable that sets the policy when no explicit option is passed. */
export const OOBI_SIGNATURE_POLICY_ENV = 'TSP_OOBI_SIGNATURE_POLICY';

/** Resolve the effective policy: explicit option → environment → `warn`. */
function resolveOobiSignaturePolicy(explicit?: OobiSignaturePolicy): OobiSignaturePolicy {
  if (explicit) return explicit;
  const raw = (process.env[OOBI_SIGNATURE_POLICY_ENV] ?? '').trim().toLowerCase();
  if (raw === 'off' || raw === 'warn' || raw === 'enforce') return raw;
  if (raw) {
    console.warn(
      `[RM] ${OOBI_SIGNATURE_POLICY_ENV}="${raw}" is not one of off|warn|enforce — using "warn"`,
    );
  }
  return 'warn';
}

export class RelationshipManager {
  private readonly transport: TspTransport;
  private readonly store: RelationshipStore;
  private readonly identity: LocalIdentity;
  private readonly didMethod: DidMethod;
  private readonly oobiSignaturePolicy: OobiSignaturePolicy;
  private readonly resolvePeerDocument?: (did: string) => Promise<DidDocument | undefined>;
  private genMessageHandler?: (remoteDid: Vid, body: Uint8Array, confidential: boolean) => void;
  private readonly onBidirectional?: (remoteDid: Vid) => void;

  constructor(params: {
    transport: TspTransport;
    store: RelationshipStore;
    identity: LocalIdentity;
    /**
     * Optional DidMethod override (Step 9 — DID-method abstraction layer).
     * Defaults to DidPeer4Method (did:peer:4) when omitted. Used to verify
     * inbound RFI/RFA DID documents in a method-agnostic way.
     */
    didMethod?: DidMethod;
    /** Callback invoked after a bidirectional relationship is confirmed (for VRC minting). */
    onBidirectional?: (remoteDid: Vid) => void;
    /**
     * OOBI introduction-signature policy (H2). Defaults to
     * `process.env[OOBI_SIGNATURE_POLICY_ENV]` and then to `warn`.
     */
    oobiSignaturePolicy?: OobiSignaturePolicy;
    /**
     * Optional anchored resolver for a peer's DID document — the LAST source the
     * introduction check consults, after the DID itself and the pinned key.
     *
     * Its whole purpose is the case the other two cannot cover: a FIRST contact
     * with a `did:scid:vh` peer, whose document cannot be resolved locally
     * (`DidPeer4Method.resolve` handles only peer4; `ScidVhMethod.resolve` needs
     * that DID's rotation log) and for which nothing has been pinned yet.
     *
     * The anchor must be something the caller trusts independently of the artifact
     * being checked — for the agent that is the utility server (a pull of
     * `exchange:identity-lookup` over the already-authenticated TSP relationship);
     * for the utility server it is its own database. Returning `undefined` simply
     * leaves the introduction unverifiable, which is reported honestly.
     */
    resolvePeerDocument?: (did: string) => Promise<DidDocument | undefined>;
  }) {
    this.transport = params.transport;
    this.store = params.store;
    this.identity = params.identity;
    this.didMethod = params.didMethod ?? new DidPeer4Method();
    this.onBidirectional = params.onBidirectional;
    this.oobiSignaturePolicy = resolveOobiSignaturePolicy(params.oobiSignaturePolicy);
    this.resolvePeerDocument = params.resolvePeerDocument;
    // State the active policy once, so the mode is never ambiguous in a log.
    console.log(
      `[RM] OOBI introduction integrity policy: ${this.oobiSignaturePolicy}` +
      (this.oobiSignaturePolicy === 'warn'
        ? ' (reported, not enforced — set ' + OOBI_SIGNATURE_POLICY_ENV + '=enforce to refuse bad introductions)'
        : ''),
    );
  }


  // ---------------------------------------------------------------------------
  // Start — register the onMessage handler
  // ---------------------------------------------------------------------------

  /**
   * Register the onMessage handler on the transport.
   *
   * Dispatches by payload.type:
   *   TSP_RFI → processRfi()
   *   TSP_RFA → processRfa()
   *   TSP_GEN → processGen() (Step 6)
   *
   * Must be called before any messages can be received.
   */
  start(): void {
    this.transport.onMessage((message, fromAddr) => {
      // Fire-and-forget: errors are logged but not propagated to the transport.
      this.handleMessage(message, fromAddr).catch((err: unknown) => {
        console.error('[RelationshipManager] handleMessage error:', err);
      });
    });
  }

  // ---------------------------------------------------------------------------
  // sendRfi — initiate a relationship
  // ---------------------------------------------------------------------------
  /**
   * Check an inbound OOBI's ML-DSA-65 introduction signature against the ML-DSA
   * key the peer publishes in its DID document.
   *
   * Returns a verdict instead of logging inline so the caller can apply the
   * configured policy (H2): `warn` reports it, `enforce` refuses the
   * introduction. See {@link OobiSignaturePolicy} for what enforcement does and
   * does not buy you.
   *
   * ## Where the key comes from
   *
   * The signature is verified against the ML-DSA key of the identity the OOBI
   * NAMES (`oobi.did`), found in this order:
   *
   *  1. **The DID itself.** A long-form `did:peer:4` embeds its document, so the
   *     key is self-contained — this is the only source that works on a true
   *     first contact.
   *  2. **The relationship record** (`remoteMlDsa65Key`) — a TOFU pin taken from
   *     the document the peer presented in a handshake or identity push we already
   *     accepted. This is what makes the check work for a `did:scid:vh` peer
   *     (including the utility server): its DID cannot be resolved locally
   *     (`DidPeer4Method.resolve` handles only peer4, and `ScidVhMethod.resolve`
   *     needs that DID's rotation log), so before this fallback existed every
   *     scvh introduction was reported `oobi_key_unresolvable` and could never be
   *     enforced.
   *
   * A first contact with an UNKNOWN `did:scid:vh` peer still cannot be checked —
   * there is genuinely nothing to verify against, and inventing a key would be
   * worse than reporting the gap.
   */
  private async checkOobiIntroductionIntegrity(oobi: OobiPayload): Promise<{
    ok: boolean;
    reason?: 'oobi_key_unresolvable' | 'oobi_no_published_key' | 'oobi_unsigned' | 'oobi_signature_invalid';
    detail: string;
  }> {
    const prefix = oobi.did.slice(0, 24);

    let publishedKey: Uint8Array | undefined;
    let keySource = 'did';
    let resolveError: string | undefined;
    let resolvedDocument: DidDocument | undefined;
    try {
      resolvedDocument = this.didMethod.resolve(oobi.did);
      publishedKey = extractMlDsa65PublicKey(resolvedDocument);
    } catch (err) {
      resolveError = (err as Error)?.message ?? String(err);
    }

    if (!publishedKey) {
      // Fall back to the key pinned when we first accepted this peer's document.
      // Looked up by IDENTITY, so a peer we know but hold no live relationship
      // with is still checkable (an introduction often precedes the relationship).
      const pinned = this.store.getRemoteMlDsa65Key(oobi.did);
      if (pinned) {
        publishedKey = pinned;
        keySource = 'pinned document (accepted on an earlier handshake or identity push)';
      }
    }

    if (!publishedKey && this.resolvePeerDocument) {
      // Last source: an ANCHORED lookup the caller trusts independently of the
      // artifact being checked (the agent asks its VTA; the server reads its own
      // database). This is what makes a first contact with a did:scid:vh peer
      // checkable at all — the two sources above cannot cover it.
      try {
        const anchored = await this.resolvePeerDocument(oobi.did);
        const anchoredKey = anchored ? extractMlDsa65PublicKey(anchored) : undefined;
        if (anchoredKey) {
          publishedKey = anchoredKey;
          keySource = 'anchored document lookup (VTA / local database)';
          resolvedDocument = anchored;
        } else if (anchored) {
          // The anchor knows the identity but its document carries no ML-DSA key:
          // a pre-PQ peer, and the honest diagnosis is "no published key".
          resolvedDocument = anchored;
        }
      } catch (err) {
        resolveError = `anchored lookup failed: ${(err as Error)?.message ?? err}`;
      }
    }

    if (!publishedKey) {
      // Two genuinely different situations, kept apart because the remedies are
      // different: a peer we could not resolve (no local document — nothing to
      // check against yet) versus a peer whose document we DID read and which
      // simply publishes no PQ key (pre-G7e).
      if (resolvedDocument) {
        return {
          ok: false,
          reason: 'oobi_no_published_key',
          detail:
            `${prefix}… publishes no ML-DSA key in its own document, and this node has no pinned ` +
            `ML-DSA key for it (it predates PQ provisioning)`,
        };
      }
      return {
        ok: false,
        reason: 'oobi_key_unresolvable',
        detail:
          `no ML-DSA-65 key is available for ${prefix}…: it cannot be resolved locally` +
          (resolveError ? ` (${resolveError})` : '') +
          ` and this node has no pinned document for it (no completed handshake or identity push yet)`,
      };
    }

    if (!oobi.mlDsa65Signature) {
      return {
        ok: false,
        reason: 'oobi_unsigned',
        detail:
          `${prefix}… is UNSIGNED although a ML-DSA-65 key is published for it ` +
          `(source: ${keySource})`,
      };
    }

    if (!verifyOobiSignature(oobi, publishedKey)) {
      return {
        ok: false,
        reason: 'oobi_signature_invalid',
        detail:
          `${prefix}… signature INVALID against the key from ${keySource} — the introduction may ` +
          `have been altered, or the peer rotated its PQ key without re-issuing the OOBI`,
      };
    }

    // A key that came from the peer's own document (peer4) proves only that the
    // artifact is internally consistent; a PINNED key is the stronger case,
    // because the document it came from was accepted on an earlier handshake.
    return {
      ok: true,
      detail: `${prefix}… ML-DSA-65 signature verified (key from ${keySource})`,
    };
  }

  /**
   * Apply the configured OOBI introduction-integrity policy.
   *
   * `off` skips everything; `warn` reports and returns; `enforce` throws a named
   * error — which is what makes this a control rather than a log line. The throw
   * is deliberate: every `sendRfi` caller must be able to distinguish "refused
   * this introduction" from "the connection silently did not happen", which is
   * the failure mode G2 and G6 spent their effort removing.
   */
  private async applyOobiSignaturePolicy(oobi: OobiPayload): Promise<void> {
    if (this.oobiSignaturePolicy === 'off') return;

    const verdict = await this.checkOobiIntroductionIntegrity(oobi);

    if (verdict.ok) {
      console.log(`[RM:sendRfi] ✓ OOBI introduction ${verdict.detail}`);
      return;
    }

    // The INVALID case is an error in both modes: it means the artifact was
    // altered or the peer's key rotated. The others are warnings under `warn`.
    const loud = verdict.reason === 'oobi_signature_invalid';
    const line = `[RM:sendRfi] ${loud ? '✗' : '⚠'} OOBI introduction ${verdict.reason}: ${verdict.detail}`;

    if (this.oobiSignaturePolicy === 'enforce') {
      throw new Error(
        `${line} — refusing the introduction (${OOBI_SIGNATURE_POLICY_ENV}=enforce). ` +
        `Set the policy to "warn" to connect anyway.`,
      );
    }
    if (loud) console.error(line);
    else console.warn(line);
  }



  /**
   * Initiate a relationship with a remote peer.
   *
   * Decodes the OOBI, builds and sends a TSP_RFI, and stores the
   * outbound-pending record in the relationship table.
   *
   * @param encodedOobi  CESR-encoded OOBI string (as produced by encodeOobi)
   * @param subjectKind  Optional subject kind for the remote identity
   *                     ('human' | 'organization'). Defaults to 'human'.
   */
  async sendRfi(encodedOobi: string, subjectKind?: string): Promise<void> {
    const oobi = decodeOobi(encodedOobi);

    // Connecting to yourself is never valid. Reject BEFORE any relationship
    // row or RFI is created — otherwise the outbound-pending record is written
    // first and then the send to our own transport fails, leaving a stale
    // pending self-connection line in the UI.
    //
    // Deliberately BEFORE the integrity policy: an OOBI you generated yourself
    // is unsigned (`encodeOobi` does not sign; `signOobi` does), so under
    // `enforce` the integrity check would otherwise report a policy failure for
    // what is really a self-connect — a confusing diagnosis for a definite one.
    if (oobi.cesrVid === this.identity.cesrVid || oobi.did === this.identity.did) {
      throw new Error('Cannot connect to yourself — share this OOBI with a peer instead.');
    }

    // PQ introduction integrity (G7e, policy in H2): check the OOBI's ML-DSA-65
    // signature against the key the peer publishes in its DID document.
    await this.applyOobiSignaturePolicy(oobi);

    const remoteTransport: TransportAddress = {
      peerId: oobi.peerId,
      multiaddrs: oobi.multiaddrs,
    };

    // Workstream A: when the OOBI carries the sender's real DID, key the stub
    // identity row by that DID (stable DID/UUID) rather than the ephemeral VID.
    // The ephemeral VID remains the TSP signing identity (remoteDid fallback).
    const remoteDid = oobi.did;
    const remoteMethod = oobi.did.startsWith('did:scid:vh:')
      ? 'did:scid:vh'
      : 'did:peer:4';

    const { sealed, digest } = buildRfi({
      localDid: this.identity.did,
      remoteDid: oobi.did,
      localDidDocument: this.identity.didDocument,
      signingSecretKey: this.identity.signingKeyPair.secretKey,
    });

    // Store the outbound-pending record before sending (so we can match the RFA).
    // The initiator does NOT have the remote peer's DID document yet —
    // only the OOBI's VID and transport info. The responder's DID document
    // arrives in the RFA payload and is stored by processRfa().
    this.store.insertOutbound({
      localDid: this.identity.did,
      localMethod: this.didMethod.methodName,
      remoteDid,
      remoteMethod,
      remoteTransport,
      rfiDigest: digest,
      subjectKind,
    });

    ceremonyTrace.rfiSent({ remoteDid: oobi.cesrVid, localDid: this.identity.did });
    await this.transport.send(sealed, remoteTransport);
  }

  // ---------------------------------------------------------------------------
  // Relationship queries
  // ---------------------------------------------------------------------------

  /**
   * Look up a relationship record by remote VID.
   * Returns undefined if no relationship exists.
   */
  getRelationship(remoteDid: Vid): RelationshipRecord | undefined {
    return this.store.get(this.identity.did, remoteDid);
  }

  /**
   * List all relationship records for the local identity.
   */
  listRelationships(): RelationshipRecord[] {
    return this.store.list(this.identity.did);
  }

  /**
   * Update the transport address for a relationship.
   * Used when a remote peer's libp2p peer ID changes (e.g., server restart
   * without a persistent seed) and the agent discovers the new peer ID via
   * bootstrap.
   */
  updateTransport(remoteDid: Vid, transport: TransportAddress): void {
    this.store.updateTransport(this.identity.did, remoteDid, transport);
  }

  /**
   * Update the remote identity's subject_kind for a relationship.
   *
   * Used to self-heal a relationship that was previously stored with the
   * wrong subject kind (e.g., a utility server stored as 'human' before the
   * subject-kind tagging was introduced).
   */
  updateRemoteSubjectKind(remoteDid: Vid, subjectKind: string): void {
    this.store.updateRemoteSubjectKind(this.identity.did, remoteDid, subjectKind);
  }

  // ---------------------------------------------------------------------------
  // Internal: message dispatch
  // ---------------------------------------------------------------------------

  private async handleMessage(
    message: Uint8Array,
    fromAddr: TransportAddress,
  ): Promise<void> {
    // Peek at the payload type without full verification first.
    // We need to extract the didDocument from the payload to get the sender's
    // public key before we can call tspOpen(). So we do a two-pass approach:
    //   1. Decode the outer frame to extract the inner payload group.
    //   2. Parse the inner payload to get the type and didDocument.
    //   3. Extract the sender's Ed25519 public key from the didDocument.
    //   4. Call tspOpen() with the extracted public key to verify the signature.

    let payloadType: string;
    let senderPublicKey: Uint8Array;
    let senderDidDocument: DidDocument | undefined;
    let vidSenderFromPeek: Vid | undefined;

    try {
      const peek = peekEnvelope(message);
      payloadType = peek.payloadType;
      senderDidDocument = peek.didDocument;
      vidSenderFromPeek = peek.vidSender;
      console.log(`[RM:handleMessage] ← type=${payloadType} fromPeerId=${fromAddr.peerId?.slice(0,12) ?? 'none'} msgLen=${message.length}`);

      if (payloadType === 'TSP_GEN' || payloadType === 'TSP_GEN_CONFIDENTIAL') {
        // Step 6/7: dispatch TSP_GEN and TSP_GEN_CONFIDENTIAL to processGen() using the relationship table.
        // Pass fromAddr so processGen() can update the stored transport if the peer's address changed.
        await this.processGen(message, vidSenderFromPeek, fromAddr);
        return;
      }

      if (payloadType === 'TSP_RFD') {
        // A decline carries no DID document, so it must be handled BEFORE the
        // didDocument guard below (which would otherwise drop it as a malformed
        // RFI/RFA and leave the initiator waiting out its full timeout).
        await this.processRfd(vidSenderFromPeek, message, fromAddr);
        return;
      }

      if (!senderDidDocument) {
        console.warn('[RelationshipManager] received RFI/RFA without didDocument, ignoring');
        return;
      }

      // Extract the sender's Ed25519 public key from the inlined didDocument.
      senderPublicKey = extractEd25519PublicKey(senderDidDocument);
    } catch (err) {
      console.warn('[RelationshipManager] failed to peek payload type:', err);
      return;
    }

    // Now call tspOpen() with the extracted public key to verify the signature.
    let envelope: ReturnType<typeof tspOpen>;
    try {
      envelope = tspOpen({ message, senderPublicKey });
    } catch (err) {
      console.warn('[RelationshipManager] tspOpen failed:', err);
      return;
    }

    // The inline document is the ONLY source of the sender's Ed25519 key — the
    // key that just verified this message's signature — while the envelope's
    // sender VID is what several paths treat as the peer's identity (the
    // relationship-record lookup for TSP_GEN, markRejected, the ceremony trace).
    // Nothing used to check that the two agreed, so a peer could name one
    // identity in the envelope and supply another's document. Refuse the
    // contradiction loudly rather than persisting a relationship whose claimed
    // identity and trusted keys disagree.
    const bindingCheck = verifySenderDocumentBinding({
      vidSender: envelope.vidSender,
      document: senderDidDocument,
    });
    if (!bindingCheck.ok) {
      // Narrow to the RFI payload so the decline can carry the offending
      // digest (the union is not narrowed by a runtime flag).
      const rfiPayload = envelope.payload.type === 'TSP_RFI' ? envelope.payload : undefined;
      console.error(
        `[RM:handleMessage] REJECT ${bindingCheck.reason} (${bindingCheck.detail}) ` +
        `type=${envelope.payload.type} fromPeerId=${fromAddr.peerId?.slice(0, 12) ?? 'none'}` +
        (rfiPayload ? ' → declining with XRFD' : ' — accept ignored, relationship NOT established'),
      );
      ceremonyTrace.error('handleMessage', bindingCheck.reason);
      if (rfiPayload) {
        await this.declineInvite(envelope.vidSender, rfiPayload.digest, fromAddr);
      }
      return;
    }

    // Verify the DID document is self-consistent (for did:peer:4 long-form DIDs).
    // A long-form did:peer:4 contains a colon after the hash component (e.g., did:peer:4<hash>:<suffix>).
    // Short-form DIDs (no second colon) and non-did:peer:4 DIDs are not verified here.
    // verifyDidPeer4 is async (uses multiformats sha256.digest), so we await it.
    const isLongFormPeer4 = senderDidDocument.id &&
      senderDidDocument.id.startsWith('did:peer:4') &&
      senderDidDocument.id.slice('did:peer:4'.length).includes(':');
    if (isLongFormPeer4) {
      try {
        const isValid = await this.didMethod.verify(senderDidDocument.id!);
        if (!isValid) {
          console.warn('[RelationshipManager] didMethod.verify returned false, ignoring message');
          return;
        }
      } catch (err) {
        console.warn('[RelationshipManager] didMethod.verify failed:', err);

        return;
      }
    }

    // Dispatch by payload type.
    if (envelope.payload.type === 'TSP_RFI') {
      ceremonyTrace.rfiReceived({ vidSender: envelope.vidSender, fromPeerId: fromAddr.peerId });
      await this.processRfi(envelope.vidSender, envelope.payload, fromAddr, senderDidDocument, envelope.vidReceiver);
    } else if (envelope.payload.type === 'TSP_RFA') {
      ceremonyTrace.rfaReceived({ vidSender: envelope.vidSender, digestMatch: true });
      await this.processRfa(envelope.vidSender, envelope.payload, fromAddr, senderDidDocument, envelope.vidReceiver);
    }
  }

  // ---------------------------------------------------------------------------
  // Internal: processRfi
  // ---------------------------------------------------------------------------

  private async processRfi(
    vidSender: Vid,
    payload: TspRfiPayload,
    fromAddr: TransportAddress,
    senderDidDocument: DidDocument,
    /** Receiver VID from the signature-verified envelope (for the addressee check). */
    receiverVid: Vid | null,
  ): Promise<void> {
    // Verify the self-addressing digest (spec 7.2.1) before acting on the invite.
    // A mismatch is LOUD: we decline with an XRFD carrying the offending digest so
    // the sender fails immediately instead of waiting out a 30 s timeout with no
    // explanation. (This used to `return` silently — which is how a stale or
    // mismatched OOBI `did` presented as "the ceremony just times out".)
    const rfiCheck = verifyRfiDigest({
      vidSender,
      localDid: this.identity.did,
      nonce: payload.nonce,
      digest: payload.digest,
      receiverVid,
    });
    if (!rfiCheck.ok) {
      console.error(
        `[RM:processRfi] REJECT ${rfiCheck.reason} (${rfiCheck.detail}) ` +
        `from=${vidSender.slice(0, 24)}... → declining with XRFD`,
      );
      ceremonyTrace.error('processRfi', rfiCheck.reason);
      await this.declineInvite(vidSender, payload.digest, fromAddr);
      return;
    }

    // Workstream A: the RFI carries the sender's real DID document; key the
    // inbound identity by that stable DID, falling back to the VID for legacy
    // handshakes.
    const realDid = senderDidDocument.id!;
    const realMethod = realDid.startsWith('did:scid:vh:') ? 'did:scid:vh' : 'did:peer:4';

    // Upsert the inbound record (applies lower-digest-wins if there's a race).
    // The remote peer's keys are stored in did_documents via
    // resolveRemoteIdentity() during upsert, and resolved at query time
    // via FK join on remote_did_document_id → did_documents.document_json.
    const result = this.store.upsertInbound({
      localDid: this.identity.did,
      localMethod: this.didMethod.methodName,
      remoteDid: realDid,
      remoteMethod: realMethod,
      didDocument: senderDidDocument,
      remoteTransport: fromAddr,
      rfiDigest: payload.digest!,
    });

    // Self-heal the remote's endpoint: the RFI's live fromAddr.peerId is the
    // sender's CURRENT node key. Record it (retiring superseded endpoints) so
    // this side reaches the peer correctly even after it re-keyed on restart.
    if (fromAddr?.peerId) {
      this.store.recordEndpointForRemote(this.identity.did, realDid, fromAddr.peerId);
    }

    ceremonyTrace.relationshipUpdated({
      localDid: this.identity.did, remoteDid: vidSender,
      direction: result === 'rejected-lower-digest' ? 'outbound' : 'inbound',
      status: result === 'rejected-lower-digest' ? 'pending' : 'established',
    });

    if (result === 'rejected-lower-digest') {
      // Our outbound RFI has a lower digest — we win, they should accept ours.
      // Do not send an RFA; wait for their RFA to arrive.
      return;
    }

    // Send TSP_RFA in response.
    const { sealed, replyDigest } = buildRfa({
      localDid: this.identity.did,
      remoteDid: vidSender,
      localDidDocument: this.identity.didDocument,
      rfiDigest: payload.digest!,
      signingSecretKey: this.identity.signingKeyPair.secretKey,
    });

    await this.transport.send(sealed, fromAddr);

    // Store the RFA reply digest on the relationship record (proof that we responded).
    this.store.setRfaReplyDigest(this.identity.did, realDid, replyDigest);

    // Once the RFA is sent, the responder considers the relationship bidirectional.
    // (The initiator will confirm bidirectional when it receives this RFA.)
    this.store.confirmBidirectional({
      localDid: this.identity.did,
      remoteDid: realDid,
      remoteTransport: fromAddr,
      rfaReplyDigest: replyDigest,
    });

    // Notify upper layer (BaseAgent) that a bidirectional relationship was formed.
    ceremonyTrace.bidirectional({ remoteDid: vidSender });
    this.onBidirectional?.(vidSender);
  }

  // ---------------------------------------------------------------------------
  // sendMessage — send a TSP_GEN application message (Step 6)
  // ---------------------------------------------------------------------------

  /**
   * Send a signed non-confidential application message (TSP_GEN) to an established peer.
   *
   * The relationship must be bidirectional before sending. The message is signed
   * with the local identity's Ed25519 key and sent via the transport to the
   * remote peer's stored transport address.
   *
   * @param remoteDid  CESR-encoded Ed25519 public key of the remote peer
   * @param body       Application-level message body (arbitrary bytes)
   * @throws Error if no bidirectional relationship exists for remoteDid
   * @throws Error if the relationship record has no stored remoteTransport
   */
  /**
   * Send a confidential application message (TSP_GEN_CONFIDENTIAL) to an established peer.
   *
   * The body is HPKE-Auth encrypted using the local X25519 agreement key (sender)
   * and the remote peer's X25519 key (recipient), then signed with the local Ed25519
   * signing key via tspSeal().
   *
   * @param remoteDid  CESR-encoded Ed25519 public key of the remote peer
   * @param body       Application-level message body (arbitrary bytes)
   * @throws Error if no bidirectional relationship exists for remoteDid
   * @throws Error if the relationship record has no stored remoteX25519Key
   */
   async sendConfidentialMessage(
     remoteDid: Vid,
     body: Uint8Array,
     _onStatus?: (message: string) => void,
   ): Promise<void> {
     const didShort = remoteDid.slice(0, 12);

     const record = this.store.get(this.identity.did, remoteDid);
     if (!record || record.direction !== 'bidirectional') {
       console.warn(`[RM:sendConfidential] FAIL: no bidirectional relationship with ${didShort}...`);
       throw new Error(
         `RelationshipManager.sendConfidentialMessage: no bidirectional relationship with ${didShort}...`,
       );
     }
     if (!record.remoteX25519Key) {
       console.warn(`[RM:sendConfidential] FAIL: no remoteX25519Key for ${didShort}...`);
       throw new Error(
         `RelationshipManager.sendConfidentialMessage: no remoteX25519Key stored for ${didShort}...`,
       );
     }

     // Encrypt the body. The KEM is chosen by what the PEER publishes: the
     // MLKEM768-X25519 hybrid when the peer's DID document carries `#key-kem`
     // (post-quantum key agreement), otherwise classical DHKEM(X25519).
     const aad = encodeAad(this.identity.did, record.remoteDid);
     const { enc, ciphertext } = record.remoteHybridKemKey
       ? await hpkeHybridSeal(record.remoteHybridKemKey, body, TSP_HPKE_INFO, aad)
       : await hpkeBaseSeal(
           await importHpkePublicKey(record.remoteX25519Key!),
           body,
           TSP_HPKE_INFO,
           aad,
         );
     console.log(
       `[RM:sendConfidential] → ${remoteDid.slice(0, 12)}… sealed with the ` +
       `${record.remoteHybridKemKey ? 'MLKEM768-X25519 hybrid' : 'DHKEM(X25519) classical'} KEM (enc=${enc.length}B)`,
     );

     const sealed = tspSeal({
       vidSender: this.identity.did,
       vidReceiver: record.remoteDid,
       payload: { type: 'TSP_GEN_CONFIDENTIAL', enc, ciphertext },
       signingSecretKey: this.identity.signingKeyPair.secretKey,
     });

     await this.sendDirect(record, sealed);
   }

    async sendMessage(
      remoteDid: Vid,
      body: Uint8Array,
      onStatus?: (message: string) => void,
    ): Promise<void> {
      const didShort = remoteDid.slice(0, 12);

      const record = this.store.get(this.identity.did, remoteDid);
      if (!record || record.direction !== 'bidirectional') {
        const err = `RelationshipManager.sendMessage: no bidirectional relationship with ${didShort}...`;
        console.warn(`[RM:sendMessage] FAIL: ${err}`);
        throw new Error(err);
      }

      const sealed = tspSeal({
        vidSender: this.identity.did,
        vidReceiver: record.remoteDid,
        payload: { type: 'TSP_GEN', body },
        signingSecretKey: this.identity.signingKeyPair.secretKey,
      });
      console.log(
        `[RM:sendMessage] signing pubKey=${Buffer.from(this.identity.signingKeyPair.publicKey).toString('hex')} ` +
        `localDid=${this.identity.did.slice(0, 24)}... → ${didShort}...`,
      );

      onStatus?.(`Sending to ${didShort}... (${body.length} bytes)`);
      try {
        await this.sendDirect(record, sealed);
        onStatus?.(`Sent to ${didShort}...`);
      } catch (sendErr: unknown) {

        // Refresh the record and the transport after the failure
        const freshRecord = this.store.get(this.identity.did, remoteDid);
        if (!freshRecord || freshRecord.direction !== 'bidirectional') {
          throw new Error(`RelationshipManager.sendMessage: relationship lost during retry for ${didShort}...`);
        }

        // Re-resolve live addresses from libp2p and re-dial.
        // This covers the NAT relay case where the circuit reservation lapsed.
        const stored = freshRecord.remoteTransport;
        if (stored) {
          const liveAddrs = this.transport.getPeerMultiaddrs?.(stored.peerId);
          if (liveAddrs && liveAddrs.length > 0) {
            const storedAddrs = stored.multiaddrs ?? [];
            if (JSON.stringify(liveAddrs.sort()) !== JSON.stringify(storedAddrs.sort())) {
              freshRecord.remoteTransport = { peerId: stored.peerId, multiaddrs: liveAddrs };
              this.store.updateTransport(this.identity.did, remoteDid, freshRecord.remoteTransport);
            }
          }
        }

        onStatus?.(`Retrying send to ${didShort}...`);
        await this.sendDirect(freshRecord, sealed);
        onStatus?.(`Sent to ${didShort}...`);
      }
    }

   // ---------------------------------------------------------------------------
   // invalidateConnection — drop a cached connection the transport can no longer trust
   // ---------------------------------------------------------------------------

   /**
    * Close the transport's cached connection(s) to `remoteDid`'s peer so the next
    * send re-dials instead of reusing a possibly-dead one.
    *
    * Called when a REQUEST to this peer timed out with no response. Unlike a
    * write failure, a half-open / black-holed connection accepts the write
    * silently — `dialProtocol` + `write` + `close` all succeed and the peer never
    * sees the frame — so without this the same wedged connection is reused for
    * every subsequent request and one silent loss becomes an indefinite stream of
    * 30s `TSP request … timed out` failures against that peer.
    *
    * Best-effort: no relationship, no stored peerId, or a transport without the
    * capability is a no-op.
    */
   async invalidateConnection(remoteDid: Vid): Promise<void> {
     const record = this.getRelationship(remoteDid);
     const peerId = record?.remoteTransport?.peerId;
     if (!peerId) return;
     try {
       await this.transport.invalidatePeer?.(peerId, 'request timed out — reuse of a silent connection avoided');
     } catch {
       // best-effort: the caller is already failing or retrying
     }
   }

   // ---------------------------------------------------------------------------
   // Internal: direct send (no automatic reconnection)
   // ---------------------------------------------------------------------------

   /**
    * Send a sealed message to a peer's stored transport address.
    *
    * Reconnection is handled at the Agent layer via ConnectivityModule,
    * which uses bootstrap-discovered addresses and circuit relay.
    * The RelationshipManager does NOT perform automatic reconnection here,
    * keeping the transport interface clean (no concrete-type casts).
    */
   private async sendDirect(
     record: RelationshipRecord,
     sealed: Uint8Array,
   ): Promise<void> {
     const stored = record.remoteTransport;
     const didShort = (record.remoteDid ?? stored?.peerId ?? 'unknown').slice(0, 12);
     if (!stored) {
       throw new Error(
         `RelationshipManager: no remoteTransport stored for ${didShort}...`,
       );
     }

     // Refresh transport addresses from libp2p's live connection state.
     // The stored multiaddrs from the RFI/RFA handshake may be stale.
     let transportAddr = stored;
     const liveAddrs = this.transport.getPeerMultiaddrs?.(stored.peerId);
     if (liveAddrs && liveAddrs.length > 0) {
       const storedAddrs = stored.multiaddrs ?? [];
       const addrsChanged = JSON.stringify(liveAddrs.sort()) !== JSON.stringify(storedAddrs.sort());
       if (addrsChanged) {
         transportAddr = { peerId: stored.peerId, multiaddrs: liveAddrs };
         // Persist the refreshed address so future sends don't need the refresh
         this.store.updateTransport(this.identity.did, record.remoteDid ?? stored.peerId, transportAddr);
       }
     }

     const addrs = transportAddr.multiaddrs?.join(', ') ?? 'none';
     const isConn = this.transport.isConnected?.(stored.peerId) ?? true; // default true if method absent
     console.log(`[RM:sendDirect] → ${didShort}... peerId=${(stored.peerId ?? 'none').slice(0,12)}... addrs=[${addrs}] isConnected=${isConn} sealedBytes=${sealed.length}`);

     await this.transport.send(sealed, transportAddr);
   }


  // ---------------------------------------------------------------------------
  // onGenMessage — register a handler for incoming TSP_GEN messages (Step 6)
  // ---------------------------------------------------------------------------

  /**
   * Register a handler for incoming TSP_GEN application messages.
   *
   * The handler is only invoked for messages from peers with an established
   * bidirectional relationship whose signature verifies against the stored
   * remoteEd25519Key. Messages from unknown or non-bidirectional peers are
   * silently discarded.
   *
   * Replaces any previously registered handler.
   *
   * @param handler  Called with (remoteDid, body) for each verified TSP_GEN message
   */
  onGenMessage(handler: (remoteDid: Vid, body: Uint8Array, confidential: boolean) => void): void {
    this.genMessageHandler = handler;
  }

  // ---------------------------------------------------------------------------
  // Internal: processGen (Step 6)
  // ---------------------------------------------------------------------------

  /**
   * Process an incoming TSP_GEN message.
   *
   * Looks up the sender's relationship record, verifies the signature using
   * the stored remoteEd25519Key, and invokes the registered genMessageHandler.
   *
   * @param message      Raw CESR-encoded TSP message bytes
   * @param vidSender    CESR-encoded sender VID (from peekPayloadType)
   */
  private async processGen(message: Uint8Array, vidSender: Vid, fromAddr?: TransportAddress): Promise<void> {
    // Look up the relationship record for the sender. The record is keyed by
    // the peer's real DID (strict OOBI); the ephemeral VID resolves onto it via
    // the keys table (lookupByVid in `get`).
    const record = this.store.get(this.identity.did, vidSender);
    if (!record || record.direction !== 'bidirectional') {
      console.warn(
        `[RelationshipManager] processGen: no bidirectional relationship for ${vidSender.slice(0, 12)}...`,
      );
      return;
    }
    if (!record.remoteEd25519Key) {
      console.warn(
      );
      return;
    }

    // Verify the signature using the stored remoteEd25519Key.
    let envelope: ReturnType<typeof tspOpen>;
    try {
      envelope = tspOpen({ message, senderPublicKey: record.remoteEd25519Key });
    } catch (err) {
      return;
    }

    // Update the stored transport address if the sender's fromAddr has changed.
    // This handles the case where a peer restarts and gets a new port/multiaddr.
    // We only update if fromAddr has a peerId that matches the stored record.
    if (fromAddr && fromAddr.peerId && fromAddr.peerId === record.remoteTransport?.peerId) {
      const storedAddrs = record.remoteTransport?.multiaddrs ?? [];
      const newAddrs = fromAddr.multiaddrs ?? [];
      const addrsChanged = newAddrs.length > 0 &&
        JSON.stringify(newAddrs.sort()) !== JSON.stringify(storedAddrs.sort());
      if (addrsChanged) {
        this.store.updateTransport(this.identity.did, record.remoteDid, fromAddr);
      }
    }

    // Self-heal the remote's endpoint even when there is no new handshake: a
    // TSP_GEN message arrives from the peer's LIVE node key. If it differs
    // from the stored endpoint, the peer re-keyed on restart — record the
    // live peer so future dials reach it.
    if (fromAddr?.peerId && fromAddr.peerId !== record.remoteTransport?.peerId) {
      this.store.recordEndpointForRemote(this.identity.did, record.remoteDid, fromAddr.peerId);
    }

    if (envelope.payload.type === 'TSP_GEN') {
      this.genMessageHandler?.(vidSender, envelope.payload.body, false);
      return;
    }

    if (envelope.payload.type === 'TSP_GEN_CONFIDENTIAL') {
      // Both sides follow the same rule — hybrid iff the SENDER publishes
      // `#key-kem` — but a relationship record can be stale, so the shared
      // openConfidentialBody() tries the expected KEM first and falls back to
      // the other, choosing the SPLIT and the KEM together. The AEAD tag
      // authenticates, so at most one attempt can produce a valid plaintext.
      const expectHybrid = !!record.remoteHybridKemKey;
      const opened = await openConfidentialBody({
        message,
        senderPublicKey: record.remoteEd25519Key,
        vidSender: envelope.vidSender,
        vidReceiver: envelope.vidReceiver,
        agreementKeyPair: this.identity.agreementKeyPair,
        hybridKemKeyPair: this.identity.hybridKemKeyPair,
        expectHybrid,
      });
      if (!opened) {
        console.warn(
          `[RM:processGen] could not decrypt a confidential message from ${vidSender.slice(0, 12)}… ` +
          `with either KEM (peer publishes #key-kem: ${expectHybrid})`,
        );
        return;
      }
      if (opened.mismatch) {
        console.warn(
          `[RM:processGen] confidential message from ${vidSender.slice(0, 12)}… opened with the ${opened.used} ` +
          `KEM although ${expectHybrid ? 'hybrid' : 'classical'} was expected — the stored peer keys ` +
          `are stale; they are re-read on the next handshake`,
        );
      }
      this.genMessageHandler?.(vidSender, opened.plaintext, true);
      return;
    }

    // Should not happen — peekPayloadType already confirmed TSP_GEN.
    console.warn('[RelationshipManager] processGen: unexpected payload type after tspOpen');
  }

  // ---------------------------------------------------------------------------
  // Internal: processRfa
  // ---------------------------------------------------------------------------
  private async processRfa(
    vidSender: Vid,
    payload: TspRfaPayload,
    fromAddr: TransportAddress,
    senderDidDocument: DidDocument,
    /** Receiver VID from the signature-verified envelope (for the addressee check). */
    receiverVid: Vid | null,
  ): Promise<void> {
    // The RFI carries the responder's real DID; key the record by it.
    const realDid = senderDidDocument.id!;

    // Look up the outbound-pending record to verify the digest matches.
    // The DID-carrying OOBI already keyed the stub by the real DID.
    const existing = this.store.get(this.identity.did, realDid);
    if (!existing) {
      ceremonyTrace.error('processRfa', `no relationship record for ${realDid.slice(0, 12)}...`);
      return;
    }
    if (!existing.rfiDigest) {
      console.warn('[RelationshipManager] received RFA but no RFI digest on record, ignoring');
      return;
    }

    // Verify BOTH digests: the echoed request digest must be the RFI we sent, and
    // the Reply_Digest must be the self-addressing digest of this accept
    // (spec 7.2.1). Shared with the utility server's responder — the two copies
    // had diverged (the server verified neither), which is how a bad accept could
    // establish a relationship without complaint.
    const rfaCheck = verifyRfaDigests({
      vidSender,
      localDid: this.identity.did,
      digest: payload.digest,
      replyDigest: payload.replyDigest,
      expectedRfiDigest: existing.rfiDigest,
      receiverVid,
    });
    if (!rfaCheck.ok) {
      console.error(
        `[RM:processRfa] REJECT ${rfaCheck.reason} (${rfaCheck.detail}) ` +
        `from=${vidSender.slice(0, 24)}... — accept ignored, relationship NOT established`,
      );
      ceremonyTrace.error('processRfa', rfaCheck.reason);
      return;
    }

    // Store the responder's DID document (arrives in the RFA payload).
    // This populates the keys table with the responder's Ed25519/X25519
    // public keys so that future TSP_GEN signature verification works.
    this.store.storeRemoteDidDocument(this.identity.did, realDid, senderDidDocument);

    // Self-heal the responder's endpoint from the live fromAddr (see processRfi).
    if (fromAddr?.peerId) {
      this.store.recordEndpointForRemote(this.identity.did, realDid, fromAddr.peerId);
    }

    // Update the record to bidirectional.
    this.store.confirmBidirectional({
      localDid: this.identity.did,
      remoteDid: realDid,
      remoteTransport: fromAddr,
      rfaReplyDigest: payload.replyDigest!,
    });

    // Notify upper layer (BaseAgent) that a bidirectional relationship was formed.
    ceremonyTrace.bidirectional({ remoteDid: vidSender });
    this.onBidirectional?.(vidSender);
  }

  // ---------------------------------------------------------------------------
  // Internal: decline an invite / handle a declined invite (TSP XRFD)
  // ---------------------------------------------------------------------------

  /**
   * Decline an invite we could not accept.
   *
   * `XRFD` carries the digest of the message being declined (spec), which lets
   * the initiator correlate the decline with the exact RFI it sent — the reason
   * itself stays in this node's log. Best-effort: a failed send must never throw
   * into the inbound-message handler.
   */
  private async declineInvite(
    remoteDid: Vid,
    declinedDigest: Uint8Array | undefined,
    toAddr: TransportAddress,
  ): Promise<void> {
    if (!declinedDigest) return;
    try {
      const sealed = tspSeal({
        vidSender: this.identity.did,
        vidReceiver: remoteDid,
        payload: { type: 'TSP_RFD', digest: declinedDigest },
        signingSecretKey: this.identity.signingKeyPair.secretKey,
      });
      await this.transport.send(sealed, toAddr);
      console.log(`[RM:declineInvite] → XRFD sent to ${remoteDid.slice(0, 24)}... (declined=${Buffer.from(declinedDigest.subarray(0, 8)).toString('hex')})`);
    } catch (err) {
      console.warn(`[RM:declineInvite] failed to send XRFD: ${(err as Error)?.message ?? err}`);
    }
  }

  /**
   * Handle an inbound decline (`XRFD`): the peer refused our invite.
   *
   * Marks the relationship `rejected` so pollers (`TspBridge.waitForBidirectional`,
   * the ceremony driver) fail fast with a real reason instead of running out a
   * 30 s timeout, and logs the correlated digest so the initiator can match it to
   * the RFI it sent.
   *
   * Signature verification is best-effort: the peer's key is normally already on
   * the outbound record, but a decline can legitimately arrive before any
   * relationship row exists, and an unverified decline can only cause a *false
   * negative* (giving up on an invite), which is logged as such.
   */
  private async processRfd(
    vidSender: Vid,
    message: Uint8Array,
    fromAddr: TransportAddress,
  ): Promise<void> {
    const record = this.store.get(this.identity.did, vidSender);

    let declinedDigest: Uint8Array | undefined;
    try {
      declinedDigest = peekEnvelope(message).digest;
    } catch {
      /* structure already validated by the caller */
    }

    const matchesOurRfi = !!declinedDigest && !!record?.rfiDigest &&
      uint8ArrayEqual(declinedDigest, record.rfiDigest);

    let authenticated = 'unverified';
    if (record?.remoteEd25519Key) {
      try {
        tspOpen({ message, senderPublicKey: record.remoteEd25519Key });
        authenticated = 'verified';
      } catch (err) {
        console.error(
          `[RM:processRfd] ignoring XRFD from ${vidSender.slice(0, 24)}...: ` +
          `signature verification failed (${(err as Error)?.message ?? err})`,
        );
        return;
      }
    }

    const rejected = this.store.markRejected(this.identity.did, vidSender);
    console.error(
      `[RM:processRfd] peer DECLINED our invite (${authenticated}) from=${vidSender.slice(0, 24)}... ` +
      `fromPeerId=${fromAddr.peerId?.slice(0, 12) ?? 'none'} ` +
      `declined=${declinedDigest ? Buffer.from(declinedDigest.subarray(0, 8)).toString('hex') : 'none'} ` +
      `matchesOurRfi=${matchesOurRfi} statusRejected=${rejected} — ` +
      `the reason is in the PEER's log (look for [RM:processRfi] REJECT / REJECT rfi_digest_mismatch)`,
    );
    ceremonyTrace.error('processRfd', 'invite declined by peer');
  }
}

// ---------------------------------------------------------------------------
// Internal helpers: build RFI / RFA
// ---------------------------------------------------------------------------

/**
 * Build and sign a TSP_RFI message.
 *
 * @returns { sealed: Uint8Array, digest: Uint8Array }
 *   sealed = the CESR-encoded TSP message bytes
 *   digest = the self-addressing digest of the RFI payload (for storage + RFA matching)
 */
function buildRfi(params: {
  localDid: Vid;
  remoteDid: Vid;
  localDidDocument: DidDocument;
  signingSecretKey: Uint8Array;
}): { sealed: Uint8Array; digest: Uint8Array } {
  const { localDid, remoteDid, localDidDocument, signingSecretKey } = params;

  // 16-byte (128-bit) random nonce.
  const nonce = crypto.getRandomValues(new Uint8Array(16));

  // Self-addressing digest (spec 7.2.1): derived over the envelope + payload.
  const digest = computeSaidDigest('RFI', localDid, remoteDid, { nonce });

  const sealed = tspSeal({
    vidSender: localDid,
    vidReceiver: remoteDid,
    payload: { type: 'TSP_RFI', nonce, didDocument: localDidDocument },
    signingSecretKey,
  });

  return { sealed, digest };
}

/**
 * Build and sign a TSP_RFA message.
 *
 * @returns { sealed: Uint8Array, replyDigest: Uint8Array }
 */
function buildRfa(params: {
  localDid: Vid;
  remoteDid: Vid;
  localDidDocument: DidDocument;
  rfiDigest: Uint8Array;
  signingSecretKey: Uint8Array;
}): { sealed: Uint8Array; replyDigest: Uint8Array } {
  const { localDid, remoteDid, localDidDocument, rfiDigest, signingSecretKey } = params;

  // Self-addressing digest (spec 7.2.1): derived over the envelope + payload.
  const replyDigest = computeSaidDigest('RFA', localDid, remoteDid, { requestDigest: rfiDigest });

  const sealed = tspSeal({
    vidSender: localDid,
    vidReceiver: remoteDid,
    payload: { type: 'TSP_RFA', digest: rfiDigest, didDocument: localDidDocument },
    signingSecretKey,
  });

  return { sealed, replyDigest };
}


// ---------------------------------------------------------------------------
// Internal helpers: Uint8Array equality
// ---------------------------------------------------------------------------

function uint8ArrayEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
