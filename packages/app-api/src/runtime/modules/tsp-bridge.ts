// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * TspBridge — agent-side bridge between RelationshipManager and TspClientModule.
 *
 * After the agent establishes a bidirectional relationship with the utility server
 * (via OOBI), this module:
 * 1. Initializes TspClientModule with a sendFn that routes through RelationshipManager
 * 2. Routes inbound TSP_GEN messages from the utility server through TspClientModule
 *    for protocol detection and request/response correlation
 * 3. Provides a clean API for sending protocol messages to the utility server
 *
 * ## Usage
 *
 * ```
 * const bridge = new TspBridge();
 *
 * // After RelationshipManager is started:
 * bridge.init({ manager, tspClient, utilityServerOobi });
 *
 * // Connect to the utility server:
 * const serverDid = await bridge.connect();
 *
 * // Send a coordinator op (raw protocol names were retired in Phases C–G):
 * await bridge.getTspClient().enqueue(serverDid, 'tx_prepare', { ... });
 * ```
 */

import { encodeProtocolMessage, type ProtocolMessage } from '@p2p-trust-stack/core/tsp-handlers/types.js';
import type { RelationshipManager } from '@p2p-trust-stack/core/relationship/manager.js';
import type { RelationshipRecord } from '@p2p-trust-stack/core/relationship/types.js';
import type { TspClientModule } from './tsp-client.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';

/**
 * How long an RFI/RFA handshake is given to complete, in milliseconds.
 *
 * Doubles as the age after which an outbound-pending record is treated as DEAD
 * rather than in flight: once a row has been waiting longer than a whole
 * handshake window, nothing is going to complete it, so waiting again can only
 * burn another 30 s.
 */
const HANDSHAKE_TIMEOUT_MS = 30_000;

export interface TspBridgeDeps {
  /** Active relationship manager (has running transport + store). */
  manager: RelationshipManager;
  /** The TSP client module (created but not yet initialized). */
  tspClient: TspClientModule;
  /** The utility server's OOBI string (for establishing relationship). */
  utilityServerOobi?: string;
  /** Optional: pre-resolved utility server VID (if already connected). */
  utilityServerDid?: string;
}

export class TspBridge {
  private manager: RelationshipManager | null = null;
  private tspClient: TspClientModule | null = null;
  private utilityServerOobi: string | null = null;
  private utilityServerDid: string | null = null;
  private connected = false;

  // ---------------------------------------------------------------------------
  // Setup
  // ---------------------------------------------------------------------------

  init(deps: TspBridgeDeps): void {
    this.manager = deps.manager;
    this.tspClient = deps.tspClient;
    this.utilityServerOobi = deps.utilityServerOobi ?? null;
    this.utilityServerDid = deps.utilityServerDid ?? null;

    // Wire the TSP client's send function to go through the relationship manager.
    // Protocol messages are sent as TSP_GEN bodies via the established relationship.
    this.tspClient.init(async (remoteDid: string, body: Uint8Array) => {
      if (!this.manager) throw new Error('TspBridge: not initialized');
      // Send as a regular TSP_GEN message — the utility server's TSP bridge
      // will detect the protocol envelope and route it to handlers.
      await this.manager.sendMessage(remoteDid, body);
    });

    // A request that times out with no response means the cached connection to
    // that peer may be a silent black hole (the write succeeded, the frame never
    // arrived). Drop it so the NEXT request re-dials instead of failing
    // identically forever — this is what turned one lost `tx_commit` into every
    // subsequent request to the utility server timing out at 30s.
    this.tspClient.setRequestTimeoutHook((remoteDid: string) => {
      void this.manager?.invalidateConnection(remoteDid);
    });

    logger.info('[TspBridge] Initialized — TSP client wired through RelationshipManager');
  }

  // ---------------------------------------------------------------------------
  // Connection
  // ---------------------------------------------------------------------------

  /**
   * Connect to the utility server by establishing a bidirectional TSP relationship.
   *
   * If `utilityServerOobi` is provided, this initiates the RFI/RFA handshake.
   * If `utilityServerDid` is pre-configured, skips the handshake (already connected).
   *
   * Returns the utility server's VID on success.
   */
  async connect(): Promise<string> {
    if (!this.manager || !this.tspClient) {
      throw new Error('TspBridge.connect: not initialized. Call init() first.');
    }

    if (this.utilityServerDid) {
      // Already have the VID — verify relationship exists
      const record = this.manager.getRelationship(this.utilityServerDid);
      if (record && record.direction === 'bidirectional') {
        // Self-heal subject kind — ensure utility server is tagged 'organization'
        if (this.manager.updateRemoteSubjectKind) {
          this.manager.updateRemoteSubjectKind(this.utilityServerDid, 'organization');
        }
        this.connected = true;
        return this.utilityServerDid;
      }
      // VID provided but no relationship — try establishing one
    }

    if (!this.utilityServerOobi) {
      throw new Error(
        'TspBridge.connect: no utilityServerOobi or utilityServerDid configured. ' +
        'Provide the utility server\'s OOBI in agent config.',
      );
    }

    // Decode the OOBI to get the remote VID. The OOBI format is now STRICT
    // 4-item (vid, peerId, multiaddrs, did) — a legacy 3-item OOBI is REJECTED.
    // Surface the exact failure so a misconfigured/stale OOBI is diagnosable.
    const { decodeOobi } = await import('@p2p-trust-stack/core/relationship/oobi.js');
    let oobi;
    try {
      oobi = decodeOobi(this.utilityServerOobi);
    } catch (err) {
      throw new Error(
        `TspBridge.connect: utility server OOBI is not the current 4-item format ` +
        `(vid, peerId, multiaddrs, did). Re-fetch the OOBI from the utility server's ` +
        `/relationships/oobi endpoint. Decode error: ${(err as Error).message}`,
      );
    }

    logger.info(
      `[TspBridge] Connecting to utility server via OOBI: vid=${oobi.cesrVid.slice(0, 12)}... peerId=${oobi.peerId.slice(0, 12)}... did=${(oobi.did ?? 'MISSING').slice(0, 24)}`,
    );

    // Check if a relationship already exists (e.g., from a previous session).
    // If it's already bidirectional, we're done. If it's pending, wait for it
    // to complete rather than trying to create a duplicate.
    const existing = this.manager.getRelationship(oobi.did);
    if (existing) {
      if (existing.direction === 'bidirectional' && existing.status === 'established') {
        // ── Update transport if the peer ID changed (utility server restart) ──
        // The utility server's peer ID changes on every restart unless a
        // persistent LIBP2P_SEED is configured.  When the agent discovers the
        // utility server via bootstrap, the OOBI carries the current peer ID.
        // If the stored transport has a stale peer ID, update it so subsequent
        // TSP_GEN messages are sent to the correct peer.
        const storedPeerId = existing.remoteTransport?.peerId;
        if (storedPeerId && storedPeerId !== oobi.peerId) {
          logger.info(
            `[TspBridge] ⚠ utility server peer ID changed: stored=${storedPeerId.slice(0, 12)}... → current=${oobi.peerId.slice(0, 12)}... (server restarted?)`,
          );
          this.manager.updateTransport(oobi.did, {
            peerId: oobi.peerId,
            multiaddrs: oobi.multiaddrs,
          });
        }
        // ── Self-heal subject kind ────────────────────────────────────────
        // If this relationship was stored before utility servers were tagged
        // as 'organization' (e.g., a previous session), update the remote
        // identity's subject_kind so it is correctly filtered from chat UI.
        if (this.manager.updateRemoteSubjectKind) {
          this.manager.updateRemoteSubjectKind(oobi.did, 'organization');
        }
        this.utilityServerDid = oobi.did;
        this.connected = true;
        return oobi.did;
      }
      // A pending row is NOT always "in flight". If its whole handshake window
      // has already elapsed, nothing will ever complete it — and while it exists
      // `sendRfi` refuses to run again (`insertOutbound` throws `already
      // exists`), so waiting for it is a guaranteed 30 s failure that repeats on
      // every reconnect tick, forever.
      //
      // That was the field bug of 2026-10-29 (MBP2014): one failed RFI send left
      // such a row behind (the send is what failed — see `sendRfi`'s rollback,
      // which now prevents the row being orphaned in the first place), and the
      // agent then logged five identical `timed out waiting for bidirectional
      // relationship` errors while its bootstrap and relay connections were
      // healthy. Recovery required restarting the app and waiting out
      // `pruneStaleOutbound`'s 5-minute window.
      //
      // Clearing the row and falling through to the send path below re-drives the
      // handshake with the CURRENT OOBI — which also repairs the second half of
      // the problem: the stored row pins the transport as it was at RFI time, and
      // a utility server that has restarted has a new peer ID.
      if (this.isStalePendingOutbound(existing)) {
        logger.warn(
          `[TspBridge] stale outbound-pending relationship with ${oobi.did.slice(0, 24)}… ` +
          `(started ${Math.round(Date.now() / 1000 - existing.createdAt)}s ago, never completed) ` +
          `— clearing it and re-sending the RFI instead of waiting for it.`,
        );
        this.manager.removeRelationship(oobi.did);
      } else {
        // Relationship exists but not yet bidirectional — wait for it. This is a
        // row YOUNGER than one handshake window: an RFA may genuinely be on its
        // way, and re-sending now would only duplicate the RFI.
        const serverDid = await this.waitForBidirectional(oobi.did, HANDSHAKE_TIMEOUT_MS);
        this.utilityServerDid = serverDid;
        this.connected = true;
        return serverDid;
      }
    }

    // Initiate the relationship handshake.
    // The utility server is an 'organization' subject — not a human peer.
    // This tags the relationship so chat UI can filter it out.
    await this.manager.sendRfi(this.utilityServerOobi, 'organization');

    // Wait for the relationship to become bidirectional (polling with timeout)
    const serverDid = await this.waitForBidirectional(oobi.did, HANDSHAKE_TIMEOUT_MS);

    this.utilityServerDid = serverDid;
    this.connected = true;

    return serverDid;
  }

  /**
   * Whether an existing record is an outbound handshake that has already had its
   * full window and can therefore never complete on its own.
   *
   * AGE is the test, not status alone. A row younger than
   * {@link HANDSHAKE_TIMEOUT_MS} may legitimately be in flight (the RFA is on its
   * way), and re-sending then would duplicate the RFI; a row older than that has
   * already had its wait and failed it.
   *
   * `created_at` is stored in unix SECONDS (`RelationshipStore` inserts
   * `unixepoch()`), hence the /1000.
   */
  private isStalePendingOutbound(record: RelationshipRecord): boolean {
    if (record.direction !== 'outbound' || record.status !== 'pending') return false;
    const ageSeconds = Date.now() / 1000 - record.createdAt;
    return ageSeconds > HANDSHAKE_TIMEOUT_MS / 1000;
  }

  /**
   * Poll for a relationship to reach bidirectional status.
   */
  private async waitForBidirectional(remoteDid: string, timeoutMs: number): Promise<string> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const record = this.manager!.getRelationship(remoteDid);
      if (record && record.direction === 'bidirectional') {
        return remoteDid;
      }
      // Fail fast when the peer DECLINED our invite (TSP XRFD). The manager marks
      // the record `rejected`, so there is nothing left to wait for — without this
      // the caller burned the full 30 s timeout and reported a generic "timed out"
      // even though the answer had already arrived.
      if (record && record.status === 'rejected') {
        throw new Error(
          `TspBridge: the peer DECLINED our connection request (${remoteDid.slice(0, 12)}...). ` +
          `The reason is in the peer's log; re-check the OOBI / address you pasted.`,
        );
      }
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    throw new Error(
      `TspBridge: timed out waiting for bidirectional relationship with ${remoteDid.slice(0, 12)}...`,
    );
  }

  // ---------------------------------------------------------------------------
  // Protocol messaging
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Connected state / reconnection
  // ---------------------------------------------------------------------------

  isConnected(): boolean {
    return this.connected;
  }

  /**
   * The utility server's DID (the identity this agent's relationship with it is keyed
   * by).
   *
   * **H12 correction (2026-09-24):** this comment used to say *"Returns null when the
   * server **VID** is not known"* — that was wrong, and the name is right.
   * `waitForBidirectional()` returns the `remoteDid` it was given, the relationship
   * store's NAMED form is keyed by `oobi.did` (`manager.ts:216`), and the value
   * originates from the OOBI's `did` field. So the **comment** was the inversion here,
   * not the identifier. (`OobiPayload` already names its two identifiers explicitly —
   * `cesrVid` vs `did` — which is the same discipline D-6a/D-5b apply elsewhere.)
   */
  getUtilityServerDid(): string | null {
    return this.utilityServerDid;
  }
  /**
   * The libp2p transport PeerId of the utility server (the peer we must dial to
   * reach it), resolved from the stored relationship's remoteTransport. Returns
   * null when the server VID is not known or the relationship was never stored.
   */
  getServerTransportPeerId(): string | null {
    if (!this.utilityServerDid || !this.manager) return null;
    const record = this.manager.getRelationship(this.utilityServerDid);
    return record?.remoteTransport?.peerId ?? null;
  }

  /**
   * Flag the utility-server connection as DOWN (e.g. libp2p peer:disconnect).
   * Keeps the server VID so a subsequent `connect()` can re-verify/re-mark UP.
   * This makes isConnected() reflect live transport health instead of staying
   * "sticky-true" from the original handshake.
   */
  markDisconnected(): void {
    if (this.connected) {
      this.connected = false;
    }
  }

  /**
   * Get the initialized TSP client for protocol-level operations.
   * The caller uses this to send protocol messages (identity_push, name_register, etc.)
   */
  getTspClient(): TspClientModule {
    if (!this.tspClient) {
      throw new Error('TspBridge.getTspClient: not initialized. Call init() first.');
    }
    return this.tspClient;
  }

  /**
   * Route an inbound TSP_GEN message through the TSP client for protocol detection.
   * Should be called from `RelationshipManager.onGenMessage()` for messages from
   * the utility server VID.
   *
   * When the handler produces a response (e.g., tx_prepare_result from the
   * transaction coordinator), the response is encoded and sent back to the
   * sender via the relationship manager.  This is the agent-side equivalent of
   * the utility server's `sendTspGenResponse()` in tsp-bridge.ts.
   *
   * @param remoteDid  The VID of the sender (utility server), used to route
   *                   any response back.
   * @returns true if the message was handled as a protocol message, false if it was plain chat.
   */
  async handleInbound(
    body: Uint8Array,
    remoteDid: string,
    handler?: (msg: ProtocolMessage) => Promise<ProtocolMessage | null>,
  ): Promise<boolean> {
    if (!this.tspClient) return false;
    const result = await this.tspClient.handleIncoming(body, handler);
    if (result !== null) {
      // ── Send response back to the sender ──────────────────────────────
      // If the handler produced a response (e.g., tx_prepare_result,
      // tx_commit_result), we must send it back.  Without this, the
      // utility server's TspRequestFn times out after 30 s waiting for
      // a response that never arrives.
      if (result.protocol !== '__handled__' && this.manager) {
        try {
          const responseBody = encodeProtocolMessage(result);
          await this.manager.sendMessage(remoteDid, responseBody);
        } catch (err) {
          logger.error(
            `[TspBridge] Failed to send ${result.protocol} response to ${remoteDid.slice(0, 12)}...:`,
            (err as Error)?.message ?? err,
          );
        }
      }
    } else {
      logger.info(`[TspBridge] handleInbound: not a protocol message or no match`);
    }
    return result !== null;
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  destroy(): void {
    if (this.tspClient) {
      this.tspClient.destroy();
      this.tspClient = null;
    }
    this.manager = null;
    this.utilityServerOobi = null;
    this.utilityServerDid = null;
    this.connected = false;
  }
}