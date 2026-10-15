// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * RecoveryModule — agent-side identity recovery logic.
 *
 * Handles fetching the full recovery state from a utility server over the
 * Computed Record Exchange (CRE) catalog (`exchange:recovery` pull).
 *
 * All identity lookups now route through the exchange layer instead of the
 * coordinator `identity_lookup` participant (retired in Phase G) or direct TSP
 * protocol messages (tspClient.request(IDENTITY_LOOKUP)).
 */

import type { TspClientModule } from './tsp-client.js';
import type { ParticipantTransport } from '@p2p-trust-stack/core/tx/participant.js';
import { lookupIdentityViaExchange } from '@p2p-trust-stack/core/tx/services/identity-service.js';
import type { IdentityLookupResultPayload } from '@p2p-trust-stack/core/tx/services/identity-service.js';
import { exchangePull } from '@p2p-trust-stack/core/exchange/index.js';
import { didToUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';

// ---------------------------------------------------------------------------
// Recovery state types (mirrors RecoveryService on the server)
// ---------------------------------------------------------------------------

export interface RecoveryState {
  identity: {
    uuid: string;
    role: string;
    subjectKind: string | null;
    name: string | null;
    vid: string | null;
    peerId: string | null;
    createdAt: number | null;
  };
  didDocuments: Array<{
    uuid: string;
    did: string;
    method: string;
    documentJson: string | null;
    isPrimary: boolean;
    status: string;
    createdAt: number | null;
  }>;
  publicKeys: Array<{
    uuid: string;
    keyType: string;
    publicKey: string;
    rotationVersion: number;
    createdAt: number | null;
  }>;
  rotationLog: Array<{
    uuid: string;
    version: number;
    previousHash: string | null;
    newPublicKey: string;
    signedEntry: string;
    createdAt: number | null;
  }>;
  witnessAttestations: Array<{
    uuid: string;
    rotationLogId: number;
    witnessDidDocumentUuid: string;
    signature: string;
    attestedAt: number | null;
  }>;
  credentials: Array<{
    uuid: string;
    vcType: string;
    issuerIdentityUuid: string;
    claim: string | null;
    status: string;
    validFrom: number;
    validUntil: number | null;
    createdAt: number | null;
  }>;
  memberships: Array<{
    uuid: string;
    communityIdentityUuid: string;
    role: string;
    status: string;
    issuedAt: number | null;
  }>;
  relationships: Array<{
    uuid: string;
    remoteIdentityUuid: string;
    direction: string;
    status: string;
    remoteTransport: string | null;
    createdAt: number | null;
  }>;
}

// ---------------------------------------------------------------------------
// RecoveryModule
// ---------------------------------------------------------------------------

export class RecoveryModule {
  private tspClient: TspClientModule | null = null;
  private utilityServerDid: string | null = null;
  private myDid: string | null = null;
  private transport: ParticipantTransport | null = null;

  /**
   * Initialize the recovery module.
   *
   * @param tspClient  Active TSP client for protocol messaging.
   * @param utilityServerDid  The VID of the utility server (from established relationship).
   * @param myDid  The DID of this agent (for self-recovery lookup).
   */
  init(tspClient: TspClientModule, utilityServerDid: string, myDid: string): void {
    this.tspClient = tspClient;
    this.utilityServerDid = utilityServerDid;
    this.myDid = myDid;
  }

  /**
   * Wire the participant transport used by the exchange pulls (exchange:recovery
   * / exchange:identity-lookup). Must be called after the agent's transaction
   * coordinator is bootstrapped. The manager is no longer needed — the
   * coordinator `identity_lookup` path was retired in Phase G.
   */
  wireCoordinator(_manager: unknown, transport: ParticipantTransport): void {
    this.transport = transport;
  }

  isInitialized(): boolean {
    return this.tspClient !== null && this.utilityServerDid !== null;
  }

  // -------------------------------------------------------------------------
  // Recovery: fetch full identity state
  // -------------------------------------------------------------------------

  /**
   * Request the full recovery state for this agent's DID from the utility server.
   *
   * Uses the `exchange:recovery` recordset pull (self-only by construction). The
   * legacy raw TSP request path was removed in Phase C and the coordinator
   * `identity_lookup` fallback was removed in Phase G.
   *
   * @returns RecoveryState if the DID is found on the server, null otherwise.
   * @throws If the TSP client hasn't been initialized.
   */
  async fetchRecoveryState(_timeoutMs?: number): Promise<RecoveryState | null> {
    if (!this.tspClient || !this.utilityServerDid || !this.myDid) {
      throw new Error(
        'RecoveryModule.fetchRecoveryState: not initialized. Call init() first.',
      );
    }

    // ── exchange:recovery pull (self-only) ─────────────────────────────
    // The server derives the target identity from the requester's real DID, so
    // only this agent's own recovery state can ever be returned.
    if (!this.transport) return null;
    try {
      const data = (await exchangePull({
        name: 'recovery',
        req: {
          requester: { realDid: this.myDid, uuid: didToUuid(this.myDid), role: 'vta' },
        },
        peer: 'server:us-1',
        transport: this.transport,
      })) as Array<{ found: boolean; recoveryState?: RecoveryState }>;
      const row = data[0];
      if (row?.found) return row.recoveryState ?? null;
      return null;
    } catch (err) {
      console.warn(`[recovery] exchange:recovery failed: ${(err as Error).message}`);
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Lookup: fetch identity data for any DID
  // -------------------------------------------------------------------------

  /**
   * Look up public identity data for a given DID (not just self).
   * Used for peer discovery via the `exchange:identity-lookup` pull recordset.
   * The legacy raw TSP request path was removed in Phase C and the coordinator
   * `identity_lookup` participant was retired in Phase G.
   */
  async lookupIdentity(did: string, _timeoutMs?: number): Promise<IdentityLookupResultPayload | null> {
    if (!this.tspClient || !this.utilityServerDid || !this.myDid) {
      throw new Error(
        'RecoveryModule.lookupIdentity: not initialized. Call init() first.',
      );
    }

    if (!this.transport) return null;
    try {
      return await lookupIdentityViaExchange(
        this.myDid,
        this.transport,
        'server:us-1',
        did,
      );
    } catch (err) {
      console.warn(`[recovery] exchange:identity-lookup failed: ${(err as Error).message}`);
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Teardown
  // -------------------------------------------------------------------------

  destroy(): void {
    this.tspClient = null;
    this.utilityServerDid = null;
    this.myDid = null;
    this.transport = null;
  }
}