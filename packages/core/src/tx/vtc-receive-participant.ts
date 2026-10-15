// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * VTC Receive Participant — agent-side participant that receives VTC data
 * pushed from the utility server and persists it to the agent's local SQLite.
 *
 * Handles the operation type:
 *   - 'exchange:vtc-membership' — the CRE wire op for a VTC package
 *     (identity + governance + memberships), delivered by the server's
 *     queue-row fan-out (exchange:vtc-membership).
 *
 * (Minted credential receipt is handled by CredentialReceiveParticipant since
 * Phase F.)
 *
 * Reuses the existing persistSyncedCommunity() logic from BaseAgent, adapted
 * to work within the participant's prepare/commit/abort lifecycle.
 */

import type { DataSource } from '../db/data-source.js';
import type {
  Operation,
  Outcome,
  Participant,
  Vote,
} from './types.js';
import { didToUuid, generateUuid } from '../db/uuid-helpers.js';
import { logger } from '../util/logger.js';

/**
 * Shape of the VTC data pushed from the utility server via the
 * exchange:vtc-membership queue-row fan-out (pending_agent_deliveries →
 * buildVtcPushData at send time).
 */
export interface VtcPushData {
  community: {
    uuid: string;
    did: string;
    name: string | null;
    role: string;
  };
  governance: {
    adminThresholdM: number | null;
    adminThresholdN: number | null;
    parentCommunityUuid: string | null;
    /** The community's allowed claim types (claim-type bindings, not a blob). */
    allowedClaimTypes?: string[];
    /** Base64 VTC governance-doc digest — a stored commitment. */
    vtcGovernanceDigest?: string | null;
  } | null;
  memberships: Array<{
    role: string;
    status: string;
    personhoodAsserted: boolean;
    uuid: string;
    memberUuid: string;
    memberDid?: string;
    memberName: string | null;
    /** credentials.uuid of this member's VMC (Verified Membership Credential).
     *  Set at community creation for founding admins; null until issued. */
    membershipCredentialUuid?: string | null;
  }>;
  didDocument?: {                       // NEW: VTC's did:peer:4 document
    did: string;
    documentJson: string;
  };
  keys?: Array<{                        // NEW: VTC's public keys
    keyType: string;                     // 'ed25519' | 'x25519'
    publicKey: string;                   // base64-encoded
  }>;
}

/**
 * Shape of a governance-only update pushed from the utility server via the
 * `exchange:governance` queue-row fan-out (policy PATCH). Mirrors the server's
 * buildGovernancePushData projection.
 */
export interface GovernancePushData {
  communityUuid: string;
  communityName: string | null;
  adminThresholdM: number | null;
  adminThresholdN: number | null;
  parentCommunityUuid: string | null;
  /** The community's allowed claim types (claim-type bindings, not a blob). */
  allowedClaimTypes: string[];
  /** Base64 VTC governance-doc digest — a stored commitment. */
  vtcGovernanceDigest: string | null;
  updatedAt: number | null;
}

/**
 * A community record this agent just persisted, announced to an observer.
 *
 * `kind` distinguishes the two pushes this participant accepts, because they mean different things to a UI:
 * a `membership` push is the community itself arriving (or its roster changing), while `governance` is the
 * community's RULES changing — the signal that an approved governance change has been applied.
 */
export interface PersistedCommunityEvent {
  communityUuid: string;
  kind: 'membership' | 'governance';
}

/**
 * Agent-side participant for receiving VTC/community data.
 *
 * pid: 'peer:{agentDid}' — identifies this agent as a participant.
 */
export class VtcReceiveParticipant implements Participant {
  readonly pid: string;
  private readonly appDb: DataSource;   // Agent's local SQLite (agent-database.db)
  private readonly txDb: DataSource;    // SQLite (tx-coordinator.db)
  /**
   * Called after a community row (or its governance) is written to the agent's local database.
   *
   * This participant is the ONLY thing that observes a community arriving — nothing else watches the table — so
   * without this hook an observer can only discover a community by polling. Not called on the idempotent
   * "already present" path: a re-delivery is not a new arrival.
   */
  private readonly onPersisted?: (community: PersistedCommunityEvent) => void;

  constructor(
    pid: string,
    appDb: DataSource,
    txDb: DataSource,
    onPersisted?: (community: PersistedCommunityEvent) => void,
  ) {
    this.pid = pid;
    this.appDb = appDb;
    this.txDb = txDb;
    this.onPersisted = onPersisted;
  }

  handlesOperation(op: Operation): boolean {
    return op.op === 'exchange:vtc-membership' || op.op === 'exchange:governance';
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    // Announced only after BOTH the loop and the 'prepared' record succeed, and collected here rather than
    // inside the loop, so a partially-applied multi-op transaction never announces.
    const persisted: PersistedCommunityEvent[] = [];

    for (const op of operations) {
      try {
        if (op.op === 'exchange:governance') {
          const data = op.params as unknown as GovernancePushData;
          if (!data?.communityUuid) return 'no';
          await this.upsertGovernance(data);
          persisted.push({ communityUuid: data.communityUuid, kind: 'governance' });
          continue;
        }
        if (op.op !== 'exchange:vtc-membership') continue;
        const data = op.params as unknown as VtcPushData;
        if (!data) return 'no';
        await this.upsertCommunity(data);
        if (data.community?.uuid) {
          persisted.push({ communityUuid: data.community.uuid, kind: 'membership' });
        }
      } catch (err) {
        logger.error(`[vtc-receive] prepare failed for tx ${txId}:`, (err as Error)?.message);
        return 'no';
      }
    }

    // Durably record 'prepared' BEFORE voting yes.
    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome)
       VALUES (?, ?, 'prepared')`,
      txId,
      this.pid,
    );

    // Announce the arrivals. Guarded on purpose: `prepare()` votes 'no' on any throw, so an observer that threw
    // would ABORT a transaction whose community has already been written — turning a successful delivery into a
    // refusal. The announcement is a side effect and must never decide the 2PC outcome.
    for (const event of persisted) {
      try {
        this.onPersisted?.(event);
      } catch (err) {
        logger.warn(`[vtc-receive] arrival observer failed: ${(err as Error)?.message ?? err}`);
      }
    }

    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'committed'
       WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
  }

  async abort(txId: string): Promise<void> {
    // TODO: Track created rows for precise rollback.
    // For now, the data is already upserted; a future enhancement would
    // store the created identity IDs in undo_hooks for deletion.
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'aborted'
       WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
  }

  async compensate(txId: string): Promise<void> {
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.txDb.get<{ outcome: string }>(
      'SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?',
      txId,
      this.pid,
    );
    return (row?.outcome as Outcome) ?? 'unknown';
  }

  // -----------------------------------------------------------------------
  // Persistence helpers (adapted from BaseAgent.persistSyncedCommunity)
  // -----------------------------------------------------------------------

  /**
   * Apply a governance-only update (exchange:governance policy PATCH fan-out).
   * Upserts the governance row keyed on community_identity_uuid; the community
   * identity is created if absent so a governance-only push is self-contained.
   */
  private async upsertGovernance(g: GovernancePushData): Promise<void> {
    const communityUuid = g.communityUuid;
    // Ensure the community identity exists (idempotent) so the FK target is present.
    await this.appDb.run(
      `INSERT INTO identities (uuid, name, role, custody, created_at)
       VALUES (?, ?, 'vtc', 'remote', unixepoch())
       ON CONFLICT(uuid) DO UPDATE SET name = COALESCE(excluded.name, identities.name)`,
      communityUuid, g.communityName,
    );
    await this.appDb.run(
      `INSERT INTO governance (community_identity_uuid,
         admin_threshold_m, admin_threshold_n, vtc_governance_digest, uuid, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(community_identity_uuid) DO UPDATE SET
         admin_threshold_m = excluded.admin_threshold_m,
         admin_threshold_n = excluded.admin_threshold_n,
         vtc_governance_digest = excluded.vtc_governance_digest,
         updated_at = excluded.updated_at`,
      communityUuid,
      g.adminThresholdM ?? 1, g.adminThresholdN ?? 1,
      g.vtcGovernanceDigest ?? null,
      communityUuid,
      Math.floor(Date.now() / 1000),
    );
    await this.applyClaimTypeBindings(communityUuid, g.allowedClaimTypes);
    logger.info(`[vtc-receive] applied governance update for community ${communityUuid.slice(0, 8)}`);
  }

  /** Write one claim-type binding per permitted type (no policy blob). */
  private async applyClaimTypeBindings(communityUuid: string, claimTypes: string[] | undefined): Promise<void> {
    for (const claimType of claimTypes ?? []) {
      await this.appDb.run(
        `INSERT INTO community_policy_bindings
           (uuid, community_identity_uuid, rule_type, enabled, params, updated_at)
         VALUES (?, ?, ?, 1, ?, unixepoch())
         ON CONFLICT(community_identity_uuid, rule_type) DO NOTHING`,
        generateUuid(), communityUuid,
        `task:p2pts:rule:claim-type-allow:0.1#${claimType}`,
        JSON.stringify({ claim_type: claimType }),
      );
    }
  }

  private async upsertCommunity(data: VtcPushData): Promise<void> {
    const c = data.community;
    const g = data.governance;
    const memberships = data.memberships;

    // 1. Upsert community identity
    const identityUuid = c.uuid ?? didToUuid(c.did);
    await this.appDb.run(
      `INSERT INTO identities (uuid, name, role, custody, created_at)
       VALUES (?, ?, ?, 'remote', unixepoch())
       ON CONFLICT(uuid) DO UPDATE SET
         name = COALESCE(excluded.name, identities.name),
         role = excluded.role`,
      identityUuid, c.name, c.role,
    );

    // Get the local identity uuid
    const communityLocal = await this.appDb.get<{ uuid: string }>(
      'SELECT uuid FROM identities WHERE uuid = ?', identityUuid,
    );
    if (!communityLocal) {
      logger.info(`[vtc-receive] community identity not found locally after upsert: ${c.uuid}`);
      return;
    }

    // 2a. Upsert the VTC's did:peer:4 document if provided
    if (data.didDocument) {
      const dd = data.didDocument;
      const existingDoc = await this.appDb.get<{ uuid: string }>(
        'SELECT uuid FROM did_documents WHERE identity_uuid = ? AND method = ?',
        communityLocal.uuid, 'peer4',
      );
      if (!existingDoc) {
        const docUuid = generateUuid();
        await this.appDb.run(
          `INSERT INTO did_documents
             (identity_uuid, did, method, document_json,
              is_primary, status, uuid, created_at)
           VALUES (?, ?, 'peer4', ?, 1, 'active', ?, unixepoch())`,
          identityUuid, dd.did, dd.documentJson, docUuid,
        );

        // 2b. Store the VTC's public keys if provided
        if (data.keys && data.keys.length > 0) {
          for (const key of data.keys) {
            const publicKeyBuf = Buffer.from(key.publicKey, 'base64');
            await this.appDb.run(
              `INSERT OR IGNORE INTO keys
                 (identity_uuid, did_document_uuid,
                  key_type, public_key, rotation_version, uuid, created_at)
               VALUES (?, ?, ?, ?, 0, ?, unixepoch())`,
              identityUuid, docUuid,
              key.keyType, publicKeyBuf, generateUuid(),
            );
          }
        }
      }
    }

    // 2. Upsert governance
    if (g) {
      // Persist the stored governance-doc digest; the community's claim types are
      // written as claim-type bindings just below (no policy document crosses the wire).
      await this.appDb.run(
        `INSERT INTO governance (community_identity_uuid,
           admin_threshold_m, admin_threshold_n, vtc_governance_digest, uuid, updated_at)
         VALUES (?, ?, ?, ?, ?, unixepoch())
         ON CONFLICT(community_identity_uuid) DO UPDATE SET
           admin_threshold_m = excluded.admin_threshold_m,
           admin_threshold_n = excluded.admin_threshold_n,
           vtc_governance_digest = excluded.vtc_governance_digest,
           updated_at = unixepoch()`,
        identityUuid,
        g.adminThresholdM ?? 1, g.adminThresholdN ?? 1,
        g.vtcGovernanceDigest ?? null, c.uuid,
      );
      await this.applyClaimTypeBindings(identityUuid, g.allowedClaimTypes);
    }

    // 3. Upsert member identities and memberships
    if (memberships) {
      for (const m of memberships) {
        // Compute deterministic UUIDv5 from the member's real DID if available,
        // otherwise use the UUID from the utility server directly.
        // This ensures identity rows don't duplicate when the agent has already
        // resolved this identity locally via a relationship handshake.
        const memberIdentityUuid = m.memberUuid ?? (m.memberDid ? didToUuid(m.memberDid) : generateUuid());

        // Use INSERT OR IGNORE so a locally-resolved identity (from a
        // relationship handshake) is never overwritten by the utility
        // server's data — the local resolution is always authoritative.
        await this.appDb.run(
          `INSERT OR IGNORE INTO identities (uuid, name, role, custody, created_at)
           VALUES (?, ?, 'vta', 'remote', unixepoch())`,
          memberIdentityUuid, m.memberName,
        );

        // Confirm the identity row exists locally (0019 uuid-first schema:
        // `uuid` is the PK — the old integer `id` column no longer exists).
        const memberRow = await this.appDb.get<{ uuid: string }>(
          'SELECT uuid FROM identities WHERE uuid = ?', memberIdentityUuid,
        );
        if (!memberRow) continue;

        // Upsert membership — incl. the VMC link (the credential itself arrives
        // separately via the `exchange:credential` fan-out, so this is what makes
        // the graph draw the VMC line between the VTC and this member).
        await this.appDb.run(
          `INSERT INTO memberships (member_identity_uuid,
             community_identity_uuid, role, status,
             personhood_asserted, membership_credential_uuid, uuid, issued_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, unixepoch())
           ON CONFLICT(member_identity_uuid, community_identity_uuid) DO UPDATE SET
             role = excluded.role, status = excluded.status,
             membership_credential_uuid = COALESCE(excluded.membership_credential_uuid, memberships.membership_credential_uuid)`,
          memberIdentityUuid, identityUuid,
          m.role, m.status, m.personhoodAsserted ? 1 : 0, m.membershipCredentialUuid ?? null, m.uuid,
        );
      }
    }

    logger.info(`[vtc-receive] persisted community: ${c.name ?? c.uuid} (${memberships?.length ?? 0} members)`);
  }
}