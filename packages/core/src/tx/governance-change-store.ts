// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * GovernanceChangeStore — durable CRUD for `governance_change_proposals` and
 * `governance_change_approvals` in tx-coordinator.db (mirrors `CeremonyStore`).
 *
 * Server-authoritative: proposals are created by a community admin and settled by the
 * server participant once enough distinct, VERIFIED approvals arrive. Agents read the
 * pending set (for their Rules UI) and submit signed approvals.
 */

import type { DataSource } from '../db/data-source.js';
import type { ApprovalScope, GovernanceChange } from '../services/governance-change.js';

export interface GovernanceChangeProposal {
  proposalId: string;
  communityUuid: string;
  communityDid: string;
  proposerUuid: string;
  change: GovernanceChange;
  scope: ApprovalScope;
  requiredApproverCount: number;
  requiredApproverUuids: string[];
  proposalHash: string;
  status: 'pending' | 'crystallized' | 'expired' | 'failed' | 'aborted';
  errorReason: string | null;
  expiresAt: number;
  createdAt: number;
  crystallizedAt: number | null;
}

export interface GovernanceChangeApproval {
  approvalId: string;
  proposalId: string;
  approverUuid: string;
  signature: string;
  receivedAt: number;
}

export interface CreateChangeProposalInput {
  proposalId: string;
  communityUuid: string;
  communityDid: string;
  proposerUuid: string;
  change: GovernanceChange;
  scope: ApprovalScope;
  requiredApproverCount: number;
  requiredApproverUuids: string[];
  proposalHash: string;
  expiresAt: number;
}

interface RawProposal {
  proposal_id: string;
  community_uuid: string;
  community_did: string;
  proposer_uuid: string;
  change_json: string;
  scope: string;
  required_approver_count: number;
  required_approver_uuids: string;
  proposal_hash: string;
  status: string;
  error_reason: string | null;
  expires_at: number;
  created_at: number;
  crystallized_at: number | null;
}

interface RawApproval {
  approval_id: string;
  proposal_id: string;
  approver_uuid: string;
  signature: string;
  received_at: number;
}

function mapProposal(row: RawProposal): GovernanceChangeProposal {
  return {
    proposalId: row.proposal_id,
    communityUuid: row.community_uuid,
    communityDid: row.community_did,
    proposerUuid: row.proposer_uuid,
    change: JSON.parse(row.change_json) as GovernanceChange,
    scope: row.scope as ApprovalScope,
    requiredApproverCount: row.required_approver_count,
    requiredApproverUuids: JSON.parse(row.required_approver_uuids) as string[],
    proposalHash: row.proposal_hash,
    status: row.status as GovernanceChangeProposal['status'],
    errorReason: row.error_reason,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    crystallizedAt: row.crystallized_at,
  };
}

function mapApproval(row: RawApproval): GovernanceChangeApproval {
  return {
    approvalId: row.approval_id,
    proposalId: row.proposal_id,
    approverUuid: row.approver_uuid,
    signature: row.signature,
    receivedAt: row.received_at,
  };
}

export class GovernanceChangeStore {
  private readonly ds: DataSource;

  constructor(ds: DataSource) { this.ds = ds; }

  async createProposal(input: CreateChangeProposalInput): Promise<void> {
    await this.ds.run(
      `INSERT INTO governance_change_proposals
        (proposal_id, community_uuid, community_did, proposer_uuid, change_json,
         scope, required_approver_count, required_approver_uuids, proposal_hash,
         status, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
      input.proposalId, input.communityUuid, input.communityDid, input.proposerUuid,
      JSON.stringify(input.change), input.scope, input.requiredApproverCount,
      JSON.stringify(input.requiredApproverUuids), input.proposalHash,
      input.expiresAt, Date.now(),
    );
  }

  async getProposal(proposalId: string): Promise<GovernanceChangeProposal | null> {
    const row = await this.ds.get<RawProposal>(
      'SELECT * FROM governance_change_proposals WHERE proposal_id = ?', proposalId);
    return row ? mapProposal(row) : null;
  }

  /**
   * Agent-side mirror of a proposal received over `exchange:governance-proposal`. The
   * authoritative row is server-side; this local copy is for display + offline
   * visibility (the agent only receives proposals it is an approver for). INSERT OR
   * IGNORE keeps a settled local row from being reset — the proposal is immutable.
   */
  async mirrorProposal(input: {
    proposalId: string;
    communityUuid: string;
    communityDid: string;
    proposalHash: string;
    scope: ApprovalScope;
    requiredApproverCount: number;
    change: GovernanceChange;
    expiresAt: number;
  }): Promise<void> {
    await this.ds.run(
      `INSERT OR IGNORE INTO governance_change_proposals
        (proposal_id, community_uuid, community_did, proposer_uuid, change_json, scope,
         required_approver_count, required_approver_uuids, proposal_hash, status, expires_at, created_at)
       VALUES (?, ?, ?, '', ?, ?, ?, '[]', ?, 'pending', ?, ?)`,
      input.proposalId, input.communityUuid, input.communityDid,
      JSON.stringify(input.change), input.scope, input.requiredApproverCount,
      input.proposalHash, input.expiresAt, Date.now(),
    );
  }

  /** Every pending proposal, newest first. */
  async listPending(): Promise<GovernanceChangeProposal[]> {
    const rows = await this.ds.all<RawProposal>(
      "SELECT * FROM governance_change_proposals WHERE status = 'pending' ORDER BY created_at DESC");
    return rows.map(mapProposal);
  }

  /** Pending proposals for which `approverUuid` is an eligible approver. */
  async listPendingForApprover(approverUuid: string): Promise<GovernanceChangeProposal[]> {
    const pending = await this.listPending();
    return pending.filter((p) => p.requiredApproverUuids.includes(approverUuid));
  }

  /** Pending proposals for a community (server-side VTN/VTC management surface). */
  async listPendingForCommunity(communityUuid: string): Promise<GovernanceChangeProposal[]> {
    const rows = await this.ds.all<RawProposal>(
      `SELECT * FROM governance_change_proposals
        WHERE status = 'pending' AND community_uuid = ? ORDER BY created_at DESC`,
      communityUuid,
    );
    return rows.map(mapProposal);
  }

  async updateStatus(
    proposalId: string,
    status: GovernanceChangeProposal['status'],
    errorReason?: string,
  ): Promise<void> {
    if (status === 'crystallized') {
      await this.ds.run(
        `UPDATE governance_change_proposals SET status = ?, error_reason = ?, crystallized_at = ?
         WHERE proposal_id = ?`,
        status, errorReason ?? null, Date.now(), proposalId);
    } else {
      await this.ds.run(
        `UPDATE governance_change_proposals SET status = ?, error_reason = ? WHERE proposal_id = ?`,
        status, errorReason ?? null, proposalId);
    }
  }

  /** Record an approval; returns false when this approver already approved. */
  async recordApproval(proposalId: string, approverUuid: string, signature: string): Promise<boolean> {
    try {
      await this.ds.run(
        `INSERT INTO governance_change_approvals (approval_id, proposal_id, approver_uuid, signature, received_at)
         VALUES (?, ?, ?, ?, ?)`,
        `${proposalId}:${approverUuid}`, proposalId, approverUuid, signature, Date.now());
      return true;
    } catch {
      return false; // UNIQUE(proposal_id, approver_uuid)
    }
  }

  async getApprovals(proposalId: string): Promise<GovernanceChangeApproval[]> {
    const rows = await this.ds.all<RawApproval>(
      'SELECT * FROM governance_change_approvals WHERE proposal_id = ? ORDER BY received_at', proposalId);
    return rows.map(mapApproval);
  }

  async countApprovals(proposalId: string): Promise<number> {
    const row = await this.ds.get<{ cnt: number }>(
      'SELECT COUNT(*) as cnt FROM governance_change_approvals WHERE proposal_id = ?', proposalId);
    return row?.cnt ?? 0;
  }
}

