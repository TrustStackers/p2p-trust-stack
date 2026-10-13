/**
 * CeremonyStore — durable CRUD for ceremony_proposals and ceremony_approvals
 * tables in tx-coordinator.db.
 *
 * Used by the utility server's CeremonyCoordinator during Phase 3 governance
 * ceremonies, and potentially by agent apps to query their own local proposal
 * state.  Exported from src/tx/index.ts alongside TransactionLog.
 */

import type { DataSource } from '../db/data-source.js';

export interface CeremonyProposal {
  proposalId: string;
  proposerDid: string;
  proposerUuid: string | null;
  vtcDid: string;
  name: string;
  kind: 'vtc' | 'vtn';
  adminDids: string[];
  adminUuids: string[];
  threshold: number;
  expiresAt: number;
  status: 'pending' | 'crystallized' | 'expired' | 'failed' | 'aborted';
  proposalHash: string;
  parentCommunityDid: string | null;
  errorReason: string | null;
  createdAt: number;
  crystallizedAt: number | null;
}

export interface CeremonyApproval {
  approvalId: string;
  proposalId: string;
  approverDid: string;
  signature: string;
  receivedAt: number;
}

export interface CreateProposalInput {
  proposalId: string; proposerDid: string; vtcDid: string;
  name: string; kind: 'vtc' | 'vtn';
  adminDids: string[]; threshold: number;
  expiresAt: number; proposalHash: string;
  parentCommunityDid?: string | null;
  proposerUuid?: string | null;
  adminUuids?: string[];
}
// ---------------------------------------------------------------------------
// CeremonyStore
// ---------------------------------------------------------------------------

export class CeremonyStore {
  private readonly ds: DataSource;

  constructor(ds: DataSource) { this.ds = ds; }

  // ── Proposal CRUD ────────────────────────────────────────────────

  async createProposal(input: CreateProposalInput): Promise<void> {
    const now = Date.now();
    await this.ds.run(
      `INSERT INTO ceremony_proposals
        (proposal_id, proposer_did, vtc_did, name, kind, admin_dids,
         threshold, expires_at, status, proposal_hash,
         parent_community_did, created_at, proposer_uuid, admin_uuids)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)`,
      input.proposalId, input.proposerDid, input.vtcDid, input.name,
      input.kind, JSON.stringify(input.adminDids), input.threshold,
      input.expiresAt, input.proposalHash, input.parentCommunityDid ?? null, now,
      input.proposerUuid ?? null,
      input.adminUuids ? JSON.stringify(input.adminUuids) : null,
    );
  }

  async getProposal(proposalId: string): Promise<CeremonyProposal | null> {
    const row = await this.ds.get<RawProposal>(
      'SELECT * FROM ceremony_proposals WHERE proposal_id = ?', proposalId);
    return row ? mapProposal(row) : null;
  }

  async listPending(): Promise<CeremonyProposal[]> {
    const rows = await this.ds.all<RawProposal>(
      "SELECT * FROM ceremony_proposals WHERE status = 'pending' ORDER BY created_at DESC");
    return rows.map(mapProposal);
  }

  async listByProposer(proposerDid: string): Promise<CeremonyProposal[]> {
    const rows = await this.ds.all<RawProposal>(
      'SELECT * FROM ceremony_proposals WHERE proposer_did = ? ORDER BY created_at DESC',
      proposerDid);
    return rows.map(mapProposal);
  }

  async listByProposerUuid(proposerUuid: string): Promise<CeremonyProposal[]> {
    const rows = await this.ds.all<RawProposal>(
      'SELECT * FROM ceremony_proposals WHERE proposer_uuid = ? ORDER BY created_at DESC',
      proposerUuid);
    return rows.map(mapProposal);
  }

  async updateStatus(proposalId: string, status: string, crystallizedAt?: number): Promise<void> {
    if (status === 'crystallized') {
      await this.ds.run(
        `UPDATE ceremony_proposals SET status = ?, crystallized_at = ? WHERE proposal_id = ?`,
        status, crystallizedAt ?? Date.now(), proposalId);
    } else {
      await this.ds.run(
        `UPDATE ceremony_proposals SET status = ? WHERE proposal_id = ?`, status, proposalId);
    }
  }

  async addAdminDid(proposalId: string, adminDid: string): Promise<void> {
    const prop = await this.getProposal(proposalId);
    if (!prop) throw new Error(`proposal ${proposalId} not found`);
    const dids = new Set(prop.adminDids);
    if (dids.has(adminDid)) return;
    dids.add(adminDid);
    await this.ds.run(`UPDATE ceremony_proposals SET admin_dids = ? WHERE proposal_id = ?`,
      JSON.stringify([...dids]), proposalId);
  }

  // ── Approval CRUD ─────────────────────────────────────────────────

  async recordApproval(proposalId: string, approverDid: string, signature: string): Promise<boolean> {
    const id = `${proposalId}:${approverDid}`;
    try {
      await this.ds.run(
        `INSERT INTO ceremony_approvals (approval_id, proposal_id, approver_did, signature, received_at)
         VALUES (?, ?, ?, ?, ?)`, id, proposalId, approverDid, signature, Date.now());
      return true;
    } catch { return false; } // UNIQUE constraint → already exists
  }

  async getApprovals(proposalId: string): Promise<CeremonyApproval[]> {
    const rows = await this.ds.all<RawApproval>(
      'SELECT * FROM ceremony_approvals WHERE proposal_id = ? ORDER BY received_at', proposalId);
    return rows.map(mapApproval);
  }

  async countApprovals(proposalId: string): Promise<number> {
    const row = await this.ds.get<{ cnt: number }>(
      'SELECT COUNT(*) as cnt FROM ceremony_approvals WHERE proposal_id = ?', proposalId);
    return row?.cnt ?? 0;
  }

  async isCrystallizable(proposalId: string): Promise<boolean> {
    const prop = await this.getProposal(proposalId);
    if (!prop || prop.status !== 'pending') return false;
    if (Date.now() > prop.expiresAt) {
      await this.updateStatus(proposalId, 'expired');
      return false;
    }
    const count = await this.countApprovals(proposalId);
    return count >= prop.threshold;
  }
}

// ── Internal row mapping ─────────────────────────────────────────────

interface RawProposal { proposal_id: string; proposer_did: string; vtc_did: string; name: string; kind: string; admin_dids: string; threshold: number; expires_at: number; status: string; proposal_hash: string; parent_community_did: string | null; created_at: number; crystallized_at: number | null; proposer_uuid: string | null; admin_uuids: string | null; error_reason: string | null; }
function mapProposal(row: RawProposal): CeremonyProposal {
  return {
    proposalId: row.proposal_id, proposerDid: row.proposer_did, vtcDid: row.vtc_did,
    name: row.name, kind: row.kind as 'vtc' | 'vtn',
    adminDids: JSON.parse(row.admin_dids), threshold: row.threshold,
    adminUuids: row.admin_uuids ? JSON.parse(row.admin_uuids) : [],
    expiresAt: row.expires_at, status: row.status as CeremonyProposal['status'],
    proposalHash: row.proposal_hash, parentCommunityDid: row.parent_community_did,
    proposerUuid: row.proposer_uuid,
    errorReason: row.error_reason,
    createdAt: row.created_at, crystallizedAt: row.crystallized_at,
  };
}

interface RawApproval { approval_id: string; proposal_id: string; approver_did: string; signature: string; received_at: number; }
function mapApproval(row: RawApproval): CeremonyApproval {
  return {
    approvalId: row.approval_id, proposalId: row.proposal_id,
    approverDid: row.approver_did, signature: row.signature, receivedAt: row.received_at,
  };
}

