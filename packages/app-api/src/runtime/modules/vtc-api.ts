/**
 * VtcApiModule — VTC/VRC operations extracted from BaseAgent.
 *
 * Handles VTC creation, VRC issuance, verification, and querying.
 * This module is injected into BaseAgent during start() to keep the base class
 * focused on its core coordination responsibilities.
 */

import type { CesrVid } from '@p2p-trust-stack/core/tsp/v3/types.js';
import { issueVrc as issueVrcApi, verifyVrc as verifyVrcApi } from '@p2p-trust-stack/core/vtc/vtc.js';
import { asCesrVid } from '@p2p-trust-stack/core/vtc/codec.js';
import type { Vrc, VrcClaim, VtcGovernanceDoc, VrcVerifyResult } from '@p2p-trust-stack/core/vtc/types.js';
import { VtcStore } from '@p2p-trust-stack/core/vtc/store.js';

// ---------------------------------------------------------------------------
// VtcApiModule
// ---------------------------------------------------------------------------

export class VtcApiModule {
  private vtcStore?: VtcStore;

  /**
   * Initialize the VTC module with a pre-constructed VtcStore.
   * Called during BaseAgent.start() after the shared AgentDatabase is opened.
   * Schema initialization is handled by AgentDatabase — this method just
   * wires the store reference.
   */
  init(vtcStore: VtcStore): void {
    this.vtcStore = vtcStore;
  }

  /**
   * Issue a VRC from a known VTC to a subject.
   *
   * `vtcDid` identifies the VTC as a **DID** (it is resolved through
   * `VtcStore.getGovernanceDoc`, which keys governance docs by DID) — see the
   * note below about the resulting `issuerVid`.
   *
   * `subjectVid` and every `signers[].vid` must be CESR-encoded Ed25519 public
   * keys (`CesrVid`), because the VTC/VRC binary codec stores VIDs in that form.
   * They are validated here so a DID/UUID is reported at this API boundary,
   * naming the offending field, rather than failing deep inside `cesrDecode`.
   *
   * ⚠️ Boundary note: the governance doc read back from the store carries
   * `vtcVid = <the VTC's DID>` (see `governanceRowToDoc`), and `issueVrc` copies
   * that into the VRC's `issuerVid`. A VRC produced this way therefore has a
   * DID-form `issuerVid` and is NOT accepted by `encodeVrc`/`asCesrVrc`. It is
   * fine for storage/verification (both are DID/DID-keyed), but it must not be
   * fed to the binary codec. Resolving that split — DID-form identity references
   * vs the codec's CESR-key VID encoding — is an open design decision, not a bug
   * this method should paper over.
   */
  issueVrc(params: {
    vtcDid: string;
    subjectVid: CesrVid;
    claim: VrcClaim;
    signers: Array<{ vid: CesrVid; signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array } }>;
    expiresAt?: number;
  }): Vrc {
    if (!this.vtcStore) {
      throw new Error('VtcApiModule.issueVrc: not initialized. Call init() first.');
    }
    const governanceDoc = this.vtcStore.getGovernanceDoc(params.vtcDid);
    if (!governanceDoc) {
      throw new Error(`VtcApiModule.issueVrc: no governance doc known locally for VTC ${params.vtcDid.slice(0, 12)}...`);
    }
    // Validate the CESR-key VID fields at the boundary (see the docblock).
    asCesrVid(params.subjectVid, 'subjectVid', 'VtcApiModule.issueVrc');
    for (const [i, signer] of params.signers.entries()) {
      asCesrVid(signer.vid, `signers[${i}].vid`, 'VtcApiModule.issueVrc');
    }
    const vrc = issueVrcApi({
      governanceDoc,
      subjectVid: params.subjectVid,
      claim: params.claim,
      signers: params.signers,
      expiresAt: params.expiresAt,
    });
    this.vtcStore.saveVrc(vrc);
    return vrc;
  }

  /**
   * Verify a VRC against its issuer's locally-known governance doc.
   */
  verifyVrc(vrc: Vrc): VrcVerifyResult {
    if (!this.vtcStore) {
      throw new Error('VtcApiModule.verifyVrc: not initialized. Call init() first.');
    }
    const governanceDoc = this.vtcStore.getGovernanceDoc(vrc.issuerVid);
    if (!governanceDoc) {
      throw new Error(`VtcApiModule.verifyVrc: no governance doc known locally for VTC ${vrc.issuerVid.slice(0, 12)}...`);
    }
    return verifyVrcApi(vrc, governanceDoc);
  }

  /** List all VTC governance docs known locally. */
  listVtcGovernanceDocs(): VtcGovernanceDoc[] {
    if (!this.vtcStore) return [];
    return this.vtcStore.listGovernanceDocs();
  }

  /** List all VRCs issued to a specific VID. */
  listVrcsForSubject(vid: string): Vrc[] {
    if (!this.vtcStore) return [];
    return this.vtcStore.listVrcsForSubject(vid);
  }

  /** Upsert a VTC/VTN received from a remote utility server via TSP. */
  async upsertRemoteVtc(params: {
    identityUuid: string;
    did: string;
    name: string;
    role: string;
    adminThresholdM: number;
    adminThresholdN: number;
    parentCommunityUuid: string | null;
    adminUuids: string[];
    /** Base64 VTC governance-doc digest received from the server (a stored commitment). */
    vtcGovernanceDigest?: string | null;
    /** The community's allowed claim types (claim-type bindings). */
    allowedClaimTypes?: string[];
  }): Promise<void> {
    if (!this.vtcStore) {
      throw new Error('VtcApiModule.upsertRemoteVtc: not initialized.');
    }
    this.vtcStore.upsertRemoteVtc(params);
  }

  /** Get a single governance doc by community DID. */
  getCommunityByDid(did: string): VtcGovernanceDoc | undefined {
    if (!this.vtcStore) return undefined;
    return this.vtcStore.getGovernanceDoc(did);
  }

  /** Clean up resources. */
  destroy(): void {
    this.vtcStore = undefined;
  }
}