// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Peer VRC minting — Step 12 extension.
 *
 * After a successful RFI/RFA handshake, each peer independently mints a
 * self-signed Verifiable Relationship Credential (VRC) and stores it in the
 * shared `credentials` table with `vc_type = 'vrc'`.
 *
 * Credential creation and DTG VC building are delegated to CredentialFactory.mint().
 * The claim-based digest is preserved for cross-node dedup in credential_digest.
 * The local agent's Ed25519 signature over the claim digest is stored in credential_signatures.
 */

import { sha256, signEd25519 } from '../crypto/primitives.js';
import { generateUuid } from '../db/uuid-helpers.js';
import type { DataSource } from '../db/data-source.js';
import type { IdentityResolver } from '../services/identity-resolver.js';
import type { RelationshipRecord, LocalIdentity } from './types.js';
import { logger } from '../util/logger.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PeerVrcClaim {
  type: 'peer-relationship';
  rfiDigest: string;
  rfaReplyDigest: string;
  localDid: string;
  remoteDid: string;
  establishedAt: number;
}

// ---------------------------------------------------------------------------
// mintPeerVrc
// ---------------------------------------------------------------------------

/**
 * Mint a self-signed peer-relationship VRC and store it in the credentials table.
 *
 * Only called after a bidirectional relationship is confirmed. The VRC proves
 * that the local agent participated in a successful RFI/RFA handshake with the
 * remote peer.
 *
 * Credential creation + DTG VC building is delegated to CredentialFactory.mint().
 *
 * @param dataSource  DataSource for the agent's SQLite database
 * @param resolver    IdentityResolver for mapping DIDs → integer FK IDs
 * @param identity    Local agent identity (for signing and issuer/subject FKs)
 * @param record      The relationship record with both rfiDigest and rfaReplyDigest
 */
export async function mintPeerVrc(params: {
  dataSource: DataSource;
  resolver: IdentityResolver;
  identity: LocalIdentity;
  record: RelationshipRecord;
}): Promise<{ success: boolean; w3cVcJson?: string; remoteDid?: string }> {
  const { dataSource, resolver, identity, record } = params;

  if (!record.rfiDigest || !record.rfaReplyDigest) {
    logger.warn('[mintPeerVrc] Cannot mint VRC: missing rfiDigest or rfaReplyDigest.');
    return { success: false };
  }

  const local = resolver.lookupByDid(identity.did);
  const remote = resolver.lookupByDid(record.remoteDid);
  if (!local || !remote) {
    logger.warn('[mintPeerVrc] Cannot mint VRC: identity not resolved for local or remote.');
    return { success: false };
  }

  const claim: PeerVrcClaim = {
    type: 'peer-relationship',
    rfiDigest: uint8ArrayToHex(record.rfiDigest),
    rfaReplyDigest: uint8ArrayToHex(record.rfaReplyDigest),
    localDid: identity.did,
    remoteDid: record.remoteDid,
    establishedAt: record.createdAt ?? Math.floor(Date.now() / 1000),
  };
  const claimJson = JSON.stringify(claim);
  const digest = sha256(new TextEncoder().encode(claimJson));
  const digestHex = uint8ArrayToHex(digest);

  // Idempotency — two independent dedup keys so the same logical VRC can never
  // be written twice by different paths:
  //   1. the exact claim digest (re-mint of the same handshake), AND
  //   2. any 'vrc' row for the same (issuer, subject) peer pair that already
  //      carries a DTG w3c_vc_json envelope.
  // The second clause closes the cross-path duplicate: a mirrored copy stored
  // by storeReceivedDtgVrc / an identity-push (both keyed on the *VC* digest)
  // never collides on the *claim* digest used here, so a shared credentials
  // table previously ended up with each of the two VRCs of a ceremony twice.
  // First-wins: the existing row is the canonical record for the pair.
  const existing = await dataSource.get<{ uuid: string }>(
    `SELECT uuid FROM credentials
     WHERE vc_type = 'vrc'
       AND (
         (issuer_identity_uuid = ? AND subject_identity_uuid = ? AND credential_digest = ?)
         OR (issuer_identity_uuid = ? AND subject_identity_uuid = ? AND w3c_vc_json IS NOT NULL)
       )
     LIMIT 1`,
    local.identityUuid, remote.identityUuid, digestHex,
    local.identityUuid, remote.identityUuid,
  );
  if (existing) {
    logger.info(`[mintPeerVrc] VRC already exists for ${record.remoteDid.slice(0, 12)}... (uuid=${existing.uuid})`);
    return { success: true, remoteDid: record.remoteDid };
  }

  const verificationMethod =
    identity.didDocument?.verificationMethod?.[0]?.id ?? `${identity.did}#key-1`;

  const { CredentialFactoryImpl } = await import('../services/credential-factory/credential-factory-impl.js');
  const factory = new CredentialFactoryImpl(dataSource);

  let credentialUuid: string;
  let w3cJson: string | null;
  try {
    const mintResult = await factory.mint({
      kind: 'RelationshipCredential',
      scenario: 'peer-verification',
      issuerDid: identity.did,
      subjectDid: record.remoteDid,
      claim: {
        relationshipType: 'peer-relationship',
        rfiDigest: claim.rfiDigest,
        rfaReplyDigest: claim.rfaReplyDigest,
        establishedAt: new Date(claim.establishedAt * 1000).toISOString(),
      },
      signerSecretKey: identity.signingKeyPair.secretKey,
      verificationMethod,
      extension: {
        issuerIdentityUuid: local.identityUuid,
        subjectIdentityUuid: remote.identityUuid,
      },
    });
    credentialUuid = mintResult.credentialUuid;
    w3cJson = mintResult.w3cVcJson;

    await dataSource.run('UPDATE credentials SET credential_digest = ? WHERE uuid = ?', digestHex, credentialUuid);
    logger.info(`[mintPeerVrc] DTG RelationshipCredential stored for ${record.remoteDid.slice(0, 12)}...`);
  } catch (err) {
    logger.warn('[mintPeerVrc] Failed to mint via factory (non-fatal):', (err as Error)?.message ?? err);
    return { success: false };
  }

  const signature = signEd25519(digest, identity.signingKeyPair.secretKey);
  const didDocRow = await dataSource.get<{ uuid: string }>(
    'SELECT uuid FROM did_documents WHERE identity_uuid = ? AND is_primary = 1', local.identityUuid);
  const sigUuid = generateUuid();
  const sigNow = Math.floor(Date.now() / 1000);
  const credRow = await dataSource.get<{ uuid: string }>('SELECT uuid FROM credentials WHERE uuid = ?', credentialUuid);

  await dataSource.run(
    `INSERT INTO credential_signatures (credential_uuid, signer_identity_uuid, signer_did_document_uuid, signature, uuid, signed_at) VALUES (?, ?, ?, ?, ?, ?)`,
    credRow?.uuid ?? '', local.identityUuid,
    didDocRow?.uuid ?? null, signature, sigUuid, sigNow);

  logger.info(`[mintPeerVrc] Stored relationship handshake record for remote ${record.remoteDid.slice(0, 12)}... (credential_uuid=${credentialUuid})`);
  return { success: true, w3cVcJson: w3cJson ?? undefined, remoteDid: record.remoteDid };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function uint8ArrayToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
