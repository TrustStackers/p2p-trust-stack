/**
 * DidManager — creates and manages context-scoped DIDs.
 *
 * Each context-scoped DID is a did:peer:4 with is_primary=0, linked to the
 * caller's root identity. The root identity (did:scid:vh) remains is_primary=1.
 *
 * Context types:
 *   C-DID — community (one per VTC/VTN)
 *   M-DID — member (one per identity+community pair)
 *   R-DID — relationship (one per relationship edge)
 *   P-DID — persona (one per profile)
 */

import type { DataSource } from '../db/data-source.js';
import { createDidPeer4 } from '../did/create.js';
import * as identitiesRepo from '../db/repositories/identities-repo.js';
import * as didDocumentsRepo from '../db/repositories/did-documents-repo.js';
import * as keysRepo from '../db/repositories/keys-repo.js';
import { decryptSecretKey } from '../keystore/sqlite-keystore.js';
import { cesrEncode, CESR_CODES } from '../crypto/cesr.js';

/**
 * Passphrase used to encrypt community signing keys at rest on the utility
 * server (Model A custody). Mirrors the DEV_PASSPHRASE convention in
 * utility-server/src/node/vta.ts; overridable via NODE_PASSPHRASE.
 */
export const COMMUNITY_KEY_PASSPHRASE =
  process.env.NODE_PASSPHRASE ?? 'dev-only-insecure-passphrase';

export type DidContext =
  | { type: 'community'; communityIdentityUuid: string }
  | { type: 'relationship'; relationshipUuid: string }
  | { type: 'persona'; profileUuid: string };

export interface CreateContextDidResult {
  did: string;
  didDocumentUuid: string;
  identityUuid: string;
  signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array };
}

export interface CommunitySigningKey {
  did: string;
  verificationMethod: string;
  /** CESR-encoded Ed25519 public key (the community's signing VID). */
  vid: string;
  signerSecretKey: Uint8Array;
}

export class DidManager {
  private readonly db: DataSource;

  constructor(db: DataSource) {
    this.db = db;
  }

  /** Create a C-DID for a newly founded VTC/VTN. */
  async createCommunityDid(communityIdentityUuid: string): Promise<CreateContextDidResult> {
    const peer4 = await createDidPeer4();
    const identity = await identitiesRepo.findByUuid(this.db, communityIdentityUuid);
    const identityUuid = identity?.uuid ?? communityIdentityUuid;

    const didDocumentUuid = await didDocumentsRepo.create(this.db, {
      identityUuid,
      did: peer4.did,
      method: 'did:peer:4',
      documentJson: JSON.stringify(peer4.document),
      isPrimary: false,
      contextType: 'community',
      contextRefUuid: communityIdentityUuid,
    });

    await keysRepo.create(this.db, {
      identityUuid,
      didDocumentUuid,
      keyType: 'ed25519',
      publicKey: Buffer.from(peer4.signingKeyPair.publicKey),
    });

    return { did: peer4.did, didDocumentUuid, identityUuid, signingKeyPair: peer4.signingKeyPair };
  }

  /**
   * Resolve + decrypt a community's Ed25519 signing key (Model A custody).
   *
   * Used to sign VICs/VMCs after community creation. Returns null when the key
   * was not persisted encrypted at creation (e.g. remote-custody communities or
   * legacy rows holding public keys only).
   */
  async resolveCommunitySigningKey(communityIdentityUuid: string): Promise<CommunitySigningKey | null> {
    const primary = await didDocumentsRepo.findPrimaryForIdentity(this.db, communityIdentityUuid);
    if (!primary) return null;
    const ed = await keysRepo.findCurrentForDidDocument(this.db, primary.uuid, 'ed25519');
    if (!ed?.encryptedSecretKey || !ed.salt || !ed.nonce || !ed.authTag) return null;
    try {
      const signerSecretKey = await decryptSecretKey(
        {
          ciphertext: ed.encryptedSecretKey,
          salt: ed.salt,
          nonce: ed.nonce,
          authTag: ed.authTag,
        },
        COMMUNITY_KEY_PASSPHRASE,
      );
      return {
        did: primary.did,
        verificationMethod: `${primary.did}#key-1`,
        vid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, ed.publicKey),
        signerSecretKey,
      };
    } catch (err) {
      console.warn(
        `[did-manager] failed to decrypt community signing key for ${communityIdentityUuid.slice(0, 8)}...:`,
        (err as Error).message,
      );
      return null;
    }
  }

  /** Create an M-DID for a member joining a community. */
  async createMemberDid(
    memberIdentityUuid: string,
    communityIdentityUuid: string,
  ): Promise<CreateContextDidResult> {
    const peer4 = await createDidPeer4();
    const member = await identitiesRepo.findByUuid(this.db, memberIdentityUuid);
    const identityUuid = member?.uuid ?? memberIdentityUuid;

    const didDocumentUuid = await didDocumentsRepo.create(this.db, {
      identityUuid,
      did: peer4.did,
      method: 'did:peer:4',
      documentJson: JSON.stringify(peer4.document),
      isPrimary: false,
      contextType: 'community',
      contextRefUuid: communityIdentityUuid,
    });

    await keysRepo.create(this.db, {
      identityUuid,
      didDocumentUuid,
      keyType: 'ed25519',
      publicKey: Buffer.from(peer4.signingKeyPair.publicKey),
    });

    return { did: peer4.did, didDocumentUuid, identityUuid, signingKeyPair: peer4.signingKeyPair };
  }

  /** Create an R-DID for a pairwise relationship. */
  async createRelationshipDid(
    identityUuid: string,
    relationshipUuid: string,
  ): Promise<CreateContextDidResult> {
    const peer4 = await createDidPeer4();
    const identity = await identitiesRepo.findByUuid(this.db, identityUuid);
    const resolvedIdentityUuid = identity?.uuid ?? identityUuid;

    const didDocumentUuid = await didDocumentsRepo.create(this.db, {
      identityUuid: resolvedIdentityUuid,
      did: peer4.did,
      method: 'did:peer:4',
      documentJson: JSON.stringify(peer4.document),
      isPrimary: false,
      contextType: 'relationship',
      contextRefUuid: relationshipUuid,
    });

    await keysRepo.create(this.db, {
      identityUuid: resolvedIdentityUuid,
      didDocumentUuid,
      keyType: 'ed25519',
      publicKey: Buffer.from(peer4.signingKeyPair.publicKey),
    });

    return { did: peer4.did, didDocumentUuid, identityUuid: resolvedIdentityUuid, signingKeyPair: peer4.signingKeyPair };
  }

  /** Create a P-DID for a persona profile. */
  async createPersonaDid(
    identityUuid: string,
    profileUuid: string,
  ): Promise<CreateContextDidResult> {
    const peer4 = await createDidPeer4();
    const identity = await identitiesRepo.findByUuid(this.db, identityUuid);
    const resolvedIdentityUuid = identity?.uuid ?? identityUuid;

    const didDocumentUuid = await didDocumentsRepo.create(this.db, {
      identityUuid: resolvedIdentityUuid,
      did: peer4.did,
      method: 'did:peer:4',
      documentJson: JSON.stringify(peer4.document),
      isPrimary: false,
      contextType: 'persona',
      contextRefUuid: profileUuid,
    });

    await keysRepo.create(this.db, {
      identityUuid: resolvedIdentityUuid,
      didDocumentUuid,
      keyType: 'ed25519',
      publicKey: Buffer.from(peer4.signingKeyPair.publicKey),
    });

    return { did: peer4.did, didDocumentUuid, identityUuid: resolvedIdentityUuid, signingKeyPair: peer4.signingKeyPair };
  }

  /** Resolve which DID to use for a given (identity, context) pair. */
  async resolveDid(identityUuid: string, context?: DidContext): Promise<string> {
    if (!context) {
      const doc = await didDocumentsRepo.findPrimaryForIdentity(this.db, identityUuid);
      if (!doc) throw new Error(`No primary DID for identity ${identityUuid}`);
      return doc.did;
    }

    const rows = await this.db.all<import('../db/repositories/did-documents-repo.js').DidDocumentRow>(
      `SELECT * FROM did_documents WHERE identity_uuid = ? AND context_type = ? AND context_ref_uuid = ? AND status = 'active' LIMIT 1`,
      identityUuid, context.type, this.contextRefUuid(context),
    );
    if (rows.length > 0) return rows[0].did;

    const doc = await didDocumentsRepo.findPrimaryForIdentity(this.db, identityUuid);
    if (!doc) throw new Error(`No primary DID for identity ${identityUuid}`);
    return doc.did;
  }

  /** Resolve a context-scoped DID back to its root identity. */
  async resolveRootIdentity(contextDid: string): Promise<{
    identityUuid: string;
    rootDid: string;
    context?: DidContext;
  } | null> {
    const doc = await didDocumentsRepo.findByRealDid(this.db, contextDid);
    if (!doc) return null;

    const primary = await didDocumentsRepo.findPrimaryForIdentity(this.db, doc.identityUuid);
    if (!primary) return null;

    let context: DidContext | undefined;
    if (doc.contextType && doc.contextRefUuid != null) {
      context = { type: doc.contextType as DidContext['type'], [this.contextRefKey(doc.contextType)]: doc.contextRefUuid } as DidContext;
    }

    return { identityUuid: doc.identityUuid, rootDid: primary.did, context };
  }

  /** List all context DIDs for an identity. */
  async listContextDids(identityUuid: string): Promise<Array<{ did: string; context: DidContext }>> {
    const rows = await this.db.all<import('../db/repositories/did-documents-repo.js').DidDocumentRow>(
      `SELECT * FROM did_documents WHERE identity_uuid = ? AND context_type IS NOT NULL AND status = 'active' ORDER BY uuid`,
      identityUuid,
    );
    return rows
      .filter(r => r.contextType && r.contextRefUuid != null)
      .map(r => ({
        did: r.did,
        context: { type: r.contextType as DidContext['type'], [this.contextRefKey(r.contextType!)]: r.contextRefUuid } as DidContext,
      }));
  }

  /** Check if a DID belongs to a specific community context. */
  async isCommunityMember(did: string, communityDid: string): Promise<boolean> {
    const community = await didDocumentsRepo.findByRealDid(this.db, communityDid);
    if (!community) return false;

    const rows = await this.db.all<{ uuid: string }>(
      `SELECT uuid FROM did_documents WHERE did = ? AND context_type = 'community' AND context_ref_uuid = ? AND status = 'active'`,
      did, community.identityUuid,
    );
    return rows.length > 0;
  }

  private contextRefUuid(context: DidContext): string {
    switch (context.type) {
      case 'community': return context.communityIdentityUuid;
      case 'relationship': return context.relationshipUuid;
      case 'persona': return context.profileUuid;
    }
  }

  private contextRefKey(contextType: string): string {
    switch (contextType) {
      case 'community': return 'communityIdentityUuid';
      case 'relationship': return 'relationshipUuid';
      case 'persona': return 'profileUuid';
      default: return 'communityIdentityUuid';
    }
  }
}
