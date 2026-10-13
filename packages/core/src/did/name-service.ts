/**
 * NameService — unified agent name API.
 *
 * Dispatches to the correct name binding path based on the DidMethod's
 * capabilities:
 *   - Path A (alsoKnownAs): did:scid:vh — names in DID document, rotation-backed
 *   - Path B (VRC): did:peer:4 — names via self-signed VRC claims
 *
 * This is the core library class. App layers (agent-app, utility-server) wire
 * it up with thin delegation.
 */

import type { DidMethod } from './did-method.js';
import type { DidDocument } from './types.js';
import type { RotationLogEntry } from './rotation-types.js';
import type { Ed25519KeyPair } from '../crypto/primitives.js';
import { buildNameUri, parseNameUri, isValidNameUri } from './name-uri.js';
import { issueNameClaim, verifyNameClaim } from './name-vrc.js';
import type { Vrc } from '../vtc/types.js';

export interface NameServiceConfig {
  didMethod: DidMethod;
  /** Resolver that can look up any DID → DidDocument (both local and remote). */
  resolveDid: (did: string) => DidDocument;
}

export interface RegisterNameParams {
  name: string;
  namespace: string;
  did: string;
  signingKeyPair: Ed25519KeyPair;
  /** Only required for alsoKnownAs binding (did:scid:vh). */
  currentLog?: RotationLogEntry[];
  outgoingSigningKeyPair?: Ed25519KeyPair;
  newSigningKeyPair?: Ed25519KeyPair;
  nextSigningPublicKey?: Uint8Array;
  expiresAt?: number;
}

export interface NameEntry {
  nameUri: string;
  namespace: string;
  name: string;
  did: string;
  bindingType: 'alsoKnownAs' | 'vrc' | 'utility_managed';
}

export class NameService {
  private config: NameServiceConfig;

  constructor(config: NameServiceConfig) {
    this.config = config;
  }

  /**
   * Register a name for a DID. Dispatches to the appropriate binding path.
   *
   * For did:scid:vh (alsoKnownAs): appends the name to the DID document's
   * alsoKnownAs via a new rotation entry. Returns the new rotation entry.
   *
   * For did:peer:4 (VRC): issues a self-signed VRC with claim type 'AgentName'.
   * Returns the VRC.
   */
  async registerName(params: RegisterNameParams): Promise<{ rotationEntry?: RotationLogEntry; vrc?: Vrc }> {
    const nameUri = buildNameUri(params.namespace, params.name);
    const bindingType = this.config.didMethod.getNameBindingType();

    if (bindingType === 'alsoKnownAs') {
      // Path A: Append to alsoKnownAs via rotation entry
      if (!params.currentLog || !params.outgoingSigningKeyPair || !params.newSigningKeyPair || !params.nextSigningPublicKey) {
        throw new Error(
          'NameService.registerName: alsoKnownAs binding requires currentLog, outgoingSigningKeyPair, newSigningKeyPair, and nextSigningPublicKey',
        );
      }
      // Import dynamically to avoid circular dependency
      const { ScidVhMethod } = await import('./scid-vh-method.js');
      const scidVhMethod = this.config.didMethod as InstanceType<typeof ScidVhMethod>;
      const entry = await scidVhMethod.claimName({
        currentLog: params.currentLog,
        nameUri,
        outgoingSigningKeyPair: params.outgoingSigningKeyPair,
        newSigningKeyPair: params.newSigningKeyPair,
        nextSigningPublicKey: params.nextSigningPublicKey,
      });
      return { rotationEntry: entry };
    }

    if (bindingType === 'vrc') {
      // Path B: Issue self-signed VRC
      const vrc = issueNameClaim({
        nameUri,
        did: params.did,
        signingKeyPair: params.signingKeyPair,
        expiresAt: params.expiresAt,
      });
      return { vrc };
    }

    throw new Error(`NameService.registerName: no binding method available for ${this.config.didMethod.methodName}`);
  }

  /**
   * Revoke a previously registered name.
   *
   * For did:scid:vh: creates a rotation entry that removes the name from alsoKnownAs.
   * For did:peer:4: this would require VRC revocation (not yet implemented —
   * VRCs with expiresAt=self-expiring are the current mechanism).
   */
  async revokeName(params: {
    nameUri: string;
    currentLog: RotationLogEntry[];
    outgoingSigningKeyPair: Ed25519KeyPair;
    newSigningKeyPair: Ed25519KeyPair;
    nextSigningPublicKey: Uint8Array;
  }): Promise<RotationLogEntry | undefined> {
    const bindingType = this.config.didMethod.getNameBindingType();

    if (bindingType === 'alsoKnownAs') {
      const { ScidVhMethod } = await import('./scid-vh-method.js');
      const scidVhMethod = this.config.didMethod as InstanceType<typeof ScidVhMethod>;
      return scidVhMethod.revokeName({
        currentLog: params.currentLog,
        nameUri: params.nameUri,
        outgoingSigningKeyPair: params.outgoingSigningKeyPair,
        newSigningKeyPair: params.newSigningKeyPair,
        nextSigningPublicKey: params.nextSigningPublicKey,
      });
    }

    // For VRC-based names, revocation is handled by expiresAt self-expiry
    return undefined;
  }

  /**
   * List all names for a given DID.
   * For alsoKnownAs methods: reads from the resolved DID document.
   * For VRC methods: the caller must track VRCs separately (not a DID doc property).
   */
  listNames(did: string): NameEntry[] {
    const bindingType = this.config.didMethod.getNameBindingType();

    if (bindingType === 'alsoKnownAs') {
      const alsoKnownAs = this.config.didMethod.getAlsoKnownAs?.(did) ?? [];
      return alsoKnownAs
        .filter(uri => isValidNameUri(uri))
        .map(uri => {
          const parsed = parseNameUri(uri);
          return {
            nameUri: uri,
            namespace: parsed.namespace,
            name: parsed.name,
            did,
            bindingType: 'alsoKnownAs' as const,
          };
        });
    }

    return [];
  }

  /**
   * Verify that a name is validly bound to a DID.
   *
   * For alsoKnownAs methods: resolves the DID and checks the alsoKnownAs array.
   * For VRC methods: verifies the VRC signature against the DID document.
   */
  verifyName(nameUri: string, did: string, vrc?: Vrc): boolean {
    const doc = this.config.resolveDid(did);
    if (!doc) return false;

    const bindingType = this.config.didMethod.getNameBindingType();

    if (bindingType === 'alsoKnownAs') {
      const alsoKnownAs = doc.alsoKnownAs ?? [];
      return alsoKnownAs.includes(nameUri);
    }

    if (bindingType === 'vrc' && vrc) {
      return verifyNameClaim(vrc, doc);
    }

    return false;
  }
}