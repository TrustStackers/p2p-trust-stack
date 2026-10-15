// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `contexts` DTOs — provisioned app contexts, and the scope a caller is handed for one.
 *
 * ## Why this file is small, and what it deliberately does not carry
 *
 * A context's whole point is isolation, so nothing here may leak the root identity's material. The provision
 * result mirrors the runtime's bundle field for field because that shape is pinned by **audit F-021 / ruling
 * Y1** ("a private key never crosses this provisioning boundary") — the DTO is a *view of a contract that is
 * already deliberately narrow*, not a place to add fields.
 */

/** A provisioned context, as stored in its own metadata. */
export interface ContextDto {
  contextId: string;
  /**
   * Which of the ROOT identity's verification methods this context may use (DID-document key ids such as
   * `#key-1`, `#key-mldsa`). This is a KEY scope, not a method scope — see `scope.ts` for why the two are
   * separate.
   */
  allowedKeyIds: string[];
  /** Unix seconds, or absent for a context that never expires. */
  expiresAt?: number;
  createdAt: number;
  deviceId?: string;
  deviceLocal: boolean;
}

/**
 * What provisioning hands back.
 *
 * PUBLIC identifiers only. There is deliberately no secret-key field: that absence is the F-021 ruling, and
 * `test/agent/context-provisioning.test.ts` pins the exact key set so a re-introduced one fails the build.
 */
export interface ProvisionedContextDto {
  contextId: string;
  contextDid: string;
  /** CESR-encoded Ed25519 PUBLIC key of the context's signing key (its VID). */
  contextSigningVid: string;
  /** CESR-encoded X25519 PUBLIC key of the context's agreement key (its VID). */
  contextAgreementVid: string;
  /** Where the private halves live. They are NOT returned to the caller. */
  keystorePath: string;
  /** Always true — spelled out so the contract is visible at the type level. */
  keysStayInContext: true;
  vtaEndpoint?: string;
  allowedKeyIds: string[];
  expiresAt?: number;
}

/**
 * What a scoped stack will let a context do.
 *
 * `'<domain>.<read|write>'`. There is no wildcard and no implicit grant: **anything not listed is refused**,
 * including every domain this union does not mention.
 */
export type ContextCapability =
  | 'identity.read'
  | 'connectivity.read'
  | 'relationships.read'
  | 'relationships.write'
  | 'messaging.read'
  | 'messaging.write'
  | 'profiles.read'
  | 'profiles.write'
  | 'names.read'
  | 'names.write'
  | 'credentials.read'
  | 'credentials.write'
  | 'communities.read'
  | 'communities.write'
  | 'delegations.read'
  | 'delegations.write';

/** The live state of a context, evaluated on every call rather than captured once. */
export interface ContextScopeStateDto {
  contextId: string;
  /** False once the context has been revoked (its directory is deleted) or has expired. */
  live: boolean;
  /** `'revoked'` when the context directory is gone, `'expired'` past `expiresAt`, else `'active'`. */
  reason: 'active' | 'revoked' | 'expired';
  capabilities: ContextCapability[];
}
