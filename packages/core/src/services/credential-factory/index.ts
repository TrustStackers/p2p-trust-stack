// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * CredentialFactory — Unified Credential Minting, Verification, and Display.
 *
 * Barrel export for the credential-factory module.
 *
 * Usage:
 *   import { CredentialFactoryImpl } from './credential-factory/index.js';
 *   const factory = new CredentialFactoryImpl(db, guard, coordinator, txManager);
 *   const result = await factory.mint({ kind: 'RelationshipCredential', ... });
 */

// Types
export type {
  DtgCredentialType,
  DtgVerifiableDataStructure,
  CredentialKind,
  CredentialScenario,
  GovernanceModel,
  CredentialFormat,
  CredentialMintRequest,
  CredentialMintResult,
  CredentialVerifyResult,
  CredentialViewModel,
  CredentialFactory,
} from './types.js';

// Implementation
export { CredentialFactoryImpl, CREDENTIAL_REGISTRY, vcTypeToKind, kindToVcType } from './credential-factory-impl.js';
