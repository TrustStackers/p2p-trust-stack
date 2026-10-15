// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * DTG PersonaCredential adapter.
 *
 * VPC links a persona-scoped DID (P-DID) to the holder's core identity,
 * allowing context-separated presentation without correlation.
 *
 * Per DTG spec WD01:
 *   type: ["VerifiableCredential", "DTGCredential", "PersonaCredential"]
 *   credentialSubject: { id, personaProfileId, personaLabel }
 */
import { buildDtgCredential, serializeDtgCredential } from '../dtg-credential.js';
import type { DtgCredentialVc } from '../dtg-credential.js';

export interface VpcAdapterParams {
  issuerDid: string;          // the holder's root identity (self-issued)
  subjectDid: string;         // the P-DID
  personaProfileId: number;   // the profile this persona represents
  personaLabel: string;       // human-readable persona name
  verificationMethod: string;
  signerSecretKey: Uint8Array;
  validFrom: number;          // unix seconds
  validUntil?: number;
}

export function toDtgVpc(params: VpcAdapterParams): DtgCredentialVc {
  const {
    issuerDid, subjectDid, personaProfileId, personaLabel,
    verificationMethod, signerSecretKey, validFrom, validUntil,
  } = params;

  return buildDtgCredential({
    subtype: 'PersonaCredential',
    id: `urn:uuid:${crypto.randomUUID()}`,
    issuerDid,
    subjectDid,
    claim: {
      personaProfileId,
      personaLabel,
    },
    validFrom,
    validUntil,
    verificationMethod,
    signerSecretKey,
  });
}

/** Serialize a VPC to JSON string for storage. */
export function serializeVpc(vc: DtgCredentialVc): string {
  return serializeDtgCredential(vc);
}
