// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * DTG InvitationCredential adapter.
 *
 * VIC wraps an OOBI (out-of-band invitation) as a signed W3C VC. The OOBI is
 * currently a CESR-encoded transport artifact; VIC promotes it to a
 * ceremony-bound credential valid only within the onboarding ceremony.
 *
 * Per DTG spec WD01:
 *   type: ["VerifiableCredential", "DTGCredential", "InvitationCredential"]
 *   credentialSubject: { id, invitation: { vid, peerId, multiaddrs }, taskContext }
 */
import { buildDtgCredential, serializeDtgCredential } from '../dtg-credential.js';
import type { DtgCredentialVc } from '../dtg-credential.js';
import type { OobiPayload } from '../../relationship/types.js';

export interface VicAdapterParams {
  oobi: OobiPayload;          // the OOBI being wrapped
  issuerDid: string;          // the inviting community's DID
  subjectDid: string;         // the prospective member's DID
  taskContext: string;        // the onboarding ceremony threadId (REQUIRED)
  verificationMethod: string;
  signerSecretKey: Uint8Array;
  validFrom: number;          // unix seconds
  validUntil?: number;
}

export function toDtgVic(params: VicAdapterParams): DtgCredentialVc {
  const {
    oobi, issuerDid, subjectDid, taskContext,
    verificationMethod, signerSecretKey, validFrom, validUntil,
  } = params;

  return buildDtgCredential({
    subtype: 'InvitationCredential',
    id: `urn:uuid:${crypto.randomUUID()}`,
    issuerDid,
    subjectDid,
    claim: {
      invitation: {
        vid: oobi.cesrVid,
        peerId: oobi.peerId,
        multiaddrs: oobi.multiaddrs,
      },
      taskContext,
    },
    validFrom,
    validUntil,
    verificationMethod,
    signerSecretKey,
  });
}

/** Serialize a VIC to JSON string for storage. */
export function serializeVic(vc: DtgCredentialVc): string {
  return serializeDtgCredential(vc);
}
