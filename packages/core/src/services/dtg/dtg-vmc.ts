/**
 * DTG MembershipCredential adapter.
 *
 * Converts a VTC-issued membership Vrc (claim type like 'witness-member')
 * to a DTG MembershipCredential W3C VC.
 *
 * Per DTG spec v0.3:
 *   type: ["VerifiableCredential", "DTGCredential", "MembershipCredential"]
 *   credentialSubject: { id, memberOf, membershipRole, membershipSince }
 *
 * A PersonhoodCredential (PHC) is a VMC from a personhood-enforcing VTC.
 * Pass `assertPersonhood: true` to add "PersonhoodCredential" to the type array.
 */
import { buildDtgCredential, serializeDtgCredential } from '../dtg-credential.js';
import type { DtgCredentialVc } from '../dtg-credential.js';
import type { Vrc } from '../../vtc/types.js';

export interface VmcAdapterParams {
  vrc: Vrc;
  issuerDid: string;        // the VTC's DID
  subjectDid: string;       // the member's DID
  membershipRole: string;   // e.g. 'member', 'admin', 'witness'
  verificationMethod: string;
  signerSecretKey: Uint8Array;
  assertPersonhood?: boolean;
}

export function toDtgVmc(params: VmcAdapterParams): DtgCredentialVc {
  const {
    vrc, issuerDid, subjectDid, membershipRole,
    verificationMethod, signerSecretKey, assertPersonhood,
  } = params;

  // The personhood type array is applied BEFORE signing via `typeOverride`
  // (F-01 / F-02). The old code built the credential, then did `vc.type = […]` —
  // which mutated the document under a signature that no longer matched it, so
  // every PHC was unverifiable. `buildDtgCredential()` now deep-freezes its
  // result, so such a post-sign mutation throws instead of corrupting the VC.
  return buildDtgCredential({
    subtype: 'MembershipCredential',
    id: `urn:uuid:${crypto.randomUUID()}`,
    issuerDid,
    subjectDid,
    claim: {
      memberOf: issuerDid,
      membershipRole,
      membershipSince: new Date(vrc.issuedAt * 1000).toISOString(),
      claimType: vrc.claim.type,
    },
    validFrom: vrc.issuedAt,
    validUntil: vrc.expiresAt,
    verificationMethod,
    signerSecretKey,
    ...(assertPersonhood
      ? { typeOverride: ['VerifiableCredential', 'DTGCredential', 'MembershipCredential', 'PersonhoodCredential'] }
      : {}),
  });
}

/** Serialize a VMC to JSON string for storage. */
export function serializeVmc(vc: DtgCredentialVc): string {
  return serializeDtgCredential(vc);
}
