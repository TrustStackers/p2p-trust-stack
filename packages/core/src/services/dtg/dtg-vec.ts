/**
 * DTG EndorsementCredential (VEC) adapter.
 *
 * VEC is additive — wraps an existing credential digest plus a community
 * endorsement in a W3C VC. Lowest complexity of the DTG credential types.
 *
 * ## Two forms, gated by `TSP_DTG_PROFILE_POLICY` (F-002, 2026-09-25)
 *
 * **WD02** (`off`/`warn`):
 *   type: ["VerifiableCredential", "DTGCredential", "EndorsementCredential"]
 *   credentialSubject: { id, endorsedCredentialDigest, endorsementType }
 *
 * **v1.0** (`enforce` — the default):
 *   type: ["VerifiableCredential", "DTGCredential", "StatementCredential"]
 *   credentialSubject: { id, predicate: "dtg:endorses",
 *                        object: { digestMultibase: "zQm…" }, endorsementType }
 *
 * `EndorsementCredential` is retained by the spec as a profile name and is
 * *"no longer a W3C type string"*, so it is not emitted beside
 * `StatementCredential`.
 *
 * INFERRED, not stated by the spec (flagged for review): the spec defines the
 * VEC as a statement "about the counterparty" whose assertion vocabulary may be
 * the VTC's or VTN's, but it does not give the VEC's `object` shape. This maps
 * the endorsed *credential* digest to `object.digestMultibase`, following the
 * spec's Digest Encoding rule that digest-valued members are multibase/multihash
 * and issue #45's note that a credential-valued object uses the same member as
 * the witness digest. `endorsementType` stays a plain subject member.
 */
import { buildDtgCredential, serializeDtgCredential } from '../dtg-credential.js';
import type { DtgCredentialVc } from '../dtg-credential.js';
import { DTG_PREDICATE_ENDORSES, emitsDtgStatementProfile } from './profile-policy.js';
import { toDigestMultibase } from './digest-encoding.js';

export interface VecAdapterParams {
  issuerDid: string;                  // the endorsing community's DID
  subjectDid: string;                 // the entity being endorsed
  endorsedCredentialDigest: string;   // digest of the credential being endorsed
  endorsementType: string;            // e.g. 'skill', 'reputation', 'qualification'
  verificationMethod: string;
  signerSecretKey: Uint8Array;
  validFrom: number;                  // unix seconds
  validUntil?: number;
}

export function toDtgVec(params: VecAdapterParams): DtgCredentialVc {
  const {
    issuerDid, subjectDid, endorsedCredentialDigest, endorsementType,
    verificationMethod, signerSecretKey, validFrom, validUntil,
  } = params;
  const asStatement = emitsDtgStatementProfile();

  return buildDtgCredential({
    subtype: 'EndorsementCredential',
    id: `urn:uuid:${crypto.randomUUID()}`,
    issuerDid,
    subjectDid,
    // The profile form moves the endorsed credential digest into the statement's
    // `object` (as a multibase multihash); WD02 keeps it as a flat member.
    claim: asStatement
      ? { endorsementType }
      : { endorsedCredentialDigest, endorsementType },
    ...(asStatement
      ? {
          statement: {
            predicate: DTG_PREDICATE_ENDORSES,
            object: { digestMultibase: toDigestMultibase(endorsedCredentialDigest) },
          },
        }
      : {}),
    validFrom,
    validUntil,
    verificationMethod,
    signerSecretKey,
  });
}

/** Serialize a VEC to JSON string for storage. */
export function serializeVec(vc: DtgCredentialVc): string {
  return serializeDtgCredential(vc);
}
