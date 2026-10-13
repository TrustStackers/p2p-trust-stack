/**
 * DTG WitnessCredential (VWC) adapter.
 *
 * Converts a VTC-issued witness Vrc to a DTG witness attestation.
 * Generalized beyond just 'rotation-witness' — supports any edge-agnostic
 * attestation claim type.
 *
 * ## Two forms, gated by `TSP_DTG_PROFILE_POLICY` (F-002, 2026-09-25)
 *
 * **WD02** (`off`/`warn`):
 *   type: ["VerifiableCredential", "DTGCredential", "WitnessCredential"]
 *   credentialSubject: { id, digest: "sha256:<hex>", witnessContext }
 *
 * **v1.0** (`enforce` — the default):
 *   type: ["VerifiableCredential", "DTGCredential", "StatementCredential"]
 *   credentialSubject: { id, predicate: "dtg:witnessed",
 *                        object: { digestMultibase: "zQm…" }, … }
 *
 * The v1.0 form follows the spec's own term definition — a VWC is *"a VSC under
 * the `dtg:witnessed` predicate profile: third-party attestation that the subject
 * issued the credential named by `object.digestMultibase`, under the conditions
 * of a specific trust task exchange"* — with `taskContext` REQUIRED by the
 * profile. `WitnessCredential` is a profile name that is *"no longer a W3C type
 * string"*, so it is not emitted beside `StatementCredential`.
 */
import { sha256 } from '../../crypto/primitives.js';
import { buildDtgCredential, serializeDtgCredential } from '../dtg-credential.js';
import type { DtgCredentialVc } from '../dtg-credential.js';
import type { Vrc } from '../../vtc/types.js';
import { DTG_PREDICATE_WITNESSED, emitsDtgStatementProfile } from './profile-policy.js';
import { toSha256MultibaseMultihash } from './digest-encoding.js';

export interface VwcAdapterParams {
  vrc: Vrc;
  issuerDid: string;        // the Witness VTC's DID
  subjectDid: string;       // the party whose event is witnessed
  verificationMethod: string;
  signerSecretKey: Uint8Array;
  /** The threadId of the originating trust task. REQUIRED per DTG spec WD01. */
  taskContext?: string;
}

export function toDtgVwc(params: VwcAdapterParams): DtgCredentialVc {
  const { vrc, issuerDid, subjectDid, verificationMethod, signerSecretKey } = params;
  const asStatement = emitsDtgStatementProfile();

  // Compute digest of the claim for the witnessContext
  const claimJson = JSON.stringify(vrc.claim);
  const claimDigest = sha256(new TextEncoder().encode(claimJson));
  const digestHex = 'sha256:' + Array.from(claimDigest)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  // Build witnessContext from the claim
  const witnessContext: Record<string, unknown> = {
    event: vrc.claim.type,
    observedAt: new Date(vrc.issuedAt * 1000).toISOString(),
  };
  // Copy claim-specific fields (excluding 'type' which is already in 'event')
  for (const [key, value] of Object.entries(vrc.claim)) {
    if (key !== 'type') witnessContext[key] = value;
  }

  // `taskContext` is REQUIRED by the `dtg:witnessed` profile, so the profile form
  // refuses to issue without it — fail closed rather than emit a non-conformant
  // witness attestation.
  if (asStatement && !params.taskContext) {
    throw new Error(
      "toDtgVwc: taskContext is REQUIRED by the 'dtg:witnessed' profile " +
        '(TSP_DTG_PROFILE_POLICY=enforce). Pass the originating trust task threadId, ' +
        'or set TSP_DTG_PROFILE_POLICY=warn to emit the WD02 form instead.',
    );
  }

  // Undefined-valued members are omitted, never spread in as `undefined`.
  //
  // jcsCanonicalize() renders an undefined value as `null` while
  // JSON.stringify() drops the key, so a `taskContext: undefined` member was
  // SIGNED over `"taskContext":null` but STORED without the member at all —
  // and verifyDtgProof() re-canonicalises the parsed document, so such a
  // credential could never verify. Omitting the member restores that invariant.
  const extras: Record<string, unknown> = { witnessContext };
  if (params.taskContext !== undefined) extras.taskContext = params.taskContext;

  return buildDtgCredential({
    subtype: 'WitnessCredential',
    id: `urn:uuid:${crypto.randomUUID()}`,
    issuerDid,
    subjectDid,
    claim: asStatement ? extras : { digest: digestHex, ...extras },
    ...(asStatement
      ? {
          statement: {
            predicate: DTG_PREDICATE_WITNESSED,
            object: { digestMultibase: toSha256MultibaseMultihash(claimDigest) },
          },
        }
      : {}),
    validFrom: vrc.issuedAt,
    validUntil: vrc.expiresAt,
    verificationMethod,
    signerSecretKey,
  });
}

export function serializeVwc(vc: DtgCredentialVc): string {
  return serializeDtgCredential(vc);
}
