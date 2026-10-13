/**
 * `credentials` DTOs — VRCs, credential signatures, and community invitations.
 *
 * Three deliberate omissions:
 *
 *  - `CredentialSignatureRow.signature` — the raw Ed25519 bytes — never crosses the boundary. The UI renders
 *    *who* signed and *when*; a signature blob in a JSON response is a leak with no consumer.
 *  - Replication bookkeeping (`recordedByNode`, `replicatedAt`) and the status-list slot describe how THIS node
 *    learned of the row, not the credential itself.
 *  - `Vrc.digest` is a `Uint8Array` and is likewise dropped.
 */
import type { CredentialViewModel } from '@p2p-trust-stack/core/services/credential-factory/types.js';
import type { VrcClaim } from '@p2p-trust-stack/core/vtc/types.js';

/** Which store a credential was read from. */
export type CredentialSourceDto = 'dtg' | 'vtc';

/**
 * A credential held in the SQLite `credentials` table (the DTG store).
 *
 * **Keyed by `uuid`.** The two stores disagree on identity — a DTG row is keyed by UUID (the cross-node key) and
 * a VTC-store credential only by its CESR VIDs — so `uuid` is the address, and `credentials.revoke()` /
 * `signatures()` take it.
 *
 * They took a SQLite `rowid` until 2026-10-10, and this DTO deliberately did not publish one. The result was
 * that both methods were **unaddressable from any consumer**: the web UI's Revoke button was disabled with
 * "no usable id to address". Integer row addresses are not a supported identity for a credential.
 */
export interface StoredCredentialDto {
  source: 'dtg';
  uuid: string;
  vcType: string;
  issuerIdentityUuid: string;
  subjectIdentityUuid: string;
  claim: string | null;
  status: string;
  w3cVcJson: string | null;
  createdAt: number | null;
}

/**
 * A credential held in the in-process VTC store (the older CESR form).
 *
 * A **separate** DTO rather than one interface with every field nullable: this store has no row and no UUID, so
 * the union makes "which identity does this have?" a compile-time distinction instead of a runtime surprise.
 */
export interface VtcCredentialDto {
  source: 'vtc';
  subjectVid: string;
  issuerVid: string;
  /** The claim type, e.g. `witness-member`. */
  claimType: string;
  issuedAt: number;
  expiresAt: number | null;
  /** How many admin co-signatures the store holds for it. */
  signatureCount: number;
}

/** A credential from either store. */
export type CredentialDto = StoredCredentialDto | VtcCredentialDto;

/** One admin's co-signature over a credential — without the signature bytes. */
export interface CredentialSignatureDto {
  uuid: string;
  credentialUuid: string;
  signerIdentityUuid: string;
  signedAt: number | null;
}

/** A community invitation addressed to the active identity. */
export interface InvitationDto {
  uuid: string;
  communityUuid: string;
  communityName: string;
  communityDid: string | null;
  createdAt: number | null;
}

/** A credential was declined, or an invitation consumed. */
export interface CredentialAckDto {
  ok: true;
}

/**
 * The result of accepting a community invitation.
 *
 * `membership` is the utility server's answer to `vtc_accept` — deliberately `unknown` here, because the layer
 * does not own that protocol's shape and inventing a DTO for it would be a contract this layer cannot keep.
 */
export interface AcceptInvitationDto {
  ok: true;
  message: string;
  membership: unknown;
}

/**
 * Input for issuing a community credential.
 *
 * **No key material appears here.** The runtime signs with the active identity's own keypair
 * (`AgentHandle.issueVrcForSelf`), which is what lets the page offer this form without ever holding a secret —
 * and why `scope.ts` can keep denying `identity.sign` to app contexts. An earlier draft of this contract had the
 * caller pass `signers: [{ vid, signingKeyPair }]`, which would have pushed private keys through the web layer.
 *
 * `subjectVid` is optional: omitted means **self-issue**, the case the page's subject select labels
 * `☆ Myself`.
 */
export interface IssueVrcInput {
  /** The issuing community, addressed by DID (the VTC store keys governance docs by DID). */
  vtcDid: string;
  /** The subject's CESR VID. Omitted = the active identity. */
  subjectVid?: string;
  /** The claim to assert, e.g. `{ type: 'witness-member' }`. */
  claim: VrcClaim;
  /** Unix seconds after which the credential is no longer valid. */
  expiresAt?: number;
}

/**
 * A credential as it was just issued — the same projection as `VtcCredentialDto`, minus the store round trip.
 *
 * Returned instead of the raw `Vrc` because `Vrc.digest` is a `Uint8Array` and `signatures` carry raw Ed25519
 * bytes, neither of which belongs on the wire (the same rule `CredentialSignatureDto` follows).
 */
export interface IssuedCredentialDto {
  subjectVid: string;
  issuerVid: string;
  claimType: string;
  issuedAt: number;
  expiresAt: number | null;
  signatureCount: number;
}

/**
 * Input for verifying a stored credential.
 *
 * Addressed by the **VTC store's own composite key** rather than a rowid or a UUID, because that is what the
 * store actually keys on (`VtcStore.getVrc(subjectDid, issuerDid, claimType)`) and what `list()` can supply for
 * a `VtcCredentialDto` — which has no row and no UUID at all. The two stores are keyed differently, so the two
 * address forms are not interchangeable: `signatures` and `revoke` take a **uuid** and therefore only reach DTG
 * rows. (Until 2026-10-10 they took a node-local rowid, which no DTO published — see `credentials.revoke()`.)
 */
export interface VerifyVrcInput {
  subjectVid: string;
  issuerVid: string;
  claimType: string;
}

/** The outcome of verifying one credential. Mirrors the runtime's `VrcVerifyResult`. */
export interface VrcVerificationDto {
  valid: boolean;
  validSignatureCount: number;
  /** Populated only when `valid === false`. */
  reason?: string;
}

/** One scenario's worth of credential view models, as the credentials page renders them. */
export interface CredentialScenarioDto {
  scenario: string;
  kinds: string[];
}

/**
 * The credentials page's read model.
 *
 * `groups` and `stats` are keyed by scenario because that is the shape the page indexes into
 * (`credGroups[scenario]`), and re-shaping them into arrays would be a breaking change to a live consumer for
 * no gain. They are maps of a **named** value type, not a row passthrough.
 */
export interface CredentialViewModelsDto {
  viewModels: CredentialViewModel[];
  groups: Record<string, CredentialViewModel[]>;
  stats: Record<string, number>;
  scenarios: CredentialScenarioDto[];
}
