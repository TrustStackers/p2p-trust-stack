/**
 * Core VTC/VRC API — Step 10, Tasks 10.3, 10.4, 10.5.
 *
 * createVtc() / issueVrc() / verifyVrc() / verifyGovernanceDoc() — enough of
 * Layer 3 to represent "VTA X is a witness member of VTC Y" via a VTC identity
 * (Decision 2.6 — VTC-as-VTA), an admin list, and M-of-N co-sign verification
 * (Decision 2.7 — message-level co-signing, not threshold cryptography).
 *
 * Reference: docs/implementation-plan-step10.md §4.
 */

import { signEd25519, verifyEd25519 } from '../crypto/primitives.js';
import { cesrDecode, cesrEncode, CESR_CODES } from '../crypto/cesr.js';
import { DidPeer4Method } from '../did/did-peer4-method.js';
import type { DidResolver } from '../did/did-resolver.js';

import type { DidMethod } from '../did/did-method.js';
import type { Vid, CesrVid } from '../tsp/v3/types.js';
import { computeGovernanceDocDigest, computeVrcDigest } from './codec.js';
import type {
  Vrc,
  VrcClaim,
  VrcSignature,
  VrcVerifyResult,
  VtcGovernanceDoc,
  VtcIdentity,
} from './types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Decode a CESR-encoded VID string to its raw Ed25519 public key bytes. */
function decodeVidToPublicKey(vid: Vid): Uint8Array {
  const decoded = cesrDecode(vid);
  if (decoded.code !== CESR_CODES.ED25519_PUBLIC_KEY) {
    throw new TypeError(`decodeVidToPublicKey: expected ED25519_PUBLIC_KEY, got code "${decoded.code}"`);
  }
  return decoded.bytes;
}

/** Constant-time-ish byte comparison for digest equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// createVtc()
// ---------------------------------------------------------------------------

export interface CreateVtcParams {
  name: string;
  /** Signing key pairs of the founding admins (each signs the governance doc digest). */
  founders: Array<{ vid: Vid; signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array } }>;
  threshold: number;
  allowedClaimTypes: string[];
  /** Defaults to DidPeer4Method, per Step 9 pattern. */
  didMethod?: DidMethod;
  /**
   * Additional admins listed on the governance doc who do NOT co-sign.
   * When omitted only `founders` are listed (existing behavior). Used by the
   * agent-side VTC creation ceremony: the originating agent is the sole signer;
   * co-admins are recorded as admins without signing. The utility server only
   * stores the minted VTC credential — it never re-creates it (deprecating the
   * old server-side VTC creation flow).
   */
  listedAdmins?: Vid[];
}

/**
 * Mint a new VTC identity (Decision 2.6 — VTC-as-VTA) and its initial
 * governance doc, signed by the founding admins.
 */
export async function createVtc(params: CreateVtcParams): Promise<VtcIdentity> {
  const { name, founders, threshold, allowedClaimTypes } = params;
  const didMethod = params.didMethod ?? new DidPeer4Method();
  console.log(
    `[vtc:create] minting VTC '${name ?? '(unnamed)'}' ` +
    `(signers=${founders.length}${params.listedAdmins?.length ? `, listedAdmins=${params.listedAdmins.length}` : ''}, threshold=${threshold})`,
  );

  const adminVids: Vid[] = params.listedAdmins && params.listedAdmins.length > 0
    ? [...new Set(founders.map(f => f.vid).concat(params.listedAdmins))]
    : founders.map(f => f.vid);

  // Genesis mint gate (Option A): the M-of-N threshold governs POST-creation
  // co-signing (VRC issuance, amendments), NOT the initial mint. Any ≥1 actual
  // signer (the originator) may found the VTC; the admin set is the signer(s)
  // plus the listed co-admins (who become founding admins BY being selected,
  // no pre-existing founding-admin credential required). We only reject a
  // configuration that is impossible to satisfy: zero signers, or M > N.
  if (founders.length === 0) {
    throw new Error('createVtc: at least one founding signer is required');
  }
  if (threshold > adminVids.length) {
    throw new Error(
      `createVtc: threshold (${threshold}) cannot exceed the number of founding admins (${adminVids.length})`,
    );
  }
  if (founders.length < threshold) {
    console.warn(
      `[vtc:create] bootstrapping VTC '${name}': ${founders.length} signer(s) with threshold ${threshold}; ` +
      `${adminVids.length - founders.length} listed co-admin(s) not co-signing at genesis`,
    );
  }

  const result = await didMethod.create();

  // The VTC's own VID is the CESR-encoded Ed25519 public key of its signing key pair,
  // same convention as Agent.identity.vid.
  const vtcVidEncoded = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, result.signingKeyPair.publicKey);

  const unsignedDoc: Omit<VtcGovernanceDoc, 'digest' | 'signatures'> = {
    vtcVid: vtcVidEncoded,
    vtcDid: result.did,
    name,
    adminVids,
    threshold,
    allowedClaimTypes,
    createdAt: Math.floor(Date.now() / 1000),
  };

  const digest = computeGovernanceDocDigest(unsignedDoc);

  const signatures: VrcSignature[] = founders.map(founder => ({
    signerVid: founder.vid,
    signature: signEd25519(digest, founder.signingKeyPair.secretKey),
  }));

  console.log(`[vtc:create] governance doc signed: did=${result.did}, digest=${digest.slice(0, 16)}..., admins=${adminVids.length}, signatures=${signatures.length}`);

  const governanceDoc: VtcGovernanceDoc = {
    ...unsignedDoc,
    digest,
    signatures,
  };

  return {
    governanceDoc,
    didDocument: result.document,
    signingKeyPair: result.signingKeyPair,
    agreementKeyPair: result.agreementKeyPair,
  };
}

// ---------------------------------------------------------------------------
// issueVrc()
// ---------------------------------------------------------------------------

export interface IssueVrcParams {
  governanceDoc: VtcGovernanceDoc;
  /**
   * Subject of the VRC. Typed `CesrVid` because `issueVrc` produces a VRC that
   * the VTC/VRC binary codec encodes, and the codec stores VIDs as CESR-encoded
   * Ed25519 public keys (see `CesrVrc`). Callers holding a DID must convert
   * the *key* with `asCesrVid()`.
   */
  subjectVid: CesrVid;
  claim: VrcClaim;
  /** Admin signing key pairs to co-sign with — caller-supplied (Step 10 scope). */
  signers: Array<{ vid: CesrVid; signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array } }>;
  expiresAt?: number;
}

/**
 * Build and co-sign a VRC given a set of admin signing key pairs supplied
 * directly by the caller (no live multi-agent signing round — Step 10 scope).
 */
export function issueVrc(params: IssueVrcParams): Vrc {
  const { governanceDoc, subjectVid, claim, signers, expiresAt } = params;

  if (!governanceDoc.allowedClaimTypes.includes(claim.type)) {
    throw new Error(
      `issueVrc: claim type "${claim.type}" is not in the VTC's allowedClaimTypes [${governanceDoc.allowedClaimTypes.join(', ')}]`,
    );
  }

  for (const signer of signers) {
    if (!governanceDoc.adminVids.includes(signer.vid)) {
      throw new Error(`issueVrc: signer ${signer.vid.slice(0, 12)}... is not on the VTC's admin list`);
    }
  }

  if (signers.length < governanceDoc.threshold) {
    throw new Error(
      `issueVrc: governance doc requires ${governanceDoc.threshold} signatures, only ${signers.length} signer(s) supplied`,
    );
  }

  const unsignedVrc: Omit<Vrc, 'digest' | 'signatures'> = {
    subjectVid,
    issuerVid: governanceDoc.vtcVid,
    claim,
    issuedAt: Math.floor(Date.now() / 1000),
    expiresAt,
  };

  const digest = computeVrcDigest(unsignedVrc);

  const signatures: VrcSignature[] = signers.map(signer => ({
    signerVid: signer.vid,
    signature: signEd25519(digest, signer.signingKeyPair.secretKey),
  }));

  return {
    ...unsignedVrc,
    digest,
    signatures,
  };
}

// ---------------------------------------------------------------------------
// verifyVrc() / verifyGovernanceDoc()
// ---------------------------------------------------------------------------

/**
 * Count valid, admin-list-matching, de-duplicated signatures over a digest.
 */
function countValidAdminSignatures(
  digest: Uint8Array,
  signatures: VrcSignature[],
  adminVids: Vid[],
): number {
  const seen = new Set<string>();
  let count = 0;
  for (const sig of signatures) {
    if (!adminVids.includes(sig.signerVid)) continue; // not an admin — excluded
    if (seen.has(sig.signerVid)) continue; // de-duplicate repeated signer
    let publicKey: Uint8Array;
    try {
      publicKey = decodeVidToPublicKey(sig.signerVid);
    } catch {
      continue; // malformed VID — excluded
    }
    if (verifyEd25519(sig.signature, digest, publicKey)) {
      seen.add(sig.signerVid);
      count++;
    }
  }
  return count;
}

/**
 * Verify a Vrc against its issuing VTC's governance doc.
 *
 * Checks: (1) the VRC's digest matches its canonical fields (tamper check),
 * (2) at least `governanceDoc.threshold` valid signatures from VIDs on the
 * governance doc's current admin list.
 */
export function verifyVrc(vrc: Vrc, governanceDoc: VtcGovernanceDoc): VrcVerifyResult {
  const expectedDigest = computeVrcDigest({
    subjectVid: vrc.subjectVid,
    issuerVid: vrc.issuerVid,
    claim: vrc.claim,
    issuedAt: vrc.issuedAt,
    expiresAt: vrc.expiresAt,
  });

  if (!bytesEqual(expectedDigest, vrc.digest)) {
    return { valid: false, validSignatureCount: 0, reason: 'digest-mismatch' };
  }

  const validSignatureCount = countValidAdminSignatures(vrc.digest, vrc.signatures, governanceDoc.adminVids);

  if (validSignatureCount < governanceDoc.threshold) {
    return { valid: false, validSignatureCount, reason: 'insufficient-signatures' };
  }

  return { valid: true, validSignatureCount };
}

/**
 * Resolution-aware VRC verification — DID-Core-aligned counterpart to the
 * self-certifying {@link verifyVrc}.
 *
 * In addition to every check performed by `verifyVrc` (digest integrity,
 * M-of-N admin co-signatures over the self-certifying `signerVid`), this
 * verifies each signature against the signer's CURRENT DID document when a
 * signer DID is available (via `VrcSignature.signerDid` or the governance
 * doc's `adminDids`). This honors key rotation: a signature whose VID has been
 * rotated out of the admin's live `assertionMethod` is rejected even though the
 * raw Ed25519 check still passes.
 *
 * Because DID resolution is asynchronous, this is an async function. The
 * self-certifying `signerVid` check remains the offline fast path; when no DIDs
 * are present (legacy governance docs), this degrades exactly to `verifyVrc`.
 */
export async function verifyVrcResolved(
  vrc: Vrc,
  governanceDoc: VtcGovernanceDoc,
  resolver: DidResolver,
): Promise<VrcVerifyResult> {
  const base = verifyVrc(vrc, governanceDoc);
  if (!base.valid) return base;

  // Build a DID-lookup path for each signature:
  //   1. signature.signerDid (most specific) wins;
  //   2. governanceDoc.adminDids[i] (parallel to adminVids) as fallback;
  //   3. no DID → skip resolution for that signature (self-certifying only).
  const resolveKey = async (sig: VrcSignature): Promise<boolean> => {
    const adminIdx = governanceDoc.adminVids.indexOf(sig.signerVid);
    const did = sig.signerDid ?? (adminIdx >= 0 ? governanceDoc.adminDids?.[adminIdx] : undefined);
    if (!did) return true; // no DID to resolve — fall back to self-certifying check (already passed)

    const deref = await resolver.dereferenceVerificationMethod(`${did}#key-1`);
    if (!deref) return false; // admin DID unresolvable or key missing

    // The signing VID's raw key must match the admin's current assertion key.
    const vidKey = decodeVidToPublicKey(sig.signerVid);
    return bytesEqual(vidKey, deref.rawKey);
  };

  const results = await Promise.all(vrc.signatures.map(resolveKey));
  const validCount = results.filter(Boolean).length;

  if (validCount < governanceDoc.threshold) {
    return { valid: false, validSignatureCount: validCount, reason: 'signer-key-rotated-or-unresolvable' };
  }

  return { valid: true, validSignatureCount: validCount };
}

/**
 * Verify a VtcGovernanceDoc's founding signatures against its own admin list
 * (self-referential — a governance doc's admins co-sign its own digest).
 *
 * Symmetric with verifyVrc() so Step 12's join-flow can reuse the same logic
 * when validating a governance doc received from elsewhere.
 */
export function verifyGovernanceDoc(doc: VtcGovernanceDoc): VrcVerifyResult {
  const expectedDigest = computeGovernanceDocDigest({
    vtcVid: doc.vtcVid,
    vtcDid: doc.vtcDid,
    name: doc.name,
    adminVids: doc.adminVids,
    threshold: doc.threshold,
    allowedClaimTypes: doc.allowedClaimTypes,
    createdAt: doc.createdAt,
  });

  if (!bytesEqual(expectedDigest, doc.digest)) {
    return { valid: false, validSignatureCount: 0, reason: 'digest-mismatch' };
  }

  const validSignatureCount = countValidAdminSignatures(doc.digest, doc.signatures, doc.adminVids);

  if (validSignatureCount < doc.threshold) {
    return { valid: false, validSignatureCount, reason: 'insufficient-signatures' };
  }

  return { valid: true, validSignatureCount };
}
