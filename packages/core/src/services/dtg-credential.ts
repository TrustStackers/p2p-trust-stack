/**
 * DTG Credential — P2P credential minting + W3C VC formatting.
 *
 * ## Two layers
 *
 * 1. **mintDtgCredential()** — store a raw credential row (existing, unchanged).
 * 2. **buildDtgCredential() / serializeDtgCredential() / deserializeDtgCredential()** —
 *    build a W3C VC JSON-LD envelope with DataIntegrityProof (eddsa-jcs-2022).
 *    Used by the verified-channel ceremony to issue DTG RelationshipCredentials.
 *
 * ## DataIntegrityProof (eddsa-jcs-2022)
 *
 * Implements the exact `eddsa-jcs-2022` cryptosuite (W3C *Data Integrity EdDSA
 * Cryptosuites v1.0*, REC 2025-05-15, §3.3), not a look-alike.
 *
 * F-01 — why this changed: the previous scheme signed `SHA-256(JCS(document))`
 * alone and attached a proof *after* signing. Everything inside `proof`
 * (`verificationMethod`, `created`, `proofPurpose`, `cryptosuite`) was therefore
 * outside the signed input: an attacker could re-point `verificationMethod` at
 * their own key and the signature still checked out. The suite label
 * `DataIntegrityProof`/`eddsa-jcs-2022` was asserted but not implemented.
 *
 * The correct construction (vc-di-eddsa §3.3.1–3.3.7) is:
 *
 *   1. proofConfig = the proof options, carrying the document's `@context`
 *      (FEP-8b32 §4.5: `canonicalProofConfig` is the proof WITHOUT `proofValue`
 *      but WITH the `@context` inherited from the unsigned document)
 *   2. hashData = SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(unsignedDocument))
 *   3. signature = Ed25519.sign(hashData); proofValue = 'z' ‖ base58btc(signature)
 *
 * JCS here is RFC 8785 via the vetted `canonicalize` package — a hand-rolled
 * subset diverged from `JSON.stringify` on `undefined` members, so a document
 * could be SIGNED over bytes different from those STORED.
 *
 * ## F-02 — the signed document is immutable
 *
 * A second class of the same defect: a caller that appends content *after*
 * signing. `assertPersonhood` used to do exactly that — it built the VMC, then
 * did `vc.type = [… 'PersonhoodCredential']`, so the verifier hashed a proofless
 * document the signer never saw and the credential could never verify.
 *
 * The type/content is now finalised BEFORE signing (`typeOverride`), and
 * `buildDtgCredential()` returns a **deeply frozen** document, so a future
 * post-sign mutation throws a `TypeError` in strict mode (ESM) instead of
 * silently producing an unverifiable credential.
 */
import canonicalize from 'canonicalize';
import type { DataSource } from '../db/data-source.js';
import { sha256, signEd25519, verifyEd25519 } from '../crypto/primitives.js';
import { generateUuid } from '../db/uuid-helpers.js';
import {
  DTG_PROFILE_POLICY_ENV,
  STATEMENT_CREDENTIAL_TYPE,
  resolveDtgProfilePolicy,
  type DtgStatement,
} from './dtg/profile-policy.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface DtgCredentialInput {
  issuerIdentityUuid: string;
  subjectIdentityUuid: string;
  claim: Record<string, unknown>;
  credentialDigest: string;
}

/**
 * The `eddsa-jcs-2022` proof as it appears in the secured document.
 *
 * `@context` is part of the proof configuration (FEP-8b32 §4.5): it inherits
 * the document's `@context`. Because the verifier re-derives the signed bytes
 * from the proof it receives, the emitted proof must carry that `@context` too —
 * otherwise sign and verify would hash different inputs.
 */
export interface DtgDataIntegrityProof {
  '@context'?: string[];
  type: 'DataIntegrityProof';
  cryptosuite: 'eddsa-jcs-2022';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  proofValue: string;
}

export interface DtgCredentialVc {
  '@context': string[];
  /**
   * The credential identifier (`urn:uuid:<uuidv4>`). F-01: it is part of the
   * unsigned document and therefore inside the signed bytes. It was previously
   * accepted as a parameter and silently dropped, leaving the signed artifact
   * with no self-identifier to key revocation or presentation on.
   */
  id?: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: Record<string, unknown>;
  proof: DtgDataIntegrityProof;
}

export interface DtgBuildParams {
  subtype: string;                        // e.g. 'RelationshipCredential'
  id: string;                             // credential ID (urn:uuid or similar)
  issuerDid: string;
  subjectDid: string;
  claim: Record<string, unknown>;
  validFrom: number;                      // unix seconds
  validUntil?: number;                    // unix seconds (optional)
  verificationMethod: string;             // DID URL for the signing key
  signerSecretKey: Uint8Array;            // Ed25519 secret key
  /**
   * F-002 — set for the two DTG predicate profiles (VEC/VWC) only.
   *
   * When present **and** `TSP_DTG_PROFILE_POLICY=enforce`, the credential is
   * emitted as a v1.0 `StatementCredential`; otherwise the WD02 concrete subtype
   * is emitted unchanged. Credentials that do not set this are byte-identical
   * under every policy value.
   */
  statement?: DtgStatement;
  /**
   * F-01 / F-02 — an explicit `type` array, e.g. appending
   * `PersonhoodCredential` to a VMC/PHC. Applied BEFORE signing so the array is
   * inside the signed bytes. The old callers mutated `vc.type` after
   * `buildDtgCredential()` returned, which changed the document under a
   * signature that already covered the old array — silently invalidating the
   * credential (a direct violation of "treat the serialized signed credential as
   * immutable"). `buildDtgCredential()` now deep-freezes its result, so that
   * post-sign mutation can no longer happen at all.
   */
  typeOverride?: string[];
}


export async function mintDtgCredential(db: DataSource, input: DtgCredentialInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const rowUuid = generateUuid();
  await db.run(
    `INSERT INTO credentials (vc_type, issuer_identity_uuid, subject_identity_uuid, claim, credential_digest, status, valid_from, created_at, uuid)
     VALUES (?, ?, ?, ?, ?, 'issued', ?, ?, ?)`,
    'custom_endorsement', input.issuerIdentityUuid,
    input.subjectIdentityUuid,
    JSON.stringify(input.claim), input.credentialDigest, now, now, rowUuid,
  );
  return rowUuid;
}

// ── JCS Canonicalization (RFC 8785) ────────────────────────────────────────

const utf8 = new TextEncoder();

/**
 * RFC 8785 JSON Canonicalization Scheme, via the vetted `canonicalize` package.
 *
 * The previous hand-rolled subset rendered `undefined` members as `null` while
 * `JSON.stringify` drops them, so a document could be signed over bytes that did
 * not match the bytes stored. The package tracks `JSON.stringify` exactly for the
 * shapes this code produces.
 */
function jcs(value: unknown): string {
  const out = canonicalize(value);
  if (typeof out !== 'string') {
    throw new Error('jcs: value is not canonicalizable');
  }
  return out;
}

/**
 * eddsa-jcs-2022 hashing (W3C vc-di-eddsa §3.3.4).
 *
 *   hashData = SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(unsignedDocument))
 *
 * Both halves are 32 bytes, so the result is 64. Sign and verify MUST derive
 * this from one definition — otherwise the two can drift and the suite reverts
 * to a private, self-consistent scheme (the F-01 defect). Both parameters are
 * passed as the objects that will be canonicalized; nothing is defaulted here.
 */
export function buildDiHashData(
  proofConfig: object,
  unsignedDocument: object,
): Uint8Array {
  const proofHash = sha256(utf8.encode(jcs(proofConfig)));
  const documentHash = sha256(utf8.encode(jcs(unsignedDocument)));
  const hashData = new Uint8Array(proofHash.length + documentHash.length);
  hashData.set(proofHash, 0);
  hashData.set(documentHash, proofHash.length);
  return hashData;
}

// ── Multibase base58btc (minimal) ──────────────────────────────────────────

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Multibase base58btc encode (`'z'` prefix). Exported for `digest-encoding.ts`. */
export function toBase58btc(bytes: Uint8Array): string {
  let leadingZeros = 0;
  for (const b of bytes) { if (b === 0) leadingZeros++; else break; }
  let num = 0n;
  for (const b of bytes) { num = (num << 8n) | BigInt(b); }
  if (num === 0n) return 'z' + B58[0].repeat(leadingZeros || 1);
  let enc = '';
  while (num > 0n) { enc = B58[Number(num % 58n)] + enc; num = num / 58n; }
  return 'z' + B58[0].repeat(leadingZeros) + enc;
}

/** Multibase base58btc decode. Exported for `digest-encoding.ts`. */
export function fromBase58btc(encoded: string): Uint8Array {
  if (encoded[0] !== 'z') throw new Error('Expected multibase "z" prefix');
  const b58 = encoded.slice(1);
  let num = 0n;
  let leadingZeros = 0;
  for (const ch of b58) {
    if (ch === '1') { leadingZeros++; continue; }
    break;
  }
  for (const ch of b58.slice(leadingZeros)) {
    const idx = B58.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid base58 char: ${ch}`);
    num = num * 58n + BigInt(idx);
  }
  if (num === 0n) return new Uint8Array(leadingZeros || 1);
  const bytes: number[] = [];
  while (num > 0n) { bytes.unshift(Number(num & 0xffn)); num = num >> 8n; }
  const result = new Uint8Array(leadingZeros + bytes.length);
  result.set(bytes, leadingZeros);
  return result;
}
// ── W3C VC Build / Serialize / Deserialize / Verify ─────────────────────────

/**
 * Recursively `Object.freeze` a plain JSON value (objects + arrays).
 *
 * F-02 — the signed credential must be immutable. A post-sign mutation (e.g.
 * `vc.type = [… 'PersonhoodCredential']`) changes the document the verifier
 * re-canonicalises, so the hash no longer matches what was signed and the
 * credential is silently unverifiable. Freezing makes that failure mode impossible
 * to reintroduce silently: in strict mode (all ESM here) the write throws
 * `TypeError` at the point of the mistake. Scoped to this module — no other
 * consumer mutates a built credential (verified across the tree).
 */
function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
  }
  return value;
}

/**
 * Build a DTG W3C VC with DataIntegrityProof (eddsa-jcs-2022).
 *
 * Algorithm (vc-di-eddsa §3.3.1–3.3.7):
 *   build unsigned document → build proof configuration (proof options + the
 *   document's @context) → hashData = SHA-256(JCS(proofConfig)) ‖
 *   SHA-256(JCS(unsignedDocument)) → Ed25519-sign → proofValue = 'z' ‖ base58btc
 *
 * F-02: the returned document is deeply frozen — see {@link deepFreeze}.
 */
export function buildDtgCredential(params: DtgBuildParams): DtgCredentialVc {
  const {
    id, subtype, issuerDid, subjectDid, claim,
    validFrom, validUntil, verificationMethod, signerSecretKey, statement, typeOverride,
  } = params;

  const createdAt = new Date();

  // ── F-002: v1.0 statement profiles vs the WD02 concrete subtypes ─────────
  //
  // A VEC and a VWC are `StatementCredential`s under the `dtg:endorses` and
  // `dtg:witnessed` predicate profiles. Under `enforce` the subtype string is
  // deliberately NOT emitted — the spec keeps those names as profile names, not
  // type strings, and the predicate carries the distinction the type used to:
  //
  //   type: ["VerifiableCredential", "DTGCredential", "StatementCredential"]
  //   credentialSubject: { id, predicate, object, … }
  //
  // Under `off` and `warn` the WD02 array is reproduced byte for byte.
  const profilePolicy = resolveDtgProfilePolicy();
  const asStatement = statement !== undefined && profilePolicy === 'enforce';
  if (statement !== undefined && profilePolicy === 'warn') {
    console.warn(
      `[dtg-profile] emitting the WD02 form for "${subtype}" because ` +
        `${DTG_PROFILE_POLICY_ENV}=warn; unset it (or set "enforce") to emit the ` +
        `v1.0 StatementCredential profile (${statement.predicate})`,
    );
  }

  const credentialSubject: Record<string, unknown> =
    statement !== undefined && asStatement
      ? { id: subjectDid, predicate: statement.predicate, object: statement.object, ...claim }
      : { id: subjectDid, ...claim };

  const typeArray =
    typeOverride ??
    (asStatement
      ? ['VerifiableCredential', 'DTGCredential', STATEMENT_CREDENTIAL_TYPE]
      : subtype === 'RelationshipCard'
        ? ['VerifiableCredential', 'RelationshipCard']
        : ['VerifiableCredential', 'DTGCredential', subtype]);

  // The unsigned document. `id` is emitted (F-01) so the credential carries a
  // stable identifier inside the signed bytes.
  const unsignedVc: Record<string, unknown> = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://trustoverip.org/dtg/credentials/v1',
      'https://w3id.org/security/data-integrity/v1',
    ],
    id,
    type: typeArray,
    issuer: issuerDid,
    validFrom: new Date(validFrom * 1000).toISOString(),
    ...(validUntil ? { validUntil: new Date(validUntil * 1000).toISOString() } : {}),
    credentialSubject,
  };

  // eddsa-jcs-2022 proof configuration. Built BEFORE signing so the whole proof
  // contract is protected by the signature (F-01): `verificationMethod`,
  // `created`, `proofPurpose` and `cryptosuite` are all inside the signed input.
  // `@context` is inherited from the document (FEP-8b32 §4.5).
  const proofOptions: Omit<DtgDataIntegrityProof, 'proofValue'> = {
    '@context': unsignedVc['@context'] as string[],
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: createdAt.toISOString(),
    verificationMethod,
    proofPurpose: 'assertionMethod',
  };

  const hashData = buildDiHashData(proofOptions, unsignedVc);
  const sigBytes = signEd25519(hashData, signerSecretKey);

  return deepFreeze({
    ...unsignedVc,
    proof: {
      ...proofOptions,
      proofValue: toBase58btc(sigBytes),
    },
  } as unknown as DtgCredentialVc);
}

export function serializeDtgCredential(vc: DtgCredentialVc): string {
  return JSON.stringify(vc);
}

export function deserializeDtgCredential(json: string): DtgCredentialVc {
  const obj = JSON.parse(json);
  if (!obj.proof || obj.proof.type !== 'DataIntegrityProof') {
    throw new Error('deserializeDtgCredential: missing or invalid proof');
  }
  if (obj.proof.cryptosuite !== 'eddsa-jcs-2022') {
    throw new Error(
      `deserializeDtgCredential: unsupported cryptosuite '${obj.proof.cryptosuite}' (expected eddsa-jcs-2022)`,
    );
  }
  return obj as DtgCredentialVc;
}

/**
 * Verify a DataIntegrityProof (eddsa-jcs-2022) against a resolved key.
 *
 * Mirrors {@link buildDtgCredential} exactly (F-01): rebuild the proof
 * configuration from the proof actually received (minus `proofValue`), apply the
 * `@context` rule of vc-di-eddsa §3.3.6–3.3.7, recompute
 * `SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(unsignedDocument))` and Ed25519-verify.
 *
 * Rejects — before any crypto — a proof whose `type`/`cryptosuite`/`proofValue`
 * are not the suite's, so a label cannot stand in for the algorithm. This
 * function does NOT resolve the key or check the issuer/controller binding; the
 * caller must have done that (`CredentialFactoryImpl.verify`).
 */
export function verifyDtgProof(
  vc: DtgCredentialVc,
  signerPublicKey: Uint8Array,
): boolean {
  try {
    const proof = vc.proof as DtgDataIntegrityProof | undefined;
    if (!proof || proof.type !== 'DataIntegrityProof') return false;
    // The label must be backed by the algorithm it names.
    if (proof.cryptosuite !== 'eddsa-jcs-2022') return false;

    const proofValue = proof.proofValue;
    if (typeof proofValue !== 'string' || proofValue.length === 0) return false;
    // Both JCS cryptosuites mandate base58btc multibase ('z'); reject any other
    // encoding rather than silently decoding it.
    if (proofValue[0] !== 'z') return false;

    const signature = fromBase58btc(proofValue);
    if (signature.length !== 64) return false;

    // proofConfig = the received proof without `proofValue`.
    const { proofValue: _proofValue, ...proofConfig } = proof;
    void _proofValue;

    // unsignedDocument = the credential without `proof`.
    const { proof: _proof, ...docRest } = vc as unknown as Record<string, unknown> & { proof?: unknown };
    void _proof;

    // §3.3.6/§3.3.7: when the proof carries an `@context`, the secured
    // document's `@context` MUST begin with the proof's values, in order, and
    // the document is then hashed with the proof's `@context` (the proof's
    // values win). Our signer always emits it; this also keeps us honest against
    // proofs that omit it (they simply hash the document as-is).
    let unsignedDocument: Record<string, unknown> = docRest;
    const proofContext = proofConfig['@context'];
    if (proofContext !== undefined) {
      const pc = Array.isArray(proofContext) ? proofContext : [proofContext];
      const docContextRaw = docRest['@context'];
      const dc = Array.isArray(docContextRaw) ? docContextRaw : [docContextRaw];
      if (dc.length < pc.length) return false;
      for (let i = 0; i < pc.length; i++) {
        if (pc[i] !== dc[i]) return false;
      }
      unsignedDocument = { ...docRest, '@context': proofContext };
    }

    const hashData = buildDiHashData(proofConfig, unsignedDocument);
    return verifyEd25519(signature, hashData, signerPublicKey);
  } catch {
    return false;
  }
}
