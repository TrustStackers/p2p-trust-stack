/**
 * Service: VTC/VTN creation (Scenario 4 — "Create a Verified Trust
 * Community"). See mockup/vtc-create.html.
 *
 * A VTC/VTN is itself an `identities` row (role='vtc'|'vtn',
 * subject_kind=NULL — it's a governance construct, not a subject),
 * governed by a set of founding admins under an M-of-N co-signing
 * threshold recorded in `governance`. Founding admins become
 * `memberships` rows (role='founding_admin', status='active') rather
 * than a flat array on the community itself, and each founding admin is
 * issued a VMC (Verified Membership Credential) at creation time: the
 * community-signed `credentials` row is minted through the
 * CredentialFactory and referenced back from the membership row via
 * `memberships.membership_credential_uuid` — the same shape the
 * join/approve flow produces for later joiners. Delivery of each VMC to
 * its holder's agent is the caller's job (the creation ceremony queues
 * the `credential` recordset fan-out; see
 * utility-server/src/services/vtc-push-data.ts). A `status_lists` row
 * (purpose='revocation') is minted alongside it, with reserved decoy
 * indices 0-3 pre-flipped so a new community's first real member isn't
 * identifiable by slot position.
 *
 * VTC creation requires at least 1 founding admin; where there is more than one,
 * every additional admin must have an established mutual (bidirectional) VRC with
 * the creator. VTN creation permits single-operator bootstrap; VTNs follow a
 * separate genesis ceremony disconnected from the VTC ceremony.
 *
 * Scenario 9 — "VTNs & Nested Communities" (see mockup/vtn-network.html
 * and docs/cross-layer-integration-plan.md Decision 2.8) extends this
 * module with affiliate/unaffiliate, hierarchy view, and effective-policy
 * resolution: a VTN is the same identities-row shape as a VTC (role='vtn'
 * instead of 'vtc'), and a VTC affiliates with a VTN simply by setting its
 * own governance.parent_community_id to the VTN's identity id. A VTN can
 * also admit unaligned individual members directly (a memberships row
 * with community_identity_id pointing at the VTN, exactly like a VTC
 * membership).
 */

import type { DataSource } from '../db/data-source.js';

import * as identitiesRepo from '../db/repositories/identities-repo.js';
import type { Identity, IdentityRole } from '../db/repositories/identities-repo.js';
import * as governanceRepo from '../db/repositories/governance-repo.js';
import type { GovernanceRow } from '../db/repositories/governance-repo.js';
import * as membershipsRepo from '../db/repositories/memberships-repo.js';
import type { MembershipRow, MembershipRole } from '../db/repositories/memberships-repo.js';
import * as statusListsRepo from '../db/repositories/status-lists-repo.js';
import type { StatusListRow } from '../db/repositories/status-lists-repo.js';
import * as relationshipsRepo from '../db/repositories/relationships-repo.js';
import * as keysRepo from '../db/repositories/keys-repo.js';
import { encryptSecretKey } from '../keystore/sqlite-keystore.js';
import { DidPeer4Method } from '../did/did-peer4-method.js';
import { generateUuid } from '../db/uuid-helpers.js';
import { DidManager, COMMUNITY_KEY_PASSPHRASE } from './did-manager.js';
import { seedDefaultBindings, resolveCommunityClaimTypes } from './policy-bindings.js';

export class CreateVtcValidationError extends Error {}
export class CreateVtcNotFoundError extends Error {}
export class CreateVtcConflictError extends Error {}

/** Reserved decoy slot indices, pre-flipped at mint so a community's first real member isn't identifiable by slot position. */
const RESERVED_DECOY_INDICES = [0, 1, 2, 3];

/** VMC (Verified Membership Credential) default validity window per OpenVTC spec.
 *  Mirrors the join/approve flow (utility-server/src/routes/layer4-governance/memberships.ts). */
const VMC_DEFAULT_VALIDITY_SECONDS = 30 * 24 * 60 * 60; // 30 days

export type VtcKind = 'vtc' | 'vtn';

/** Known DTG credential types for VTC governance. RCards are excluded —
 *  they are a data format derived from profile claims, not a credential type. */
export const CREDENTIAL_TYPES = [
  { code: 'VRC', label: 'Verified Relationship Credential' },
  { code: 'VMC', label: 'Verified Membership Credential' },
  { code: 'VWC', label: 'Verified Witness Credential' },
  { code: 'VIC', label: 'Verified Invitation Credential' },
  { code: 'VPC', label: 'Verified Persona Credential' },
  { code: 'VEC', label: 'Verified Endorsement Credential' },
] as const;

export type CredentialTypeCode = typeof CREDENTIAL_TYPES[number]['code'];

/** Validate that a credential type is known or a custom x-prefixed type. */
export function validateCredentialType(credType: string): boolean {
  const knownCodes: Set<string> = new Set(CREDENTIAL_TYPES.map((t) => t.code));
  return knownCodes.has(credType) || credType.startsWith('x-');
}

/**
 * Check whether a community name is available.
 *
 * Case-insensitive lookup over VTC + VTN identities.  The UNIQUE partial
 * index on identities(name) WHERE role IN ('vtc','vtn') is the ultimate
 * guard (23505 / SQLITE_CONSTRAINT on collision) — this function provides
 * a clean pre-flight check for the UI.
 */
export async function checkCommunityNameAvailable(
  db: DataSource,
  candidate: string,
): Promise<{ available: boolean; message: string; existingName?: string }> {
  if (!candidate || !candidate.trim()) {
    return { available: false, message: 'Name is required.' };
  }
  const normalized = candidate.trim();
  const row = await db.get<{ name: string }>(
    `SELECT name FROM identities
     WHERE role IN ('vtc','vtn') AND name IS NOT NULL AND LOWER(name) = LOWER(?)`,
    normalized,
  );
  if (row) {
    return {
      available: false,
      message: `A community named "${row.name}" already exists.`,
      existingName: row.name,
    };
  }
  return { available: true, message: 'Name is available.' };
}

export interface CreateVtcInput {
  name: string;
  kind?: VtcKind;
  adminIdentityUuids: string[];
  threshold?: number;
  parentCommunityUuid?: string;
}

export interface CreateVtcResult {
  identity: Identity;
  governance: GovernanceRow;
  foundingAdmins: MembershipRow[];
  statusList: StatusListRow;
  /** Governance bootstrap status for the UI. */
  governanceBootstrap: {
    /** Whether the VTC meets minimal TOIP/DTG governance (2+ admins with mutual VRCs). */
    meetsMinimalGovernance: boolean;
    /** Whether the VTC is partially formed — not all admin pairs have established VRCs. */
    isBootstrapping: boolean;
    /** Human-readable guidance message. */
    message: string;
  };
}

/**
 * Mint a member's VMC (Verified Membership Credential) through the
 * CredentialFactory and return the new `credentials` row uuid, so the caller
 * can store it on the membership row
 * (`memberships.membership_credential_uuid`) and deliver it to that member's
 * agent. Returns null when minting fails: creating/admitting a membership must
 * never fail because a credential could not be minted (mirrors the non-fatal
 * C-DID/M-DID handling in createVtc).
 *
 * At community creation this is signed with the VTC's own creation-time Ed25519
 * key. The community's private key is never persisted (only its public key
 * lands in `keys`), so creation is the one moment a DTG-conformant,
 * community-signed VMC can be produced — callers without a signing key (later
 * admin additions, REST routes) get the factory's record-only credential
 * (claim JSON, no W3C VC envelope), exactly as the join/approve route produces.
 *
 * `issuerDid` and `governanceDid` are the same community DID in the default
 * (self-issuing) flow: the guard always authorizes the community's own DID to
 * act on its own behalf. Since F-012 stage 3 a *different* admin's DID also
 * satisfies `actor_is_admin`, because the guard resolves each member to their
 * primary DID before building the policy facts — previously it compared the
 * actor's DID against member **identity UUIDs**, so only self-issuance could
 * ever pass and a divergent issuer was denied. The facts are DID-space
 * throughout: an issuer or subject that reaches the guard as a bare
 * `identities.uuid` (e.g. the `member.did ?? member.uuid` fallback below, on an
 * identity with no primary DID) matches no fact and cannot be authorized.
 *
 * Call this BEFORE the membership row is approved (while it is still
 * `pending`): the baseline policy's `vmc-issue` rule is `actor_is_admin AND NOT
 * subject_is_active_member`, so minting after activation is denied. The REST
 * approve route already enforces this ordering by 409-ing on a non-pending
 * membership (`memberships.ts:187`).
 */
export async function mintMembershipVmc(
  db: DataSource,
  params: {
    /** The community (VTC/VTN) identity that issues the VMC. */
    community: Identity;
    /** The community's DID — used as issuer AND governance DID. */
    communityDid: string;
    /** The member identity the VMC is issued to. */
    member: Identity;
    /** The membership row uuid carried in the claim. */
    membershipUuid: string;
    /** Claim `membershipRole` (e.g. 'founding_admin', 'admin', 'member'). */
    membershipRole: string;
    /** DID URL of the issuer's signing key. Defaults to `<communityDid>#key-1`. */
    verificationMethod?: string;
    /** Issuer signing key — omit for a record-only credential. */
    signerSecretKey?: Uint8Array;
  },
): Promise<string | null> {
  const { community, communityDid, member, membershipUuid, membershipRole } = params;
  const now = Math.floor(Date.now() / 1000);
  try {
    const [{ CredentialFactoryImpl }, { GovernanceGuard }, { createPolicyEngine }] = await Promise.all([
      import('./credential-factory/credential-factory-impl.js'),
      import('./governance-guard.js'),
      import('./policy-engine-config.js'),
    ]);
    const factory = new CredentialFactoryImpl(db, new GovernanceGuard(db, createPolicyEngine()));
    const result = await factory.mint({
      kind: 'MembershipCredential',
      scenario: 'community-join',
      issuerDid: communityDid,
      subjectDid: member.did ?? member.uuid,
      governanceDid: communityDid,
      claim: {
        memberOf: communityDid,
        membershipRole,
        membershipSince: new Date(now * 1000).toISOString(),
        communityName: community.name,
        membershipUuid,
      },
      verificationMethod: params.verificationMethod ?? `${communityDid}#key-1`,
      signerSecretKey: params.signerSecretKey,
      validUntil: new Date((now + VMC_DEFAULT_VALIDITY_SECONDS) * 1000),
      extension: {
        issuerIdentityUuid: community.uuid,
        subjectIdentityUuid: member.uuid,
      },
    });
    console.log(`[mintMembershipVmc] VMC minted for ${membershipRole} ${member.name ?? member.uuid} in ${community.name ?? community.uuid} (credential=${result.credentialUuid.slice(0, 8)})`);
    return result.credentialUuid;
  } catch (err) {
    console.warn(
      `[mintMembershipVmc] VMC mint failed for ${membershipRole} ${member.name ?? member.uuid} (non-fatal):`,
      (err as Error)?.message ?? err,
    );
    return null;
  }
}

/**
 * Join a community by DID — create a `pending` membership for a prospective
 * member whose identity already exists on this node (pushed via identity_push).
 *
 * Shared by the REST `join-by-invite` route and the TSP `vtc_join` participant
 * op so both paths produce the identical membership row.
 */
export async function joinCommunityByDid(
  db: DataSource,
  params: { communityDid: string; memberDid: string; role?: string },
): Promise<{ membership: MembershipRow; community: Identity }> {
  const community = await identitiesRepo.findByRealDid(db, params.communityDid);
  if (!community) throw new CreateVtcNotFoundError(`community ${params.communityDid} not found`);
  if (community.role !== 'vtc' && community.role !== 'vtn') {
    throw new CreateVtcValidationError(
      `identity ${params.communityDid} is not a community (role=${community.role})`,
    );
  }
  const member = await identitiesRepo.findByRealDid(db, params.memberDid);
  if (!member) {
    throw new CreateVtcNotFoundError(
      `identity ${params.memberDid} not found — register the VTA on this server first`,
    );
  }
  const existing = await membershipsRepo.findByPair(db, member.uuid, community.uuid);
  if (existing) {
    throw new CreateVtcConflictError(
      `identity ${params.memberDid} already has a membership (status=${existing.status}) in community ${community.uuid}`,
    );
  }

  const membershipUuid = await membershipsRepo.create(db, {
    memberIdentityUuid: member.uuid,
    communityIdentityUuid: community.uuid,
    role: (params.role ?? 'member') as MembershipRole,
    status: 'pending',
  });
  const membership = await membershipsRepo.findByUuid(db, membershipUuid);
  if (!membership) throw new Error('joinCommunityByDid: membership not found after create');
  return { membership, community };
}

export async function createVtc(db: DataSource, input: CreateVtcInput): Promise<CreateVtcResult> {
  if (!input.name || !input.name.trim()) {
    throw new CreateVtcValidationError('name is required');
  }
  const kind: VtcKind = input.kind ?? 'vtc';
  if (kind !== 'vtc' && kind !== 'vtn') {
    throw new CreateVtcValidationError("kind must be one of: vtc, vtn");
  }
  if (!Array.isArray(input.adminIdentityUuids) || input.adminIdentityUuids.length === 0) {
    throw new CreateVtcValidationError('adminIdentityUuids is required and must contain at least one identity uuid');
  }

  const n = input.adminIdentityUuids.length;
  const m = input.threshold ?? (kind === 'vtc' ? 2 : 1);
  if (!Number.isInteger(m) || m < 1) {
    throw new CreateVtcValidationError('threshold must be a positive integer');
  }

  // ── Pre-flight: community names must be unique across the network ────
  {
    const avail = await checkCommunityNameAvailable(db, input.name);
    if (!avail.available) {
      throw new CreateVtcConflictError(avail.message);
    }
  }

  // Resolve + validate each founding admin references an existing VTA identity.
  const admins: Identity[] = [];
  for (const adminUuid of input.adminIdentityUuids) {
    const identity = await identitiesRepo.findByUuid(db, adminUuid);
    if (!identity) {
      throw new CreateVtcNotFoundError(`admin identity ${adminUuid} not found`);
    }
    if (identity.role !== 'vta') {
      throw new CreateVtcValidationError(`admin identity ${adminUuid} is not a VTA (role=${identity.role})`);
    }
    // Only human VTAs can serve as founding admins (TOIP/DTG governance requirement).
    if (identity.subjectKind !== 'human') {
      throw new CreateVtcValidationError(
        `admin identity ${adminUuid} (${identity.name ?? 'unnamed'}) has subject_kind=${identity.subjectKind ?? 'null'}; only human VTAs can be founding admins`,
      );
    }
    // Exclude TSP-bridge fakes: real VTAs have an ACTIVE libp2p endpoint (from
    // their Agent App); fakes have no peer_endpoints row / no endpoint,
    // recordedByNode IS NULL, createdAt IS NULL.
    const isRealVta = await identitiesRepo.hasAnyEndpoint(db, identity.uuid);
    if (!isRealVta) {
      throw new CreateVtcValidationError(
        `admin identity ${adminUuid} (${identity.name ?? 'unnamed'}) has no libp2p endpoint — likely a TSP-bridge fake, not a real Agent App VTA`,
      );
    }
    admins.push(identity);
  }

  // ── VRC validation: any founding admin beyond the creator must have
  // an established bidirectional VRC with the creator. The creator is
  // the first admin in the list (adminIdentityUuids[0]).
  if (n > 1) {
    const creator = admins[0];
    const missingVrcNames: string[] = [];
    for (let i = 1; i < admins.length; i++) {
      const hasVrc = await relationshipsRepo.hasEstablishedVrcBetween(
        db,
        creator.uuid,
        admins[i].uuid,
      );
      if (!hasVrc) {
        missingVrcNames.push(admins[i].name ?? `uuid=${admins[i].uuid}`);
      }
    }
    if (missingVrcNames.length > 0) {
      throw new CreateVtcValidationError(
        `Cannot invite admin(s) without an established VRC: ${missingVrcNames.join(', ')}. ` +
        `Each founding admin must have a bidirectional, established relationship with the creator (${creator.name ?? 'uuid=' + creator.uuid}). ` +
        `Establish a VRC first via the Relationships page.`,
      );
    }
  }

  // A VTC may be founded by as few as one admin (a single-admin bootstrap is
  // allowed). Higher counts are encouraged — see the create UI's recommendation.
  if (kind === 'vtc') {
    if (n < 1) {
      throw new CreateVtcValidationError(
        `VTC requires at least 1 founding admin (got ${n}).`,
      );
    }
    // Enforce threshold <= admin count (M-of-N must be achievable).
    if (m > n) {
      throw new CreateVtcValidationError(
        `threshold (${m}) cannot exceed number of admins (${n})`,
      );
    }
    // Enforce minimum M-of-N governance: VTCs require threshold ≥ 1. A threshold
    // of 1 is allowed (a single admin may authorize actions); the founding-ADMIN
    // count is still required to be ≥ 2 (see the mutual-VRC check above).
    if (m < 1) {
      throw new CreateVtcValidationError(
        `VTC creation requires a threshold of at least 1 (requested: ${m} with ${n} admin(s)).`,
      );
    }
  }

  // Founding admins must have established mutual VRCs before the community
  // can be created — this is enforced in the VRC validation block above
  // (lines ~138–157). personhood verification (VRC ceremonies,
  // personhood_asserted memberships) happens within the community after
  // creation and is not a prerequisite for founding.

  if (input.parentCommunityUuid !== undefined) {
    const parent = await identitiesRepo.findByUuid(db, input.parentCommunityUuid);
    if (!parent) {
      throw new CreateVtcNotFoundError(`parent community identity ${input.parentCommunityUuid} not found`);
    }
    if (parent.role !== 'vtn') {
      throw new CreateVtcValidationError(
        `parent community identity ${input.parentCommunityUuid} is not a VTN (role=${parent.role})`,
      );
    }
  }

  // Credential type is a governance parameter set post-creation
  // via PATCH /communities/:id/governance, not part of the founding ceremony.

  // ── 1a. Generate a proper did:peer:4 for the VTC (Decision 2.6 — VTC-as-VTA) ──
  const didMethod = new DidPeer4Method();
  const vtcKeys = await didMethod.create();
  const communityDid = vtcKeys.did;

  const communityUuid = await identitiesRepo.create(db, {
    realDid: communityDid,
    role: kind as IdentityRole,
    subjectKind: 'organization',
    custody: 'local',
    name: input.name.trim(),
  });

  // 1b. Insert did_documents row with the VTC's DID document
  const community = await identitiesRepo.findByUuid(db, communityUuid);
  if (!community) throw new Error('createVtc: community identity not found after creation');
  const now = Math.floor(Date.now() / 1000);
  const docUuid = generateUuid();
  await db.run(
    `INSERT INTO did_documents
       (identity_uuid, did, method, document_json,
        is_primary, status, context_type, context_ref_uuid,
        uuid, recorded_by_node, created_at)
     VALUES (?, ?, 'peer4', ?, 1, 'active', NULL, NULL, ?, ?, ?)`,
    community.uuid, communityDid,
    JSON.stringify(vtcKeys.document),
    docUuid,
    (db as any).nodeId ?? null,
    now,
  );

  // 1c. Store the VTC's Ed25519 + X25519 keys. The Ed25519 secret key is
  // encrypted at rest (Model A custody) so the community can sign VICs/VMCs
  // after creation — mirroring the server-VTA path in
  // utility-server/src/node/vta.ts. X25519 is stored the same way for symmetry.
  const edEncrypted = await encryptSecretKey(vtcKeys.signingKeyPair.secretKey, COMMUNITY_KEY_PASSPHRASE);
  await keysRepo.createWithSecret(db, {
    identityUuid: community.uuid,
    didDocumentUuid: docUuid,
    keyType: 'ed25519',
    publicKey: vtcKeys.signingKeyPair.publicKey,
    encryptedSecretKey: edEncrypted.ciphertext,
    salt: edEncrypted.salt,
    nonce: edEncrypted.nonce,
    authTag: edEncrypted.authTag,
  });
  const xEncrypted = await encryptSecretKey(vtcKeys.agreementKeyPair.secretKey, COMMUNITY_KEY_PASSPHRASE);
  await keysRepo.createWithSecret(db, {
    identityUuid: community.uuid,
    didDocumentUuid: docUuid,
    keyType: 'x25519',
    publicKey: vtcKeys.agreementKeyPair.publicKey,
    encryptedSecretKey: xEncrypted.ciphertext,
    salt: xEncrypted.salt,
    nonce: xEncrypted.nonce,
    authTag: xEncrypted.authTag,
  });
  // ── 1d. Create a C-DID for credential issuance ──────────────────────
  // The community's primary DID is for identity/resolution. The C-DID is a
  // separate context-scoped did:peer:4 used as issuer in VMC/VWC credentials.
  const didManager = new DidManager(db);
  try {
    const cDid = await didManager.createCommunityDid(communityUuid);
    console.log(
      `[createVtc] C-DID created for community ${input.name.trim()}: ${cDid.did.slice(0, 32)}...`,
    );
  } catch (err) {
    console.warn(
      `[createVtc] C-DID creation failed (non-fatal):`,
      (err as Error)?.message ?? err,
    );
  }

  // ── 2. governance row ───────────────────────────────────────────────────
  // Governance holds the thresholds + (later) the VTC governance-doc digest. Policy
  // RULES are NOT stored here — they are atomic catalog templates applied through
  // `community_policy_bindings`, written just below by `seedDefaultBindings`.
  const governanceUuid = await governanceRepo.create(db, {
    communityIdentityUuid: community.uuid,
    adminThresholdM: m,
    adminThresholdN: n,
    parentCommunityUuid: input.parentCommunityUuid
      ? (await identitiesRepo.findByUuid(db, input.parentCommunityUuid))?.uuid ?? undefined
      : undefined,
  });

  // Tier 1 (catalog rule templates) + Tier 2 (per-community bindings): every
  // baseline rule applicable to this kind, plus one claim-type binding per declared
  // allowed claim type.
  await seedDefaultBindings(db, community.uuid, kind, {
    allowedClaimTypes: (input as { allowedClaimTypes?: string[] }).allowedClaimTypes ?? [],
  });

  // ── 3. founding_admin membership rows + their VMC credentials ────────
  // Each founding admin gets a community-issued VMC (vc_type='vmc') minted
  // through the CredentialFactory, referenced from the membership row's
  // `membership_credential_uuid`. The membership row is created `pending` and
  // only approved (→ 'active' + issued_at + credential uuid) after the mint,
  // because the baseline policy's `vmc-issue` rule is
  // `actor_is_admin AND NOT subject_is_active_member` and the active-member
  // fact is matched on the member-identity UUID — minting after activation
  // would be denied whenever the subject DID falls back to its UUID.
  // `communityDid` (declared with the VTC's did:peer:4 above) is used for both
  // issuerDid and governanceDid — they must match for the policy's
  // actor_is_admin check.
  const vtcVerificationMethod =
    vtcKeys.document.verificationMethod?.[0]?.id
    ?? `${communityDid}#key-1`;
  const foundingAdmins: MembershipRow[] = [];
  for (const admin of admins) {
    const membershipUuid = await membershipsRepo.create(db, {
      memberIdentityUuid: admin.uuid,
      communityIdentityUuid: community.uuid,
      role: 'founding_admin',
      status: 'pending',
    });
    const credentialUuid = await mintMembershipVmc(db, {
      community,
      communityDid,
      member: admin,
      membershipUuid,
      membershipRole: 'founding_admin',
      verificationMethod: vtcVerificationMethod,
      signerSecretKey: vtcKeys.signingKeyPair.secretKey,
    });
    await membershipsRepo.approve(db, membershipUuid, credentialUuid);
    try { await didManager.createMemberDid(admin.uuid, communityUuid); } catch (err) { console.warn("[createVtc] M-DID skipped for admin", admin.uuid, ":", (err as Error).message); }
    const membership = await membershipsRepo.findByUuid(db, membershipUuid);
    if (membership) foundingAdmins.push(membership);
  }

  // 4. status_lists row (revocation) with pre-flipped decoy indices
  const statusListUuid = await statusListsRepo.create(db, {
    communityIdentityUuid: community.uuid,
    purpose: 'revocation',
  });
  const statusList = await statusListsRepo.findByUuid(db, statusListUuid);
  if (!statusList) throw new Error('createVtc: status list not found after creation');
  for (const decoyIndex of RESERVED_DECOY_INDICES) {
    await statusListsRepo.flip(db, {
      statusListUuid: statusList.uuid,
      slotIndex: decoyIndex,
      value: 1,
      reason: 'reserved decoy — pre-flipped at mint',
    });
  }

  const finalIdentity = await identitiesRepo.findByUuid(db, communityUuid);
  const finalGovernance = await governanceRepo.findByUuid(db, governanceUuid);
  const finalStatusList = await statusListsRepo.findByUuid(db, statusListUuid);
  if (!finalIdentity || !finalGovernance || !finalStatusList) {
    throw new Error('createVtc: failed to read back created rows');
  }

  // ── Compute governance bootstrap status ────────────────────────────
  // Check if all admin pairs have VRCs (true crystallization).
  let allAdminsHaveVrcs = true;
  for (let i = 0; i < admins.length && allAdminsHaveVrcs; i++) {
    for (let j = i + 1; j < admins.length && allAdminsHaveVrcs; j++) {
      const hasVrc = await relationshipsRepo.hasEstablishedVrcBetween(
        db,
        admins[i].uuid,
        admins[j].uuid,
      );
      if (!hasVrc) allAdminsHaveVrcs = false;
    }
  }

  // VTCs require ≥2 admins + mutual VRCs between all pairs for full governance.
  // This status may be partial (not all admin pairs have VRCs).
  const isBootstrapping = !allAdminsHaveVrcs;
  const meetsMinimal = allAdminsHaveVrcs && n >= 2;

  let bootstrapMessage: string;
  if (isBootstrapping) {
    bootstrapMessage =
      `⚠️ Partial bootstrap: Not all admin pairs have established VRCs. ` +
      `The community requires mutual VRCs between all founding admins to crystallize. ` +
      `Establish missing VRCs via the Relationships page.`;
  } else {
    bootstrapMessage =
      `✅ This community meets minimal governance requirements: ${n} admins with mutual VRCs.`;
  }

  return {
    identity: finalIdentity,
    governance: finalGovernance,
    foundingAdmins,
    statusList: finalStatusList,
    governanceBootstrap: {
      meetsMinimalGovernance: meetsMinimal,
      isBootstrapping,
      message: bootstrapMessage,
    },
  };
}

export interface VtcListItem {
  identity: Identity;
  governance: GovernanceRow | null;
  activeMemberCount: number;
}

/** List every community (VTC + VTN) identity, enriched with governance + active member count. */
export async function listVtcs(db: DataSource): Promise<VtcListItem[]> {
  const vtcs = await identitiesRepo.findByRole(db, 'vtc');
  const vtns = await identitiesRepo.findByRole(db, 'vtn');
  const all = [...vtcs, ...vtns].sort((a, b) => (a.createdAt ?? 0) - (b.createdAt ?? 0));

  const result: VtcListItem[] = [];
  for (const identity of all) {
    const governance = await governanceRepo.findForCommunity(db, identity.uuid);
    const roster = await membershipsRepo.findForCommunity(db, identity.uuid);
    const activeMemberCount = roster.filter((m) => m.status === 'active').length;
    result.push({ identity, governance, activeMemberCount });
  }
  return result;
}

// ---------------------------------------------------------------------------
// Scenario 9 — VTNs & Nested Communities
// ---------------------------------------------------------------------------

export class AffiliateCycleError extends CreateVtcValidationError {}

/** ...
 * ...
 */
export async function affiliateVtc(
  db: DataSource,
  childVtcUuid: string,
  parentVtnUuid: string,
): Promise<{ child: Identity; childGovernance: GovernanceRow }> {
  const child = await identitiesRepo.findByUuid(db, childVtcUuid);
  if (!child) throw new CreateVtcNotFoundError(`VTC identity ${childVtcUuid} not found`);
  if (child.role !== 'vtc') throw new CreateVtcValidationError(`identity ${childVtcUuid} is not a VTC (role=${child.role})`);
  const parent = await identitiesRepo.findByUuid(db, parentVtnUuid);
  if (!parent) throw new CreateVtcNotFoundError(`VTN identity ${parentVtnUuid} not found`);
  if (parent.role !== 'vtn') throw new CreateVtcValidationError(`identity ${parentVtnUuid} is not a VTN (role=${parent.role})`);
  if (childVtcUuid === parentVtnUuid) throw new AffiliateCycleError('a community cannot be affiliated with itself');

  let cursor: string | null = parentVtnUuid;
  const seen = new Set<string>();
  while (cursor !== null) {
    if (seen.has(cursor)) break;
    seen.add(cursor);
    if (cursor === childVtcUuid) throw new AffiliateCycleError('affiliation would create a cycle');
    const gov = await governanceRepo.findForCommunity(db, cursor);
    cursor = gov?.parentCommunityUuid ?? null;
  }

  await governanceRepo.findOrCreateForCommunity(db, childVtcUuid);
  const updatedGovernance = await governanceRepo.update(db, childVtcUuid, { parentCommunityUuid: parentVtnUuid });
  if (!updatedGovernance) throw new Error('affiliateVtc: governance update failed');
  const finalChild = await identitiesRepo.findByUuid(db, childVtcUuid);
  if (!finalChild) throw new Error('affiliateVtc: child identity not found after update');
  return { child: finalChild, childGovernance: updatedGovernance };
}

/**
 * Unaffiliate a VTC from its parent VTN: clears
 * `governance.parent_community_id`. No cascading revocation of the VTC's
 * own previously-issued member VRCs — per Decision 2.8, the VTC simply
 * loses VTN-affiliate status going forward.
 */
export async function unaffiliateVtc(
  db: DataSource,
  childVtcUuid: string,
): Promise<{ child: Identity; childGovernance: GovernanceRow }> {
  const child = await identitiesRepo.findByUuid(db, childVtcUuid);
  if (!child) throw new CreateVtcNotFoundError(`VTC identity ${childVtcUuid} not found`);
  if (child.role !== 'vtc') throw new CreateVtcValidationError(`identity ${childVtcUuid} is not a VTC (role=${child.role})`);
  const governance = await governanceRepo.findForCommunity(db, childVtcUuid);
  if (!governance || governance.parentCommunityUuid === null) {
    throw new CreateVtcValidationError(`VTC ${childVtcUuid} is not currently affiliated with any VTN`);
  }
  const updatedGovernance = await governanceRepo.update(db, childVtcUuid, {
    parentCommunityUuid: null,
  });
  if (!updatedGovernance) throw new Error('unaffiliateVtc: governance update failed');
  const finalChild = await identitiesRepo.findByUuid(db, childVtcUuid);
  if (!finalChild) throw new Error('unaffiliateVtc: child identity not found after update');
  return { child: finalChild, childGovernance: updatedGovernance };
}

export interface VtnHierarchyChildVtc {
  identity: Identity;
  activeMemberCount: number;
}

export interface VtnHierarchyResult {
  vtn: Identity;
  governance: GovernanceRow | null;
  childVtcs: VtnHierarchyChildVtc[];
  directMemberships: MembershipRow[];
}

export async function getVtnHierarchy(db: DataSource, vtnUuid: string): Promise<VtnHierarchyResult> {
  const vtn = await identitiesRepo.findByUuid(db, vtnUuid);
  if (!vtn) throw new CreateVtcNotFoundError(`VTN identity ${vtnUuid} not found`);
  if (vtn.role !== 'vtn') throw new CreateVtcValidationError(`identity ${vtnUuid} is not a VTN (role=${vtn.role})`);

  const governance = await governanceRepo.findForCommunity(db, vtnUuid);

  const allVtcs = await identitiesRepo.findByRole(db, 'vtc');
  const childVtcs: VtnHierarchyChildVtc[] = [];
  const childMemberIdentityUuids = new Set<string>();
  for (const vtc of allVtcs) {
    const vtcGovernance = await governanceRepo.findForCommunity(db, vtc.uuid);
    if (vtcGovernance?.parentCommunityUuid !== vtnUuid) continue;
    const roster = await membershipsRepo.findForCommunity(db, vtc.uuid);
    const activeRoster = roster.filter((m) => m.status === 'active');
    activeRoster.forEach((m) => childMemberIdentityUuids.add(m.memberIdentityUuid));
    childVtcs.push({ identity: vtc, activeMemberCount: activeRoster.length });
  }

  const vtnRoster = await membershipsRepo.findForCommunity(db, vtn.uuid);
  const directMemberships = vtnRoster.filter(
    (m) => m.status === 'active' && !childMemberIdentityUuids.has(m.memberIdentityUuid),
  );

  return { vtn, governance, childVtcs, directMemberships };
}

export interface EffectivePolicyLevel {
  communityUuid: string;
  communityName: string | null;
  communityRole: IdentityRole;
  allowedClaimTypes: string[] | null;
  notes: string | null;
}

export interface EffectivePolicyResult {
  identityUuid: string;
  levels: EffectivePolicyLevel[];
  effectiveAllowedClaimTypes: string[] | null;
  notes: string[];
}

export async function resolveEffectivePolicy(
  db: DataSource,
  identityUuid: string,
): Promise<EffectivePolicyResult> {
  const identity = await identitiesRepo.findByUuid(db, identityUuid);
  if (!identity) throw new CreateVtcNotFoundError(`identity ${identityUuid} not found`);

  const allMemberships = await membershipsRepo.findForMember(db, identity.uuid);
  const memberships = allMemberships.filter((m) => m.status === 'active');

  const levels: EffectivePolicyLevel[] = [];
  const seenCommunityUuids = new Set<string>();

  const pushLevel = async (community: Identity) => {
    if (seenCommunityUuids.has(community.uuid)) return;
    seenCommunityUuids.add(community.uuid);
    // Allowed claim types are the community's `claim-type-allow` bindings. A
    // community that declares none has `null` (no restriction), preserving the
    // previous semantics where an absent `allowedClaimTypes` meant unrestricted.
    const types = await resolveCommunityClaimTypes(db, community.uuid);
    levels.push({
      communityUuid: community.uuid,
      communityName: community.name,
      communityRole: community.role,
      allowedClaimTypes: types.length > 0 ? types : null,
      notes: null,
    });
  };

  for (const membership of memberships) {
    const community = await identitiesRepo.findByUuid(db, membership.communityIdentityUuid);
    if (!community) continue;
    const communityGovernance = await governanceRepo.findForCommunity(db, community.uuid);

    if (community.role === 'vtc' && communityGovernance?.parentCommunityUuid) {
      const vtn = await identitiesRepo.findByUuid(db, communityGovernance.parentCommunityUuid);
      if (vtn) await pushLevel(vtn);
    }

    await pushLevel(community);
  }

  const restrictingLists = levels.map((l) => l.allowedClaimTypes).filter((l): l is string[] => l !== null);
  let effectiveAllowedClaimTypes: string[] | null = null;
  if (restrictingLists.length > 0) {
    effectiveAllowedClaimTypes = restrictingLists.reduce((acc, list) => acc.filter((x) => list.includes(x)));
  }

  const notes = levels.map((l) => l.notes).filter((n): n is string => !!n);

  return { identityUuid, levels, effectiveAllowedClaimTypes, notes };
}