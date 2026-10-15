// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Service: Profiles (Scenario 3 — "Manage Multiple Profiles").
 */

import type { DataSource } from '../db/data-source.js';
import { createHash, randomBytes } from 'node:crypto';

import * as profilesRepo from '../db/repositories/profiles-repo.js';
import type { ProfileVisibility } from '../db/repositories/profiles-repo.js';
import * as profileClaimsRepo from '../db/repositories/profile-claims-repo.js';
import type { ProfileClaimValueType, ProfileClaimDisclosure } from '../db/repositories/profile-claims-repo.js';
import * as identitiesRepo from '../db/repositories/identities-repo.js';
export type { ProfileRow, ProfileVisibility } from '../db/repositories/profiles-repo.js';

export class ProfileValidationError extends Error {}
export class ProfileNotFoundError extends Error {}

export function computeCommitment(claimValue: string, salt: string): string {
  return createHash('sha256').update(salt, 'utf8').update(claimValue, 'utf8').digest('hex');
}
export function generateSalt(): string {
  return randomBytes(16).toString('hex');
}
export function verifyCommitment(claimValue: string, salt: string, commitment: string): boolean {
  return computeCommitment(claimValue, salt) === commitment;
}

export interface CreateProfileInput { identityUuid: string; label: string; purpose?: string; visibility?: ProfileVisibility; }

export async function createProfile(db: DataSource, input: CreateProfileInput): Promise<profilesRepo.ProfileRow> {
  if (!input.identityUuid) throw new ProfileValidationError('identityUuid is required');
  if (!input.label || !input.label.trim()) throw new ProfileValidationError('label is required');
  const identity = await identitiesRepo.findByUuid(db, input.identityUuid);
  if (!identity) throw new ProfileNotFoundError(`identity ${input.identityUuid} not found`);
  const existingCount = await profilesRepo.countForIdentity(db, input.identityUuid);
  const isDefault = existingCount === 0;
  const uuid = await profilesRepo.create(db, { identityUuid: input.identityUuid, label: input.label.trim(), purpose: input.purpose, visibility: input.visibility, isDefault });
  return (await profilesRepo.findByUuid(db, uuid))!;
}

export async function listProfiles(db: DataSource, identityUuid: string): Promise<profilesRepo.ProfileRow[]> {
  return profilesRepo.findForIdentity(db, identityUuid);
}

export async function getProfile(db: DataSource, uuid: string): Promise<profilesRepo.ProfileRow> {
  const profile = await profilesRepo.findByUuid(db, uuid);
  if (!profile) throw new ProfileNotFoundError(`profile ${uuid} not found`);
  return profile;
}

export interface UpdateProfileInput { label?: string; purpose?: string | null; visibility?: ProfileVisibility; setDefault?: boolean; }

export async function updateProfile(db: DataSource, uuid: string, input: UpdateProfileInput): Promise<profilesRepo.ProfileRow> {
  const profile = await profilesRepo.findByUuid(db, uuid);
  if (!profile) throw new ProfileNotFoundError(`profile ${uuid} not found`);
  if (input.label !== undefined && !input.label.trim()) throw new ProfileValidationError('label cannot be empty');
  await profilesRepo.update(db, uuid, { label: input.label?.trim(), purpose: input.purpose, visibility: input.visibility });
  if (input.setDefault) await profilesRepo.setDefault(db, uuid, profile.identityUuid);
  return (await profilesRepo.findByUuid(db, uuid))!;
}

export async function removeProfile(db: DataSource, uuid: string): Promise<void> {
  const profile = await profilesRepo.findByUuid(db, uuid);
  if (!profile) throw new ProfileNotFoundError(`profile ${uuid} not found`);
  const siblings = await profilesRepo.findForIdentity(db, profile.identityUuid);
  if (siblings.length <= 1) throw new ProfileValidationError('cannot remove the last profile for an identity');
  await profilesRepo.remove(db, uuid);
  if (profile.isDefault) {
    const remaining = await profilesRepo.findForIdentity(db, profile.identityUuid);
    if (remaining.length > 0) await profilesRepo.setDefault(db, remaining[0].uuid, profile.identityUuid);
  }
}

export interface AddClaimInput { profileUuid: string; claimKey: string; claimValue?: string | null; valueType?: ProfileClaimValueType; disclosure?: ProfileClaimDisclosure; displayOrder?: number; }

export async function addClaim(db: DataSource, input: AddClaimInput): Promise<profileClaimsRepo.ProfileClaimRow> {
  if (!input.profileUuid) throw new ProfileValidationError('profileUuid is required');
  if (!input.claimKey || !input.claimKey.trim()) throw new ProfileValidationError('claimKey is required');
  const profile = await profilesRepo.findByUuid(db, input.profileUuid);
  if (!profile) throw new ProfileNotFoundError(`profile ${input.profileUuid} not found`);
  if (await profileClaimsRepo.findByKey(db, profile.uuid, input.claimKey.trim())) throw new ProfileValidationError(`claim "${input.claimKey}" already exists on profile ${input.profileUuid}`);
  const disclosure = input.disclosure ?? 'discretionary';
  let commitment: string | null = null;
  let salt: string | null = null;
  if (disclosure === 'zkp_only' && input.claimValue) { salt = generateSalt(); commitment = computeCommitment(input.claimValue, salt); }
  const claimUuid = await profileClaimsRepo.create(db, { profileUuid: profile.uuid, claimKey: input.claimKey.trim(), claimValue: input.claimValue ?? null, valueType: input.valueType, disclosure, commitment, salt, displayOrder: input.displayOrder });
  return (await profileClaimsRepo.findByUuid(db, claimUuid))!;
}

export async function listClaims(db: DataSource, profileUuid: string): Promise<profileClaimsRepo.ProfileClaimRow[]> {
  const profile = await profilesRepo.findByUuid(db, profileUuid);
  if (!profile) throw new ProfileNotFoundError(`profile ${profileUuid} not found`);
  return profileClaimsRepo.findForProfile(db, profile.uuid);
}

export interface UpdateClaimInput { claimValue?: string | null; valueType?: ProfileClaimValueType; disclosure?: ProfileClaimDisclosure; displayOrder?: number; }

export async function updateClaim(db: DataSource, claimUuid: string, input: UpdateClaimInput): Promise<profileClaimsRepo.ProfileClaimRow> {
  const claim = await profileClaimsRepo.findByUuid(db, claimUuid);
  if (!claim) throw new ProfileNotFoundError(`profile_claim ${claimUuid} not found`);
  const nextDisclosure = input.disclosure ?? claim.disclosure;
  const nextValue = input.claimValue !== undefined ? input.claimValue : claim.claimValue;
  let commitment: string | null | undefined = undefined;
  let salt: string | null | undefined = undefined;
  if (nextDisclosure === 'zkp_only' && nextValue) { salt = generateSalt(); commitment = computeCommitment(nextValue, salt); } else if (nextDisclosure !== 'zkp_only') { commitment = null; salt = null; }
  await profileClaimsRepo.update(db, claimUuid, { claimValue: input.claimValue, valueType: input.valueType, disclosure: input.disclosure, displayOrder: input.displayOrder, commitment, salt });
  return (await profileClaimsRepo.findByUuid(db, claimUuid))!;
}

export async function removeClaim(db: DataSource, claimUuid: string): Promise<void> {
  const claim = await profileClaimsRepo.findByUuid(db, claimUuid);
  if (!claim) throw new ProfileNotFoundError(`profile_claim ${claimUuid} not found`);
  await profileClaimsRepo.remove(db, claimUuid);
}

export interface ProfileCardClaim { key: string; value: string | null; valueType: ProfileClaimValueType; disclosure: ProfileClaimDisclosure; commitment?: string; }
export interface ProfileCard { profileUuid: string; identityUuid: string; label: string; purpose: string | null; visibility: ProfileVisibility; claims: ProfileCardClaim[]; }

export async function getProfileCard(db: DataSource, profileUuid: string, requestedKeys: string[] = []): Promise<ProfileCard> {
  const profile = await profilesRepo.findByUuid(db, profileUuid);
  if (!profile) throw new ProfileNotFoundError(`profile ${profileUuid} not found`);
  const requested = new Set(requestedKeys);
  const allClaims = await profileClaimsRepo.findForProfile(db, profile.uuid);
  const claims: ProfileCardClaim[] = [];
  for (const claim of allClaims) {
    if (claim.disclosure === 'never') continue;
    if (claim.disclosure === 'zkp_only') { claims.push({ key: claim.claimKey, value: null, valueType: claim.valueType, disclosure: claim.disclosure, commitment: claim.commitment ?? undefined }); continue; }
    if (claim.disclosure === 'discretionary' && !requested.has(claim.claimKey)) continue;
    claims.push({ key: claim.claimKey, value: claim.claimValue, valueType: claim.valueType, disclosure: claim.disclosure });
  }
  return { profileUuid: profile.uuid, identityUuid: profile.identityUuid, label: profile.label, purpose: profile.purpose, visibility: profile.visibility, claims };
}

// ── DTG RCard / JCard ──────────────────────────────────────────────────────
export { profileToJCard, buildRCard } from './dtg/rcard.js';