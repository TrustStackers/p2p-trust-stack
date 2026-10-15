// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Profile & claim DTOs.
 *
 * These are written out explicitly rather than aliased from `ProfileRow` / `ProfileClaimRow`, because those
 * **are** database rows: they carry replication bookkeeping (`recordedByNode`, `replicatedAt`) that is not part
 * of the API contract, and `ProfileClaimRow` carries `salt` — the salt of a claim commitment, which must never
 * leave the agent. Omitting them here is the whole point of having DTOs.
 */
export type ProfileVisibilityDto = string;
export type ProfileClaimValueTypeDto = string;
export type ProfileClaimDisclosureDto = string;

/** A profile belonging to the active identity. */
export interface ProfileDto {
  uuid: string;
  label: string;
  purpose: string | null;
  visibility: ProfileVisibilityDto;
  isDefault: boolean;
  createdAt: number | null;
  updatedAt: number | null;
}

/** One claim on a profile. **No `salt`** — see the file header. */
export interface ProfileClaimDto {
  uuid: string;
  profileUuid: string;
  claimKey: string;
  claimValue: string | null;
  valueType: ProfileClaimValueTypeDto;
  disclosure: ProfileClaimDisclosureDto;
  /** Present when the claim is committed rather than disclosed. */
  commitment: string | null;
  displayOrder: number;
}

/** A claim as it appears on a shareable profile card. */
export interface ProfileCardClaimDto {
  key: string;
  value: string | null;
  valueType: ProfileClaimValueTypeDto;
  disclosure: ProfileClaimDisclosureDto;
  commitment?: string;
}

/** A profile card — the disclosable view of a profile. */
export interface ProfileCardDto {
  profileUuid: string;
  identityUuid: string;
  label: string;
  purpose: string | null;
  visibility: ProfileVisibilityDto;
  claims: ProfileCardClaimDto[];
}

/** Whether profile changes are waiting to reach the utility server. */
export interface ProfileSyncStatusDto {
  pending: boolean;
  lastError: string | null;
}

/** Result of a delete-style operation. */
export interface RemovedDto {
  ok: true;
}
