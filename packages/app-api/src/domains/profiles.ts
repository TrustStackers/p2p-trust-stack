/**
 * `profiles` domain — profile and claim CRUD, the shareable card, and sync status.
 *
 * Every mutation emits `profile.changed` on success. The projections below are the reason this domain is not a
 * pass-through: the runtime returns `ProfileRow` / `ProfileClaimRow`, which are **database rows** carrying
 * replication bookkeeping — and, for claims, the commitment `salt`. Only contract fields cross the boundary.
 */
import { requireAgent, type DomainContext } from './context.js';
import type {
  ProfileCardClaimDto,
  ProfileCardDto,
  ProfileClaimDto,
  ProfileDto,
  ProfileSyncStatusDto,
  RemovedDto,
} from '../dto/profiles.js';

export interface CreateProfileOpts {
  label: string;
  purpose?: string;
  visibility?: string;
}

export interface UpdateProfileOpts {
  label?: string;
  purpose?: string | null;
  visibility?: string;
  setDefault?: boolean;
}

export interface AddClaimOpts {
  profileUuid: string;
  claimKey: string;
  claimValue?: string | null;
  disclosure?: string;
}

export interface UpdateClaimOpts {
  claimValue?: string | null;
  disclosure?: string;
}

export interface ProfilesApi {
  list(): Promise<ProfileDto[]>;
  create(input: CreateProfileOpts): Promise<ProfileDto>;
  update(uuid: string, input: UpdateProfileOpts): Promise<ProfileDto>;
  remove(uuid: string): Promise<RemovedDto>;
  claims(profileUuid: string): Promise<ProfileClaimDto[]>;
  addClaim(input: AddClaimOpts): Promise<ProfileClaimDto>;
  updateClaim(claimUuid: string, input: UpdateClaimOpts): Promise<ProfileClaimDto>;
  removeClaim(claimUuid: string): Promise<RemovedDto>;
  /** The disclosable view of a profile, optionally narrowed to specific claim keys. */
  card(profileUuid: string, requestedKeys?: string[]): Promise<ProfileCardDto>;
  /** Whether profile changes are still waiting to reach the utility server. */
  syncStatus(): Promise<ProfileSyncStatusDto>;
}

/** Project a `ProfileRow` onto the contract. */
function toProfileDto(row: {
  uuid: string;
  label: string;
  purpose: string | null;
  visibility: string;
  isDefault: boolean;
  createdAt: number | null;
  updatedAt: number | null;
}): ProfileDto {
  return {
    uuid: row.uuid,
    label: row.label,
    purpose: row.purpose,
    visibility: row.visibility,
    isDefault: row.isDefault,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

/** Project a `ProfileClaimRow` onto the contract — deliberately dropping `salt`. */
function toClaimDto(row: {
  uuid: string;
  profileUuid: string;
  claimKey: string;
  claimValue: string | null;
  valueType: string;
  disclosure: string;
  commitment: string | null;
  displayOrder: number;
}): ProfileClaimDto {
  return {
    uuid: row.uuid,
    profileUuid: row.profileUuid,
    claimKey: row.claimKey,
    claimValue: row.claimValue,
    valueType: row.valueType,
    disclosure: row.disclosure,
    commitment: row.commitment,
    displayOrder: row.displayOrder,
  };
}

/** Build the `profiles` domain. */
export function createProfilesApi(ctx: DomainContext): ProfilesApi {
  /** Announce a profile change, so a UI never has to re-poll to confirm its own write. */
  function announce(profileUuid: string): void {
    ctx.bus.emit('profile.changed', { profileUuid, at: Date.now() });
  }

  return {
    async list(): Promise<ProfileDto[]> {
      const agent = requireAgent(ctx, 'list profiles');
      return (await agent.listProfiles()).map(toProfileDto);
    },

    async create(input: CreateProfileOpts): Promise<ProfileDto> {
      const agent = requireAgent(ctx, 'create a profile');
      if (!input.label) throw new Error('label is required');
      const row = await agent.createProfile(input);
      announce(row.uuid);
      return toProfileDto(row);
    },

    async update(uuid: string, input: UpdateProfileOpts): Promise<ProfileDto> {
      const agent = requireAgent(ctx, 'update a profile');
      const row = await agent.updateProfile(uuid, input);
      announce(row.uuid);
      return toProfileDto(row);
    },

    async remove(uuid: string): Promise<RemovedDto> {
      const agent = requireAgent(ctx, 'remove a profile');
      await agent.removeProfile(uuid);
      announce(uuid);
      return { ok: true };
    },

    async claims(profileUuid: string): Promise<ProfileClaimDto[]> {
      const agent = requireAgent(ctx, 'list profile claims');
      return (await agent.listProfileClaims(profileUuid)).map(toClaimDto);
    },

    async addClaim(input: AddClaimOpts): Promise<ProfileClaimDto> {
      const agent = requireAgent(ctx, 'add a profile claim');
      const row = await agent.addProfileClaim(input);
      announce(input.profileUuid);
      return toClaimDto(row);
    },

    async updateClaim(claimUuid: string, input: UpdateClaimOpts): Promise<ProfileClaimDto> {
      const agent = requireAgent(ctx, 'update a profile claim');
      const row = await agent.updateProfileClaim(claimUuid, input);
      announce(row.profileUuid);
      return toClaimDto(row);
    },

    async removeClaim(claimUuid: string): Promise<RemovedDto> {
      const agent = requireAgent(ctx, 'remove a profile claim');
      await agent.removeProfileClaim(claimUuid);
      // The row is gone, so its profile uuid is unavailable afterwards — announce against the claim uuid.
      // A subscriber that needs the profile uuid can read it before deleting.
      announce(claimUuid);
      return { ok: true };
    },

    async card(profileUuid: string, requestedKeys: string[] = []): Promise<ProfileCardDto> {
      const agent = requireAgent(ctx, 'read a profile card');
      const card = await agent.getProfileCard(profileUuid, requestedKeys);
      const claims: ProfileCardClaimDto[] = card.claims.map((c) => ({
        key: c.key,
        value: c.value,
        valueType: c.valueType,
        disclosure: c.disclosure,
        ...(c.commitment !== undefined ? { commitment: c.commitment } : {}),
      }));
      return {
        profileUuid: card.profileUuid,
        identityUuid: card.identityUuid,
        label: card.label,
        purpose: card.purpose,
        visibility: card.visibility,
        claims,
      };
    },

    async syncStatus(): Promise<ProfileSyncStatusDto> {
      const agent = requireAgent(ctx, 'read profile sync status');
      return agent.getProfileSyncStatus
        ? agent.getProfileSyncStatus()
        : { pending: false, lastError: null };
    },
  };
}

