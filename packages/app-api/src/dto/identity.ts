// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Identity & lifecycle DTOs.
 *
 * The rule this file exists to enforce: **a method returns a DTO, never a database row.** Every interface
 * below lists its fields explicitly and has **no index signature** — a `[key: string]: unknown` escape hatch
 * is the tell that a raw row has leaked through, and `test/trust_app_api/surface.test.ts` fails if one appears
 * in this directory.
 *
 * Where the underlying service already returns a purpose-built result type (rather than a table row), the
 * DTO *aliases* it instead of re-declaring every field. Duplicating 30 fields would drift from the service
 * without adding safety. Each alias says so explicitly, and names the phase that will flatten it if needed.
 */
import type { AgentMeta } from '../runtime/types.js';
import type { Identity } from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import type { RecoveryState } from '../runtime/modules/recovery.js';
import type { IdentityLookupResultPayload } from '@p2p-trust-stack/core/tx/services/identity-service.js';

/** Non-secret agent metadata (the persisted, readable-without-unlock record). */
export interface AgentMetaDto {
  name: string;
  vid: string;
  did: string;
  createdAt: number;
  /** The DID method this agent was created with (`scid-vh` / `peer4`). */
  method: string;
  /** The agent's own data directory under P2PTS_HOME. */
  dataDir: string;
  bootstrapUrl?: string;
  /**
   * `human` | `ai_agent` | `object` | `organization`, resolved from the identity row.
   *
   * The runtime's `AgentMeta` does **not** carry this, yet the reference UI reads
   * `identity.meta.subjectKind` to pick its Human/AI icon — so that read has always been `undefined` and the
   * icon has always said "Human". The layer resolves the identity row anyway, so it fills this in and the
   * existing UI reads start working.
   */
  subjectKind?: string | null;
}

/** The identity row behind the active VTA — explicit fields, no row spread. */
export interface IdentityRowDto {
  uuid: string;
  role: string;
  subjectKind: string | null;
  custody: string;
  name: string | null;
  createdAt: number | null;
}

/**
 * The active identity, or `{ active: false }` when no VTA is unlocked.
 *
 * `identity` is null when the row could not be resolved (the profile page degrades rather than failing).
 */
export interface IdentityDto {
  active: boolean;
  name?: string;
  vid?: string;
  did?: string;
  multiaddrs?: string[];
  peerId?: string;
  meta?: AgentMetaDto;
  identity?: IdentityRowDto | null;
}

/** Result of signing an arbitrary message with the VTA's Ed25519 key. */
export interface SignResultDto {
  /** base64 signature. */
  signature: string;
}

/** Result of activating (unlocking + starting) a VTA. */
export interface ActivateResultDto {
  ok: true;
  agent: { name: string; vid: string; did: string };
}

/** Result of deactivating the active VTA. */
export interface DeactivateResultDto {
  ok: true;
}

/**
 * A newly created or imported VTA.
 *
 * Deliberately NOT `CreateVtaResult`: that type carries `Identity` and `DidDocumentRow`, which are row
 * shapes. Only the fields an API consumer needs cross this boundary.
 */
export interface CreatedIdentityDto {
  name: string;
  did: string;
  uuid: string;
  publicKeys: { ed25519: string; x25519: string };
}

/**
 * Recovery state as reported by the utility server.
 *
 * ALIAS, not a re-declaration: this is the runtime's purpose-built `RecoveryState`. It is the one P2 DTO
 * whose sub-arrays (`didDocuments`, `publicKeys`, `rotationLog`, `witnessAttestations`) still mirror table
 * columns; flattening it belongs with the credentials domain in P4. The alias keeps the public surface
 * stable until then.
 */
export type RecoveryStateDto = RecoveryState;

/**
 * Result of looking up another identity's public data.
 *
 * ALIAS: already a clean result payload from `src/tx/services/identity-service.ts`.
 */
export type IdentityLookupDto = IdentityLookupResultPayload;

/** The persisted metadata record, re-exported for callers that need the raw service type. */
export type { AgentMeta, Identity };

/**
 * One agent as listed by the registry.
 *
 * `id`, `subjectKind` and `custody` come from that agent's **own** database. (The reference endpoint used to
 * resolve them against the *active* agent's database, which could only ever be right for the active agent —
 * see the note in `domains/identity.ts`.)
 */
export interface AgentSummaryDto extends AgentMetaDto {
  id?: string;
  subjectKind?: string | null;
  custody?: string;
}
