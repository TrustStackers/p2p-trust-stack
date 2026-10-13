/**
 * Name Service — shared-core API for name operations via the transaction
 * coordinator.
 *
 * Agent-side and server-side code use these functions instead of direct
 * TSP protocol messages (tspClient.request(NAME_RESOLVE), etc.).
 *
 * All operations route through the transaction coordinator subsystem to
 * ensure consistent delivery, connectivity pre-flight, and audit logging.
 */

import { RemoteParticipant } from '../participant.js';
import type { ParticipantTransport } from '../participant.js';
import type { TransactionManager } from '../manager.js';
import type { SpeculativeRotationResult } from '../../did/speculative-rotation.js';
import { AgentNameRegistrationParticipant } from '../participants/name-registration-participant.js';
import type { FinalizeRotationParams, RotationLogStore } from '../participants/name-registration-participant.js';
import { exchangePull } from '../../exchange/index.js';
import type { ExchangeIdentity } from '../../exchange/index.js';

// ---------------------------------------------------------------------------
// resolveNameViaCoordinator
// ---------------------------------------------------------------------------

export interface ResolveNameResult {
  found: boolean;
  did?: string;
  didDocument?: object;
  rCard?: object;
  profileUuid?: string;
}

/**
 * Resolve a name through the utility server's registry recordset
 * (`exchange:registry` — the catalog formalization of the legacy name_resolve
 * coordinator op). The recordset materializes name_registry → did_documents →
 * R-Card at send time under ACL role gate + N6 projection guard.
 *
 * @param manager   Agent's TransactionManager
 * @param transport TSP participant transport for reaching the utility server
 * @param serverPid The utility server's participant pid (e.g. 'server:us-1')
 * @param namespace The name namespace (e.g. 'vta')
 * @param name      The name to resolve
 */
export async function resolveNameViaCoordinator(
  manager: TransactionManager,
  transport: ParticipantTransport,
  serverPid: string,
  namespace: string,
  name: string,
  requestedKeys?: string[],
  requester?: ExchangeIdentity,
): Promise<ResolveNameResult> {
  const serverParticipant = new RemoteParticipant(serverPid, transport);
  manager.registerParticipant(serverParticipant);

  try {
    if (!requester) {
      throw new Error(
        'resolveNameViaCoordinator: requester identity is required for the exchange:registry ACL gate',
      );
    }
    // exchange:registry recordset pull (Phase 3 — unconditional since Phase C).
    const data = (await exchangePull({
      name: 'registry',
      req: { requester, filters: { namespace, name, requestedKeys } },
      peer: serverPid,
      transport,
    })) as ResolveNameResult[];
    return data[0] ?? { found: false };
  } finally {
    manager.unregisterParticipant(serverPid);
  }
}

// ---------------------------------------------------------------------------
// revokeNameViaCoordinator
// ---------------------------------------------------------------------------

export interface RevokeNameResult {
  success: boolean;
  reason?: string;
}

/**
 * Revoke a name through the utility server's NameRegistryParticipant.
 *
 * Uses the full two-phase commit lifecycle: prepare checks ownership and
 * marks revoked_at; commit finalises; abort rolls back.
 *
 * @param manager   Agent's TransactionManager
 * @param transport TSP participant transport for reaching the utility server
 * @param serverPid The utility server's participant pid (e.g. 'server:us-1')
 * @param namespace The name namespace
 * @param name      The name to revoke
 * @param did       The DID that owns the name
 * @param proof     Proof that the DID owns the name (currently alsoKnownAs)
 */
export async function revokeNameViaCoordinator(
  manager: TransactionManager,
  transport: ParticipantTransport,
  serverPid: string,
  namespace: string,
  name: string,
  did: string,
  proof: { type: 'alsoKnownAs'; didDocument?: object },
): Promise<RevokeNameResult> {
  const serverParticipant = new RemoteParticipant(serverPid, transport);

  const result = await manager.run(async (tx) => {
    tx.enlist(serverParticipant, [
      {
        op: 'name_revoke',
        params: {
          namespace,
          name,
          did,
          proof,
        },
      },
    ]);
  });

  if (result.outcome === 'committed') {
    return { success: true };
  }
  return {
    success: false,
    reason: 'Name revocation was rejected by the utility server.',
  };
}

// ---------------------------------------------------------------------------
// registerNameViaCoordinator
// ---------------------------------------------------------------------------

export interface RegisterNameResult {
  success: boolean;
  reason?: string;
}

export interface RegisterNameInput {
  /** The name to register. */
  name: string;
  /** The namespace for the name. */
  namespace: string;
  /** The agent's DID. */
  did: string;
  /** Speculative rotation params (computed by the caller). */
  speculative: SpeculativeRotationResult;
  /** The agent's app database (for name_registry cache). */
  appDb: import('../../db/data-source.js').DataSource;
  /** The transaction coordinator database. */
  txDb: import('../../db/data-source.js').DataSource;
  /** Rotation log store for finalizing the rotation entry. */
  rotationStore: RotationLogStore;
  /** Callback to update the agent's in-memory identity after finalization. */
  onFinalize: (params: FinalizeRotationParams) => Promise<void>;
  /**
   * Agent-local profile uuid the caller selected as this name's primary R-Card
   * profile (informational — the server resolves the canonical profile by
   * `primaryProfileLabel`).
   */
  profileUuid?: string;
  /**
   * Label of the primary R-Card profile to attach to this name. The server
   * links `name_registry.profile_uuid`/`profile_id` to the matching profile
   * row at registration-commit time, closing the race where the lossy
   * profile sync would otherwise be the only thing that ever sets it.
   */
  primaryProfileLabel?: string;
  /**
   * Workstream E.3: identity_push payload (new DID document + live public keys)
   * folded into the SAME transaction so the server's document, keys, and
   * name_registry row are atomic. Enlisted as a nested child transaction.
   */
  identityPushPayload?: Record<string, unknown>;
}

/**
 * Register a name through the transaction coordinator.
 *
 * This is the shared-core API for agent name registration. It:
 *   1. Creates a RemoteParticipant for the utility server's NameRegistryParticipant
 *   2. Creates an AgentNameRegistrationParticipant for local rotation finalization
 *   3. Runs the transaction through the coordinator
 *   4. Returns the outcome
 *
 * The speculative rotation entry is computed by the caller BEFORE calling
 * this function, so the caller controls the rotation parameters (keys, log, etc.).
 *
 * @param manager   Agent's TransactionManager
 * @param transport TSP participant transport for reaching the utility server
 * @param serverPid The utility server's participant pid (e.g. 'server:us-1')
 * @param input     Registration parameters including the speculative rotation
 */
export async function registerNameViaCoordinator(
  manager: TransactionManager,
  transport: ParticipantTransport,
  serverPid: string,
  input: RegisterNameInput,
): Promise<RegisterNameResult> {
  const serverParticipant = new RemoteParticipant(serverPid, transport);

  const localParticipant = new AgentNameRegistrationParticipant(
    input.appDb,
    input.txDb,
    input.rotationStore,
    input.onFinalize,
  );

  const result = await manager.run(async (tx) => {
    // Enlist the server participant: check availability + commit name
    tx.enlist(serverParticipant, [{
      op: 'name_register',
      params: {
        namespace: input.namespace,
        name: input.name,
        did: input.did,
        // Primary R-Card profile linkage (uuid is resolved server-side).
        profileUuid: input.profileUuid,
        primaryProfileLabel: input.primaryProfileLabel,
        // Include the DID document for backup storage on the server
        didDocument: input.speculative.didDocument,
      },
    }]);

    // Enlist the local participant: finalize rotation on commit
    tx.enlist(localParticipant, [{
      op: 'finalize_rotation',
      params: {
        rotationEntry: input.speculative.rotationEntry,
        didDocument: input.speculative.didDocument,
        name: input.name,
        namespace: input.namespace,
        did: input.did,
        rotationDigest: input.speculative.rotationEntry.digest,
      } as unknown as Record<string, unknown>,
    }]);

    // Record app-variable undo for UI state rollback
    tx.setVar('pendingName', input.speculative.nameUri, {
      type: 'setVar',
      name: 'pendingName',
      previousValue: null,
    });

    // Workstream E.3: run the identity push as a NESTED child transaction of the
    // same 2PC, so document + keys + name_registry are atomic on the server.
    // The wire op is the CRE `exchange:identity` push (ExchangePushParticipant
    // unwraps params.payload and applies via the shared identity-push logic).
    if (input.identityPushPayload) {
      await tx.run(async (sub) => {
        sub.enlist(serverParticipant, [{
          op: 'exchange:identity',
          params: { payload: input.identityPushPayload },
        }]);
      });
    }
  });

  if (result.outcome === 'committed') {
    return { success: true };
  }
  return {
    success: false,
    reason: 'Name registration could not be completed. The name may have been taken by another user.',
  };
}
