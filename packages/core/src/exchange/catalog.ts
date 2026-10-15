// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * RecordSet catalog — the single source of truth for "what data moves, to whom,
 * and how". A static TS registry so `materialize` closures type-check; a JSON
 * metadata export is provided for observability.
 *
 * Phase 1 seeds every entry with full metadata. Materializers that live in
 * shared core (registry, recovery, rcard) are wired here; side-specific
 * materializers (identity on the agent, vtc-membership/governance/credential on
 * the server) are `not_wired` stubs overridable via registerMaterializer() in
 * later phases — keeping core free of agent/utility-server imports.
 */
import type { DataSource } from '../db/data-source.js';
import { didToUuid } from '../db/uuid-helpers.js';
import * as identitiesRepo from '../db/repositories/identities-repo.js';
import * as didDocumentsRepo from '../db/repositories/did-documents-repo.js';
import * as keysRepo from '../db/repositories/keys-repo.js';
import { REPLICATION_TOPIC } from '../transport/replication.js';
import type { ExchangeContext, RecordSetDef, RecordSetName } from './types.js';
import { ExchangeError } from './types.js';
import { logger } from '../util/logger.js';

/** Side-specific materializer overrides (agent/server wire their own later). */
const materializerOverrides = new Map<RecordSetName, RecordSetDef['materialize']>();

/** Register (or override) the materializer for a recordset (later phases). */
export function registerMaterializer(
  name: RecordSetName,
  fn: RecordSetDef['materialize'],
): void {
  materializerOverrides.set(name, fn);
}

function notWired(name: RecordSetName): Promise<never> {
  return Promise.reject(
    new ExchangeError(
      'not_wired',
      `recordset '${name}' materializer not wired yet (Phase 1 skeleton)`,
    ),
  );
}

// ── Core materializers (shared src/services — safe for both sides) ─────────

/** registry — the generalized name_resolve read (name_registry → did_documents → R-Card). */
async function materializeRegistry(db: DataSource, ctx: ExchangeContext): Promise<Record<string, unknown>[]> {
  const p = (ctx.filters ?? {}) as { namespace?: string; name?: string; requestedKeys?: string[] };
  if (!p.namespace || !p.name) {
    throw new ExchangeError('denied', 'registry requires filters.namespace and filters.name');
  }
  const row = await db.get<{ did: string; profile_uuid: string | null }>(
    'SELECT did, profile_uuid FROM name_registry WHERE namespace = ? AND name = ? AND revoked_at IS NULL',
    p.namespace,
    p.name,
  );
  if (!row) return [{ found: false }];

  let didDocument: object | undefined;
  try {
    const docRow = await db.get<{ document_json: string }>(
      'SELECT document_json FROM did_documents WHERE did = ? AND is_primary = 1',
      row.did,
    );
    if (docRow) {
      try { didDocument = JSON.parse(docRow.document_json); } catch { /* ignore */ }
    }
  } catch { /* table may not exist (tests, early setup) */ }

  let rCard: object | undefined;
  let resolvedProfileUuid: string | undefined;
  if (row.profile_uuid) {
    try {
      const { getProfileCard } = await import('../services/profiles.js');
      rCard = await getProfileCard(db, row.profile_uuid, p.requestedKeys ?? []);
      resolvedProfileUuid = row.profile_uuid;
    } catch { /* R-Card is best-effort */ }
  }

  return [{
    found: true,
    did: row.did,
    profileUuid: resolvedProfileUuid ?? row.profile_uuid ?? undefined,
    didDocument,
    rCard,
  }];
}

/** recovery — self-only full public state (assembleRecoveryState). */
async function materializeRecovery(db: DataSource, ctx: ExchangeContext): Promise<Record<string, unknown>[]> {
  const requester = ctx.requester;
  if (!requester?.realDid) {
    throw new ExchangeError('denied', 'recovery requires a requester identity');
  }
  // Self-only: derive the canonical identity uuid from the requester's real DID
  // server-side, so a caller can never pull another identity's recovery state by
  // passing a foreign uuid in the request.
  const identityUuid = didToUuid(requester.realDid);
  const { assembleRecoveryState } = await import('../services/recovery.js');
  const state = await assembleRecoveryState(db, identityUuid);
  if (!state) return [];
  return [{ found: true, did: requester.realDid, recoveryState: state }];
}

/**
 * identity-lookup — a general-DID public read (did → primary document + base64
 * public keys). The successor to the retired coordinator `identity_lookup`
 * participant (Phase G): standard-lookup mode only, so `filters.did` may be ANY
 * DID (requester's own or another agent's — peer discovery). Full self-only
 * recovery state stays on the `recovery` recordset.
 */
async function materializeIdentityLookup(db: DataSource, ctx: ExchangeContext): Promise<Record<string, unknown>[]> {
  const p = (ctx.filters ?? {}) as { did?: string };
  if (!p.did) {
    throw new ExchangeError('denied', 'identity-lookup requires filters.did');
  }
  const identity = await identitiesRepo.findByRealDid(db, p.did);
  if (!identity) return [{ found: false }];

  const primaryDoc = await didDocumentsRepo.findPrimaryForIdentity(db, identity.uuid);
  const publicKeyRows = (await keysRepo.findByIdentityUuid(db, identity.uuid))
    .filter((k) => k.encryptedSecretKey !== null && k.encryptedSecretKey !== undefined);

  return [{
    found: true,
    did: primaryDoc?.did,
    didDocument: primaryDoc?.documentJson ? JSON.parse(primaryDoc.documentJson) : null,
    publicKeys: {
      ed25519: publicKeyRows.find((k) => k.keyType === 'ed25519')?.publicKey
        ? Buffer.from(publicKeyRows.find((k) => k.keyType === 'ed25519')!.publicKey!).toString('base64') : '',
      x25519: publicKeyRows.find((k) => k.keyType === 'x25519')?.publicKey
        ? Buffer.from(publicKeyRows.find((k) => k.keyType === 'x25519')!.publicKey!).toString('base64') : '',
    },
  }];
}

/** rcard — the requester's canonical R-Card (default profile → getProfileCard). */
async function materializeRcard(db: DataSource, ctx: ExchangeContext): Promise<Record<string, unknown>[]> {
  const requester = ctx.requester;
  if (!requester?.realDid) {
    throw new ExchangeError('denied', 'rcard requires a requester identity');
  }
  // Canonical identity key derived from the real DID (self-only by construction).
  const identityUuid = didToUuid(requester.realDid);
  const profile = await db.get<{ uuid: string }>(
    'SELECT uuid FROM profiles WHERE identity_uuid = ? ORDER BY is_default DESC, uuid ASC LIMIT 1',
    identityUuid,
  );
  if (!profile) return [];
  const { getProfileCard } = await import('../services/profiles.js');
  const keys = (ctx.filters?.requestedKeys as string[] | undefined) ?? [];
  const card = await getProfileCard(db, profile.uuid, keys);

  // Phase 6 — policy-gated disclosure (step 4): drop claims outside the
  // effective allowedClaimTypes intersection (VTN∩VTC). resolveEffectivePolicy
  // returns the intersection; null means "no restriction" (allow all).
  let effectiveAllowed: string[] | null = null;
  try {
    const { resolveEffectivePolicy } = await import('../services/vtc.js');
    const effective = await resolveEffectivePolicy(db, identityUuid);
    effectiveAllowed = effective.effectiveAllowedClaimTypes ?? null;
  } catch (err) {
    // resolveEffectivePolicy is best-effort for disclosure gating — a db issue
    // must not break the pull; fall through with no extra restriction.
    logger.warn(`[exchange:rcard] policy filter unavailable: ${(err as Error)?.message ?? err}`);
  }
  let claims = card.claims;
  if (effectiveAllowed !== null) {
    const allowed = new Set(effectiveAllowed);
    claims = claims.filter((c) => c.key === 'name' || allowed.has(c.key));
  }

  return [{ ...card, claims }];
}
/** witness-endorsement — a DID's witnessed rotation attestations (pull + push-event). */
async function materializeWitnessEndorsement(db: DataSource, ctx: ExchangeContext): Promise<Record<string, unknown>[]> {
  // Self-only by default: a requester's accumulation of witnessed attestations.
  const requester = ctx.requester;
  const targetIdentityUuid = (ctx.filters?.witnessDidDocumentUuid as string | undefined)
    ?? (requester?.realDid ? didToUuid(requester.realDid) : undefined);
  if (!targetIdentityUuid) {
    throw new ExchangeError('denied', 'witness-endorsement requires a requester identity or filters.witnessDidDocumentUuid');
  }

  // Rotation log entries for the target identity (did_documents → rotation_log).
  const docs = await db.all<{ uuid: string }>(
    `SELECT dd.uuid FROM did_documents dd WHERE dd.identity_uuid = ? AND dd.is_primary = 1`,
    targetIdentityUuid,
  );
  const attestations: Record<string, unknown>[] = [];
  for (const doc of docs) {
    const { findForRotationLog } = await import('../db/repositories/rotation-repo.js');
    const logRows = await db.all<{ uuid: string }>(
      `SELECT uuid FROM rotation_log WHERE did_document_uuid = ? ORDER BY version ASC`,
      doc.uuid,
    );
    for (const log of logRows) {
      const rows = await findForRotationLog(db, log.uuid);
      for (const wa of rows) {
        const witnessDid = await db.get<{ did: string }>(
          `SELECT did FROM did_documents WHERE uuid = ?`, wa.witnessDidDocumentUuid,
        );
        attestations.push({
          uuid: wa.uuid,
          rotationLogUuid: wa.rotationLogUuid,
          witnessDidDocumentUuid: wa.witnessDidDocumentUuid,
          witnessDid: witnessDid?.did ?? null,
          signature: Buffer.from(wa.signature).toString('base64'),
          attestedAt: wa.attestedAt,
        });
      }
    }
  }
  return attestations;
}

// ── The catalog ────────────────────────────────────────────────────────────

export const RECORD_SETS: readonly RecordSetDef[] = [
  {
    name: 'identity',
    target: 'server',
    materialize: () => notWired('identity'),
    transport: { delivery: 'push-event', wireOp: 'exchange:identity', handler: 'ExchangePushParticipant' },
    acl: { roles: ['vta', 'server'], include: [], exclude: ['encrypted_secret_key', 'salt', 'nonce'] },
    // Phase D: the agent's periodic identity heartbeat. The explicit on-write
    // push (ExchangeEngine.push from pushIdentityToUtilityServer) remains the
    // primary path; the periodic driver re-materializes identity every 60s and
    // re-pushes ONLY when the payload changed (ack-gated) — so a self-healing
    // catch-up for any on-write push that was lost/aborted, plus liveness.
    resync: 'periodic(60000)',
    idempotencyKey: (r) => `identity:${String(r.identityUuid ?? r.uuid ?? '')}:${String(r.updatedAt ?? Date.now())}`,
    ownership: { localCustody: true, remoteCustody: true, recordedBy: 'agent-push' },
  },
  {
    name: 'rcard',
    target: 'server', // 'peer' later (Hybrid → P2P, Phase 7)
    materialize: materializeRcard,
    // No legacy wireOp: name_resolve was retired in Phase C — this IS the reader.
    transport: { delivery: 'pull', handler: 'ExchangeQueryParticipant' },
    acl: {
      roles: ['vta', 'server'],
      include: ['label', 'purpose', 'claims'],
      exclude: ['salt', 'commitment'],
      disclosureGate: 'discretionary',
      // Phase 6 (step 4): policy-gated disclosure is enforced inside the
      // materializer (materializeRcard drops claims outside the effective
      // allowedClaimTypes intersection via resolveEffectivePolicy).
    },
    resync: 'on-demand',
    idempotencyKey: (r) => `rcard:${String(r.profileUuid ?? '')}:${String(r.updatedAt ?? Date.now())}`,
    ownership: { localCustody: true, recordedBy: 'agent-push' },
  },
  {
    name: 'vtc-membership',
    target: 'peer',
    materialize: () => notWired('vtc-membership'),
    // Pull-capable (a member refreshes their communities on demand via
    // ExchangeQueryParticipant). The queue-row fan-out direction (server → agent)
    // uses wire op `exchange:vtc-membership` via the ExchangeEngine's
    // AgentDeliveryQueue fan-out store; `delivery` here describes the on-demand
    // read path. The driver treats it as on-connect (resync keyed on `resync`).
    transport: { delivery: 'pull', wireOp: 'exchange:vtc-membership', handler: 'ExchangeQueryParticipant' },
    acl: {
      roles: ['admin', 'member'],
      include: ['community', 'governance', 'memberships', 'identities'],
      exclude: [],
    },
    resync: 'on-connect',
    idempotencyKey: (r) => `vtc:${String(r.communityUuid ?? '')}:${String(r.updatedAt ?? Date.now())}`,
    ownership: { localCustody: true, remoteCustody: true, recordedBy: 'server' },
  },
  {
    name: 'governance',
    target: 'peer',
    materialize: () => notWired('governance'),
    // Pull-capable — ExchangeQueryParticipant serves `exchange:governance` on
    // demand (materializeGovernance). The queue-row side (policy change fan-out)
    // uses wire op `exchange:governance` via the ExchangeEngine fan-out store, so
    // governance state reaches offline members too.
    transport: { delivery: 'pull', wireOp: 'exchange:governance', handler: 'ExchangeQueryParticipant' },
    acl: { roles: ['admin', 'member'], include: ['thresholds', 'bindings'], exclude: [] },
    resync: 'on-connect',
    idempotencyKey: (r) => `governance:${String(r.communityUuid ?? '')}:${String(r.updatedAt ?? Date.now())}`,
    ownership: { localCustody: true, remoteCustody: true, recordedBy: 'server' },
  },
  {
    // Phase B — the governance-change-proposal fan-out. A proposal is IMMUTABLE (its
    // content is committed to by `proposal_hash`), so the delivery REF carries the
    // proposal itself and the materializer returns it verbatim — no snapshot-staleness
    // risk, and no cross-database read (the proposal lives in tx-coordinator.db while
    // this materializer receives the app DB). One durable row per required approver.
    name: 'governance-proposal',
    target: 'peer',
    materialize: () => notWired('governance-proposal'),
    transport: { delivery: 'pull', wireOp: 'exchange:governance-proposal', handler: 'ExchangeQueryParticipant' },
    acl: { roles: ['admin', 'member'], include: ['proposal'], exclude: [] },
    resync: 'on-demand',
    idempotencyKey: (r) => `govprop:${String(r.proposalId ?? '')}`,
    ownership: { localCustody: true, remoteCustody: true, recordedBy: 'server' },
  },
  {
    // Phase E — the first `utilities`-target recordset: a semantic broadcast of
    // governance (policy/VTN-knob) changes to other utility-server nodes via
    // pubsub (delivery: 'pubsub', topic = REPLICATION_TOPIC). materialize
    // returns ExchangeEvent rows (buildExchangeEvents), the ExchangePubsubParticipant
    // publishes them post-commit, and receivers dedup on eventUuid. Agents do
    // NOT subscribe to this topic — they keep the queue-row/pull governance path.
    name: 'governance-events',
    target: 'utilities',
    materialize: () => notWired('governance-events'),
    transport: {
      delivery: 'pubsub',
      topic: REPLICATION_TOPIC,
      handler: 'ExchangePubsubParticipant',
    },
    acl: { roles: ['server'], include: ['events'], exclude: [] },
    resync: 'on-demand',
    idempotencyKey: (r) => `gov-event:${String(r.eventUuid ?? '')}`,
    ownership: { localCustody: true, recordedBy: 'server' },
  },
  {
    // Ceremony PROGRESS — a lightweight nudge, not the log itself.
    //
    // The founding ceremony is driven server-side, and each admin's co-signature is recorded into the server's
    // `trust_tasks`. Nothing announced that, so an agent watching a founding could only discover a co-signer
    // had moved by asking — which is why `communities.html` polled `/api/ceremony-log` every 4 s.
    //
    // This set carries NO log content: the payload is `{ communityUuid, threadId, step }` and the page re-reads
    // its own endpoint for the shape it renders, exactly like the other push wire names. That keeps the durable
    // row small and avoids shipping a second copy of the log to every admin.
    //
    // `target: 'peer'` is what makes it a SERVER → AGENT push. (`governance-events` is the neighbouring name
    // and is NOT this: its target is `utilities`, a server↔server replication channel that agents do not
    // subscribe to.)
    name: 'ceremony-event',
    target: 'peer',
    materialize: () => notWired('ceremony-event'),
    transport: { delivery: 'pull', wireOp: 'exchange:ceremony-event', handler: 'ExchangeQueryParticipant' },
    acl: { roles: ['admin', 'member'], include: ['ceremony'], exclude: [] },
    resync: 'on-demand',
    // Versioned by the STEP, not just the thread: the queue table has UNIQUE(idempotency_key), so a
    // thread-only key would dedupe every step after the first and the nudge would silently never arrive
    // (the same trap as the governance-proposal progress nudge).
    idempotencyKey: (r) => `ceremony:${String(r.threadId ?? '')}:${String(r.step ?? '')}`,
    ownership: { localCustody: true, remoteCustody: true, recordedBy: 'server' },
  },
  {
    name: 'credential',
    target: 'peer',
    materialize: () => notWired('credential'),
    // Pull-capable — a holder refreshes their own credential wallet via
    // exchange:credential (requester-scoped, self-only like recovery/rcard). The
    // server→agent minted-delivery direction rides wire op `exchange:credential`
    // via the ExchangeEngine fan-out store (AgentDeliveryQueue).
    transport: { delivery: 'pull', wireOp: 'exchange:credential', handler: 'ExchangeQueryParticipant' },
    acl: { roles: ['vta'], include: ['credential'], exclude: [] },
    resync: 'on-connect',
    idempotencyKey: (r) => `credential:${String(r.credentialUuid ?? r.uuid ?? '')}`,
    ownership: { localCustody: true, remoteCustody: true, recordedBy: 'server' },
  },
  {
    name: 'registry',
    target: 'server',
    materialize: materializeRegistry,
    // No legacy wireOp: name_resolve was retired in Phase C — this IS the reader.
    transport: { delivery: 'pull', handler: 'ExchangeQueryParticipant' },
    acl: {
      roles: ['vta', 'server'],
      include: ['did', 'didDocument', 'rCard'],
      exclude: ['salt', 'commitment'],
      disclosureGate: 'discretionary',
    },
    resync: 'on-demand',
    idempotencyKey: (r) => `registry:${String(r.did ?? '')}:${String(r.profileUuid ?? '')}`,
    ownership: { localCustody: true },
  },
  {
    name: 'recovery',
    target: 'server',
    materialize: materializeRecovery,
    // No legacy wireOp: identity_lookup was retired in Phase G — this IS the reader.
    transport: { delivery: 'pull', handler: 'ExchangeQueryParticipant' },
    acl: { roles: ['vta'], include: ['recoveryState'], exclude: [] },
    resync: 'on-demand',
    idempotencyKey: (r) => `recovery:${String(r.did ?? '')}`,
    ownership: { localCustody: true },
  },
  {
    // Phase G — the general-DID public read that replaces the retired
    // coordinator `identity_lookup` participant. Pull-only, standard-lookup
    // mode (filters.did may be any DID); ACL-gated by role and N6-guarded like
    // every other read. Full self-only recovery state stays on `recovery`.
    name: 'identity-lookup',
    target: 'server',
    materialize: materializeIdentityLookup,
    transport: { delivery: 'pull', handler: 'ExchangeQueryParticipant' },
    acl: { roles: ['vta', 'server'], include: ['did', 'didDocument', 'publicKeys'], exclude: [] },
    resync: 'on-demand',
    idempotencyKey: (r) => `identity-lookup:${String(r.did ?? '')}`,
    ownership: { localCustody: true },
  },
  {
    name: 'witness-endorsement',
    target: 'peer',
    materialize: materializeWitnessEndorsement,
    transport: { delivery: 'pull', handler: 'ExchangeQueryParticipant' },
    acl: { roles: ['vta', 'server'], include: ['attestations'], exclude: [] },
    resync: 'on-demand',
    idempotencyKey: (r) => `witness:${String(r.uuid ?? '')}`,
    ownership: { localCustody: true, recordedBy: 'server' },
  },
];

export function getRecordSet(name: RecordSetName): RecordSetDef {
  const def = RECORD_SETS.find((d) => d.name === name);
  if (!def) throw new ExchangeError('not_found', `no recordset named '${name}'`);
  return def;
}

/** Resolve the effective materializer for a recordset (override-aware). */
export function getMaterialize(name: RecordSetName): RecordSetDef['materialize'] {
  return materializerOverrides.get(name) ?? getRecordSet(name).materialize;
}

/** JSON metadata export for observability (no closures — data only). */
export function catalogMetadataJson(): string {
  return JSON.stringify(
    RECORD_SETS.map((d) => ({
      name: d.name,
      target: d.target,
      delivery: d.transport.delivery,
      wireOp: d.transport.wireOp ?? null,
      topic: d.transport.topic ?? null,
      handler: d.transport.handler ?? null,
      roles: d.acl.roles,
      include: d.acl.include,
      exclude: d.acl.exclude,
      disclosureGate: d.acl.disclosureGate ?? null,
      resync: d.resync,
      localCustody: d.ownership.localCustody ?? false,
      remoteCustody: d.ownership.remoteCustody ?? false,
      recordedBy: d.ownership.recordedBy ?? null,
    })),
    null,
    2,
  );
}

