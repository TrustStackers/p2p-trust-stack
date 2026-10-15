// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Agent Transaction Coordinator Bootstrap — initializes the transaction
 * coordination layer for an agent app.
 *
 * This module:
 *   1. Opens the dedicated tx-coordinator.db SQLite database
 *   2. Applies the schema
 *   3. Creates the TransactionLog, TransactionCoordinator,
 *      CompensationExecutor, and TransactionManager
 *   4. Registers the VtcReceiveParticipant + CredentialReceiveParticipant
 *   5. Starts the TTL janitor
 *   6. Recovers any interrupted transactions from the log
 *
 * Usage (in trust-app-api/runtime/base-agent.ts or similar):
 *   const tx = await bootstrapAgentTxCoordinator(appDb, { agentDid: '...' });
 *   // tx.manager is the TransactionManager
 *   // tx.coordinator is the TransactionCoordinator
 *   // tx.receiveParticipant is the VtcReceiveParticipant (communities)
 *   // tx.credentialReceiveParticipant is the CredentialReceiveParticipant (minted credentials)
 */

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { getVtaPaths } from '@p2p-trust-stack/core/platform/p2pts-home.js';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import {
  DataSourceLogSink,
  TransactionLog,
  TransactionCoordinator,
  CompensationExecutor,
  TransactionManager,
  TxJanitor,
  TX_SCHEMA_SQL,
  applyTxSchemaAdditions,
  ConnectionWatch,
  DurableOutbox,
  markServerEntriesDelivered,
  makePreparedPidResolver,
  createDedupedTxInbound,
} from '@p2p-trust-stack/core/tx/index.js';
import type { TxWireMessage, DedupedTxInboundResult } from '@p2p-trust-stack/core/tx/index.js';
import type { Transaction } from '@p2p-trust-stack/core/tx/index.js';
import type { WireSend } from '@p2p-trust-stack/core/tx/index.js';
import { VtcReceiveParticipant } from '@p2p-trust-stack/core/tx/vtc-receive-participant.js';
import type { PersistedCommunityEvent } from '@p2p-trust-stack/core/tx/vtc-receive-participant.js';
import { CredentialReceiveParticipant } from './credential-receive-participant.js';
import type { PersistedCredentialEvent } from './credential-receive-participant.js';
import { GovernanceProposalReceiveParticipant } from './governance-proposal-receive-participant.js';
import type { PersistedProposalEvent } from './governance-proposal-receive-participant.js';
import { CeremonyEventReceiveParticipant } from './ceremony-event-receive-participant.js';
import type { PersistedCeremonyEvent } from './ceremony-event-receive-participant.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';

export interface AgentTxBootstrapOptions {
  /** Agent VID for participant pid (e.g., 'peer:{vid}'). */
  agentDid: string;
  /**
   * Stable name of THIS agent (the registry key, e.g. `AGENT_NAME=alice`).
   *
   * Used to give the agent its OWN tx-coordinator database. Several agents
   * launched from the same working directory used to share
   * `data/tx/tx-coordinator.db`: they shared one transaction log, one
   * `tx_participant_state` and one `tx_outbox`, so one agent's reconnect drain
   * could deliver — and its blanket `sent → delivered` promotion could MARK
   * delivered — another agent's entries. Set this in production; omitted (tests,
   * single-agent tools) keeps the legacy shared path.
   */
  agentName?: string;
  /** Path to the tx-coordinator.db file (overrides `agentName`-derived default). */
  dbPath?: string;
  /**
   * Optional low-level send for the durable outbox. Encode the payload as a
   * protocol message and send via the active transport (RelationshipManager
   * TSP_GEN path). Returns true only when the next hop accepts the bytes.
   * When omitted, the outbox persists entries but never delivers (inert —
   * Phase 0 keeps the outbox dormant until Phase 2 wires real pushes).
   */
  send?: WireSend;
  /** Optional connection watch; created internally when omitted. */
  watch?: ConnectionWatch;
  /**
   * Called after a delivered credential is written to the agent's local `credentials` table.
   *
   * Threaded through to `CredentialReceiveParticipant`, which is the only component that observes a delivery.
   * Optional: with no callback the participant behaves exactly as before.
   */
  onCredentialPersisted?: (credential: PersistedCredentialEvent) => void;
  /**
   * Called after a delivered community record (or its governance) is written to the agent's local database.
   *
   * Threaded through to `VtcReceiveParticipant`, which is the only component that observes a community
   * arriving. Optional: with no callback the participant behaves exactly as before.
   */
  onCommunityPersisted?: (community: PersistedCommunityEvent) => void;
  /**
   * Called after a governance-change proposal is mirrored into the agent's local store.
   *
   * Threaded through to `GovernanceProposalReceiveParticipant`, which is the only component that observes a
   * proposal arriving. Optional: with no callback the participant behaves exactly as before.
   */
  onGovernanceProposalPersisted?: (proposal: PersistedProposalEvent) => void;
  /**
   * Called when the server nudges this agent that a ceremony step landed (a founding co-signature).
   *
   * Threaded through to `CeremonyEventReceiveParticipant`, which is the only component that observes ceremony
   * progress. Optional: with no callback the participant behaves exactly as before.
   */
  onCeremonyEventPersisted?: (event: PersistedCeremonyEvent) => void;
}

/**
 * Per-agent tx-coordinator database path:
 * `P2PTS_HOME/vta/<agentKey>/tx-coordinator.db`.
 *
 * The tx-coordinator DB lives INSIDE the agent's own VTA directory — alongside
 * its `p2pts-database.db` and `p2pts-keystore.db` — and NOT in the application
 * source tree (`agent-app/data/tx/…`, the old location). Each agent is fully
 * isolated on disk. The name is sanitized because the agent name comes from
 * `AGENT_NAME` and is used as a path segment.
 *
 * @param agentName  The agent's registry name (AGENT_NAME).
 * @param p2ptsHome  Optional P2PTS_HOME override.
 */
export function agentTxDbPath(agentName: string, p2ptsHome?: string): string {
  return getVtaPaths(agentName, p2ptsHome).txDbPath;
}

export interface AgentTxBootstrapResult {
  manager: TransactionManager;
  coordinator: TransactionCoordinator;
  compensation: CompensationExecutor;
  janitor: TxJanitor;
  receiveParticipant: VtcReceiveParticipant;
  /** Phase B — mirrors governance-change proposals pushed over exchange:governance-proposal. */
  governanceProposalReceiveParticipant: GovernanceProposalReceiveParticipant;
  /** Ceremony-progress nudge participant (persists nothing; exists so the op is claimed). */
  ceremonyEventReceiveParticipant: CeremonyEventReceiveParticipant;
  /** Credential receive participant (minted credential delivery, since Phase F). */
  credentialReceiveParticipant: CredentialReceiveParticipant;
  txDataSource: DataSource;
  /**
   * Inbound 2PC entry point, DEDUPED on `(txId, messageId)` (H7 / decision D-4a).
   *
   * Both runtimes must route inbound tx_* messages through this rather than calling
   * `coordinator.handleInboundTxMessage` directly: the coordinator's `recover()`
   * re-drive and the outbox's retry on reconnect both produce replays by design, and
   * the operations they carry (mint VRC, store_remote_vrc, exchange:identity) are not
   * idempotent in general — so a replay could double-apply.
   *
   * `duplicate: true` means the message was recognised and deliberately dropped: the
   * caller must treat it as HANDLED (so it does not fall through to an
   * "unrecognised message" path), not as unhandled.
   */
  handleInboundTxMessage: (msg: TxWireMessage) => Promise<DedupedTxInboundResult>;
  /** Durable outbox: persist-before-send with retry + reconnect drain. */
  outbox: DurableOutbox;
  /** Connection-state watch driving the outbox (fires drain on 'up'). */
  watch: ConnectionWatch;
  /** Shut down the transaction layer cleanly. */
  shutdown: () => Promise<void>;
}

export async function bootstrapAgentTxCoordinator(
  appDb: DataSource,
  options: AgentTxBootstrapOptions,
): Promise<AgentTxBootstrapResult> {
  // Every agent owns its tx-coordinator database inside its own VTA directory
  // (P2PTS_HOME/vta/<agentKey>/tx-coordinator.db). Callers without a name
  // (tests, single-agent tools) fall back to the `default` agent directory.
  const dbPath = options.dbPath
    ?? agentTxDbPath(options.agentName ?? 'default');

  // Open the dedicated SQLite database for the transaction coordinator
  const txDataSource = new SqliteDataSource(dbPath);

  // Apply schema
  await txDataSource.exec(TX_SCHEMA_SQL);
  // Existing databases keep their original tables (CREATE TABLE IF NOT EXISTS
  // never alters one), so columns added in later builds are applied here.
  const addedColumns = await applyTxSchemaAdditions(txDataSource);
  logger.info(`[agent-tx] tx-coordinator.db initialized at ${dbPath}`
    + (addedColumns.length > 0 ? ` (schema additions: ${addedColumns.join(', ')})` : ''));

  // Create the connection watch + durable outbox (persist-before-send).
  // The outbox drains undelivered entries whenever the watch flips to 'up'
  // (reconnect), so a message persisted while offline is never silently lost.
  const watch = options.watch ?? new ConnectionWatch();
  const outbox = new DurableOutbox(
    txDataSource,
    options.send ?? (async () => false),
    watch,
    { owner: options.agentName },
  );
  watch.subscribe((state) => {
    if (state === 'up') {
      outbox.drain()
        .then(() =>
          // A committed exchange: a push to a `server:` destination IS a durable
          // ack (the 2PC committed server-side), so promote sent -> delivered to
          // keep the drain from re-sending the same snapshot on the next
          // reconnect. Owner-scoped — see markServerEntriesDelivered().
          markServerEntriesDelivered(txDataSource, options.agentName ?? null),
        )
        .catch((err) =>
          logger.error('[agent-tx] outbox drain on reconnect error:', (err as Error)?.message ?? err),
        );
    }
  });

  // Create the log sink and transaction log
  const sink = new DataSourceLogSink(txDataSource);
  const log = new TransactionLog(sink);

  // Create the coordinator. The prepared-pid resolver lets a commit/abort/inquiry
  // that arrives after a restart reach the participant that actually prepared
  // (otherwise it falls through to the first registered participant).
  const coordinator = new TransactionCoordinator(log, {
    resolvePreparedPid: makePreparedPidResolver(txDataSource),
  });

  // Create the compensation executor
  const compensation = new CompensationExecutor();

  // Nested child transactions register a `_compensateChild` descriptor on their
  // PARENT (Transaction.run()); registering the handler here is what makes a
  // parent abort actually undo a already-committed child (e.g. the nested
  // `exchange:identity` child inside registerNameViaCoordinator). Without it the
  // executor logged `no CompensationHandler registered for type '_compensateChild'`
  // and the child's effects stood.
  compensation.register({
    type: '_compensateChild',
    async execute(desc) {
      const child = (desc as unknown as { child?: Transaction }).child;
      if (!child) return;
      await child.compensate();
    },
  });

  // Register a setVar compensation handler for UI state rollback
  compensation.register({
    type: 'setVar',
    async execute(desc) {
      // Application code registers the actual variable store.
      // This is a no-op handler that gets overridden by the app.
      logger.info(`[agent-tx] setVar undo: ${desc.name} → ${desc.previousValue}`);
    },
  });

  // Create the VTC receive participant
  const receiveParticipant = new VtcReceiveParticipant(
    `peer:${options.agentDid}`,
    appDb,
    txDataSource,
    options.onCommunityPersisted,
  );
  coordinator.registerParticipant(receiveParticipant);

  // Create the credential receive participant (Phase F — minted credential delivery).
  const credentialReceiveParticipant = new CredentialReceiveParticipant(
    `peer:${options.agentDid}`,
    appDb,
    txDataSource,
    undefined,
    undefined,
    undefined,
    options.onCredentialPersisted,
  );
  coordinator.registerParticipant(credentialReceiveParticipant);

  // Governance-change proposal receive participant (Phase B): mirrors proposals the
  // server fans out over exchange:governance-proposal so the Rules UI can show them.
  const governanceProposalReceiveParticipant = new GovernanceProposalReceiveParticipant(
    `peer:${options.agentDid}`,
    appDb,
    txDataSource,
    options.onGovernanceProposalPersisted,
  );
  coordinator.registerParticipant(governanceProposalReceiveParticipant);

  // Ceremony-progress nudge participant. It persists nothing (the nudge carries no content), but it MUST be
  // registered: the coordinator votes 'no' when no participant claims an operation, so without it the
  // server's nudge delivery would be refused outright.
  const ceremonyEventReceiveParticipant = new CeremonyEventReceiveParticipant(
    `peer:${options.agentDid}`,
    appDb,
    txDataSource,
    options.onCeremonyEventPersisted,
  );
  coordinator.registerParticipant(ceremonyEventReceiveParticipant);

  // Create the transaction manager
  const manager = new TransactionManager(coordinator, compensation);

  // Start the TTL janitor
  const janitor = new TxJanitor(txDataSource);
  janitor.start();

  // Recover any interrupted transactions from the log
  try {
    const recovered = await coordinator.recover();
    if (recovered.length > 0) {
      logger.info(`[agent-tx] recovered ${recovered.length} interrupted transaction(s):`,
        recovered.map((r) => `${r.txId}=${r.outcome}`).join(', '));
    }
  } catch (err) {
    logger.error('[agent-tx] recovery error:', (err as Error)?.message ?? err);
  }

  // Subscribe to status events for logging
  manager.onStatus((event) => {
    logger.info(`[agent-tx ${event.txId.slice(0, 8)}] ${event.state}${event.detail ? `: ${event.detail}` : ''}`);
  });

  logger.info(`[agent-tx] transaction coordinator ready (agentDid=${options.agentDid.slice(0, 12)}...)`);

  return {
    manager,
    coordinator,
    compensation,
    janitor,
    receiveParticipant,
    governanceProposalReceiveParticipant,
    ceremonyEventReceiveParticipant,
    credentialReceiveParticipant,
    txDataSource,
    // H7 wiring: the ONE inbound 2PC entry point, deduped on (txId, messageId).
    // The handler is the coordinator's own inbound method, so behaviour is identical
    // on a first delivery and nothing is re-applied on a replay.
    handleInboundTxMessage: createDedupedTxInbound(
      (msg) => coordinator.handleInboundTxMessage(msg),
      txDataSource,
    ),
    outbox,
    watch,
    shutdown: async () => {
      janitor.stop();
      await txDataSource.close();
      logger.info('[agent-tx] transaction coordinator shut down');
    },
  };
}