/**
 * Transaction Coordination Layer — Public Exports
 *
 * This module provides a standardized, durable, monitorable transaction layer
 * for all agent↔utility-server and agent↔agent TSP-based communication.
 *
 * Usage:
 *   import { TransactionManager, TransactionCoordinator, ... } from '../src/tx/index.js';
 *
 * See docs/tx-coordinator-usage.md for the pre-prompt / usage rules.
 * See docs/plan-tx-coordination-layer-implementation.md for the full plan.
 */

// Types
export type {
  ParticipantId,
  Operation,
  Vote,
  Outcome,
  TransactionState,
  UndoDescriptor,
  ExecutionResult,
  OperationExecutor,
  Participant,
  SendReceiptStatus,
  SendReceipt,
  OutboxState,
  OutboxEntry,
  ConnState,
  LayerReceipt,
  LogEntry,
  TransactionResult,
  Enlisted,
  StatusEvent,
  CompensationHandler,
  JanitorConfig,
} from './types.js';

export { DEFAULT_JANITOR_CONFIG } from './types.js';

// Schema
export { TX_SCHEMA_SQL, TX_ADDITIVE_COLUMNS, applyTxSchemaAdditions } from './schema.js';
export type { TxAdditiveColumn } from './schema.js';

// Log sink
export { DataSourceLogSink } from './tx-log-sink.js';
export type { LogSink } from './tx-log-sink.js';

// Transaction log
export { TransactionLog } from './tx-log.js';

// Ceremony store — Phase 3 governance ceremonies
export { CeremonyStore } from './ceremony-store.js';
export type {
  CeremonyProposal,
  CeremonyApproval,
  CreateProposalInput,
} from './ceremony-store.js';

// Ceremony coordinator — multi-admin VTC/VTN founding ceremonies
export { CeremonyCoordinator } from './ceremony-coordinator.js';
export type { InitiateProposalInput, CeremonyCoordinatorDeps } from './ceremony-coordinator.js';

// VRC ceremony saga store
export { VrcCeremonyStore } from './vrc-ceremony-store.js';
export type {
  VrcCeremonySession,
  VrcCeremonyPhase,
  VrcCeremonyStepResult,
} from './vrc-ceremony-store.js';

// Janitor
export { TxJanitor } from './janitor.js';

// Delivery (Layer 1)
export {
  ConnectionWatch,
  DurableOutbox,
  DurableInbox,
  Dispatcher,
  markServerEntriesDelivered,
} from './delivery.js';
export type { WireSend, InboxHandler } from './delivery.js';

// Compensation
export { CompensationExecutor } from './compensation.js';

// Wire Protocol
export {
  TX_PROTOCOLS,
  isTxProtocol,
  extractTxId,
  inboxKeyFor,
  inboxFingerprintFor,
} from './wire-protocol.js';

// Operation proofs (F-010 / ruling R1)
export {
  OPERATION_PROOF_POLICY_ENV,
  canonicalJson,
  operationDocumentPayload,
  resolveOperationProofPolicy,
  signOperationProof,
  verifyOperationProof,
  gateOperationProof,
  proofRefusalResponse,
  requiresOperationProof,
  attachOperationProof,
  setLocalOperationSigner,
  getLocalOperationSigner,
} from './operation-proof.js';
export type {
  OperationProof,
  OperationProofPolicy,
  OperationProofVerdict,
  OperationProofOutcome,
  OperationSigner,
} from './operation-proof.js';
export type {
  TxPrepareMessage,
  TxPrepareResultMessage,
  TxCommitMessage,
  TxCommitResultMessage,
  TxAbortMessage,
  TxAbortResultMessage,
  TxInquiryMessage,
  TxInquiryResultMessage,
  TxQueryMessage,
  TxQueryResultMessage,
  TxStatusMessage,
  TxWireMessage,
} from './wire-protocol.js';

// Participant
export {
  InProcessParticipant,
  RemoteParticipant,
} from './participant.js';
export type { ParticipantTransport } from './participant.js';

// Shared-core participants
export { AgentNameRegistrationParticipant } from './participants/name-registration-participant.js';
export type {
  FinalizeRotationParams,
  RotationLogStore,
} from './participants/name-registration-participant.js';

// Shared-core services
export {
  resolveNameViaCoordinator,
  revokeNameViaCoordinator,
  registerNameViaCoordinator,
} from './services/name-service.js';
export type {
  ResolveNameResult,
  RevokeNameResult,
  RegisterNameResult,
  RegisterNameInput,
} from './services/name-service.js';
export { lookupIdentityViaExchange } from './services/identity-service.js';
export type { IdentityLookupResultPayload } from './services/identity-service.js';

// Coordinator
export { TransactionCoordinator, makePreparedPidResolver } from './coordinator.js';
export type { BeginOptions, StatusListener } from './coordinator.js';

// Transaction
export { Transaction } from './transaction.js';
export type { TransactionOptions } from './transaction.js';

// Manager
export { TransactionManager } from './manager.js';

// TSP Participant Transport
export {
  TspParticipantTransport,
  createTxProtocolHandler,
  withInboundDedup,
  createDedupedTxInbound,
} from './tsp-participant-transport.js';
export type {
  TspRequestFn,
  TxInboundHandler,
  ConnectivityCheckFn,
  TspParticipantTransportOptions,
  DedupedTxInboundResult,
} from './tsp-participant-transport.js';