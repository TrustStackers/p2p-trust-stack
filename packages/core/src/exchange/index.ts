/**
 * Computed Record Exchange (CRE) — public exports.
 * Design reference: docs/05_CRE-SystemDesign.md.
 */
export {
  ExchangeError,
} from './types.js';
export type {
  RecordSetName,
  RecordSetTarget,
  DeliveryType,
  ResyncPolicy,
  DisclosureGate,
  ExchangeHandlerKind,
  ExchangeIdentity,
  ExchangeRequest,
  ExchangeContext,
  RecordSetAcl,
  RecordSetOwnership,
  RecordSetDef,
  ExchangeErrorCode,
  ExchangeResult,
  ExchangeEvent,
  ExchangeEventType,
  ExchangePubsubTransport,
  ExchangeFanoutStore,
} from './types.js';

export {
  RECORD_SETS,
  getRecordSet,
  getMaterialize,
  registerMaterializer,
  catalogMetadataJson,
} from './catalog.js';
export { readWatermark, bumpWatermark } from './watermark.js';
export {
  ExchangeEngine,
  exchangePull,
  buildExchangeEvents,
  assertSafeProjection,
  FORBIDDEN_PROJECTION_KEYS,
  parsePeriodicMs,
  isPeriodicPolicy,
  getDriverDefs,
} from './engine.js';
export type { ExchangeEngineDeps, ExchangePullOptions } from './engine.js';
export { ExchangeQueryParticipant } from './participants/exchange-query-participant.js';
export { ExchangePubsubParticipant } from './participants/exchange-pubsub-participant.js';
