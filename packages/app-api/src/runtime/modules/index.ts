/**
 * Agent modules — barrel export.
 *
 * Each module encapsulates a coherent responsibility extracted from BaseAgent,
 * enabling independent testing and potential future extraction into separate packages.
 */

export { ConnectivityModule } from './connectivity.js';
export { NetworkDetectModule } from '@p2p-trust-stack/core/platform/network-detect.js';
export type { NetworkProfile, NetworkChangeEvent } from '@p2p-trust-stack/core/platform/network-detect.js';
export { buildDialableMultiaddrs, getLocalLanIps } from '@p2p-trust-stack/core/platform/network-detect.js';
export {
  deriveConnectivityStatus,
  describeConnectivityFailure,
  describeRelayHealth,
  expiringRelayConnections,
  hasRelayReservation,
  needsRefresh,
  readRelayHealth,
  relayHealthLabel,
} from '@p2p-trust-stack/core/transport/relay-health.js';
export type {
  ConnectivityInputs,
  ConnectivityLayer,
  ConnectivityStatus,
  RelayConnectionInfo,
  RelayHealthSnapshot,
} from '@p2p-trust-stack/core/transport/relay-health.js';
export { VtcApiModule } from './vtc-api.js';
