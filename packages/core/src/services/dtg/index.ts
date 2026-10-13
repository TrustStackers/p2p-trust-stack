/**
 * DTG Credential Adapters — barrel export.
 */
export { toDtgVmc, serializeVmc } from './dtg-vmc.js';
export type { VmcAdapterParams } from './dtg-vmc.js';

export { toDtgVwc, serializeVwc } from './dtg-vwc.js';
export type { VwcAdapterParams } from './dtg-vwc.js';

export { toDtgVic, serializeVic } from './dtg-vic.js';
export type { VicAdapterParams } from './dtg-vic.js';

export { toDtgVpc, serializeVpc } from './dtg-vpc.js';
export type { VpcAdapterParams } from './dtg-vpc.js';

export { toDtgVec, serializeVec } from './dtg-vec.js';
export type { VecAdapterParams } from './dtg-vec.js';

export { profileToJCard, buildRCard } from './rcard.js';

// F-002 — the v1.0 statement-profile switch and its digest encoding.
export {
  DTG_PROFILE_POLICY_ENV,
  DEFAULT_DTG_PROFILE_POLICY,
  STATEMENT_CREDENTIAL_TYPE,
  DTG_PREDICATE_ENDORSES,
  DTG_PREDICATE_WITNESSED,
  resolveDtgProfilePolicy,
  emitsDtgStatementProfile,
} from './profile-policy.js';
export type { DtgProfilePolicy, DtgStatement } from './profile-policy.js';

export {
  toSha256MultibaseMultihash,
  sha256MultibaseMultihash,
  fromSha256MultibaseMultihash,
  toDigestMultibase,
} from './digest-encoding.js';
