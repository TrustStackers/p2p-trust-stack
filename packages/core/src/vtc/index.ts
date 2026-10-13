/**
 * VTC module — barrel export — Step 10, Task 6.3.
 */

export { createVtc, issueVrc, verifyVrc, verifyVrcResolved, verifyGovernanceDoc } from './vtc.js';
export type { CreateVtcParams, IssueVrcParams } from './vtc.js';
export { VtcStore } from './store.js';
export {
  encodeVidList,
  decodeVidList,
  encodeSignatureList,
  decodeSignatureList,
  encodeGovernanceDoc,
  decodeGovernanceDoc,
  encodeVrc,
  decodeVrc,
  computeGovernanceDocDigest,
  computeVrcDigest,
} from './codec.js';
export type {
  Vrc,
  VrcSignature,
  VrcClaim,
  VtcGovernanceDoc,
  VtcIdentity,
  VrcVerifyResult,
} from './types.js';
