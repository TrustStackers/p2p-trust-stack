// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

// Crypto primitives
export type { Ed25519KeyPair, X25519KeyPair, HpkeKeyPair } from './primitives.js';
export {
  generateEd25519KeyPair,
  signEd25519,
  verifyEd25519,
  generateX25519KeyPair,
  ed25519ToX25519,
  sha256,
  blake2b256,
  hkdf,
  generateHpkeKeyPair,
  importHpkePublicKey,
  importHpkeKeyPair,
  hpkeAuthSeal,
  hpkeAuthOpen,
  hpkeBaseSeal,
  hpkeBaseOpen,
} from './primitives.js';

// CESR codec
export { cesrEncode, cesrDecode, cesrEncodeGroup, cesrDecodeGroup, CESR_CODES } from './cesr.js';
export type { CesrCode } from './cesr.js';

// Code table (for consumers that need the raw constants)
export { CESR_BYTE_LENGTHS } from './codes.js';

// CESR 2.0 framing helpers (TSP v3)
export {
  encodeNonce,
  decodeNonce,
  NONCE_BYTES,
  encodeEnvelopeTag,
  encodePayloadTag,
  decodeCounter,
  encodeHpkeBaseCipher,
  decodeHpkeBaseCipher,
} from './cesr-v2.js';
export type { CounterInfo } from './cesr-v2.js';

// Post-quantum primitives (TSP v3)
export {
  generateMlDsa65KeyPair,
  mlDsa65Sign,
  mlDsa65Verify,
  mlDsa65GetPublicKey,
  generateMlKem768X25519KeyPair,
  mlKem768X25519Encap,
  mlKem768X25519Decap,
  ML_DSA_65_SIG_BYTES,
  ML_DSA_65_SIGNATURE_CODE,
  MLKEM768_X25519_KEM_ID,
  MLKEM768_X25519_ENC_BYTES,
  MLKEM768_X25519_SS_BYTES,
  MLKEM768_X25519_PK_BYTES,
  MLKEM768_X25519_SK_BYTES,
} from './pqc.js';
export type { MlDsa65KeyPair, MlKem768X25519KeyPair } from './pqc.js';

// MLKEM768-X25519 hybrid KEM as an HPKE KemInterface
export { MlKem768X25519 } from './ml-kem-x25519.js';

// BIP-39 seed phrase (cross-device VTA key transfer)
export {
  BIP39_ENGLISH_WORDLIST,
  exportSeedPhrase,
  importSeedPhrase,
  validateMnemonic,
} from './seed-phrase.js';
export type { SeedPhraseResult } from './seed-phrase.js';
