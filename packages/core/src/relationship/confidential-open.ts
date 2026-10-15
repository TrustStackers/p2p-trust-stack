// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Confidential (`TSP_GEN_CONFIDENTIAL`) open — the ONE implementation both
 * receivers use.
 *
 * ## Why this module exists
 *
 * A CESR HPKE-Base cipher carries **no KEM identifier**: `enc || ciphertext` is
 * a single opaque primitive, so the split between them is decided by whichever
 * KEM sealed the message — DHKEM(X25519) (enc = 32) or MLKEM768-X25519
 * (enc = 1120). The sender's rule is "hybrid iff the RECEIVER publishes
 * `#key-kem`", but a relationship record can be stale, so a receiver cannot
 * trust that rule as fact.
 *
 * The rule is therefore: try the expected split first, fall back to the other,
 * and let the AEAD decide — the authentication tag means **at most one attempt
 * can produce a valid plaintext**, so this is sound rather than guesswork.
 *
 * Two receivers need this rule: the agent's `RelationshipManager` (which owns
 * the relationship table) and the utility server's `tsp-bridge` (which has its
 * own store). They are independent implementations of one wire rule, which is
 * exactly the divergence that `handshake-verify.ts` was created to stop — hence
 * one module, parameterised by the receiver's key pairs rather than by any
 * particular store.
 */

import { tspOpen, encodeAad, TSP_HPKE_INFO, X25519_ENC_SIZE } from '../tsp/v3/message.js';
import type { Vid } from '../tsp/v3/types.js';
import { MLKEM768_X25519_ENC_BYTES } from '../crypto/pqc.js';
import { hpkeBaseOpen, importHpkeKeyPair } from '../crypto/primitives.js';
import { hpkeHybridOpen } from '../crypto/ml-kem-x25519.js';

/** Which KEM actually opened the message. */
export type ConfidentialKem = 'hybrid' | 'classical';

/** A successfully opened confidential payload. */
export interface ConfidentialOpenResult {
  plaintext: Uint8Array;
  used: ConfidentialKem;
  /**
   * True when `used` is not the KEM the caller's stored record implied — the
   * stored peer keys are stale. The plaintext is still authentic (the AEAD only
   * opens under the right key), so callers should accept it and log the drift.
   */
  mismatch: boolean;
}

export interface OpenConfidentialBodyParams {
  /** The whole sealed TSP message (needed to RE-OPEN with the matching split). */
  message: Uint8Array;
  /** The sender's Ed25519 public key, from the relationship record. */
  senderPublicKey: Uint8Array;
  /** Sender / receiver VID/DID from the signature-verified envelope (for the AAD). */
  vidSender: Vid;
  vidReceiver: Vid | null;
  /** This receiver's X25519 agreement pair (the classical path). */
  agreementKeyPair?: { publicKey: Uint8Array; secretKey: Uint8Array };
  /** This receiver's MLKEM768-X25519 pair (the hybrid path). */
  hybridKemKeyPair?: { publicKey: Uint8Array; secretKey: Uint8Array };
  /** Whether the caller's record says the sender publishes `#key-kem`. */
  expectHybrid: boolean;
}

/**
 * Open a confidential body, trying both KEM splits.
 *
 * @returns the plaintext plus which KEM opened it, or `undefined` when neither
 *          attempt authenticated (wrong key, corrupt frame, or not sealed to
 *          this identity). Callers must not treat `undefined` as retryable
 *          without their own evidence — the AEAD failing is conclusive.
 */
export async function openConfidentialBody(
  params: OpenConfidentialBodyParams,
): Promise<ConfidentialOpenResult | undefined> {
  const aad = encodeAad(params.vidSender, params.vidReceiver);

  const attempts: Array<{ hybrid: boolean; encSize: number }> = params.expectHybrid
    ? [{ hybrid: true, encSize: MLKEM768_X25519_ENC_BYTES },
       { hybrid: false, encSize: X25519_ENC_SIZE }]
    : [{ hybrid: false, encSize: X25519_ENC_SIZE },
       { hybrid: true, encSize: MLKEM768_X25519_ENC_BYTES }];

  for (const attempt of attempts) {
    try {
      const opened = tspOpen({
        message: params.message,
        senderPublicKey: params.senderPublicKey,
        hpkeEncSize: attempt.encSize,
      });
      if (opened.payload.type !== 'TSP_GEN_CONFIDENTIAL') continue;
      const { enc, ciphertext } = opened.payload;

      const plaintext = attempt.hybrid
        ? await openHybrid(enc, ciphertext, aad, params.hybridKemKeyPair)
        : await openClassical(enc, ciphertext, aad, params.agreementKeyPair);

      return {
        plaintext,
        used: attempt.hybrid ? 'hybrid' : 'classical',
        mismatch: attempt.hybrid !== params.expectHybrid,
      };
    } catch {
      // Wrong KEM/split (or wrong key) — try the other one.
    }
  }
  return undefined;
}

/** Open under the MLKEM768-X25519 hybrid KEM (enc = 1120 bytes). */
async function openHybrid(
  enc: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
  kp: { publicKey: Uint8Array; secretKey: Uint8Array } | undefined,
): Promise<Uint8Array> {
  if (!kp) throw new Error('openHybrid: this identity has no MLKEM768-X25519 key');
  // Both raw halves are needed: the KEM decapsulates ML-KEM with the secret key
  // and X25519 with the secret key, but the context also carries the public half.
  return hpkeHybridOpen(kp.secretKey, enc, ciphertext, TSP_HPKE_INFO, aad, kp.publicKey);
}

/** Open under the classical DHKEM(X25519) KEM (enc = 32 bytes). */
async function openClassical(
  enc: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
  kp: { publicKey: Uint8Array; secretKey: Uint8Array } | undefined,
): Promise<Uint8Array> {
  if (!kp) throw new Error('openClassical: this identity has no agreement key pair');
  const recipientHpkeKp = await importHpkeKeyPair(kp);
  return hpkeBaseOpen(recipientHpkeKp, enc, ciphertext, TSP_HPKE_INFO, aad);
}
