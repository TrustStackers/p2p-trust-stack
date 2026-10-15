// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * TSP v3 (Rev 3) message codec — public API.
 */

export { tspSeal, tspOpen, peekEnvelope, encodeAad, computeSaidDigest } from './message.js';
export type { PeekedEnvelope } from './message.js';
export type {
  Vid,
  TspPayload,
  TspGenPayload,
  TspRfiPayload,
  TspRfaPayload,
  TspRfdPayload,
  TspGenConfidentialPayload,
  TspEnvelope,
  TspSealParams,
  TspOpenParams,
} from './types.js';
