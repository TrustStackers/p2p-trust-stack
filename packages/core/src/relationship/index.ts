// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Relationship module — Step 4.
 *
 * Public API:
 *   encodeOobi() / decodeOobi()  — OOBI encoding/decoding (task 4.1)
 *   RelationshipStore             — SQLite-backed relationship table (task 4.6)
 *   RelationshipManager           — stateful RFI/RFA orchestrator (tasks 4.2–4.5)
 *
 * Types:
 *   OobiPayload, RelationshipRecord, RelationshipDirection, RelationshipStatus, LocalIdentity
 */

export { encodeOobi, decodeOobi } from './oobi.js';
export { RelationshipStore } from './store.js';
export { RelationshipManager } from './manager.js';
export type {
  OobiPayload,
  RelationshipRecord,
  RelationshipDirection,
  RelationshipStatus,
  LocalIdentity,
} from './types.js';
