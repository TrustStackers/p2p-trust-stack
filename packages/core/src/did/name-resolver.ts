// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Name resolver — resolves an agent name URI to a connectable peer target.
 *
 * Resolution chain:
 *   vta:<namespace>:<name>
 *     → Look up DID in name_registry (local DB or TSP name_resolve)
 *     → Resolve DID → DID document
 *     → Extract peerId + multiaddrs from service endpoints
 *     → Return PeerTarget { peerId, multiaddrs, did }
 */

import type { DatabaseSync } from 'node:sqlite';
import { parseNameUri, type NameUri } from './name-uri.js';
import type { DidDocument } from './types.js';

/** A resolved peer target: everything needed to establish a libp2p connection. */
export interface PeerTarget {
  peerId: string;
  multiaddrs: string[];
  did: string;
}

/**
 * Resolve a name URI to a peer target using a local `name_registry` table
 * and a DID resolver function. The DID resolver should be able to resolve
 * any DID string to a DidDocument (offline for did:peer:4/scidvh).
 */
export function resolveNameFromLocalDb(
  nameUri: string,
  db: DatabaseSync,
  resolveDid: (did: string) => DidDocument,
): PeerTarget | undefined {
  const parsed: NameUri = parseNameUri(nameUri);

  // 1. Look up DID in local name_registry cache
  const row = db.prepare(
    'SELECT did FROM name_registry WHERE namespace = ? AND name = ? AND revoked_at IS NULL'
  ).get(parsed.namespace, parsed.name) as { did: string } | undefined;

  if (!row) return undefined;

  // 2. Resolve DID → DID document
  const doc = resolveDid(row.did);

  // 3. Extract peer target from DID document service endpoints
  let target = extractPeerTarget(doc, row.did);

  // scid:vh resolvers reconstruct documents from the rotation log, whose
  // entries omit `service` (peerId/multiaddrs). Fall back to the persisted
  // did_documents JSON, which carries the live TSPTransport endpoint, so a
  // registered name still resolves to a connectable peer even when the
  // rotation-log entry lacks the service block.
  if (!target) {
    const docRow = db
      .prepare('SELECT document_json FROM did_documents WHERE did = ? AND is_primary = 1')
      .get(row.did) as { document_json: string } | undefined;
    if (docRow) {
      try {
        target = extractPeerTarget(JSON.parse(docRow.document_json) as DidDocument, row.did);
      } catch { /* malformed document — ignore; target stays undefined */ }
    }
  }

  return target;
}

/**
 * Extract a PeerTarget from a DID document's service endpoints.
 */
export function extractPeerTarget(doc: DidDocument, did: string): PeerTarget | undefined {
  // Match both 'libp2p' and 'TSPTransport' service types.
  // The did:scid:vh documents use 'TSPTransport' for TSP protocol endpoints.
  const svc = doc.service?.find(s => s.type === 'libp2p' || s.type === 'TSPTransport');
  if (!svc || typeof svc.serviceEndpoint === 'string') return undefined;

  const ep = svc.serviceEndpoint;
  return {
    peerId: ep.peerId,
    multiaddrs: ep.multiaddrs ?? [],
    did,
  };
}

/**
 * Resolve a name URI given an already-resolved DID and DID document.
 * Used when the DID comes from a TSP name_resolve response.
 */
export function resolveNameFromDid(
  nameUri: string,
  did: string,
  didDocument: DidDocument,
): PeerTarget | undefined {
  // Validate the name URI parses
  parseNameUri(nameUri);
  return extractPeerTarget(didDocument, did);
}