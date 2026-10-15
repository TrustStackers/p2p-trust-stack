// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Peer display-name resolution for the agent web UI.
 *
 * The chat UI identifies a peer by their **agent login name**; the DID stays the
 * machine key (API path parameters, relationship lookups) and is rendered as
 * secondary text so the cryptographic identity is still visible.
 *
 * ## Lookup order
 *
 *   1. `identities.name` — the peer's registered agent name, captured during the
 *      RFI/RFA handshake from the `vta:<namespace>:<name>` URIs in the peer's DID
 *      document `alsoKnownAs` (see `extractDisplayNameFromDocument` in
 *      src/relationship/key-extract.ts, called by RelationshipStore).
 *   2. `name_registry.name` — a name the operator has explicitly resolved
 *      locally (rendered as `name (namespace)`), plus its revoked_at guard.
 *   3. `null` — the caller falls back to displaying the DID, i.e. no regression
 *      for a peer that never registered a name.
 *
 * ## Why the Ed25519 key is the first lookup key
 *
 * An RFI/RFA handshake can leave more than one identity row for a single peer
 * (an ephemeral `did:peer:4` stub recorded by tsp-bridge, and the peer's real
 * VTA identity), and either row may be the one carrying the name. The shared
 * Ed25519 public-key bytes are the only reliable signal that two rows are the
 * same agent — the same rule `buildLocalCanonicalizationMap()` applies when it
 * labels the trust graph. The DID-keyed query is the fallback for a peer whose
 * key material has not been extracted into `keys` yet.
 *
 * The queries are intentionally tiny (single-row, index-assisted) because
 * `/api/relationships` is polled by the dashboard every 2 s.
 */

import type { DatabaseSync } from 'node:sqlite';
import { logger } from '@p2p-trust-stack/core/util/logger.js';

// ---------------------------------------------------------------------------
// SQL fragments
// ---------------------------------------------------------------------------

interface PeerNameRow {
  name: string | null;
  registered_name: string | null;
  namespace: string | null;
}

const NAME_SELECT = `
  SELECT
    i.name        AS name,
    nr.name       AS registered_name,
    nr.namespace  AS namespace
  FROM identities i
  LEFT JOIN keys k
    ON k.identity_uuid = i.uuid
   AND k.key_type = 'ed25519'
   AND k.rotation_version = 0
  LEFT JOIN name_registry nr
    ON nr.identity_uuid = i.uuid
   AND nr.revoked_at IS NULL
`;

/** Both name sources must actually be populated for a row to be usable. */
const NAME_PRESENT = `
  ((i.name IS NOT NULL AND i.name != '')
   OR (nr.name IS NOT NULL AND nr.name != ''))
`;

// NOTE: SQLite's hex() emits UPPERCASE hex while Node's Buffer.toString('hex')
// emits lowercase, so the comparison must be case-normalized on both sides —
// otherwise the key lookup silently matches nothing.
const BY_KEY_QUERY = `${NAME_SELECT} WHERE lower(hex(k.public_key)) = ? AND ${NAME_PRESENT} LIMIT 1`;

const BY_DID_QUERY = `
  ${NAME_SELECT}
  WHERE i.uuid = (
    SELECT i2.uuid FROM identities i2
    JOIN did_documents d ON d.identity_uuid = i2.uuid
    WHERE d.did = ?
    LIMIT 1
  )
  AND ${NAME_PRESENT}
  LIMIT 1
`;

// ---------------------------------------------------------------------------
// resolvePeerAgentName
// ---------------------------------------------------------------------------

/**
 * Resolve a remote peer's agent login name from the local database.
 *
 * @returns the login name, `name (namespace)` for a name known only through the
 *          local name registry, or `null` when the peer's name is unknown.
 */
export function resolvePeerAgentName(
  db: InstanceType<typeof DatabaseSync>,
  opts: { remoteDid: string; remoteEd25519Key?: Uint8Array | null },
): string | null {
  const remoteDid = typeof opts.remoteDid === 'string' ? opts.remoteDid.trim() : '';
  const key = opts.remoteEd25519Key;
  if (!remoteDid && !(key && key.length > 0)) return null;

  try {
    let row: PeerNameRow | undefined;
    if (key && key.length > 0) {
      row = db.prepare(BY_KEY_QUERY).get(Buffer.from(key).toString('hex').toLowerCase()) as PeerNameRow | undefined;
    }
    if (!row && remoteDid) {
      row = db.prepare(BY_DID_QUERY).get(remoteDid) as PeerNameRow | undefined;
    }
    if (!row) return null;

    const name = row.name?.trim();
    if (name) return name;
    const registered = row.registered_name?.trim();
    if (registered) return row.namespace ? `${registered} (${row.namespace})` : registered;
    return null;
  } catch (err: any) {
    // Never let a display-name lookup break the route that called it.
    logger.warn('[peer-name] resolvePeerAgentName failed:', err?.message ?? err);
    return null;
  }
}
