// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * did:peer:4 self-certification verification — Step 2.
 *
 * Verifies that a did:peer:4 DID string is self-consistent: recomputes the
 * hash component from the embedded long-form suffix and confirms it matches
 * the hash in the DID string.
 */

import { verifyPeer4Hash } from './numalgo4.js';

/**
 * Verify a did:peer:4 DID string.
 *
 * Recomputes the SHA-256 multihash of the long-form suffix and confirms it
 * matches the hash component embedded in the DID string. This is the
 * self-certifying check — any tampering with the document or the DID string
 * will cause this to return false.
 *
 * @returns true if the DID is self-consistent; false if tampered or malformed
 */
export async function verifyDidPeer4(did: string): Promise<boolean> {
  return verifyPeer4Hash(did);
}
