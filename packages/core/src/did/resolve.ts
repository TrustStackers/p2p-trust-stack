/**
 * did:peer:4 local resolution — Step 2.
 *
 * Resolves a long-form did:peer:4 DID string to its embedded DID document
 * entirely offline — no network call, no DHT.
 */

import { decodePeer4 } from './numalgo4.js';
import type { DidDocument } from './types.js';

/**
 * Resolve a long-form did:peer:4 DID string to its embedded DID document.
 *
 * The resolved document has its `id` field populated with the full long-form
 * DID string (per the DID Core spec — the resolved document should include
 * the DID as its `id`).
 *
 * Short-form-only DIDs (without the long-form suffix) cannot be resolved
 * offline and are out of scope for this phase.
 *
 * @throws if the DID string is not a valid long-form did:peer:4
 */
export function resolveDidPeer4(did: string): DidDocument {
  const { document } = decodePeer4(did);
  // Populate the id field with the full long-form DID
  return { ...document, id: did };
}
