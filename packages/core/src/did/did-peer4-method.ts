// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * DidPeer4Method — concrete DidMethod implementation for did:peer:4 — Step 9, Task 9.2.
 *
 * A thin adapter wrapping the existing createDidPeer4()/resolveDidPeer4()/
 * verifyDidPeer4() free functions (Step 2) so they can be used behind the
 * DID-method-agnostic DidMethod interface. No behavior change vs. calling
 * the free functions directly.
 *
 * Reference: docs/cross-layer-integration-plan.md, Decision 2.1, Step 9.
 */

import { createDidPeer4 } from './create.js';
import { resolveDidPeer4 } from './resolve.js';
import { verifyDidPeer4 } from './verify.js';
import type { DidDocument, ServiceEndpoint } from './types.js';
import type { DidMethod, DidMethodCreateResult } from './did-method.js';

// ---------------------------------------------------------------------------
// DidPeer4Method
// ---------------------------------------------------------------------------

export class DidPeer4Method implements DidMethod {
  readonly methodName = 'did:peer:4';
  readonly supportsRotation = false;

  /** did:peer:4 does not embed alsoKnownAs in its self-certifying DID string. */
  readonly supportsAlsoKnownAs = false;

  /** did:peer:4 agents use VRC-based name claims. */
  getNameBindingType(): 'alsoKnownAs' | 'vrc' | 'none' {
    return 'vrc';
  }

  async create(transport?: ServiceEndpoint): Promise<DidMethodCreateResult> {
    const result = await createDidPeer4(transport);
    const document = this.resolve(result.did);
    return {
      did: result.did,
      document,
      signingKeyPair: result.signingKeyPair,
      agreementKeyPair: result.agreementKeyPair,
    };
  }

  resolve(did: string): DidDocument {
    return resolveDidPeer4(did);
  }

  async verify(did: string): Promise<boolean> {
    return verifyDidPeer4(did);
  }
}
