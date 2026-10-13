/**
 * Trust Tasks — the document-level bridge (P5).
 *
 * Two things live here:
 *
 *   - `type-uris.ts` — the action↔type-URI map and type-URI builder.
 *   - `envelope.ts` — the `{id, type, threadId, issuer, recipient, issuedAt, payload,
 *       proof}` builder/parser, with `#response` and error forms, and the
 *       "unauthenticated proof ⇒ indeterminate" rule.
 *   - `project.ts` — projections from our engine model to the `policy/_shared`
 *       `PolicyDecision` / `PolicyInput` shapes.
 *
 * The bridge is document-level only: it produces and consumes conformant JSON and
 * never imports the trusttasks.org runtime (docs/08 §2). Cryptographic verification
 * of `proof` remains the responsibility of `GovernanceGuard` — this module only
 * refuses to *silently ignore* a proof it cannot attribute (see `envelope.ts`).
 */

export * from './type-uris.js';
export * from './envelope.js';
export * from './project.js';
export * from './catalog.js';
export * from './driver.js';
export * from './authorizer.js';