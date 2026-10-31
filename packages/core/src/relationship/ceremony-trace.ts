// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * CeremonyTrace — focused tracing for the OOBI→RFI→RFA→bidirectional flow.
 * Emits concise, structured log lines marked [CEREMONY] so they stand out.
 *
 * Enable via env: CEREMONY_TRACE=1 node ...
 *
 * Read **per call**, not at import time: a module-level constant would freeze the flag when this
 * module is first loaded, so a process that hosts an embedder (or a test) could not turn tracing
 * on or off afterwards. The read is a cheap property lookup on an already-populated object.
 *
 * ## Why there is also a setter
 *
 * The environment variable is not reachable everywhere this module runs. An app whose
 * `package.json` script cannot assign one (Windows), or that is launched by a native
 * host rather than npm (the Capacitor mobile build), has no way to set it — so the
 * flag is also settable programmatically and from a config file, via
 * {@link setCeremonyTrace} / `config/logging-env.ts`. Precedence mirrors the logger:
 *
 *   setCeremonyTrace() override  >  CEREMONY_TRACE env var  >  off
 *
 * Tracing stays independent of the log level on purpose: it is an opt-in diagnostic
 * that must not be silenced by `P2PTS_LOG_LEVEL=silent`, and not be switched on by
 * `P2PTS_LOG_LEVEL=debug`.
 */

/** The environment variable that turns tracing on when no override is set. */
export const CEREMONY_TRACE_ENV = 'CEREMONY_TRACE';

let overrideTrace: boolean | undefined;

/**
 * Turn tracing on/off for this process, or pass `undefined` to fall back to the
 * `CEREMONY_TRACE` environment variable.
 */
export function setCeremonyTrace(enabled: boolean | undefined): void {
  overrideTrace = enabled;
}

/** Whether a `[CEREMONY]` line would be emitted right now. */
export function isCeremonyTraceEnabled(): boolean {
  if (overrideTrace !== undefined) return overrideTrace;
  return process.env[CEREMONY_TRACE_ENV] === '1' || process.env[CEREMONY_TRACE_ENV] === 'true';
}

function isEnabled(): boolean {
  return isCeremonyTraceEnabled();
}

function short(v: string | undefined, len = 8): string {
  if (!v) return '?';
  return v.length > len ? v.slice(0, len) + '...' : v;
}

export const ceremonyTrace = {
  /** OOBI sent — agent initiated an RFI */
  rfiSent(params: { remoteDid: string; localDid: string }): void {
    if (!isEnabled()) return;
    console.log(`[CEREMONY] RFI SENT → remote=${short(params.remoteDid, 12)} local=${short(params.localDid, 20)}`);
  },

  /** RFI received — handleMessage dispatched to processRfi */
  rfiReceived(params: { vidSender: string; fromPeerId?: string }): void {
    if (!isEnabled()) return;
    console.log(`[CEREMONY] RFI RCVD ← sender=${short(params.vidSender, 12)} peer=${short(params.fromPeerId, 8)}`);
  },

  /** RFA received — the initiator got a response */
  rfaReceived(params: { vidSender: string; digestMatch: boolean }): void {
    if (!isEnabled()) return;
    console.log(`[CEREMONY] RFA RCVD ← sender=${short(params.vidSender, 12)} digest=${params.digestMatch ? 'OK' : 'MISMATCH'}`);
  },

  /** Identity resolved for relationship */
  identityResolved(params: { did: string; identityUuid?: string; newlyCreated: boolean }): void {
    if (!isEnabled()) return;
    console.log(`[CEREMONY] IDENTITY ${params.newlyCreated ? 'NEW' : 'FOUND'} did=${short(params.did, 20)} uuid=${params.identityUuid ?? '?'}`);
  },

  /** Relationship record upserted */
  relationshipUpdated(params: { localDid: string; remoteDid: string; direction: string; status: string }): void {
    if (!isEnabled()) return;
    console.log(`[CEREMONY] REL ${params.direction}/${params.status} local=${short(params.localDid, 20)} remote=${short(params.remoteDid, 12)}`);
  },

  /** Bidirectional complete — ceremony can proceed */
  bidirectional(params: { remoteDid: string }): void {
    if (!isEnabled()) return;
    console.log(`[CEREMONY] → BIDIRECTIONAL with ${short(params.remoteDid, 12)}`);
  },

  /** Flow error */
  error(step: string, detail: string): void {
    if (!isEnabled()) return;
    console.warn(`[CEREMONY] ERROR at ${step}: ${detail}`);
  },
};