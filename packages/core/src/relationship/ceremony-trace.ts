/**
 * CeremonyTrace — focused tracing for the OOBI→RFI→RFA→bidirectional flow.
 * Emits concise, structured log lines marked [CEREMONY] so they stand out.
 *
 * Enable via env: CEREMONY_TRACE=1 node ...
 *
 * Read **per call**, not at import time: a module-level constant would freeze the flag when this
 * module is first loaded, so a process that hosts an embedder (or a test) could not turn tracing
 * on or off afterwards. The read is a cheap property lookup on an already-populated object.
 */
function isEnabled(): boolean {
  return process.env.CEREMONY_TRACE === '1' || process.env.CEREMONY_TRACE === 'true';
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