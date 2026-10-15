// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Operation proofs — audit **F-010**, ruling **R1**: signed operation documents on
 * **cross-node** operations only (the node's own admin surface keeps session authority).
 *
 * The finding: *"trust-establishing operations take their authority from the HMAC
 * transport credential rather than from a signed, addressed document"* — and
 * `F-009` is the same root. In this stack that means a peer's `tx_prepare` arrived
 * carrying no statement of *who* was asking or *what* they were asking for; the only
 * authority was that the transport delivered it.
 *
 * ## What a proof is
 *
 * ```ts
 * { actor, issuedAt, expiresAt, signature }
 * ```
 *
 * where `actor` is the actor's **CESR-encoded Ed25519 public key** — its TSP VID. That
 * choice carries real weight: the VID *is* the public key (D-6a/D-5b), so the
 * signature verifies **offline**, with no identity-store lookup and therefore no
 * dependency on the identity push having landed. It also makes the sender binding a
 * like-for-like comparison against the envelope's `vidSender`.
 *
 * The signature covers `operationDocumentPayload(...)` — a **canonical** string
 * defined in exactly one place, covering the actor, the transaction, the message id
 * and the operations themselves. A challenge string assembled separately at each end
 * is the standard way a scheme like this silently never verifies (the same lesson as
 * `admissionChallenge()` in F-001b).
 *
 * ## The F-031 discipline
 *
 * Four verdicts, kept apart, because "I cannot check" must never read as "forged":
 *
 *   verified      — the signature checks out over exactly this message
 *   invalid       — a definite failure: bad signature, tampered payload, wrong actor,
 *                   expired, or an actor that is not the transport sender
 *   indeterminate — the actor is not a key we can check against (e.g. a DID, which
 *                   needs resolution) — admitted, and logged
 *   absent        — no proof at all (pre-F-010 behaviour)
 *
 * Only `invalid` is refused, and only under `enforce`.
 *
 * ## Scope, deliberately narrow
 *
 * The gate applies to **`tx_prepare`** — the message that asks this node to act. A
 * `tx_commit`/`tx_abort` belongs to a transaction that was already authorised at
 * prepare, and refusing those mid-flight can strand a transaction that is half
 * committed. Refusal therefore happens at the decision point, exactly as the
 * credential verifier (F-003) refuses with a `no` vote rather than an exception.
 */

import { verifyEd25519 } from '../crypto/primitives.js';
import { cesrDecode } from '../crypto/cesr.js';
import { CESR_CODES } from '../crypto/codes.js';
import type { TxWireMessage } from './wire-protocol.js';

export const OPERATION_PROOF_POLICY_ENV = 'TSP_OPERATION_PROOF_POLICY';

/**
 *   off      — do not look at proofs (pre-F-010 behaviour, byte-for-byte)
 *   warn     — check, log the verdict, ALLOW regardless              (default)
 *   enforce  — check, log, and REFUSE a definitely-invalid or missing proof
 *
 * `warn` is the default for the same reason as the other three policies in this
 * codebase: every deployed peer predates the proof, and turning this on must be an
 * operator decision with a known prerequisite (every peer issuing proofs), not a
 * side effect of an upgrade.
 */
export type OperationProofPolicy = 'off' | 'warn' | 'enforce';

/** The proof a cross-node operation carries. */
export interface OperationProof {
  /** The actor's CESR-encoded Ed25519 public key (its TSP VID). Self-authenticating. */
  actor: string;
  /** Unix seconds. */
  issuedAt: number;
  /** Unix seconds — a proof is a statement about a moment, not forever. */
  expiresAt: number;
  /** base64url Ed25519 signature over `operationDocumentPayload(...)`. */
  signature: string;
}

export type OperationProofVerdict = 'verified' | 'invalid' | 'indeterminate' | 'absent';

export interface OperationProofOutcome {
  verdict: OperationProofVerdict;
  reason: string;
  actor?: string;
}

/**
 * Deterministic JSON: object keys sorted, `Uint8Array` as `{"$bytes":"<base64url>"}`,
 * `undefined` object members skipped, `undefined` array members as `null`.
 *
 * Determinism is the whole point — the signer and the verifier must agree byte for
 * byte, and `JSON.stringify` does not promise key order across callers that build
 * their objects differently.
 */
export function canonicalJson(value: unknown): string {
  const encode = (v: unknown): string => {
    if (v === null) return 'null';
    if (v === undefined) return 'null';
    if (typeof v === 'number') return Number.isFinite(v) ? String(v) : 'null';
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'string') return JSON.stringify(v);
    if (v instanceof Uint8Array) {
      return `{"$bytes":${JSON.stringify(Buffer.from(v).toString('base64url'))}}`;
    }
    if (Array.isArray(v)) return `[${v.map(encode).join(',')}]`;
    if (typeof v === 'object') {
      const entries = Object.entries(v as Record<string, unknown>)
        .filter(([, val]) => val !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      return `{${entries.map(([k, val]) => `${JSON.stringify(k)}:${encode(val)}`).join(',')}}`;
    }
    // functions/symbols/bigint: not representable on the wire.
    return 'null';
  };
  return encode(value);
}

/**
 * THE canonical bytes a proof signs. Defined once; every producer and verifier calls
 * this, so the two ends cannot drift.
 *
 * It covers the actor (no proof-swapping between identities), the `txId` and
 * `messageId` (no replay onto a different message — and with H7's dedup, a proof
 * cannot be reused across messages either), the message `kind`, and the operations
 * **including their params** (the actual content being authorised).
 */
export function operationDocumentPayload(input: {
  actor: string;
  txId: string;
  kind: string;
  messageId?: string;
  operations: unknown;
}): string {
  return canonicalJson({
    v: 1,
    actor: input.actor,
    txId: input.txId,
    kind: input.kind,
    messageId: input.messageId ?? null,
    operations: input.operations,
  });
}

/** Resolve the policy: explicit option → environment → `warn`. Unknown → `warn`. */
export function resolveOperationProofPolicy(
  raw: string | undefined = process.env[OPERATION_PROOF_POLICY_ENV],
): OperationProofPolicy {
  const v = (raw ?? '').trim().toLowerCase();
  if (v === 'off' || v === 'warn' || v === 'enforce') return v;
  if (v.length > 0) {
    console.warn(
      `[operation-proof] unrecognised ${OPERATION_PROOF_POLICY_ENV}="${raw}" — falling back to "warn"`,
    );
  }
  return 'warn';
}

/**
 * Produce a proof. Used by a producer (a peer about to send a `tx_prepare`) and by the
 * tests — the *same* payload function the verifier uses, so a change to the signed
 * shape cannot leave one end behind.
 */
export function signOperationProof(
  input: {
    actorVid: string;
    txId: string;
    kind: string;
    messageId?: string;
    operations: unknown;
    ttlSeconds?: number;
    issuedAt?: number;
  },
  sign: (message: Uint8Array, secretKey: Uint8Array) => Uint8Array,
  secretKey: Uint8Array,
): OperationProof {
  const issuedAt = input.issuedAt ?? Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + (input.ttlSeconds ?? 300);
  const payload = operationDocumentPayload({
    actor: input.actorVid,
    txId: input.txId,
    kind: input.kind,
    messageId: input.messageId,
    operations: input.operations,
  });
  const signature = sign(new TextEncoder().encode(payload), secretKey);
  return {
    actor: input.actorVid,
    issuedAt,
    expiresAt,
    signature: Buffer.from(signature).toString('base64url'),
  };
}

/** The actor's Ed25519 public key, or null when the actor is not a key we can check. */
function actorPublicKey(actor: string): Uint8Array | null {
  try {
    const { code, bytes } = cesrDecode(actor);
    if (code !== CESR_CODES.ED25519_PUBLIC_KEY) return null;
    return bytes;
  } catch {
    return null;
  }
}

/**
 * The local identity's proof signer, installed once at startup.
 *
 * Follows the established idiom in this codebase for a key that lives far from the
 * components that need it (`setOobiSignerFromKey` in `oobi-signer.ts`, the module-level
 * `setServerNodeInfo` in `tsp-bridge.ts`): *install once, use everywhere*. The
 * alternative — threading a signer through all ten-odd `new RemoteParticipant(...)`
 * sites — would have left the per-call transports (ceremony routes, name service,
 * exchange engine) silently proof-less, which is precisely the gap that makes an
 * `enforce` policy dangerous.
 *
 * Trade-off, stated: one local identity per process. That is already true of the other
 * module-level setters, and true of both runtimes.
 */
export interface OperationSigner {
  /** The sender's CESR-encoded Ed25519 public key (its TSP VID). */
  actorVid: string;
  secretKey: Uint8Array;
}

let localSigner: OperationSigner | undefined;

/** Install (or clear) the local operation signer. */
export function setLocalOperationSigner(signer: OperationSigner | undefined): void {
  localSigner = signer;
}

/** The installed signer, for the transport and for diagnostics/tests. */
export function getLocalOperationSigner(): OperationSigner | undefined {
  return localSigner;
}

/**
 * Does this message kind carry an operation that needs a proof?
 *
 * Only `tx_prepare` asks a peer to DO something. A commit/abort/inquiry belongs to a
 * transaction already authorised at prepare, and refusing one mid-flight can strand a
 * half-committed transaction — so the gate deliberately does not cover them.
 */
export function requiresOperationProof(kind: string): boolean {
  return kind === 'tx_prepare';
}

/**
 * Attach a proof to an outbound message, if we have a signer and the kind is gated.
 *
 * Pure: returns the message unchanged when there is nothing to do, and never overwrites
 * a proof the caller already supplied (a caller signing with its own key must win).
 */
export function attachOperationProof(
  msg: TxWireMessage,
  sign: (message: Uint8Array, secretKey: Uint8Array) => Uint8Array,
  signer: OperationSigner | undefined = getLocalOperationSigner(),
  now?: number,
): TxWireMessage {
  if (!signer) return msg;
  if (!requiresOperationProof(msg.kind)) return msg;
  if (msg.proof) return msg;

  return {
    ...msg,
    proof: signOperationProof(
      {
        actorVid: signer.actorVid,
        txId: msg.txId,
        kind: msg.kind,
        messageId: msg.messageId,
        operations: (msg as { operations?: unknown }).operations,
        issuedAt: now,
      },
      sign,
      signer.secretKey,
    ),
  };
}

/**
 * Classify the proof on an inbound operation message.
 *
 * `senderVid` is the transport sender's VID (the envelope's `vidSender`, which the
 * digest binds). When it is known, the actor must BE that sender — a proof from someone
 * else does not authorise this message. That is the anti-substitution check, the same
 * shape as the credential binding check (F-001/F-026).
 */
export function verifyOperationProof(
  msg: { kind: string; txId: string; messageId?: string; operations?: unknown; proof?: OperationProof },
  opts: { senderVid?: string; now?: number; clockSkewSeconds?: number } = {},
): OperationProofOutcome {
  const proof = msg.proof;

  if (!proof) {
    return {
      verdict: 'absent',
      reason: 'no operation proof supplied (the sender did not state who is asking)',
    };
  }
  if (!proof.actor || !proof.signature
      || !Number.isFinite(proof.issuedAt) || !Number.isFinite(proof.expiresAt)) {
    return { verdict: 'invalid', reason: 'the operation proof is malformed', actor: proof.actor };
  }

  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const skew = opts.clockSkewSeconds ?? 60;
  if (now - skew > proof.expiresAt) {
    return { verdict: 'invalid', reason: 'the operation proof has expired', actor: proof.actor };
  }
  if (proof.issuedAt - skew > now) {
    return { verdict: 'invalid', reason: 'the operation proof is not yet valid', actor: proof.actor };
  }

  let bindingIndeterminate = false;
  if (opts.senderVid !== undefined && opts.senderVid !== '' && proof.actor !== opts.senderVid) {
    // The sender binding is an anti-substitution check (the F-001/F-026 shape): the proof's
    // actor must BE the transport sender. It is only DECIDABLE when both sides are the same
    // kind of identifier — a CESR VID, i.e. a self-authenticating key.
    //
    // In this deployment the envelope's `vidSender` carries a DID (`did:scid:vh:…`) while the
    // proof's `actor` is a VID (`vta.tspVid` / the agent's `meta.vid`), so the previous plain
    // string comparison reported `invalid` on EVERY message — observed 2026-09-25 as
    // `[operation-proof] … invalid actor=DIdB25_WgIXu… but the message came from did:scid:vh:…`
    // on every prepare. `warn` (the default) masked it; `enforce` would have refused every
    // cross-node operation. A verdict that is wrong for 100% of traffic is not a check.
    //
    // F-031 discipline, applied to the binding as well as the signature: "cannot check" is
    // not "forged". A definite `invalid` requires comparable forms; when the transport
    // identifier is not a key we can compare against, the binding is `indeterminate` — the
    // signature itself is still verified below, so a forged signature is still refused under
    // `enforce`, but a correctly-signed proof is no longer called a substitution.
    if (actorPublicKey(proof.actor) && actorPublicKey(opts.senderVid)) {
      return {
        verdict: 'invalid',
        reason:
          `the proof names actor ${proof.actor.slice(0, 12)}… but the message came from ` +
          `${opts.senderVid.slice(0, 12)}…`,
        actor: proof.actor,
      };
    }
    // NOT an early return: the signature must still be verified. Returning here would let a
    // FORGED signature pass as `indeterminate` (allowed under `enforce`) whenever the sender
    // identifier is a DID — relaxing the binding must not relax the signature. The binding
    // concern is carried to the end and only downgrades a *verified* proof.
    bindingIndeterminate = true;
  }

  const publicKey = actorPublicKey(proof.actor);
  if (!publicKey) {
    // F-031 discipline: "cannot check" is not "forged". A DID-form actor would need
    // resolution, which this verifier deliberately does not depend on.
    return {
      verdict: 'indeterminate',
      reason: 'the actor is not a CESR Ed25519 key, so the proof could not be checked',
      actor: proof.actor,
    };
  }

  const payload = operationDocumentPayload({
    actor: proof.actor,
    txId: msg.txId,
    kind: msg.kind,
    messageId: msg.messageId,
    operations: msg.operations,
  });

  try {
    const ok = verifyEd25519(
      Buffer.from(proof.signature, 'base64url'),
      new TextEncoder().encode(payload),
      publicKey,
    );
    if (!ok) {
      return {
        verdict: 'invalid',
        reason: 'the signature does not verify over this operation document',
        actor: proof.actor,
      };
    }
  } catch (err) {
    return {
      verdict: 'invalid',
      reason: `the operation proof could not be verified: ${(err as Error)?.message ?? 'malformed signature'}`,
      actor: proof.actor,
    };
  }

  if (bindingIndeterminate) {
    return {
      verdict: 'indeterminate',
      reason:
        'the signature is valid, but the transport sender identifier ' +
        `(${(opts.senderVid ?? '').slice(0, 12)}…) is not a CESR key, so the actor could not be ` +
        'bound to it (a DID needs resolution, which this verifier deliberately does not depend on)',
      actor: proof.actor,
    };
  }

  return {
    verdict: 'verified',
    reason: 'the actor signed exactly this operation document',
    actor: proof.actor,
  };
}

/**
 * The refusal a runtime sends when `enforce` blocks an operation.
 *
 * Returns the protocol-correct **`no` vote** for `tx_prepare`, or `null` when the
 * operation may proceed. Extracted so the refusal shape is defined once for both
 * runtimes — and so it can be tested without standing up libp2p (the call sites are
 * then a single `if (refusal) return refusal` each).
 *
 * A `no` vote, never an exception: the coordinator sees a clean abort, which is the
 * same refusal semantics the credential verifier uses (F-003).
 */
export function proofRefusalResponse(
  msg: TxWireMessage,
  opts: { senderVid?: string; policy?: OperationProofPolicy; now?: number } = {},
): TxWireMessage | null {
  if (!requiresOperationProof(msg.kind)) return null;
  const gate = gateOperationProof(msg, opts);
  if (gate.allow) return null;
  return { kind: 'tx_prepare_result', txId: msg.txId, vote: 'no' };
}

/**
 * Apply the policy to a verdict — the gate both runtimes call.
 *
 * `allow: false` means the caller must REFUSE; `proofRefusalResponse()` turns that into
 * the protocol's answer for you.
 */
export function gateOperationProof(
  msg: TxWireMessage,
  opts: { senderVid?: string; policy?: OperationProofPolicy; now?: number } = {},
): { allow: boolean; verdict: OperationProofVerdict; reason: string } {
  const policy = opts.policy ?? resolveOperationProofPolicy();
  if (policy === 'off') {
    return { allow: true, verdict: 'absent', reason: 'proof checking disabled by policy' };
  }

  const outcome = verifyOperationProof(msg, opts);
  const allow =
    policy === 'enforce' ? (outcome.verdict !== 'invalid' && outcome.verdict !== 'absent') : true;

  const line =
    `[operation-proof] ${msg.kind} ${msg.txId.slice(0, 8)}: ${outcome.verdict}` +
    `${outcome.actor ? ` actor=${outcome.actor.slice(0, 12)}…` : ''} (policy=${policy}) — ${outcome.reason}`;
  if (allow) console.log(line); else console.warn(`REFUSED ${line}`);

  return { allow, verdict: outcome.verdict, reason: outcome.reason };
}
