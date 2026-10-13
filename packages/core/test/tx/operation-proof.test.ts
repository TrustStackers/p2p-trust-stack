/**
 * F-010 / ruling R1 — signed operation documents on cross-node operations.
 *
 * The finding: trust-establishing operations took their authority from the **transport
 * credential** rather than from a signed, addressed document — a peer's `tx_prepare`
 * carried no statement of who was asking or what they were asking for.
 *
 * Four verdicts, kept apart (the F-031 discipline): `verified` / `invalid` /
 * `indeterminate` (the actor is not a key we can check — admitted) / `absent`. Only a
 * definite failure is refused, and only under `enforce`.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tx/operation-proof.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateEd25519KeyPair, signEd25519 } from '../../src/crypto/primitives.js';
import { cesrEncode } from '../../src/crypto/cesr.js';
import { CESR_CODES } from '../../src/crypto/codes.js';
import {
  canonicalJson,
  operationDocumentPayload,
  resolveOperationProofPolicy,
  signOperationProof,
  verifyOperationProof,
  gateOperationProof,
  attachOperationProof,
  setLocalOperationSigner,
  proofRefusalResponse,
  requiresOperationProof,
} from '../../src/tx/index.js';
import type { TxWireMessage } from '../../src/tx/index.js';

const kp = generateEd25519KeyPair();
const actorVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, kp.publicKey);

const OPERATIONS = [
  { op: 'name_register', params: { name: 'alice', meta: { z: 2, a: 1 } } },
];

function prepareWithProof(
  over: Partial<{ txId: string; messageId: string; operations: unknown; proof: unknown }> = {},
): TxWireMessage & { proof?: unknown } {
  const txId = over.txId ?? 'tx-proof-1';
  const messageId = over.messageId ?? 'msg-1';
  const operations = over.operations ?? OPERATIONS;
  const proof = over.proof === undefined
    ? signOperationProof({ actorVid, txId, kind: 'tx_prepare', messageId, operations }, signEd25519, kp.secretKey)
    : over.proof;
  return { kind: 'tx_prepare', txId, messageId, operations, proof } as unknown as TxWireMessage & { proof?: unknown };
}

test('PRODUCER → VERIFIER round trip: what the transport signs is what the gate verifies', () => {
  // The end-to-end claim of F-010: an outbound prepare signed by the transport is
  // accepted by the receiver's gate. This is the test that would have caught the classic
  // failure — a payload built differently at each end, so the signature never verifies.
  setLocalOperationSigner({ actorVid, secretKey: kp.secretKey });
  try {
    const outbound = attachOperationProof({ kind: 'tx_prepare', txId: 'tx-rt', messageId: 'm-rt', operations: OPERATIONS } as TxWireMessage, signEd25519);
    assert.ok(outbound.proof, 'the producer must attach a proof');

    // The receiver verifies with the sender's VID, as the runtime does.
    const outcome = verifyOperationProof(outbound, { senderVid: actorVid });
    assert.equal(outcome.verdict, 'verified', outcome.reason);

    // And `enforce` lets it through — the whole point of the producer half.
    assert.equal(gateOperationProof(outbound, { policy: 'enforce', senderVid: actorVid }).allow, true);
    assert.equal(proofRefusalResponse(outbound, { policy: 'enforce', senderVid: actorVid }), null);
  } finally {
    setLocalOperationSigner(undefined);
  }
});

test('attachOperationProof: no signer → nothing added; a caller-supplied proof wins; only gated kinds', () => {
  setLocalOperationSigner(undefined);
  const prepare = { kind: 'tx_prepare', txId: 'tx-1', messageId: 'm1', operations: OPERATIONS } as TxWireMessage;

  // No installed signer: unchanged (pre-F-010 behaviour, byte-for-byte).
  assert.equal(attachOperationProof(prepare, signEd25519).proof, undefined);

  // With a signer: gated kinds get a proof…
  setLocalOperationSigner({ actorVid, secretKey: kp.secretKey });
  assert.ok(attachOperationProof(prepare, signEd25519).proof);

  // …a caller's own proof is never overwritten…
  const own = { ...prepare, proof: { actor: 'Dcustom', issuedAt: 1, expiresAt: 2, signature: 'x' } } as TxWireMessage;
  assert.equal(attachOperationProof(own, signEd25519).proof!.actor, 'Dcustom');

  // …and non-gated kinds are left alone (commits must not grow a proof).
  const commit = { kind: 'tx_commit', txId: 'tx-1', messageId: 'm1' } as TxWireMessage;
  assert.equal(attachOperationProof(commit, signEd25519).proof, undefined);

  setLocalOperationSigner(undefined);
});

test('proofRefusalResponse: the runtimes\' refusal is a clean `no` vote, never an exception', () => {
  const base = prepareWithProof();
  const vid = actorVid;

  // A good proof, or a non-gated kind: nothing to refuse.
  assert.equal(proofRefusalResponse(base, { policy: 'enforce', senderVid: vid }), null);
  assert.equal(
    proofRefusalResponse({ kind: 'tx_commit', txId: 'tx-1' } as TxWireMessage, { policy: 'enforce' }),
    null,
    'a commit is never refused — it belongs to a transaction already authorised at prepare',
  );

  // A missing proof under enforce: the answer is the protocol's `no` vote.
  const refusal = proofRefusalResponse({ ...base, proof: undefined } as TxWireMessage, {
    policy: 'enforce',
    senderVid: vid,
  });
  assert.ok(refusal, 'enforce must produce a refusal');
  assert.equal(refusal!.kind, 'tx_prepare_result');
  assert.equal((refusal as { vote: string }).vote, 'no', 'a vote, not a thrown error');
  assert.equal(refusal!.txId, base.txId);

  // Under the default (warn) the same message proceeds.
  assert.equal(
    proofRefusalResponse({ ...base, proof: undefined } as TxWireMessage, { senderVid: vid }),
    null,
    'the default policy changes nothing',
  );
});

test('canonicalJson: deterministic regardless of key order (the signed bytes must not depend on construction)', () => {
  const a = canonicalJson({ b: 1, a: 2, nested: { y: 1, x: [3, { d: 4, c: 5 }] } });
  const b = canonicalJson({ nested: { x: [3, { c: 5, d: 4 }], y: 1 }, a: 2, b: 1 });
  assert.equal(a, b, 'key order must not change the signed bytes');
  assert.equal(a, '{"a":2,"b":1,"nested":{"x":[3,{"c":5,"d":4}],"y":1}}');

  // Binary params round-trip deterministically too.
  assert.equal(canonicalJson(new Uint8Array([1, 2, 3])), '{"$bytes":"AQID"}');
  assert.equal(canonicalJson({ u: undefined, v: 1 }), '{"v":1}', 'undefined members are skipped');
});

test('gateOperationProof: warn admits everything, enforce refuses only definite failures', () => {
  const base = prepareWithProof();

  // off — not even looked at.
  const off = gateOperationProof({ ...base, proof: undefined } as TxWireMessage, { policy: 'off', senderVid: actorVid });
  assert.equal(off.allow, true);
  assert.match(off.reason, /disabled by policy/);

  // warn — the default: report, allow.
  for (const msg of [base, { ...base, proof: undefined }, { ...base, operations: [] }]) {
    const g = gateOperationProof(msg as TxWireMessage, { policy: 'warn', senderVid: actorVid });
    assert.equal(g.allow, true, `warn must admit (verdict was ${g.verdict})`);
  }

  // enforce — a missing proof and an invalid one are refused; a good one is not.
  assert.equal(
    gateOperationProof({ ...base, proof: undefined } as TxWireMessage, { policy: 'enforce', senderVid: actorVid }).allow,
    false,
  );
  assert.equal(
    gateOperationProof({ ...base, operations: [] } as TxWireMessage, { policy: 'enforce', senderVid: actorVid }).allow,
    false,
  );
  assert.equal(gateOperationProof(base, { policy: 'enforce', senderVid: actorVid }).allow, true);

  // enforce + INDETERMINATE must still admit: refusing the uncheckable would reject
  // every peer whose actor this node cannot interpret.
  const indeterminate = prepareWithProof({
    proof: { actor: 'did:scid:vh:1:zSomeone', issuedAt: 1, expiresAt: 2_000_000_000, signature: 'AAAA' },
  });
  const g = gateOperationProof(indeterminate as TxWireMessage, { policy: 'enforce' });
  assert.equal(g.verdict, 'indeterminate');
  assert.equal(g.allow, true, 'enforce must not refuse the uncheckable');
});

test('the gate covers tx_prepare only (commits belong to an already-authorised transaction)', () => {
  assert.equal(requiresOperationProof('tx_prepare'), true);
  for (const kind of ['tx_commit', 'tx_abort', 'tx_inquiry', 'tx_query', 'tx_status']) {
    assert.equal(requiresOperationProof(kind), false, `${kind} must not require a proof`);
  }
});

test('policy resolution: warn by default, unknown falls back to warn', () => {
  assert.equal(resolveOperationProofPolicy(undefined), 'warn');
  assert.equal(resolveOperationProofPolicy(' ENFORCE '), 'enforce');
  assert.equal(resolveOperationProofPolicy('off'), 'off');
  // A typo must never start refusing operations.
  assert.equal(resolveOperationProofPolicy('enforced'), 'warn');
});

test('operationDocumentPayload: versioned, and binds actor + tx + kind + message id', () => {
  const p = operationDocumentPayload({ actor: 'D123', txId: 't1', kind: 'tx_prepare', messageId: 'm1', operations: [] });
  const parsed = JSON.parse(p) as Record<string, unknown>;
  assert.equal(parsed.v, 1, 'a version marker so the signed shape can evolve');
  assert.equal(parsed.actor, 'D123');
  assert.equal(parsed.txId, 't1');
  assert.equal(parsed.kind, 'tx_prepare');
  assert.equal(parsed.messageId, 'm1');
});

test('verifyOperationProof: a proof over exactly this message is VERIFIED (positive control)', () => {
  const outcome = verifyOperationProof(prepareWithProof(), { senderVid: actorVid });
  assert.equal(outcome.verdict, 'verified', outcome.reason);
  assert.equal(outcome.actor, actorVid);
});

test('verifyOperationProof: tampering with ANY covered field is INVALID', () => {
  const base = prepareWithProof();

  // The params are covered: changing them must break the signature.
  const tamperedParams = { ...base, operations: [{ op: 'name_register', params: { name: 'mallory' } }] };
  assert.equal(verifyOperationProof(tamperedParams, { senderVid: actorVid }).verdict, 'invalid');

  // So are the message id (no replay onto a different message) and the txId.
  assert.equal(verifyOperationProof({ ...base, messageId: 'msg-2' }, { senderVid: actorVid }).verdict, 'invalid');
  assert.equal(verifyOperationProof({ ...base, txId: 'tx-other' }, { senderVid: actorVid }).verdict, 'invalid');

  // And so is the actor field: renaming the actor breaks the signed payload.
  const otherVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, generateEd25519KeyPair().publicKey);
  assert.equal(
    verifyOperationProof({ ...base, proof: { ...(base.proof as object), actor: otherVid } } as never, {}).verdict,
    'invalid',
  );
});

test('verifyOperationProof: a proof from a DIFFERENT identity does not authorise this sender', () => {
  // The anti-substitution check: the envelope says who sent it; the proof must agree.
  const impostorVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, generateEd25519KeyPair().publicKey);
  const outcome = verifyOperationProof(prepareWithProof(), { senderVid: impostorVid });

  assert.equal(outcome.verdict, 'invalid');
  assert.match(outcome.reason, /but the message came from/);
});

test('verifyOperationProof: expiry and clock skew are enforced', () => {
  const now = 1_000_000;
  const fresh = signOperationProof(
    { actorVid, txId: 'tx-1', kind: 'tx_prepare', messageId: 'm1', operations: OPERATIONS, issuedAt: now, ttlSeconds: 300 },
    signEd25519, kp.secretKey,
  );
  const msg = { kind: 'tx_prepare', txId: 'tx-1', messageId: 'm1', operations: OPERATIONS, proof: fresh };

  assert.equal(verifyOperationProof(msg, { now: now + 100 }).verdict, 'verified', 'inside the window');
  assert.equal(verifyOperationProof(msg, { now: now + 1000 }).verdict, 'invalid', 'past expiry');

  const future = { ...fresh, issuedAt: now + 3600, expiresAt: now + 7200 };
  assert.equal(
    verifyOperationProof({ ...msg, proof: future }, { now }).verdict,
    'invalid',
    'a proof issued in the future is not usable yet',
  );
});

test('verifyOperationProof: a non-key actor is INDETERMINATE, never invalid', () => {
  // A DID-form actor would need resolution, which this verifier deliberately does not
  // depend on. "Cannot check" must not read as "forged" — the F-031 discipline.
  const msg = prepareWithProof({
    proof: { actor: 'did:scid:vh:1:zSomeone', issuedAt: 1, expiresAt: 2_000_000_000, signature: 'AAAA' },
  });
  const outcome = verifyOperationProof(msg, {});
  assert.equal(outcome.verdict, 'indeterminate');
  assert.match(outcome.reason, /could not be checked/);
});

/**
 * The 2026-09-25 field case.
 *
 * Every cross-node `tx_prepare` logged:
 *   [operation-proof] tx_prepare …: invalid actor=DIdB25_WgIXu… (policy=warn) —
 *     the proof names actor DIdB25_WgIXu… but the message came from did:scid:vh:…
 *
 * Cause: the proof's `actor` is a CESR VID (`vta.tspVid` / the agent's `meta.vid`) while the
 * envelope's `vidSender` carries a DID — so the plain string comparison could NEVER match.
 * `warn` masked it; `enforce` would have refused every cross-node operation, i.e. the gate
 * was unusable and the check was decorative.
 *
 * The binding is only DECIDABLE between comparable forms, so a DID-form sender identifier is
 * `indeterminate` — the same discipline the file already applies to a DID-form actor.
 */
test('verifyOperationProof: a DID-form sender identifier is INDETERMINATE, never a false substitution', () => {
  const didFormSender = 'did:scid:vh:1:zSomeDidFormSender';
  const msg = prepareWithProof();
  const outcome = verifyOperationProof(msg, { senderVid: didFormSender });

  assert.equal(outcome.verdict, 'indeterminate', outcome.reason);
  assert.match(outcome.reason, /not a CESR key/);

  // …and the gate must not refuse a correctly-signed proof just because the transport
  // identifier happens to be a DID rather than a key.
  assert.equal(
    gateOperationProof(msg, { policy: 'enforce', senderVid: didFormSender }).allow,
    true,
    'enforce must not refuse a valid proof over an un-comparable sender identifier',
  );
});

test('verifyOperationProof: with a DID-form sender a FORGED signature is still refused under enforce', () => {
  // The other half of the discipline: relaxing the BINDING must not relax the SIGNATURE.
  const wrongKey = generateEd25519KeyPair();
  const forged = signOperationProof(
    { actorVid, txId: 'tx-proof-forged', kind: 'tx_prepare', messageId: 'msg-1', operations: OPERATIONS },
    signEd25519,
    wrongKey.secretKey,
  );
  const msg = prepareWithProof({ txId: 'tx-proof-forged', proof: forged });
  const didFormSender = 'did:scid:vh:1:zSomeDidFormSender';

  assert.equal(verifyOperationProof(msg, { senderVid: didFormSender }).verdict, 'invalid');
  assert.equal(gateOperationProof(msg, { policy: 'enforce', senderVid: didFormSender }).allow, false);
});
