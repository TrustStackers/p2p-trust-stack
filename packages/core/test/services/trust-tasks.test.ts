/**
 * Trust Tasks — the document-level bridge (P5).
 *
 * Pins the deliverables, using OUR OWN `task:p2pts:…` namespace (interop, not
 * conformance — see `type-uris.ts`):
 *
 *  1. **The type vocabulary + action↔type map** — the four P4 policy operations as
 *     canonical `task:p2pts:…` identifiers, plus the boundary interop map to
 *     trusttasks.org.
 *  2. **The envelope** — `{id, type, threadId, issuer, recipient, issuedAt, payload,
 *     proof}` with `#request`/`#response` and error forms.
 *  3. **The decision projection** — `PolicyResult → PolicyDecision` (lossless except
 *     the documented `minApprovalsFromFact` case).
 *
 * Also pins the correctness rule: a proof with no authenticated-transport identity
 * binding is INDETERMINATE, never silently allowed.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/services/trust-tasks.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  taskType,
  POLICY_UPSERT_TYPE,
  POLICY_EVALUATE_TYPE,
  POLICY_TEST_TYPE,
  POLICY_VALIDATE_TYPE,
  POLICY_OPERATION_TO_TYPE,
  typeUriToOperation,
  TASK_TO_TRUSTTASKS_URI,
  buildTrustTask,
  buildResponse,
  buildError,
  parseTrustTask,
  isIndeterminateForProof,
  resultToPolicyDecision,
} from '../../src/services/trust-tasks/index.js';
import type { PolicyResult } from '../../src/services/policy-engine.js';

// ── type identifiers ─────────────────────────────────────────────────────────

test('taskType builds a namespace-scoped identifier (scheme task, opaque p2pts part)', () => {
  assert.equal(taskType('policy', 'evaluate', '0.1'), 'task:p2pts:policy:evaluate:0.1');
  assert.equal(
    taskType('policy', 'evaluate', '0.1', 'other'),
    'task:other:policy:evaluate:0.1',
  );
});

test('the four P4 policy operations are canonical task types under p2pts', () => {
  assert.equal(POLICY_UPSERT_TYPE, 'task:p2pts:policy:upsert:0.1');
  assert.equal(POLICY_EVALUATE_TYPE, 'task:p2pts:policy:evaluate:0.1');
  assert.equal(POLICY_TEST_TYPE, 'task:p2pts:policy:test:0.1');
  assert.equal(POLICY_VALIDATE_TYPE, 'task:p2pts:policy:validate:0.1');
  assert.equal(POLICY_OPERATION_TO_TYPE.upsert, POLICY_UPSERT_TYPE);
  assert.equal(POLICY_OPERATION_TO_TYPE.test, POLICY_TEST_TYPE);
});

test('typeUriToOperation routes our identifiers and ignores the fragment', () => {
  assert.equal(typeUriToOperation(POLICY_EVALUATE_TYPE), 'evaluate');
  assert.equal(typeUriToOperation(`${POLICY_EVALUATE_TYPE}#request`), 'evaluate');
  assert.equal(typeUriToOperation(`${POLICY_EVALUATE_TYPE}#response`), 'evaluate');
  assert.equal(typeUriToOperation('task:p2pts:unknown:0.1'), undefined);
});

test('the interop map is boundary-only: only true equivalents, test/validate absent', () => {
  assert.equal(TASK_TO_TRUSTTASKS_URI.upsert, 'https://trusttasks.org/spec/policy/upsert/0.2');
  assert.equal(
    TASK_TO_TRUSTTASKS_URI.evaluate,
    'https://trusttasks.org/spec/policy/evaluate/0.3',
  );
  assert.equal(TASK_TO_TRUSTTASKS_URI.test, undefined);
  assert.equal(TASK_TO_TRUSTTASKS_URI.validate, undefined);
});

// ── envelope ────────────────────────────────────────────────────────────────

test('buildTrustTask fills a unique id and now() issuedAt when not supplied', () => {
  const doc = buildTrustTask(POLICY_EVALUATE_TYPE, { payload: { candidateModule: 'x' } });
  assert.ok(doc.id.length > 0);
  assert.equal(doc.type, POLICY_EVALUATE_TYPE);
  assert.ok(doc.issuedAt && !Number.isNaN(Date.parse(doc.issuedAt)));
  assert.deepEqual(doc.payload, { candidateModule: 'x' });
});

test('buildResponse echoes threadId and swaps issuer/recipient with #response', () => {
  const req = buildTrustTask(POLICY_EVALUATE_TYPE, {
    threadId: 'thread-1',
    issuer: 'did:example:alice',
    recipient: 'did:example:bob',
    payload: {},
  });
  const res = buildResponse(req, { decision: 'allow' });
  assert.equal(res.type, `${POLICY_EVALUATE_TYPE}#response`);
  assert.equal(res.threadId, 'thread-1');
  assert.equal(res.issuer, 'did:example:bob');
  assert.equal(res.recipient, 'did:example:alice');
  assert.notEqual(res.id, req.id);
});

test('buildError emits a #response carrying {code, message}; bare falls back to OUR type', () => {
  const req = buildTrustTask(POLICY_EVALUATE_TYPE, { threadId: 't', payload: {} });
  const err = buildError(req, { code: 'policy/evaluate:candidateRegoInvalid', message: 'bad' });
  assert.equal(err.type, `${POLICY_EVALUATE_TYPE}#response`);
  assert.equal(err.threadId, 't');
  assert.deepEqual(err.payload, { code: 'policy/evaluate:candidateRegoInvalid', message: 'bad' });
  // No request → falls back to OUR error type, not a trusttasks.org URI.
  const bare = buildError(undefined, { code: 'malformedRequest', message: 'x' });
  assert.equal(bare.type, 'task:p2pts:error:trust-task:0.1#response');
});

test('parseTrustTask accepts a conforming envelope and rejects missing members', () => {
  const good = parseTrustTask({ id: '1', type: POLICY_EVALUATE_TYPE, payload: {} });
  assert.equal(good.ok, true);
  assert.equal(parseTrustTask({ type: POLICY_EVALUATE_TYPE, payload: {} }).ok, false); // no id
  assert.equal(parseTrustTask({ id: '1', payload: {} }).ok, false); // no type
  assert.equal(parseTrustTask({ id: '1', type: POLICY_EVALUATE_TYPE, payload: 'x' }).ok, false);
  assert.equal(parseTrustTask(null).ok, false);
});

test('isIndeterminateForProof: proof without authenticated issuer is indeterminate', () => {
  const withProof = buildTrustTask(POLICY_EVALUATE_TYPE, {
    issuer: 'did:example:alice',
    payload: {},
    proof: { type: 'Ed25519Signature2020' },
  });
  const withoutProof = buildTrustTask(POLICY_EVALUATE_TYPE, { payload: {} });
  assert.equal(isIndeterminateForProof(withProof, false), true); // proof, not authenticated
  assert.equal(isIndeterminateForProof(withProof, true), false); // proof, authenticated
  assert.equal(isIndeterminateForProof(withoutProof, false), false); // no proof
});

// ── projection ──────────────────────────────────────────────────────────────

test('resultToPolicyDecision maps decision/explanation/requireConsent 1:1', () => {
  const result: PolicyResult = {
    allowed: false,
    decision: {
      decision: 'requireConsent',
      explanation: 'needs admin quorum',
      requireConsent: {
        approverSet: 'community-admins',
        minApprovals: 2,
        excludeRequester: true,
      },
    },
  };
  assert.deepEqual(resultToPolicyDecision(result), {
    decision: 'requireConsent',
    explanation: 'needs admin quorum',
    requireConsent: { approverSet: 'community-admins', minApprovals: 2, excludeRequester: true },
  });
});

test('resultToPolicyDecision omits minApprovalsFromFact rather than corrupting an integer', () => {
  const result: PolicyResult = {
    allowed: false,
    decision: {
      decision: 'requireConsent',
      requireConsent: { approverSet: 'community-admins', minApprovalsFromFact: 'threshold_m' },
    },
  };
  const projected = resultToPolicyDecision(result);
  assert.equal(projected.decision, 'requireConsent');
  assert.deepEqual(projected.requireConsent, { approverSet: 'community-admins' });
});

test('resultToPolicyDecision caps explanation at the schema maxLength (1024)', () => {
  const result: PolicyResult = {
    allowed: false,
    decision: { decision: 'deny', explanation: 'x'.repeat(1200) },
  };
  assert.equal(resultToPolicyDecision(result).explanation!.length, 1024);
});
