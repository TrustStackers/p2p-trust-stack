/**
 * Tests for the ceremony poll policy + driver (G6).
 *
 * The create-VTC button used to resolve anywhere between a second and ~23
 * MINUTES depending on how the server's ceremony queries failed, because the
 * loop counted attempts (30) rather than time and each attempt could block for
 * the full transport budget (15 s connectivity + 30 s request). It also polled
 * BEFORE the first query, and treated a definitive `ceremony not found` as
 * transient — so a hard failure was indistinguishable from slowness.
 *
 * These tests pin the replacement policy:
 *  - the first query is immediate (no initial sleep);
 *  - a definitive error terminates the loop at once;
 *  - transient errors keep polling, but the TOTAL wall-clock time is bounded;
 *  - budget expiry returns `pending` with the last observed status/error;
 *  - a throwing query is transient (never aborts the loop).
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tx/ceremony-poll.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  awaitCeremonyTerminal,
  classifyCeremonyStatus,
  isHardQueryError,
  CEREMONY_POLL_DEFAULTS,
} from '../../src/runtime/tx/ceremony-poll.js';

/** Deterministic virtual clock: `sleep` advances it instead of waiting. */
function makeClock() {
  let t = 1_000_000;
  const sleeps: number[] = [];
  return {
    now: () => t,
    sleep: async (ms: number) => { sleeps.push(ms); t += ms; },
    sleeps,
  };
}

test('classifyCeremonyStatus: terminal, pending, definitive and transient cases', () => {
  assert.deepEqual(classifyCeremonyStatus({ status: 'crystallized' }), { kind: 'crystallized' });
  assert.deepEqual(classifyCeremonyStatus({ status: 'pending' }), { kind: 'pending' });

  const failed = classifyCeremonyStatus({ status: 'failed', errorReason: 'Name "acme" is already taken.' });
  assert.deepEqual(failed, { kind: 'failed', error: 'Name "acme" is already taken.' });

  // A failed ceremony with no reason still reports something true.
  assert.deepEqual(classifyCeremonyStatus({ status: 'failed' }), { kind: 'failed', error: 'Ceremony failed.' });
  assert.deepEqual(classifyCeremonyStatus({ status: 'expired' }), { kind: 'expired', error: 'Ceremony expired.' });

  // Definitive answers are `hard_error`, NOT transient.
  assert.deepEqual(classifyCeremonyStatus({ error: 'ceremony not found' }), {
    kind: 'hard_error', error: 'ceremony not found',
  });
  assert.deepEqual(classifyCeremonyStatus({ error: 'ceremonyId required' }), {
    kind: 'hard_error', error: 'ceremonyId required',
  });

  // Transport-ish failures are transient (retryable).
  assert.deepEqual(classifyCeremonyStatus({ error: 'Not connected to utility server.' }), {
    kind: 'transient', error: 'Not connected to utility server.',
  });
  assert.deepEqual(classifyCeremonyStatus({ error: 'TSP request timed out after 8000ms' }), {
    kind: 'transient', error: 'TSP request timed out after 8000ms',
  });

  // Missing/unrecognised data is transient, never a silent success or failure.
  assert.equal(classifyCeremonyStatus(null).kind, 'transient');
  assert.equal(classifyCeremonyStatus({}).kind, 'transient');
});

test('first query is immediate — no sleep before it', async () => {
  const clock = makeClock();
  let calls = 0;
  const result = await awaitCeremonyTerminal({
    now: clock.now,
    sleep: clock.sleep,
    query: async () => { calls++; return { status: 'crystallized' }; },
  });

  assert.deepEqual(result, { outcome: 'crystallized', attempts: 1 });
  assert.equal(calls, 1);
  assert.deepEqual(clock.sleeps, [], 'the loop must not sleep before the first query');
});

test('a definitive error terminates immediately instead of polling 30 times', async () => {
  const clock = makeClock();
  let calls = 0;
  const result = await awaitCeremonyTerminal({
    now: clock.now,
    sleep: clock.sleep,
    query: async () => { calls++; return { error: 'ceremony not found' }; },
  });

  assert.equal(result.outcome, 'failed');
  assert.equal(result.error, 'ceremony not found');
  assert.equal(calls, 1, 'one attempt is enough for a definitive answer');
  assert.deepEqual(clock.sleeps, []);
});

test('transient errors keep polling but the total wall-clock time is bounded', async () => {
  const clock = makeClock();
  let calls = 0;
  const result = await awaitCeremonyTerminal({
    now: clock.now,
    sleep: clock.sleep,
    query: async () => { calls++; return { error: 'Not connected to utility server.' }; },
    totalBudgetMs: 10_000,
    pollDelayMs: 2_000,
  });

  assert.equal(result.outcome, 'pending');
  assert.ok(result.error.includes('last check failed: Not connected to utility server.'), result.error);
  assert.ok(result.error.includes('after 10s'), result.error);
  // 10 s budget / 2 s delay = 5 attempts + the immediate first one.
  assert.equal(calls, 6, `expected 6 attempts, got ${calls}`);
  assert.ok(clock.now() >= 1_000_000 + 10_000, 'budget elapsed');
});

test('pending → crystallized: returns as soon as the terminal state appears', async () => {
  const clock = makeClock();
  const statuses = [{ status: 'pending' }, { status: 'pending' }, { status: 'crystallized' }];
  let calls = 0;
  const progress: number[] = [];
  const result = await awaitCeremonyTerminal({
    now: clock.now,
    sleep: clock.sleep,
    query: async () => statuses[calls++] ?? { status: 'crystallized' },
    onProgress: (attempt) => progress.push(attempt),
  });

  assert.deepEqual(result, { outcome: 'crystallized', attempts: 3 });
  assert.deepEqual(progress, [1, 2, 3]);
  assert.deepEqual(clock.sleeps, [CEREMONY_POLL_DEFAULTS.pollDelayMs, CEREMONY_POLL_DEFAULTS.pollDelayMs]);
});

test('a throwing query is transient and does not abort the loop', async () => {
  const clock = makeClock();
  let calls = 0;
  const result = await awaitCeremonyTerminal({
    now: clock.now,
    sleep: clock.sleep,
    query: async () => {
      calls++;
      if (calls === 1) throw new Error('TSP request timed out after 8000ms');
      return { status: 'crystallized' };
    },
  });

  assert.deepEqual(result, { outcome: 'crystallized', attempts: 2 });
});

test('budget expiry after a successful status read reports that status', async () => {
  const clock = makeClock();
  const result = await awaitCeremonyTerminal({
    now: clock.now,
    sleep: clock.sleep,
    query: async () => ({ status: 'pending' }),
    totalBudgetMs: 4_000,
    pollDelayMs: 1_000,
  });

  assert.equal(result.outcome, 'pending');
  assert.equal(result.lastStatus, 'pending');
  assert.equal(result.lastError, undefined);
  assert.ok(result.error.includes('still pending after 4s'), result.error);
  assert.ok(result.error.includes('Use ceremonyId to query/resume'), result.error);
});

test('a failed ceremony surfaces the server errorReason verbatim', async () => {
  const clock = makeClock();
  const result = await awaitCeremonyTerminal({
    now: clock.now,
    sleep: clock.sleep,
    query: async () => ({ status: 'failed', errorReason: 'Name "acme" is already taken.' }),
  });

  assert.equal(result.outcome, 'failed');
  assert.equal(result.error, 'Name "acme" is already taken.');
});


test('isHardQueryError: matches case-insensitively, ignores empty values', () => {
  assert.equal(isHardQueryError('Ceremony NOT Found'), true);
  assert.equal(isHardQueryError('participant does not support query: x'), true);
  assert.equal(isHardQueryError(undefined), false);
  assert.equal(isHardQueryError(''), false);
  assert.equal(isHardQueryError('connection refused'), false);
});
