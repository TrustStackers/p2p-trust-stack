/**
 * Ceremony terminal-state polling policy + driver (G6).
 *
 * `BaseAgent.createCommunityCeremony` used to poll the server's ceremony status
 * with `maxAttempts = 30` and `pollDelayMs = 2000` — but it counted ATTEMPTS,
 * not time, and each attempt could block for the full transport budget
 * (connectivity wait up to 15 s + request timeout up to 30 s = ~45 s). The worst
 * case was therefore ~30 × 47 s ≈ 23 MINUTES before the create button resolved,
 * while the UI displayed an indefinite "Creating…".
 *
 * Two further faults compounded it:
 *
 *  1. every query error was treated as transient (`continue`), so a definitive
 *     answer — `ceremony not found`, a malformed request — was polled 30 more
 *     times instead of being reported;
 *  2. the loop always slept BEFORE the first query, even though the server
 *     crystallizes synchronously inside `ceremony_approve`'s `prepare()`, so the
 *     common case (already crystallized) paid a 2 s delay for nothing.
 *
 * This module replaces that with a *time-budgeted* policy:
 *
 *  - the first query runs immediately (no initial delay);
 *  - a definitive answer returns at once;
 *  - transient errors keep polling until the budget expires;
 *  - expiry returns `pending` with the last observed status/error so the caller
 *    can tell the user something true and point at `ceremonyId` to resume.
 *
 * The policy is pure and the driver takes its clock, sleep and query function as
 * dependencies, so the whole thing is unit-testable without a server.
 */

/** Shape returned by `BaseAgent.queryCeremony`. */
export interface CeremonyQueryResult {
  status?: string;
  errorReason?: string | null;
  error?: string;
}

export interface CeremonyPollOptions {
  /** Total wall-clock budget for the whole poll loop. */
  totalBudgetMs?: number;
  /** Delay between attempts (never before the first attempt). */
  pollDelayMs?: number;
  /** Per-attempt request timeout passed to the transport. */
  queryTimeoutMs?: number;
  /** Per-attempt connectivity wait passed to the transport. */
  connectivityTimeoutMs?: number;
}

/**
 * Defaults. `totalBudgetMs` preserves the old ~30 attempts × 2 s cadence while
 * bounding wall-clock time instead of attempt count, and the per-attempt
 * timeouts are deliberately far shorter than the transport defaults (30 s / 15 s)
 * so that a hung attempt cannot eat the whole budget.
 */
export const CEREMONY_POLL_DEFAULTS = {
  totalBudgetMs: 60_000,
  pollDelayMs: 2_000,
  queryTimeoutMs: 8_000,
  connectivityTimeoutMs: 3_000,
} as const;

/**
 * Query errors that are a DEFINITIVE answer about the ceremony rather than a
 * transport problem. Polling again cannot change these, so they terminate the
 * loop immediately.
 */
const HARD_QUERY_ERROR_PATTERNS = [
  'ceremony not found',
  'ceremonyid required',
  'does not support query',
];

/** Whether a query error is a definitive answer (stop) vs. transient (retry). */
export function isHardQueryError(error: string | null | undefined): boolean {
  if (!error) return false;
  const lower = error.toLowerCase();
  return HARD_QUERY_ERROR_PATTERNS.some((p) => lower.includes(p));
}

export type CeremonyStatusVerdict =
  | { kind: 'crystallized' }
  | { kind: 'failed'; error: string }
  | { kind: 'expired'; error: string }
  | { kind: 'hard_error'; error: string }
  | { kind: 'pending' }
  | { kind: 'transient'; error: string };

/** Classify one ceremony-status response. */
export function classifyCeremonyStatus(result: CeremonyQueryResult | null | undefined): CeremonyStatusVerdict {
  if (!result) return { kind: 'transient', error: 'No ceremony data returned.' };

  if (result.status === 'crystallized') return { kind: 'crystallized' };
  if (result.status === 'failed') return { kind: 'failed', error: result.errorReason || 'Ceremony failed.' };
  if (result.status === 'expired') return { kind: 'expired', error: 'Ceremony expired.' };
  if (result.status === 'pending') return { kind: 'pending' };

  // No recognised status: either a definitive error or a transport failure.
  const error = result.error
    ?? (result.status ? `Unexpected ceremony status '${result.status}'.` : 'No ceremony status returned.');
  return isHardQueryError(error) ? { kind: 'hard_error', error } : { kind: 'transient', error };
}

export type CeremonyPollOutcome =
  | { outcome: 'crystallized'; attempts: number }
  | { outcome: 'failed'; error: string; attempts: number }
  | { outcome: 'expired'; error: string; attempts: number }
  | {
      outcome: 'pending';
      error: string;
      attempts: number;
      lastStatus?: string;
      lastError?: string;
    };

export interface CeremonyPollDriver {
  /** Performs one status query. May throw; the driver catches and treats it as transient. */
  query: () => Promise<CeremonyQueryResult>;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  totalBudgetMs?: number;
  pollDelayMs?: number;
  onProgress?: (attempt: number, result: CeremonyQueryResult) => void;
}

/**
 * Poll until the ceremony reaches a terminal state or the budget expires.
 *
 * Never throws: a throwing `query` is classified as transient so a transient
 * transport fault cannot abort the loop early.
 */
export async function awaitCeremonyTerminal(opts: CeremonyPollDriver): Promise<CeremonyPollOutcome> {
  const now = opts.now ?? (() => Date.now());
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const budget = opts.totalBudgetMs ?? CEREMONY_POLL_DEFAULTS.totalBudgetMs;
  const delay = opts.pollDelayMs ?? CEREMONY_POLL_DEFAULTS.pollDelayMs;
  const deadline = now() + budget;

  let attempts = 0;
  let lastStatus: string | undefined;
  let lastError: string | undefined;

  // Every exit is an explicit return; the budget check below is the single place
  // time is enforced, so no attempt can loop unbounded.
  for (;;) {
    attempts++;

    let result: CeremonyQueryResult;
    try {
      result = await opts.query();
    } catch (err) {
      result = { error: (err as Error)?.message ?? String(err) };
    }
    opts.onProgress?.(attempts, result);

    const verdict = classifyCeremonyStatus(result);
    switch (verdict.kind) {
      case 'crystallized':
        return { outcome: 'crystallized', attempts };
      case 'failed':
        return { outcome: 'failed', error: verdict.error, attempts };
      case 'expired':
        return { outcome: 'expired', error: verdict.error, attempts };
      case 'hard_error':
        // A definitive answer — polling again cannot change it.
        return { outcome: 'failed', error: verdict.error, attempts };
      case 'pending':
        lastStatus = result.status;
        lastError = undefined;
        break;
      case 'transient':
        lastError = verdict.error;
        break;
    }

    if (now() >= deadline) {
      const detail = lastError
        ? `last check failed: ${lastError}`
        : `last status: ${lastStatus ?? 'unknown'}`;
      return {
        outcome: 'pending',
        attempts,
        lastStatus,
        lastError,
        error:
          `Ceremony is still ${lastStatus ?? 'pending'} after ${Math.round(budget / 1000)}s ` +
          `(${detail}). Use ceremonyId to query/resume.`,
      };
    }

    await sleep(delay);
  }
}
