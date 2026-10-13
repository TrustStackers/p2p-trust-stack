/**
 * Typed errors for the `trust-app-api` surface.
 *
 * A domain method never leaks a raw runtime error: callers get a stable `code` they can branch on, with the
 * original message preserved for humans. The reference adapter maps these to HTTP status codes; a third-party
 * consumer branches on `code`.
 */

/** Base class for every error the API layer raises deliberately. */
export class StackError extends Error {
  /** Stable, machine-readable code. */
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'StackError';
    this.code = code;
  }
}

/** Thrown when an operation needs an active (unlocked, started) VTA and there is none. */
export class NoActiveAgentError extends StackError {
  constructor(operation: string) {
    super('no_active_agent', `No active VTA — cannot ${operation}. Activate an identity first.`);
  }
}

/** Thrown when a capability-scoped stack is asked for something outside its scope (P4). */
export class CapabilityError extends StackError {
  constructor(message: string) {
    super('capability_denied', message);
  }
}

/** Thrown when an operation is not part of the implemented surface yet. */
export class NotImplementedError extends StackError {
  constructor(what: string, phase: string) {
    super('not_implemented', `${what} is not implemented yet — it lands in ${phase}.`);
  }
}

/** Thrown when the utility server is required but not reachable. */
export class UtilityServerUnavailableError extends StackError {
  constructor(operation: string) {
    super('utility_server_unavailable', `Utility server not connected — cannot ${operation}.`);
  }
}
