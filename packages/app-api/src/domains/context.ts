// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The shared context every domain is built with.
 *
 * A domain never reaches for a global: it is handed the host, the registry, the bus, and an accessor for the
 * **currently active** agent. That accessor is the important part — the active agent is swapped at runtime
 * (`identity.activate` / `identity.deactivate`), so a domain must read it on every call rather than capture
 * it at construction. Capturing it is the bug the reference app already had to work around
 * (`web-server.ts`: "All route handlers read deps.agent (not a destructured copy)").
 */
import type { Host } from '../host/types.js';
import type { AgentRegistry } from '../runtime/agent-registry.js';
import type { AgentHandle } from '../runtime/handle.js';
import type { EventBus } from '../client/events.js';
import { NoActiveAgentError } from '../errors.js';

export interface DomainContext {
  readonly host: Host;
  readonly registry: AgentRegistry;
  readonly bus: EventBus;
  /** The active agent, or null when no VTA is unlocked. */
  getAgent(): AgentHandle | null;
  /**
   * Swap the active agent (used by `identity.activate` / `identity.deactivate`).
   *
   * Async because switching agents also re-points the durable outbox at the new agent's database, which
   * seeds the bus's sequence counter from that database's high-water mark.
   */
  setAgent(agent: AgentHandle | null): Promise<void>;
}

/** Return the active agent or throw {@link NoActiveAgentError}. */
export function requireAgent(ctx: DomainContext, operation: string): AgentHandle {
  const agent = ctx.getAgent();
  if (!agent) throw new NoActiveAgentError(operation);
  return agent;
}
