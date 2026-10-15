// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Agent — factory that dispatches to the correct concrete Agent class based
 * on the configured DidMethod.
 *
 * When `didMethod` is provided in the config:
 *   - ScidVhMethod → ScidVhAgent
 *   - DidPeer4Method    → Peer4Agent
 *   - Any other DidMethod → Peer4Agent (default)
 *
 * When `didMethod` is omitted, defaults to Peer4Agent (did:peer:4).
 *
 * ## Agent listing
 *
 * Agents are listed by querying `identities` + `did_documents` directly.
 * There is no separate `agents` table.
 */

import type { DidMethod } from '@p2p-trust-stack/core/did/did-method.js';

import { Peer4Agent } from './peer4-agent.js';
import { ScidVhAgent } from './scid-vh-agent.js';
import { AgentRegistry, defaultRegistry } from './agent-registry.js';
import type { AgentConfig, AgentSummary } from './types.js';


// ---------------------------------------------------------------------------
// AgentInstance — union of all concrete agent types
// ---------------------------------------------------------------------------

export type AgentInstance = Peer4Agent | ScidVhAgent;


// ---------------------------------------------------------------------------
// Factory: create
// ---------------------------------------------------------------------------

export async function createAgent(
  config: AgentConfig,
  registry: AgentRegistry = defaultRegistry,
): Promise<AgentInstance> {
  const agentClass = resolveAgentClass(config.didMethod);
  return agentClass.create(config, registry);
}


// ---------------------------------------------------------------------------
// Factory: unlock
// ---------------------------------------------------------------------------

export async function unlockAgent(
  config: AgentConfig,
  registry: AgentRegistry = defaultRegistry,
): Promise<AgentInstance> {
  const agentClass = resolveAgentClass(config.didMethod);
  return agentClass.unlock(config, registry);
}


// ---------------------------------------------------------------------------
// Factory: list
// ---------------------------------------------------------------------------

/**
 * List all agents by scanning the per-agent directories under P2PTS_HOME/vta/.
 * Each agent owns its own database, so there is no single database to query.
 */
export function listAgents(
  registry: AgentRegistry = defaultRegistry,
): AgentSummary[] {
  return registry.listAgents();
}


// ---------------------------------------------------------------------------
// Factory: delete
// ---------------------------------------------------------------------------

/** Permanently delete an agent by removing its directory. */
export function deleteAgent(
  name: string,
  registry: AgentRegistry = defaultRegistry,
): void {
  registry.deleteAgent(name);
}


// ---------------------------------------------------------------------------
// Agent factory class (static API)
// ---------------------------------------------------------------------------

export class Agent {
  static async create(config: AgentConfig, registry?: AgentRegistry): Promise<AgentInstance> {
    return createAgent(config, registry);
  }

  static async unlock(config: AgentConfig, registry?: AgentRegistry): Promise<AgentInstance> {
    return unlockAgent(config, registry);
  }

  static list(registry?: AgentRegistry): AgentSummary[] {
    return listAgents(registry);
  }

  static delete(name: string, registry?: AgentRegistry): void {
    deleteAgent(name, registry);
  }
}


// ---------------------------------------------------------------------------
// Internal: resolve the correct agent class from the DidMethod
// ---------------------------------------------------------------------------

function resolveAgentClass(didMethod?: DidMethod): typeof Peer4Agent | typeof ScidVhAgent {
  if (!didMethod) {
    return ScidVhAgent;
  }
  if (didMethod.supportsRotation) {
    return ScidVhAgent;
  }
  return Peer4Agent;
}
