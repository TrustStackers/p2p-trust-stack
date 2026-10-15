// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The canonical, CLOSED event catalogue for `trust-app-api`.
 *
 * This file is the single source of truth for what the stack can announce. It replaces the six ad-hoc
 * SSE names (`message`, `duplicate-connect-notice`, `ceremony-state`, `ceremony-expired`,
 * `ceremony-complete`, `ceremony-failed`) and the nine timer polls that used to be the only way a UI
 * learned that anything had happened.
 *
 * **Closed** means: a domain may only emit a name listed here, and `STACK_EVENTS` is exported so a test
 * can assert exactly that. Adding an event is a deliberate edit to this file, not an incidental string
 * somewhere in a route handler.
 *
 * ## Why `at` is on every payload
 *
 * Every payload carries `at` (unix ms). Subscribers that receive an event both live and via replay need a
 * stable way to order and de-duplicate them, and the bus's own sequence number is not part of the payload.
 *
 * ## Scope keys (for `filter`)
 *
 * A subscription may filter on any payload field, matched by strict equality — e.g.
 * `on('message.received', h, { filter: { peerDid } })`. The field names below are the intended filter keys
 * per event family: `peerDid` (messaging, relationships), `communityUuid` (communities, invitations),
 * `contextId` (capability-scoped events).
 */

/** Every event name the stack may emit. Runtime list — kept in sync with {@link StackEvent}. */
export const STACK_EVENTS = [
  // Identity & lifecycle
  'identity.created',
  'identity.activated',
  'identity.deactivated',
  'identity.rotated',
  // Connectivity
  'connection.open',
  'connection.close',
  'connection.changed',
  'network.changed',
  // Messaging
  'message.received',
  'message.sent',
  'chat.cleared',
  // Relationships
  'relationship.changed',
  'relationship.ceremony',
  // A peer tried to connect with an OOBI that is already bound to a DIFFERENT identity. Announced so a UI can
  // warn without polling: the notice is one-shot and time-boxed, which made it exactly the kind of thing the
  // nine retired polls existed for. Before this event, `sse-bridge.ts` reached past the layer to
  // `AgentHandle.onDuplicateConnectNotice` because there was no bus event of its own — a documented hole in the
  // boundary that a second client (the TUI) had no way to cross.
  'duplicate.connect.notice',
  // Credentials & invitations
  'credential.issued',
  'credential.revoked',
  'credential.changed',
  'invitation.sent',
  'invitation.received',
  'invitation.changed',
  // Communities & governance
  'community.changed',
  'governance.proposal',
  // A founding ceremony advanced (a co-signature landed). Distinct from `community.changed`: the community does
  // not exist until the ceremony crystallizes, so this is the only signal of progress BEFORE that.
  'ceremony.step',
  // Names & profiles
  'name.registered',
  'name.revoked',
  'profile.changed',
  // Sync
  'sync.started',
  'sync.completed',
  'sync.failed',
  // Errors
  'error',
] as const;

/** The closed union of event names. */
export type StackEvent = (typeof STACK_EVENTS)[number];

/**
 * Payload for every event. Fields are explicit — no index signatures — so a payload can never
 * accidentally become a database row.
 */
export interface StackEventPayloads {
  'identity.created': { name: string; did: string; at: number };
  'identity.activated': { name: string; did: string; at: number };
  'identity.deactivated': { name: string | null; at: number };
  'identity.rotated': { did: string; version: number; at: number };

  'connection.open': {
    peerId: string;
    direction: 'inbound' | 'outbound';
    method: string;
    remoteAddr?: string;
    at: number;
  };
  'connection.close': {
    peerId: string;
    direction: 'inbound' | 'outbound';
    method: string;
    at: number;
  };
  'connection.changed': {
    layer: string;
    bootstrapConnected: boolean;
    utilityServerConnected: boolean;
    degraded: boolean;
    at: number;
  };
  'network.changed': { changedFields: string[]; at: number };

  'message.received': { peerDid: string; confidential: boolean; bytes: number; at: number };
  'message.sent': { peerDid: string; confidential: boolean; bytes: number; at: number };
  'chat.cleared': { peerDid: string; at: number };

  'relationship.changed': { peerDid: string; status: string; at: number };
  'relationship.ceremony': {
    peerDid: string;
    /**
     * Which leg of the ceremony this is: `prompt` | `ack` | `complete` | `expired` | `failed` | `reset`.
     *
     * The runtime exposes these as separate callbacks (`onCeremonyPrompt`, `onCeremonyAckChange`,
     * `onCeremonyComplete`, `onCeremonyExpired`, `onCeremonyFailed`); the bus unifies them under one event
     * with `step` distinguishing them, so a subscriber follows a whole ceremony with one subscription instead
     * of five.
     */
    step: string;
    /** Present when `step` is `failed` — the reason, for display. */
    error?: string;
    at: number;
  };
  'duplicate.connect.notice': {
    /** The peer whose OOBI collided. */
    peerDid: string;
    /** The name the OTHER identity claims, or null when it never registered one. */
    remoteName: string | null;
    at: number;
  };

  'credential.issued': { uuid: string; vcType: string; at: number };
  'credential.revoked': { uuid: string; vcType: string; at: number };
  'credential.changed': { uuid: string; status: string; at: number };
  'invitation.sent': { uuid: string; communityUuid: string; at: number };
  'invitation.received': { uuid: string; communityUuid: string; at: number };
  'invitation.changed': { uuid: string; status: string; at: number };

  'community.changed': { communityUuid: string; kind: 'membership' | 'governance'; at: number };
  'governance.proposal': { proposalId: string; communityUuid: string; at: number };
  'ceremony.step': { threadId: string; step: string | null; communityUuid: string | null; at: number };

  'name.registered': { name: string; namespace: string; did: string; at: number };
  'name.revoked': { name: string; namespace: string; did: string; at: number };
  'profile.changed': { profileUuid: string; at: number };

  'sync.started': { kind: string; at: number };
  'sync.completed': { kind: string; at: number };
  'sync.failed': { kind: string; reason: string; at: number };

  error: { operation: string; message: string; at: number };
}

/** Payload type for a specific event name. */
export type StackEventPayload<E extends StackEvent> = StackEventPayloads[E];

/** A filter is a set of payload fields that must all match exactly. */
export type EventFilter = Record<string, string | number | boolean>;

/** True when every key in `filter` equals the same key in `payload`. */
export function matchesFilter(payload: unknown, filter?: EventFilter): boolean {
  if (!filter) return true;
  if (payload === null || typeof payload !== 'object') return false;
  const p = payload as Record<string, unknown>;
  for (const [k, v] of Object.entries(filter)) {
    if (p[k] !== v) return false;
  }
  return true;
}
