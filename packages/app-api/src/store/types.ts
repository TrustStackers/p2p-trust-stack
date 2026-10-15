// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The durable event-store seam.
 *
 * Lives in its own module so `client/events.ts` (which needs the type) and
 * `store/agent-events-store.ts` (which implements it) can both import it without a runtime cycle — both
 * directions here are `import type`, which is erased.
 */
import type { EventFilter, StackEvent } from '../events/catalog.js';
import type { StoredEvent } from '../client/events.js';

export interface EventStore {
  /** Persist one event. Called by the bus on every emit. */
  append(event: StoredEvent): Promise<void>;
  /** Read events after a cursor, optionally narrowed to one event name and/or a payload filter. */
  read(opts: {
    since: number;
    event?: StackEvent;
    filter?: EventFilter;
    limit?: number;
  }): Promise<{ events: StoredEvent[]; truncated: boolean }>;
  /** The highest sequence number recorded, or 0 when empty. */
  latestSequence(): Promise<number>;
  /** Keep only the newest `keep` rows. Returns how many were deleted. */
  prune(keep: number): Promise<number>;
}
