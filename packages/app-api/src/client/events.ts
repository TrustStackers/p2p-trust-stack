/**
 * The typed event bus — the subscription half of the `trust-app-api` contract.
 *
 * Replaces two ad-hoc mechanisms at once:
 *   - `broadcastSSE` (`web-server.ts:1076-1080`), which fanned **every** event out to **every** connected
 *     client with no filtering and no cursor; and
 *   - the nine `setInterval` polls that pages used to discover that anything had changed.
 *
 * ## Guarantees
 *
 * - **Typed.** `emit` only accepts a name from the closed catalogue, and the payload type follows the name.
 * - **Filtered.** A subscription may filter on payload fields, matched by strict equality. Events reach only
 *   matching subscribers — there is no all→all fan-out.
 * - **Cursorable.** `since` replays matching events the subscriber missed (see the durability note below).
 * - **Isolated.** A throwing handler cannot break the emitter or starve other subscribers; the error is
 *   reported through `onHandlerError` instead.
 * - **Ordered.** Delivery is synchronous and in emit order, per subscriber.
 * - **Immediately cancellable.** `unsubscribe()` takes effect at once, including mid-delivery — a handler
 *   that unsubscribes another subscriber stops it receiving the event currently being emitted. (The delivery
 *   set is iterated from a snapshot, so cancelling cannot corrupt the loop; membership is simply re-checked
 *   before each delivery.) This is what P4's context revocation relies on.
 *
 * ## Durability (P2 vs P3)
 *
 * P2 keeps a **bounded in-memory replay buffer** and reports `oldestSeq`, so a caller can tell when a
 * `since` cursor is too old to satisfy. P3 swaps the backing store for the durable `agent_events` outbox
 * (decision D2) without changing this interface — that is why `replay()` is a method here rather than the
 * caller reaching into a buffer.
 */
import {
  STACK_EVENTS,
  matchesFilter,
  type EventFilter,
  type StackEvent,
  type StackEventPayloads,
} from '../events/catalog.js';
import type { EventStore } from '../store/types.js';

/** Options accepted by `on` / `once`. */
export interface SubscribeOpts {
  /** Replay matching events with a sequence number greater than this before going live. */
  since?: number;
  /** Only receive events whose payload matches every key/value here. */
  filter?: EventFilter;
}

/** Handle returned by `on` / `once`. */
export interface Subscription {
  readonly id: number;
  /** The event name this subscription listens for. */
  readonly event: StackEvent;
  unsubscribe(): void;
}

/** An event as retained for replay. */
export interface StoredEvent<E extends StackEvent = StackEvent> {
  /** Monotonic sequence number, assigned by the bus. */
  seq: number;
  event: E;
  payload: StackEventPayloads[E];
  /** When the bus accepted the event (unix ms). */
  at: number;
}

interface Subscriber {
  id: number;
  event: StackEvent;
  filter?: EventFilter;
  handler: (payload: unknown) => void;
  once: boolean;
}

/** Result of a `replay()` call — `truncated` means the cursor predates the retained window. */
export interface ReplayResult<E extends StackEvent = StackEvent> {
  events: StoredEvent<E>[];
  truncated: boolean;
}

export interface EventBusOptions {
  /** Maximum retained events for replay. Default 1000. */
  bufferLimit?: number;
  /** Called when a subscriber's handler throws, so one bad handler cannot hide itself. */
  onHandlerError?: (err: unknown, event: StackEvent, subscriberId: number) => void;
  /** Called when the durable store fails to persist an event. Delivery is unaffected. */
  onStoreError?: (err: unknown, event: StackEvent) => void;
}

const DEFAULT_BUFFER_LIMIT = 1000;

export class EventBus {
  private readonly bufferLimit: number;
  private readonly onHandlerError: EventBusOptions['onHandlerError'];
  private readonly onStoreError: EventBusOptions['onStoreError'];
  private readonly subscribers = new Map<number, Subscriber>();
  private readonly buffer: StoredEvent[] = [];
  private nextSubId = 1;
  private seq = 0;

  /** Optional durable sink. Appends are queued so their order matches emit order. */
  private store?: EventStore;
  private storeQueue: Promise<void> = Promise.resolve();

  constructor(opts: EventBusOptions = {}) {
    this.bufferLimit = Math.max(1, opts.bufferLimit ?? DEFAULT_BUFFER_LIMIT);
    this.onHandlerError = opts.onHandlerError;
    this.onStoreError = opts.onStoreError;
  }

  /**
   * Attach (or detach) the durable store. Every subsequent emit is appended to it.
   *
   * **Async because it seeds the sequence counter from the store.** A fresh process starts its counter at 0,
   * so without this the first events after a restart would reuse sequence numbers that already exist in the
   * outbox — `UNIQUE(sequence)` would reject the inserts, and the writes would be lost silently. Attaching is
   * therefore the moment the in-memory counter has to catch up with the durable high-water mark.
   *
   * Separate from the constructor because the store needs the agent's database, which does not exist until
   * an agent has been created or unlocked.
   */
  async attachStore(store: EventStore | undefined): Promise<void> {
    this.store = store;
    if (!store) return;
    await this.flush();
    const durable = await store.latestSequence();
    if (durable > this.seq) this.seq = durable;
  }

  /** True when a durable store is attached. */
  get isDurable(): boolean {
    return this.store !== undefined;
  }

  /** Wait for every queued store append to finish. Call before shutdown, and in tests. */
  async flush(): Promise<void> {
    await this.storeQueue;
  }

  /**
   * The cursor a caller should resume from later.
   *
   * Reads the durable high-water mark when a store is attached, so a cursor taken now is still valid after a
   * restart — which `latestSeq` alone cannot promise, since a fresh process starts its counter at 0 while the
   * outbox may already hold rows.
   */
  async latestDurableSeq(): Promise<number> {
    if (!this.store) return this.seq;
    await this.flush();
    return Math.max(this.seq, await this.store.latestSequence());
  }

  /** The most recently assigned sequence number (0 before the first emit). */
  get latestSeq(): number {
    return this.seq;
  }

  /**
   * The oldest sequence number still retained for replay, or `latestSeq + 1` when the buffer is empty.
   * A `since` cursor below `oldestSeq - 1` cannot be fully satisfied.
   */
  get oldestSeq(): number {
    return this.buffer.length > 0 ? this.buffer[0].seq : this.seq + 1;
  }

  /** Number of live subscriptions, optionally for one event. */
  listenerCount(event?: StackEvent): number {
    if (!event) return this.subscribers.size;
    let n = 0;
    for (const s of this.subscribers.values()) if (s.event === event) n++;
    return n;
  }

  /**
   * Publish an event. Assigns the next sequence number, retains it for replay, and delivers it
   * synchronously to every matching subscriber.
   *
   * @returns the sequence number assigned to this event.
   */
  emit<E extends StackEvent>(event: E, payload: StackEventPayloads[E]): number {
    if (!(STACK_EVENTS as readonly string[]).includes(event)) {
      throw new Error(`unknown stack event: ${String(event)} — add it to trust-app-api/events/catalog.ts`);
    }

    const seq = ++this.seq;
    const stored: StoredEvent = { seq, event, payload, at: Date.now() };

    this.buffer.push(stored);
    if (this.buffer.length > this.bufferLimit) {
      this.buffer.splice(0, this.buffer.length - this.bufferLimit);
    }

    // Durable append, queued so store order matches emit order. Delivery does not wait for it: an event that
    // reached a subscriber is real even if persistence fails, and blocking the emitter on I/O would turn a
    // slow disk into a delivery outage.
    if (this.store) {
      const store = this.store;
      this.storeQueue = this.storeQueue
        .then(() => store.append(stored))
        .catch((err) => {
          this.onStoreError?.(err, event);
        });
    }

    // Iterate a snapshot so subscription changes during delivery cannot corrupt the loop, but re-check
    // membership before each delivery: `unsubscribe()` takes effect **immediately**, including mid-delivery.
    // That matters for P4, where revoking a context must stop its events at once rather than after the
    // current pass.
    for (const sub of [...this.subscribers.values()]) {
      if (sub.event !== event) continue;
      if (!this.subscribers.has(sub.id)) continue;
      if (!matchesFilter(payload, sub.filter)) continue;
      if (sub.once) this.subscribers.delete(sub.id);
      try {
        sub.handler(payload);
      } catch (err) {
        this.onHandlerError?.(err, event, sub.id);
      }
    }

    return seq;
  }

  /** Subscribe to an event. With `since`, matching buffered events are delivered first. */
  on<E extends StackEvent>(
    event: E,
    handler: (payload: StackEventPayloads[E]) => void,
    opts: SubscribeOpts = {},
  ): Subscription {
    const sub: Subscriber = {
      id: this.nextSubId++,
      event,
      filter: opts.filter,
      handler: handler as (payload: unknown) => void,
      once: false,
    };

    if (opts.since !== undefined) {
      for (const stored of this.replay(event, { since: opts.since, filter: opts.filter }).events) {
        try {
          sub.handler(stored.payload);
        } catch (err) {
          this.onHandlerError?.(err, event, sub.id);
        }
      }
    }

    this.subscribers.set(sub.id, sub);
    return this.makeHandle(sub);
  }

  /** Subscribe for exactly one delivery. */
  once<E extends StackEvent>(
    event: E,
    handler: (payload: StackEventPayloads[E]) => void,
    opts: SubscribeOpts = {},
  ): Subscription {
    const sub: Subscriber = {
      id: this.nextSubId++,
      event,
      filter: opts.filter,
      handler: handler as (payload: unknown) => void,
      once: true,
    };
    this.subscribers.set(sub.id, sub);
    return this.makeHandle(sub);
  }

  /** Cancel a subscription. Idempotent. */
  off(sub: Subscription | undefined | null): void {
    if (sub) this.subscribers.delete(sub.id);
  }

  /**
   * Read retained events matching a cursor, without subscribing.
   *
   * `truncated` is true when `since` predates the retained window, i.e. some events were dropped and this
   * result is not a complete history. P3's outbox removes the possibility.
   */
  replay<E extends StackEvent>(
    event: E,
    opts: { since: number; filter?: EventFilter; limit?: number },
  ): ReplayResult<E> {
    const truncated = opts.since < this.oldestSeq - 1;
    const events: StoredEvent<E>[] = [];
    for (const stored of this.buffer) {
      if (stored.event !== event) continue;
      if (stored.seq <= opts.since) continue;
      if (!matchesFilter(stored.payload, opts.filter)) continue;
      events.push(stored as StoredEvent<E>);
      if (opts.limit !== undefined && events.length >= opts.limit) break;
    }
    return { events, truncated };
  }

  /** Drop every subscription and retained event. Used by tests and on agent switch. */
  clear(): void {
    this.subscribers.clear();
    this.buffer.length = 0;
  }

  /**
   * Read **durable** history from the attached store, surviving process restarts and exceeding the in-memory
   * window.
   *
   * The recommended pattern is to subscribe first and then read history, so nothing is missed in between:
   *
   * ```ts
   * const sub = stack.on('message.received', handler);
   * const { events } = await stack.replayDurable({ since: cursor });
   * ```
   *
   * With no store attached this falls back to the in-memory window, and `truncated` then tells the caller
   * whether that window was big enough.
   */
  async replayDurable(opts: {
    since: number;
    event?: StackEvent;
    filter?: EventFilter;
    limit?: number;
  }): Promise<ReplayResult> {
    if (!this.store) {
      const events = opts.event
        ? this.replay(opts.event, { since: opts.since, filter: opts.filter, limit: opts.limit }).events
        : this.buffer
            .filter((e) => e.seq > opts.since && matchesFilter(e.payload, opts.filter))
            .slice(0, opts.limit ?? undefined);
      const truncated = opts.since < this.oldestSeq - 1;
      return { events: events as StoredEvent[], truncated };
    }
    await this.flush(); // include appends already queued by emits earlier in this tick
    return this.store.read(opts);
  }

  private makeHandle(sub: Subscriber): Subscription {
    return {
      id: sub.id,
      event: sub.event,
      unsubscribe: () => {
        this.subscribers.delete(sub.id);
      },
    };
  }
}
