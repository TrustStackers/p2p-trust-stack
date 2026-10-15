// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Deduplicating console.log wrapper.
 *
 * Suppresses consecutive identical log messages. When a different message
 * appears between two identical ones, the second one is printed normally.
 *
 * Usage:
 *   import { dedupLog } from '../util/dedup-log.js';
 *   const log = dedupLog('[my-prefix]');
 *   log('message');  // printed
 *   log('message');  // suppressed (same as previous)
 *   log('other');    // printed (different)
 *   log('message');  // printed (intervening different message reset)
 */

const lastMessages = new Map<string, string>();

/**
 * Create a deduplicating logger for a given prefix.
 * Returns a function that behaves like console.log but suppresses
 * consecutive identical messages.
 */
export function dedupLog(prefix: string): (...args: unknown[]) => void {
  return (...args: unknown[]) => {
    const msg = args.map(a => String(a)).join(' ');
    const last = lastMessages.get(prefix);
    if (msg === last) return; // suppress duplicate
    lastMessages.set(prefix, msg);
    console.log(prefix, ...args);
  };
}

/**
 * Create a deduplicating logger for a given prefix (warn level).
 */
export function dedupWarn(prefix: string): (...args: unknown[]) => void {
  return (...args: unknown[]) => {
    const msg = args.map(a => String(a)).join(' ');
    const last = lastMessages.get(prefix);
    if (msg === last) return;
    lastMessages.set(prefix, msg);
    console.warn(prefix, ...args);
  };
}

/**
 * Create a deduplicating logger for a given prefix (error level).
 */
export function dedupError(prefix: string): (...args: unknown[]) => void {
  return (...args: unknown[]) => {
    const msg = args.map(a => String(a)).join(' ');
    const last = lastMessages.get(prefix);
    if (msg === last) return;
    lastMessages.set(prefix, msg);
    console.error(prefix, ...args);
  };
}