// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * CompensationRegistry — durable undo for application-variable rollback.
 *
 * Unlike the reference implementation (which stores closures), the production
 * layer stores serializable UndoDescriptors. A CompensationExecutor replays
 * them in reverse (LIFO) order on abort.
 *
 * Handlers are registered by the application at startup for each undo type
 * (e.g., 'setVar', 'incrementCounter', 'updateUiState').
 */

import type { CompensationHandler, UndoDescriptor } from './types.js';

/**
 * CompensationExecutor — replays UndoDescriptors in reverse order.
 *
 * Application code registers CompensationHandlers for each undo type.
 * On abort, the executor runs all descriptors in LIFO order, catching
 * and logging individual handler errors so one failed undo doesn't
 * prevent the rest from running.
 */
export class CompensationExecutor {
  private readonly handlers = new Map<string, CompensationHandler>();

  /** Register a handler for a given undo descriptor type. */
  register(handler: CompensationHandler): void {
    this.handlers.set(handler.type, handler);
  }

  /**
   * Execute all undo descriptors in reverse (LIFO) order.
   * Individual handler errors are caught and collected — one failed undo
   * does not prevent subsequent undos from running.
   *
   * @returns Array of error messages from failed undos (empty if all succeeded).
   */
  async execute(descriptors: UndoDescriptor[]): Promise<string[]> {
    const errors: string[] = [];
    for (let i = descriptors.length - 1; i >= 0; i--) {
      const desc = descriptors[i];
      const handler = this.handlers.get(desc.type);
      if (!handler) {
        errors.push(`no CompensationHandler registered for type '${desc.type}'`);
        continue;
      }
      try {
        await handler.execute(desc);
      } catch (err) {
        errors.push(
          `compensation '${desc.type}' failed: ${(err as Error)?.message ?? String(err)}`,
        );
      }
    }
    return errors;
  }
}