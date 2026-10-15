// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Resolve the SQLite migration assets shipped with this package.
 *
 * The `.sql` files and `SCHEMA_VERSION` live at the **package root**, not under `src/`, because
 * `tsc` only emits `.ts` — anything the library reads at runtime has to be listed in `files`
 * explicitly. From here (`<pkg>/src/db/` in development, `<pkg>/dist/db/` once built) the
 * expression `../../migrations/` lands on the same directory in BOTH layouts, so it keeps
 * working after publication, when `src/` is not in the tarball at all.
 *
 * Callers that need a different set of migrations (utility-server ships its own Postgres copies)
 * still pass their own path — this is only the default.
 */
import { fileURLToPath } from 'node:url';

export function getMigrationsDir(): string {
  return fileURLToPath(new URL('../../migrations/', import.meta.url));
}
