// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * DatabaseSync wrapper + pragma setup for the utility server.
 */

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * Open (creating parent directories if needed) a SQLite database with the
 * pragmas this server relies on: foreign key enforcement and WAL mode for
 * concurrent read/write access.
 */
export function openDatabase(dbPath: string): InstanceType<typeof DatabaseSync> {
  if (dbPath !== ':memory:') {
    mkdirSync(dirname(dbPath), { recursive: true });
  }

  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('PRAGMA journal_mode = WAL');
  return db;
}
