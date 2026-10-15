// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { DataSource } from './data-source.js';
import { getMigrationsDir } from './migrations-dir.js';

async function ensureLedger(ds: DataSource): Promise<void> {
  await ds.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      filename    TEXT PRIMARY KEY,
      applied_at  BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
    )
  `);
}

async function alreadyApplied(ds: DataSource, filename: string): Promise<boolean> {
  const row = await ds.get('SELECT 1 FROM schema_migrations WHERE filename = ?', filename);
  return row !== null;
}

async function markApplied(ds: DataSource, filename: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await ds.run('INSERT INTO schema_migrations (filename, applied_at) VALUES (?, ?)', filename, now);
}

function readExpectedVersion(migrationsDir: string): number {
  const content = readFileSync(join(migrationsDir, '..', 'SCHEMA_VERSION'), 'utf8').trim();
  const version = parseInt(content, 10);
  if (isNaN(version)) throw new Error(`SCHEMA_VERSION file contains invalid version: "${content}"`);
  return version;
}

async function getRecordedVersion(ds: DataSource): Promise<number | undefined> {
  const row = await ds.get<{ filename: string }>(
    "SELECT filename FROM schema_migrations WHERE filename LIKE '__schema_version__:%'",
  );
  if (!row) return undefined;
  const parts = row.filename.split(':');
  const v = parseInt(parts[1], 10);
  return isNaN(v) ? undefined : v;
}

async function setRecordedVersion(ds: DataSource, version: number): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await ds.run(
    "INSERT INTO schema_migrations (filename, applied_at) VALUES (?, ?) ON CONFLICT (filename) DO UPDATE SET applied_at = ?",
    `__schema_version__:${version}`, now, now,
  );
}

export async function runDataSourceMigrations(
  ds: DataSource,
  migrationsDir: string = getMigrationsDir(),
): Promise<string[]> {
  await ensureLedger(ds);

  const expectedVersion = readExpectedVersion(migrationsDir);
  const recordedVersion = await getRecordedVersion(ds);
  if (recordedVersion !== undefined && recordedVersion > expectedVersion) {
    throw new Error(`Database schema version (${recordedVersion}) is newer than this application's expected version (${expectedVersion}).`);
  }

  const files = readdirSync(migrationsDir).filter((f: string) => f.endsWith('.sql')).sort();
  const applied: string[] = [];

  for (const filename of files) {
    if (await alreadyApplied(ds, filename)) continue;
    const sql = readFileSync(join(migrationsDir, filename), 'utf8');
    await ds.transaction(async (tx) => {
      try {
        await tx.exec(sql);
        await markApplied(tx, filename);
      } catch (err) {
        throw new Error(`Migration failed: ${filename}: ${(err as Error).message}`);
      }
    });
    applied.push(filename);
  }

  await setRecordedVersion(ds, expectedVersion);
  return applied;
}