#!/usr/bin/env node
/**
 * Packed-tarball smoke test — the gate that proves the package works when INSTALLED.
 *
 * Every other suite resolves through a symlink whose real path is outside `node_modules`, so none
 * of them can see the failure modes that only appear for a real consumer. This test extracts the
 * published tarball into a throwaway `node_modules` and drives the real public API:
 *
 *   - the `.sql` files and `SCHEMA_VERSION` are actually IN the tarball (`files`) — the R1 defect
 *   - `getMigrationsDir()` resolves to the shipped assets
 *   - `runMigrations(db)` applies all of them with NO explicit path
 *
 * It exists because a source-based `exports` map passed every in-repo suite and still could not be
 * installed (`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`).
 *
 * Run: npm run smoke:pack
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PKGS = ['core', 'app-api'];
const EXPECTED_MIGRATIONS = 20;

let failures = 0;
const ok = (m) => console.log(`  ok   ${m}`);
const bad = (m) => { failures++; console.log(`  FAIL ${m}`); };

// Inside the repo on purpose: the packed packages are the NEAREST match, so `@p2p-trust-stack/*`
// resolves to the TARBALL, while their third-party deps fall back to the repo's own install. So this
// validates the package's layout, exports map and shipped assets — not a hermetic dependency
// install. A fully hermetic `npm install <tarball>` belongs in the public repo's CI (Phase 3).
const work = join(ROOT, '.smoke');
rmSync(work, { recursive: true, force: true });
mkdirSync(work, { recursive: true });
try {
  for (const name of PKGS) {
    const dir = join(ROOT, 'packages', name);
    const tgz = execFileSync('npm', ['pack', '--silent'], { cwd: dir, encoding: 'utf8' })
      .trim().split('\n').pop();
    const tgzPath = join(dir, tgz);
    if (!existsSync(tgzPath)) { bad(`${name}: npm pack produced no tarball`); continue; }
    ok(`${name}: packed ${tgz}`);

    const dest = join(work, 'node_modules', '@p2p-trust-stack', name);
    mkdirSync(dest, { recursive: true });
    execFileSync('tar', ['-xzf', tgzPath, '-C', dest, '--strip-components=1']);
    rmSync(tgzPath, { force: true });

    for (const p of ['dist', 'package.json']) {
      if (!existsSync(join(dest, p))) bad(`${name}: tarball is missing ${p}`);
    }
    if (name === 'core') {
      if (!existsSync(join(dest, 'migrations'))) bad('core: tarball is missing migrations/');
      if (!existsSync(join(dest, 'SCHEMA_VERSION'))) bad('core: tarball is missing SCHEMA_VERSION');
      const sql = existsSync(join(dest, 'migrations'))
        ? readdirSync(join(dest, 'migrations')).filter((f) => f.endsWith('.sql')).length : 0;
      if (sql === 0) bad('core: no .sql files shipped'); else ok(`core: ${sql} .sql files shipped`);
    }
  }

  // Drive the real public API from the installed layout, with no explicit migrations path.
  writeFileSync(join(work, 'consumer.mjs'), [
    "import { DatabaseSync } from 'node:sqlite';",
    "import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';",
    "import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';",
    "import * as appApi from '@p2p-trust-stack/app-api';", // the BARE package root — the documented entry point
    'const dir = getMigrationsDir();',
    "const db = new DatabaseSync(':memory:');",
    'const applied = runMigrations(db);',
    "const ledger = db.prepare('SELECT count(*) AS c FROM schema_migrations').get();",
    'const t = db.prepare("SELECT name FROM sqlite_master"',
    '  + " WHERE type=\'table\' AND name=\'identities\'").get();',
    'console.log(JSON.stringify({ dir, applied: applied.length, ledger: ledger.c,',
    '  identities: !!t, appApiExports: Object.keys(appApi).length }));',
  ].join('\n'));

  const out = execFileSync('node', ['consumer.mjs'], { cwd: work, encoding: 'utf8' }).trim();
  const r = JSON.parse(out.split('\n').pop());
  if (r.applied === EXPECTED_MIGRATIONS) {
    ok(`installed: runMigrations() applied ${r.applied} migrations with no explicit path`);
  } else {
    bad(`installed: expected ${EXPECTED_MIGRATIONS} migrations, got ${r.applied}`);
  }
  if (r.identities) ok('installed: identities table created');
  else bad('installed: identities table missing');
  // The root export is the one an application is meant to import. A `"./*"` pattern alone does NOT
  // cover it — the bare specifier maps to `"."`, so this catches an exports map that only lists subpaths.
  if (r.appApiExports > 0) ok(`installed: bare '@p2p-trust-stack/app-api' exports ${r.appApiExports} names`);
  else bad("installed: bare '@p2p-trust-stack/app-api' resolved to an empty module");
  ok(`installed: resolved to ${r.dir}`);
} finally {
  rmSync(work, { recursive: true, force: true });
}

if (failures) {
  console.error(`\nsmoke:pack FAILED (${failures} problem(s))`);
  process.exit(1);
}
console.log('\nsmoke:pack OK');
