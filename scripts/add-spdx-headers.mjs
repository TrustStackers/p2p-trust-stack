#!/usr/bin/env node
// SPDX header tool for the P2P Trust Stack.
//
// Usage:
//   node scripts/add-spdx-headers.mjs <root-dir> [...]           # add headers (idempotent)
//   node scripts/add-spdx-headers.mjs --check <root-dir> [...]   # verify; exit 1 if any missing
//
// Options:
//   --license=<SPDX expression>  default: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
//   --copyright=<text>           default: Copyright (C) 2026 Trust Stackers
//   --exclude=<dir-name>         skip a directory by name (repeatable), e.g. examples
//
// A leading BOM and a leading shebang line are preserved. Generated output
// (dist/, node_modules/) is ignored.

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, extname } from 'node:path';

const DEFAULT_LICENSE_ID = 'GPL-3.0-only OR LicenseRef-TrustStackers-Commercial';
const DEFAULT_COPYRIGHT = 'Copyright (C) 2026 Trust Stackers';

const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', 'coverage', '.smoke']);
const COMMENT = {
  '.ts': '//',
  '.mts': '//',
  '.cts': '//',
  '.js': '//',
  '.mjs': '//',
  '.cjs': '//',
  '.sql': '--',
};

const args = process.argv.slice(2);
const check = args.includes('--check');

function flag(name) {
  const hit = args.find((a) => a.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : undefined;
}

const LICENSE_ID = flag('--license') || DEFAULT_LICENSE_ID;
const COPYRIGHT = flag('--copyright') || DEFAULT_COPYRIGHT;
const EXCLUDES = args
  .filter((a) => a.startsWith('--exclude='))
  .map((a) => a.slice('--exclude='.length));
const roots = args.filter((a) => !a.startsWith('--'));

if (roots.length === 0) {
  console.error(
    'usage: add-spdx-headers.mjs [--check] [--license=<SPDX>] [--copyright=<text>] ' +
      '[--exclude=<dir>]... <root-dir> [...]',
  );
  process.exit(2);
}

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      if (EXCLUDES.includes(entry.name)) continue;
      yield* walk(join(dir, entry.name));
    } else if (entry.isFile()) {
      yield join(dir, entry.name);
    }
  }
}

// A real header is a comment line naming the SPDX identifier near the top of
// the file (after an optional BOM and shebang). A bare substring test is wrong:
// this very script *mentions* the identifier in its own source.
const HEADER_RE = /^(?:\uFEFF)?(?:#![^\n]*\n\s*)?(?:\/\/|--)\s*SPDX-License-Identifier:/;

function hasHeader(text) {
  return HEADER_RE.test(text);
}

let added = 0;
let ok = 0;
const missing = [];

for (const root of roots) {
  for (const file of walk(root)) {
    const prefix = COMMENT[extname(file)];
    if (!prefix) continue;

    const original = readFileSync(file, 'utf8');
    if (hasHeader(original)) {
      ok++;
      continue;
    }
    if (check) {
      missing.push(file);
      continue;
    }

    const header = `${prefix} SPDX-License-Identifier: ${LICENSE_ID}\n${prefix} ${COPYRIGHT}\n`;

    let body = original;
    let bom = '';
    if (body.startsWith('\uFEFF')) {
      bom = '\uFEFF';
      body = body.slice(1);
    }

    let shebang = '';
    if (body.startsWith('#!')) {
      const nl = body.indexOf('\n');
      if (nl !== -1) {
        shebang = `${body.slice(0, nl + 1)}\n`;
        body = body.slice(nl + 1);
      }
    }

    writeFileSync(file, `${bom}${shebang}${header}\n${body}`);
    added++;
  }
}

if (check) {
  if (missing.length) {
    console.error(`FAIL: ${missing.length} file(s) are missing an SPDX header:`);
    for (const file of missing) console.error(`  - ${file}`);
    console.error('\nFix: node scripts/add-spdx-headers.mjs <root-dir>');
    process.exit(1);
  }
  console.log(`OK: all ${ok} source file(s) carry an SPDX header.`);
} else {
  console.log(`SPDX headers added: ${added}; already present (skipped): ${ok}`);
}
