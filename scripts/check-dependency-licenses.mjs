#!/usr/bin/env node
// Fail if any runtime dependency of the published packages carries a copyleft
// license (GPL / AGPL / LGPL / SSPL / EUPL).
//
// Policy: CONTRIBUTING.md, "Dependency policy (hard rule)".
//
// Usage: node scripts/check-dependency-licenses.mjs [package-dir ...]
// Default targets: packages/* (any subdirectory containing a package.json).
//
// Walks the full runtime closure (dependencies + optionalDependencies +
// peerDependencies) and reads each package's declared license. First-party
// packages (@p2p-trust-stack/*) are exempt from the license test, but their
// dependencies are still walked.

import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';

const COPYLEFT = /\b(A?L?GPL|SSPL|EUPL)\b/i;
const FIRST_PARTY = /^@p2p-trust-stack\//;

function stripOuterParens(expr) {
  let e = expr.trim();
  for (;;) {
    if (!(e.startsWith('(') && e.endsWith(')'))) break;
    let depth = 0;
    let wraps = true;
    for (let i = 0; i < e.length; i++) {
      if (e[i] === '(') depth++;
      else if (e[i] === ')') {
        depth--;
        if (depth === 0 && i !== e.length - 1) { wraps = false; break; }
      }
    }
    if (!wraps) break;
    e = e.slice(1, -1).trim();
  }
  return e;
}

function splitTopLevel(expr, op) {
  const parts = [];
  let depth = 0;
  let cur = '';
  for (let i = 0; i < expr.length; i++) {
    const c = expr[i];
    if (c === '(') depth++;
    else if (c === ')') depth--;
    if (depth === 0 && expr.startsWith(op, i)) {
      parts.push(cur);
      cur = '';
      i += op.length - 1;
      continue;
    }
    cur += c;
  }
  parts.push(cur);
  return parts.map((s) => s.trim()).filter(Boolean);
}

// Acceptable if some OR branch is permissive and every AND branch is permissive.
function isPermissive(expr) {
  expr = stripOuterParens(expr);
  const or = splitTopLevel(expr, ' OR ');
  if (or.length > 1) return or.some(isPermissive);
  const and = splitTopLevel(expr, ' AND ');
  if (and.length > 1) return and.every(isPermissive);
  const term = expr.replace(/[()]/g, '').trim();
  if (!term || /^UNLICENSED$/i.test(term)) return false;
  return !COPYLEFT.test(term);
}

function licenseOf(pkg) {
  if (typeof pkg.license === 'string' && pkg.license.trim()) return pkg.license.trim();
  if (pkg.license && typeof pkg.license === 'object' && pkg.license.type) return pkg.license.type;
  if (Array.isArray(pkg.licenses)) {
    const ids = pkg.licenses.map((l) => (typeof l === 'string' ? l : l && l.type)).filter(Boolean);
    if (ids.length) return ids.join(' OR ');
  }
  return null;
}

// Locate a package's package.json by walking up the node_modules chain from
// `fromDir`. Robust against `exports` maps that do not expose ".".
function resolvePackageJson(name, fromDir) {
  let dir = resolve(fromDir);
  for (;;) {
    const candidate = join(dir, 'node_modules', name, 'package.json');
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function targetDirs(args) {
  if (args.length) return args.map((a) => resolve(a));
  if (!existsSync('packages')) {
    console.error('No packages/ directory here; pass package dirs explicitly.');
    process.exit(2);
  }
  return readdirSync('packages')
    .map((name) => resolve(join('packages', name)))
    .filter((dir) => existsSync(join(dir, 'package.json')));
}

const state = { seen: new Set(), copyleft: [], unknown: [], unresolved: [], checked: 0 };

function runtimeDeps(pkg) {
  return {
    ...(pkg.dependencies ?? {}),
    ...(pkg.optionalDependencies ?? {}),
    ...(pkg.peerDependencies ?? {}),
  };
}

function visit(name, fromPkgJson) {
  if (state.seen.has(name)) return;
  state.seen.add(name);

  const pkgJsonPath = resolvePackageJson(name, dirname(fromPkgJson));
  if (!pkgJsonPath) {
    state.unresolved.push(name);
    return;
  }

  let pkg;
  try {
    pkg = JSON.parse(readFileSync(pkgJsonPath, 'utf8'));
  } catch {
    state.unresolved.push(name);
    return;
  }

  state.checked++;
  if (!FIRST_PARTY.test(name)) {
    const license = licenseOf(pkg);
    if (!license) state.unknown.push(name);
    else if (!isPermissive(license)) state.copyleft.push({ name, license, pkgJsonPath });
  }

  for (const dep of Object.keys(runtimeDeps(pkg))) visit(dep, pkgJsonPath);
}

const targets = targetDirs(process.argv.slice(2));
for (const dir of targets) {
  const pkgJsonPath = join(dir, 'package.json');
  const pkg = JSON.parse(readFileSync(pkgJsonPath, 'utf8'));
  for (const dep of Object.keys(runtimeDeps(pkg))) visit(dep, pkgJsonPath);
}

console.log(`Checked ${state.checked} runtime package(s) across ${targets.length} target(s).`);

if (state.unknown.length) {
  console.log(`\nWarning: ${state.unknown.length} package(s) declare no license:`);
  for (const n of state.unknown) console.log(`  - ${n}`);
}
if (state.unresolved.length) {
  console.log(`\nNote: ${state.unresolved.length} dependency name(s) not installed locally (optional/platform peers):`);
  for (const n of state.unresolved) console.log(`  - ${n}`);
}

if (state.copyleft.length) {
  console.error(`\nFAIL: ${state.copyleft.length} copyleft runtime dependency(ies) found:`);
  for (const { name, license, pkgJsonPath } of state.copyleft) {
    console.error(`  - ${name}: ${license}  (${pkgJsonPath})`);
  }
  console.error('\nPolicy: CONTRIBUTING.md — no GPL/AGPL/LGPL/SSPL/EUPL runtime dependencies.');
  process.exit(1);
}

console.log('\nOK: no copyleft runtime dependencies.');
