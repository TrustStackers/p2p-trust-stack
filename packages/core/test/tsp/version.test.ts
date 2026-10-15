// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for the TSP version string codec (Rev 3).
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/tsp/version.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  encodeTspVersion,
  decodeTspVersion,
  TSP_VERSION_CODE,
  TSP_VERSION_0_2,
  TSP_CURRENT_VERSION,
  TSP_CURRENT_VERSION_STRING,
} from '../../src/tsp/version.js';

test('encode 0.2 produces YTSP-AAC', () => {
  assert.equal(encodeTspVersion(0, 2), 'YTSP-AAC');
});

test('TSP_VERSION_0_2 equals YTSP-AAC and decodes to 0.2', () => {
  assert.equal(TSP_VERSION_0_2, 'YTSP-AAC');
  assert.deepEqual(decodeTspVersion(TSP_VERSION_0_2), { major: 0, minor: 2 });
});

test('TSP_CURRENT_VERSION is 0.2 and its string is YTSP-AAC', () => {
  assert.deepEqual(TSP_CURRENT_VERSION, { major: 0, minor: 2 });
  assert.equal(TSP_CURRENT_VERSION_STRING, 'YTSP-AAC');
});

test('encode/decode round trips across the value range', () => {
  const cases: Array<[number, number]> = [
    [0, 0], [0, 1], [0, 2], [0, 63], [0, 64], [0, 4095],
    [1, 0], [1, 1], [63, 0], [63, 4095], [10, 123],
  ];
  for (const [major, minor] of cases) {
    const encoded = encodeTspVersion(major, minor);
    assert.equal(encoded.length, 8, `${major}.${minor} should be 8 chars`);
    assert.ok(encoded.startsWith(TSP_VERSION_CODE), `${encoded} should start with YTSP-`);
    assert.deepEqual(decodeTspVersion(encoded), { major, minor });
  }
});

test('minor encoding uses base64url: YTSP-AAC => minor 2, YTSP-AA_ => minor 63', () => {
  assert.deepEqual(decodeTspVersion('YTSP-AA_'), { major: 0, minor: 63 });
  assert.deepEqual(decodeTspVersion('YTSP-AA-'), { major: 0, minor: 62 });
});

test('encodeTspVersion rejects out-of-range values', () => {
  assert.throws(() => encodeTspVersion(64, 0), RangeError);
  assert.throws(() => encodeTspVersion(-1, 0), RangeError);
  assert.throws(() => encodeTspVersion(0, 4096), RangeError);
  assert.throws(() => encodeTspVersion(0, -1), RangeError);
  assert.throws(() => encodeTspVersion(0.5, 0), RangeError);
});

test('decodeTspVersion rejects malformed strings', () => {
  assert.throws(() => decodeTspVersion('YTSP-AA'), SyntaxError);        // too short
  assert.throws(() => decodeTspVersion('YTSP-AACC'), SyntaxError);      // too long
  assert.throws(() => decodeTspVersion('KERI-AAC'), SyntaxError);       // wrong prefix
  assert.throws(() => decodeTspVersion('YTSP-AA$'), SyntaxError);       // bad char
});
