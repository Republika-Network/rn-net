// RN-NET-03B2-WP2: the fork-aware gas rules as repository facts.
//   - the committed vectors are current;
//   - the module stays pure: its imports are fixed, and it names no clock, environment or network;
//   - it is NOT wired into preparation, signing, broadcasting, C6 or gate F;
//   - the live switches are unchanged.
// Offline; reads files only.
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { build, DIR, FILE, runCase } from './gas-rules/build-gas-rules-vectors.mjs';

const ROOT = new URL('../', import.meta.url);
const read = (path) => readFileSync(new URL(path, ROOT), 'utf8');
const MODULE = 'packages/tx-intent/src/gas-rules.mjs';
const SKIP = new Set(['.git', 'node_modules', 'fixtures']);
const walk = (dir) =>
  readdirSync(new URL(dir, ROOT), { withFileTypes: true }).flatMap((e) => {
    const path = dir === './' ? e.name : `${dir}${e.name}`;
    if (e.isDirectory()) return SKIP.has(e.name) ? [] : walk(`${path}/`);
    return path.endsWith('.mjs') ? [path] : [];
  });

test('the committed gas-rules vectors are exactly what the builder produces', () => {
  assert.equal(readFileSync(DIR + FILE, 'utf8'), build());
});

test('every committed vector replays to its recorded outcome', () => {
  const { cases } = JSON.parse(readFileSync(DIR + FILE, 'utf8'));
  assert.ok(cases.length >= 150);
  for (const c of cases) assert.deepEqual(runCase(c), c.expect, c.name);
});

test('the gas-rules module imports only its fixed dependencies', () => {
  const imports = [...read(MODULE).matchAll(/^import .* from '([^']+)';$/gm)].map((m) => m[1]);
  assert.deepEqual(imports, ['node:buffer', 'node:crypto', '../../canonical/src/index.mjs', '../../anchor/src/index.mjs', './errors.mjs', './genesis.mjs']);
  assert.doesNotMatch(read(MODULE), /\bimport\s*\(/);
});

test('the gas-rules module names no clock, environment, randomness or network capability', () => {
  const code = read(MODULE).replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
  for (const name of ['Date', 'process', 'performance', 'setTimeout', 'setInterval', 'random', 'fetch', 'require', 'globalThis', 'env', 'hrtime', 'WebSocket']) {
    assert.doesNotMatch(code, new RegExp(`\\b${name}\\b`), name);
  }
});

test('the engine reaches only tx-prepare\'s v2 path (WP3); WP2 itself wired it into nothing else', () => {
  const NAMES = /\b(evaluateGenesisGas|selectSepoliaGasRules|calldataGas|calldataGasForInput|checkForkBoundary|validateReviewedRulesHorizon|validateGenesisGasPreconditions|SEPOLIA_GAS_RULES_REVIEW|gas-rules\.mjs)\b/;
  const files = walk('./');
  assert.ok(files.length > 100);
  const users = files.filter((f) => NAMES.test(read(f)));
  assert.deepEqual(users.sort(), [
    'packages/tx-intent/src/gas-rules.mjs',
    'packages/tx-intent/src/index.mjs',
    'packages/tx-intent/test/gas-rules.test.mjs',
    // RN-NET-03B2-WP3: the offline v2 preparation and verifier, their unit tests and the v2 fixture
    // test. tools/preparation-v2.test.mjs proves no operational caller (prepare-live, rehearsal,
    // submit, signer, txverify) uses the v2 path.
    ['packages', 'tx-prepare', 'src', 'prepare-v2.mjs'].join('/'), // built from parts: the import scans read text
    ['packages', 'tx-prepare', 'test', 'tx-prepare-v2.test.mjs'].join('/'),
    'tools/gas-rules.test.mjs',
    'tools/gas-rules/build-gas-rules-vectors.mjs',
    'tools/preparation-v2.test.mjs',
  ]);
});

test('the live switches are unchanged (WP2 is offline only)', () => {
  for (const f of ['tools/compat-live/compat-live.mjs', 'tools/prepare/prepare-live.mjs', 'tools/submit/submit-anchor.mjs', 'tools/submit/status-check.mjs']) {
    assert.match(read(f), /^export const LIVE_NETWORK_ACCESS = false;$/m, f);
  }
  for (const f of ['tools/compat-live/entry.mjs', 'tools/prepare/entry.mjs']) assert.match(read(f), /^export const AGREED_EVIDENCE_DIR = null;$/m, f);
  assert.match(read(MODULE), /^export const SEPOLIA_GAS_RULES_REVIEW = null;$/m);
});
