// RN-NET-03B2-WP3: the v2 fixtures, the test seam's importers, v1 untouched, live switches unchanged.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { verifySepoliaPreparationV2WithAuthority, prepareSepoliaIntentV2WithAuthority } from '../packages/tx-prepare/src/prepare-v2.mjs';
import { fakeTransport } from '../packages/tx-prepare/test/fake-providers.mjs';
import { build, PATH } from './preparation-v2/build-v2-fixtures.mjs';

const ROOT = new URL('../', import.meta.url);
const read = (path) => readFileSync(new URL(path, ROOT), 'utf8');
const SKIP = new Set(['.git', 'node_modules', 'fixtures']);
const walk = (dir) =>
  readdirSync(new URL(dir, ROOT), { withFileTypes: true }).flatMap((e) => {
    const path = dir === './' ? e.name : `${dir}${e.name}`;
    if (e.isDirectory()) return SKIP.has(e.name) ? [] : walk(`${path}/`);
    return path.endsWith('.mjs') ? [path] : [];
  });
const doc = JSON.parse(readFileSync(PATH, 'utf8'));

test('the committed v2 fixtures are exactly what the builder produces', async () => {
  assert.equal(readFileSync(PATH, 'utf8'), await build());
});

test('every v2 preparation replays from its recorded exchanges to its recorded result', async () => {
  assert.ok(doc.preparations.length >= 30);
  for (const c of doc.preparations) {
    // Answer each request from the recording only, in order, per provider.
    const queues = new Map();
    for (const e of c.exchanges) queues.set(e.providerId, [...(queues.get(e.providerId) ?? []), e]);
    const transport = async (request) => {
      const e = queues.get(request.providerId)?.shift();
      assert.ok(e, `${c.id}: unexpected request`);
      assert.equal(Buffer.from(request.body).toString('utf8'), e.request, c.id);
      if (e.error) throw Object.assign(new Error(e.error), { code: e.error });
      return { status: e.response.status, body: new TextEncoder().encode(e.response.body) };
    };
    let got;
    try {
      const { intent, digest } = await prepareSepoliaIntentV2WithAuthority({ ...c.input, providers: c.input.providers, transport }, c.testRulesReview);
      got = { outcome: 'PASS', code: null, providerId: null, gasRules: null, blocked: null, digest, intent };
    } catch (error) {
      assert.equal(error.name, 'PrepError', `${c.id}: ${error.message}`);
      got = { outcome: 'FAIL', code: error.code, providerId: error.providerId, gasRules: error.gasRules ?? null, blocked: error.blocked, digest: null, intent: null };
    }
    assert.deepEqual(JSON.parse(JSON.stringify(got)), c.expected, c.id);
    assert.ok([...queues.values()].every((q) => q.length === 0), `${c.id}: unused exchanges`);
  }
  assert.equal(typeof fakeTransport, 'function');
});

test('every v2 record verifies to its recorded outcome (valid, tampered, downgraded)', () => {
  assert.ok(doc.records.length >= 40);
  for (const r of doc.records) {
    let got;
    try {
      verifySepoliaPreparationV2WithAuthority(r.intent, r.approvedDigest, r.testRulesReview);
      got = 'PASS';
    } catch (error) {
      assert.equal(error.name, 'PrepError', `${r.id}: ${error.message}`);
      got = [error.code, error.gasRules ?? null];
    }
    assert.deepEqual(got, r.expected, r.id);
  }
});

test('the authority test seam (prepare-v2.mjs) is imported only by tx-prepare, its tests and the WP3 fixtures', () => {
  const users = walk('./').filter((f) => /^(?:import|export) [^;]* from '[^']*prepare-v2\.mjs';$/m.test(read(f)));
  assert.deepEqual(users.sort(), [
    'packages/tx-prepare/src/index.mjs',
    'packages/tx-prepare/test/tx-prepare-v2.test.mjs',
    'tools/preparation-v2.test.mjs',
    'tools/preparation-v2/build-v2-fixtures.mjs',
  ]);
  assert.doesNotMatch(read('packages/tx-prepare/src/index.mjs'), /WithAuthority/);
  // Nothing operational calls the v2 path yet: not tools/prepare/, the rehearsal, the signer or submit.
  for (const f of walk('./').filter((p) => p.startsWith('tools/prepare/') || p.startsWith('tools/rehearsal/') || p.startsWith('tools/submit/') || p.startsWith('signer/') || p.startsWith('txverify/'))) {
    assert.doesNotMatch(read(f), /prepareSepoliaIntentV2|verifySepoliaPreparationV2|tx-preparation\.v2/, f);
  }
});

test('the live switches and the gas-rules review are unchanged (WP3 is offline only)', () => {
  for (const f of ['tools/compat-live/compat-live.mjs', 'tools/prepare/prepare-live.mjs', 'tools/submit/submit-anchor.mjs', 'tools/submit/status-check.mjs']) {
    assert.match(read(f), /^export const LIVE_NETWORK_ACCESS = false;$/m, f);
  }
  for (const f of ['tools/compat-live/entry.mjs', 'tools/prepare/entry.mjs']) assert.match(read(f), /^export const AGREED_EVIDENCE_DIR = null;$/m, f);
  assert.match(read('packages/tx-intent/src/gas-rules.mjs'), /^export const SEPOLIA_GAS_RULES_REVIEW = null;$/m);
  assert.match(read('tools/guards/dependency-boundaries.mjs'), /^export const PREPARE_TRANSPORT_JOINERS = \[\];$/m);
});
