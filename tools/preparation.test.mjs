// RN-NET-03B2-B2 fixtures (fixtures/preparation-b2): the committed corpus is current, and every
// case gives its recorded result when packages/tx-prepare is run on the recorded exchanges alone.
// Offline: the only transport replays the corpus. tools/reference/rnnet_prep_reference.py checks
// the same corpus independently.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalBytes } from '../packages/canonical/src/index.mjs';
import { prepareSepoliaIntent, prepareXrplIntent } from '../packages/tx-prepare/src/index.mjs';
import { build, CASES, INPUT_CASES, PATH } from './preparation/build-b2-fixtures.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const corpus = JSON.parse(readFileSync(PATH, 'utf8'));

/** Answers only from a case's recorded exchanges, in order per provider; anything else fails the test. */
function replay(exchanges) {
  const queues = new Map();
  for (const e of exchanges) {
    if (!queues.has(e.providerId)) queues.set(e.providerId, []);
    queues.get(e.providerId).push(e);
  }
  const transport = async (request) => {
    const next = queues.get(request.providerId)?.shift();
    assert.ok(next, `no recorded exchange for ${request.providerId}`);
    assert.equal(Buffer.from(request.body).toString('utf8'), next.request);
    if (next.error) throw Object.assign(new Error(next.error), { code: next.error });
    return { status: next.response.status, body: new Uint8Array(Buffer.from(next.response.body, 'utf8')) };
  };
  transport.unused = () => [...queues.values()].reduce((n, q) => n + q.length, 0);
  return transport;
}

test('the committed corpus is current and canonical', async () => {
  assert.equal(readFileSync(PATH, 'utf8'), await build());
  assert.equal(corpus.format, 'rnnet.preparation-b2-fixtures.v2');
  assert.equal(corpus.cases.length, CASES.length + INPUT_CASES.length);
  assert.equal(new Set(corpus.cases.map((c) => c.id)).size, corpus.cases.length);
});

test('every case reproduces from its recorded exchanges', async () => {
  for (const c of corpus.cases) {
    const transport = replay(c.exchanges);
    const providers = c.input.providers;
    const prepare = c.network === 'xrpl:testnet' ? prepareXrplIntent : prepareSepoliaIntent;
    let got;
    try {
      const { intent, digest } = await prepare({ ...c.input, providers, transport });
      got = { outcome: 'PASS', code: null, providerId: null, blocked: null, digest, intent };
    } catch (error) {
      assert.equal(error.name, 'PrepError', `${c.id}: ${error.message}`);
      got = { outcome: 'FAIL', code: error.code, providerId: error.providerId, blocked: error.blocked, digest: null, intent: null };
    }
    assert.deepEqual(Buffer.from(canonicalBytes(got)), Buffer.from(canonicalBytes(c.expected)), c.id);
    assert.equal(transport.unused(), 0, `${c.id}: unused exchanges`);
  }
});

test('the corpus covers every refusal code and only synthetic hosts', () => {
  const codes = new Set(corpus.cases.map((c) => c.expected.code));
  for (const code of ['RNTP_INTENT_INVALID', 'RNTP_INPUT_INVALID', 'RNTP_PROVIDER_UNAVAILABLE', 'RNTP_PROVIDER_ERROR', 'RNTP_MALFORMED', 'RNTP_WRONG_NETWORK', 'RNTP_NOT_SYNCED', 'RNTP_STALE',
    'RNTP_INCONSISTENT', 'RNTP_ACCOUNT_NOT_FOUND', 'RNTP_ACCOUNT_UNSUITABLE', 'RNTP_FEE_TOO_HIGH', 'RNTP_GAS_TOO_HIGH', 'RNTP_NONCE_PENDING', 'RNTP_INSUFFICIENT_BALANCE']) {
    assert.ok(codes.has(code), code);
  }
  assert.ok(corpus.cases.filter((c) => c.expected.outcome === 'PASS').length >= 8);
  for (const c of corpus.cases) for (const p of c.input.providers) assert.match(p.url, /^https:\/\/[a-z0-9-]+\.fixture\.invalid\/$/);
});

test('no live path: only the fixture builder, the disabled entry point, the rehearsal and tests reach tx-prepare, and none of them a transport', () => {
  const files = ['tools', 'packages', 'signer'].flatMap((dir) => readdirSync(`${ROOT}/${dir}`, { recursive: true }).map((f) => `${dir}/${f}`))
    .filter((f) => /\.(mjs|js|cjs)$/.test(f) && !f.includes('node_modules/'));
  // The guard's own tests hold such imports as string test data; they are left out by exact path.
  // The guard itself names tx-prepare's path in its C3 rule that keeps preparation off the network.
  const testData = ['tools/guards/dependency-boundaries.test.mjs', 'tools/guards/dependency-boundaries.mjs'];
  const importers = files.filter((f) => !f.startsWith('packages/tx-prepare/') && !testData.includes(f) && /tx-prepare\//.test(readFileSync(`${ROOT}/${f}`, 'utf8')));
  // RN-NET-03B2-C3 adds the live entry point (disabled for live use, no transport), its test, and the
  // offline rehearsal's simulated network (the B2 simulated providers on a simulated clock).
  // RN-NET-03B2-WP3 adds the offline v2 fixture builder and its test (simulated providers; no transport).
  assert.deepEqual(importers.sort(), ['tools/preparation-v2.test.mjs', 'tools/preparation-v2/build-v2-fixtures.mjs', 'tools/preparation.test.mjs', 'tools/preparation/build-b2-fixtures.mjs', 'tools/prepare-live.test.mjs', 'tools/prepare/prepare-live.mjs', 'tools/rehearsal/network.mjs']);
  // This file names the forbidden modules in the pattern below, so it is left out of the scan.
  for (const f of [...importers, ...files.filter((x) => x.startsWith('packages/tx-prepare/'))].filter((x) => x !== 'tools/preparation.test.mjs')) {
    const text = readFileSync(`${ROOT}/${f}`, 'utf8');
    assert.ok(!/https-transport|tools\/live|node:https|node:http\b|node:net|node:tls|\bfetch\(/.test(text), f);
  }
  // The preparation readers are reached only through tx-prepare: no file outside packages/ names them.
  const readers = files.filter((f) => !f.startsWith('packages/') && f !== 'tools/preparation.test.mjs' && /readXrplAccount|readSepoliaHead|readSepoliaPin/.test(readFileSync(`${ROOT}/${f}`, 'utf8')));
  assert.deepEqual(readers, []);
});
