// RN-NET-03B2-C6-PREP: the C6 provider compatibility manifest, its run over simulated providers,
// its classification and its fixtures. Offline: nothing here builds a transport.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { READ_ONLY_METHODS, requestBytes } from '../packages/chain-readonly/src/index.mjs';
import { intrinsicGas as txIntrinsicGas, payloadHex } from '../packages/tx-intent/src/index.mjs';
import { GENESIS_COMMITMENT, REVIEWED_PREPARATION_PROVIDERS } from './prepare/entry.mjs';
import { buildCases, fixtureText, replayTranscript } from './compat/build-c6-fixtures.mjs';
import { branches, classify, intrinsicGas, parseLedgerRanges } from './compat/classify.mjs';
import { C6_BUDGET, C6_CALLDATA, C6_COMMITMENT, C6_LIMITS, C6_PROVIDERS, C6_REQUESTS, C6_TEST_ADDRESS, C6_TOTAL_REQUESTS, C6_UNKNOWN_BLOCK_HASH, checkManifest, describeManifest, manifestBytes, WRITE_METHODS } from './compat/manifest.mjs';
import { runCompatibility, sanitizeMessage } from './compat/run.mjs';
import { SCENARIOS, SIM_NOW, simulatedTransport } from './compat/simulated.mjs';

const ROOT = new URL('../', import.meta.url);
/** The digest a C6 read authorization binds: SHA-256 of the manifest's canonical bytes. */
const C6_MANIFEST_SHA256 = 'sha256:2a45e37c0067e6e7e9aaa0705a298c712335b9a85060e332f794bac935088037';
const read = (path) => readFileSync(new URL(path, ROOT), 'utf8');
const endpoints = () => JSON.parse(read('config/rpc-endpoints.json'));
const scenario = (name) => SCENARIOS.find((s) => s.name === name);
const run = (s, extra = {}) => runCompatibility({ endpoints: endpoints(), transport: simulatedTransport(s), now: SIM_NOW, ...extra });

test('the manifest is exactly the 22 planned read-only requests within the per-provider budget', () => {
  assert.equal(C6_REQUESTS.length, 22);
  assert.equal(C6_TOTAL_REQUESTS, 22);
  assert.deepEqual({ ...C6_BUDGET }, { 'xrpl-testnet-ripple': 2, 'xrpl-testnet-xrpl-labs': 2, 'sepolia-publicnode': 9, 'sepolia-1rpc': 9 });
  for (const p of C6_PROVIDERS) assert.equal(C6_REQUESTS.filter((e) => e.providerId === p.id).length, C6_BUDGET[p.id]);
  for (const e of C6_REQUESTS) {
    const network = C6_PROVIDERS.find((p) => p.id === e.providerId).network;
    assert.ok(READ_ONLY_METHODS[network].includes(e.method), `${e.id} ${e.method}`);
    assert.ok(!WRITE_METHODS.includes(e.method));
  }
  for (const list of Object.values(READ_ONLY_METHODS)) for (const m of WRITE_METHODS) assert.ok(!list.includes(m), m);
  assert.deepEqual(C6_REQUESTS.map((e) => e.seq), Array.from({ length: 22 }, (_, i) => i + 1));
  assert.deepEqual({ ...C6_LIMITS }, { attempts: 1, timeoutMs: 10_000, maxResponseBytes: 262_144 });
});

test('the manifest names exactly the reviewed providers at their configured URLs, and refuses a substitution', () => {
  const loaded = checkManifest(endpoints());
  assert.deepEqual(loaded.map((p) => [p.id, p.url]), C6_PROVIDERS.map((p) => [p.id, p.url]));
  // The same four providers, URLs and operators preparation reviews (no provider is substituted).
  assert.deepEqual(C6_PROVIDERS.map((p) => ({ ...p })), REVIEWED_PREPARATION_PROVIDERS.map((p) => ({ ...p })));
  const substituted = endpoints();
  substituted.providers[3].url = 'https://sepolia.example.org/';
  assert.throws(() => checkManifest(substituted), /not at its reviewed url/);
  const extra = endpoints();
  extra.providers.push({ id: 'sepolia-extra', network: 'evm:11155111', url: 'https://rpc.example.org/', operator: 'Example' });
  assert.throws(() => checkManifest(extra), /exactly the four reviewed providers/);
  const missing = endpoints();
  missing.providers.splice(1, 1);
  assert.throws(() => checkManifest(missing), /not in the endpoint file/);
});

test('the estimate uses the Genesis payload and the public test address, as preparation does', () => {
  assert.equal(C6_COMMITMENT, GENESIS_COMMITMENT);
  assert.equal(C6_CALLDATA, `0x${payloadHex(GENESIS_COMMITMENT)}`);
  const b1 = read('fixtures/signing-b1/golden.json');
  assert.ok(b1.includes(C6_TEST_ADDRESS), 'the B1 label-derived test address');
  // The same minimum preparation enforces: the EIP-7623 floor, 22,680 for this payload (C6 review 1).
  assert.equal(intrinsicGas(), txIntrinsicGas(Buffer.from(C6_CALLDATA.slice(2), 'hex')).gasUsed);
  assert.equal(intrinsicGas(), 22_680);
});

test('fixtures/compat-c6/manifest.json is the manifest', () => {
  assert.equal(read('fixtures/compat-c6/manifest.json'), fixtureText(describeManifest()));
});

test('a compatible run sends each request once, in order, to its own provider, in its planned bytes', async () => {
  const seen = [];
  const inner = simulatedTransport(scenario('all-compatible'));
  const { evidence, responses } = await runCompatibility({ endpoints: endpoints(), now: SIM_NOW, transport: async (r) => { seen.push(r); return inner(r); } });
  assert.equal(seen.length, 22);
  assert.equal(evidence.requestCount, 22);
  assert.equal(new Set(seen.map((r) => `${r.providerId} ${Buffer.from(r.body).toString('hex')}`)).size, 22, 'no request repeated on a provider');
  seen.forEach((r, i) => {
    const e = C6_REQUESTS[i];
    assert.equal(r.providerId, e.providerId);
    assert.equal(r.url, C6_PROVIDERS.find((p) => p.id === e.providerId).url);
    assert.equal(r.timeoutMs, 10_000);
    assert.equal(r.maxResponseBytes, 262_144);
    assert.equal(JSON.parse(Buffer.from(r.body).toString('utf8')).method, e.method);
    assert.equal(Buffer.from(r.body).toString('utf8'), evidence.exchanges[i].request);
  });
  const body = (id) => JSON.parse(evidence.exchanges.find((e) => e.id === id).request);
  const pin = body('S05').params[0];
  assert.equal(pin, `0x${(9_500_000 - 2).toString(16)}`, 'the pin is the lowest head - 2');
  assert.deepEqual(body('S06').params, [pin, false]);
  for (const id of ['S07', 'S08', 'S09', 'S11', 'S12', 'S13']) assert.deepEqual(Object.keys(body(id).params[1]).sort(), ['blockHash', 'requireCanonical']);
  for (const id of ['S10', 'S14']) {
    assert.deepEqual(body(id).params[0], { data: C6_CALLDATA, from: C6_TEST_ADDRESS, to: C6_TEST_ADDRESS, value: '0x0' });
    assert.equal(body(id).params[1].requireCanonical, true);
  }
  assert.equal(body('S15').params[1].blockHash, C6_UNKNOWN_BLOCK_HASH);
  assert.deepEqual(body('X03').params[0].max_ledger - body('X03').params[0].min_ledger, 999);
  assert.equal(responses.length, 22);
  assert.ok(!JSON.stringify(evidence).includes('"transactions"'), 'no response body in the evidence');
  assert.deepEqual(evidence.verdict, { xrpl: 'PASS', sepolia: 'PASS' });
  assert.deepEqual(evidence.sepoliaBranches, ['A']);
  assert.deepEqual(evidence.compatibilityCandidate, { 'sepolia-publicnode': { eip1898AccountReads: true, estimateGasBlockHash: true }, 'sepolia-1rpc': { eip1898AccountReads: true, estimateGasBlockHash: true } });
});

const EXPECTED = {
  'all-compatible': ['PASS', 'PASS', ['A']],
  'estimate-gas-refused-publicnode': ['PASS', 'BLOCKED', ['B']],
  'estimate-gas-refused-both': ['PASS', 'BLOCKED', ['B']],
  'estimate-gas-refused-http-400': ['PASS', 'BLOCKED', ['B']],
  'estimate-gas-above-limit': ['PASS', 'BLOCKED', ['B']],
  'pin-hash-disagreement': ['PASS', 'BLOCKED', ['C']],
  'head-same-number-two-hashes': ['PASS', 'BLOCKED', ['C']],
  'finality-lag-blocks-window': ['PASS', 'BLOCKED', ['D']],
  'finality-lag-unresolved': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'estimate-refused-and-finality-lag': ['PASS', 'BLOCKED', ['B', 'D']],
  'account-read-refused-1rpc': ['PASS', 'BLOCKED', ['E']],
  'unknown-hash-served': ['PASS', 'BLOCKED', ['E']],
  'sepolia-wrong-chain-1rpc': ['PASS', 'BLOCKED', ['E']],
  'head-timeout-1rpc': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'head-stale': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'head-skew-5': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'estimate-rate-limited': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'code-invalid-json': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'response-too-large': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'error-message-sanitized': ['PASS', 'BLOCKED', ['B']],
  'error-message-mapped-ipv6-and-long': ['PASS', 'BLOCKED', ['B']],
  'xrpl-wrong-network-labs': ['BLOCKED', 'PASS', ['A']],
  'xrpl-build-version-differs': ['UNRESOLVED', 'PASS', ['A']],
  'xrpl-searched-all-false': ['BLOCKED', 'PASS', ['A']],
  'xrpl-searched-all-absent': ['BLOCKED', 'PASS', ['A']],
  'xrpl-history-short': ['BLOCKED', 'PASS', ['A']],
  'xrpl-stale': ['UNRESOLVED', 'PASS', ['A']],
  'xrpl-ledger-conflict': ['BLOCKED', 'PASS', ['A']],
  'xrpl-server-info-connection-error': ['UNRESOLVED', 'PASS', ['A']],
  // C6 review: threshold edges, malformed blocks, transient codes, per-provider B, content check.
  'edge-head-skew-4': ['PASS', 'PASS', ['A']],
  'edge-head-age-60': ['PASS', 'PASS', ['A']],
  'edge-head-age-61': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'edge-head-ahead-14': ['PASS', 'PASS', ['A']],
  'edge-head-ahead-15': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'edge-pin-age-90': ['PASS', 'PASS', ['A']],
  'edge-pin-age-91': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'edge-finality-apart-64': ['PASS', 'PASS', ['A']],
  'edge-finality-apart-65': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'edge-finality-apart-192': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'edge-finality-apart-193': ['PASS', 'BLOCKED', ['D']],
  'edge-estimate-22679': ['PASS', 'BLOCKED', ['B']],
  'edge-estimate-30000': ['PASS', 'PASS', ['A']],
  'pin-wrong-number-both': ['PASS', 'BLOCKED', ['C']],
  'pin-two-contents': ['PASS', 'BLOCKED', ['C']],
  'head-result-null': ['PASS', 'BLOCKED', ['E']],
  'pin-result-null': ['PASS', 'BLOCKED', ['C']],
  'transport-too-large': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'unknown-hash-rate-limited': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'estimate-internal-error': ['PASS', 'UNRESOLVED', ['UNRESOLVED']],
  'estimate-refused-account-timeout': ['PASS', 'BLOCKED', ['B']],
  'estimate-refused-same-provider-account-refused': ['PASS', 'BLOCKED', ['E']],
  'xrpl-server-state-connected': ['UNRESOLVED', 'PASS', ['A']],
  'xrpl-negative-age': ['BLOCKED', 'PASS', ['A']],
  'xrpl-build-version-with-address': ['UNRESOLVED', 'PASS', ['A']],
  'edge-xrpl-age-30': ['PASS', 'PASS', ['A']],
  'edge-xrpl-age-31': ['UNRESOLVED', 'PASS', ['A']],
  'edge-xrpl-skew-4': ['PASS', 'PASS', ['A']],
  'edge-xrpl-skew-5': ['UNRESOLVED', 'PASS', ['A']],
};

test('every scenario has its expected verdicts and Sepolia branch', async () => {
  assert.deepEqual(SCENARIOS.map((s) => s.name).sort(), Object.keys(EXPECTED).sort());
  for (const s of SCENARIOS) {
    const { evidence } = await run(s);
    const [x, sep, br] = EXPECTED[s.name];
    assert.deepEqual([evidence.verdict.xrpl, evidence.verdict.sepolia, evidence.sepoliaBranches], [x, sep, br], s.name);
    assert.ok(evidence.requestCount <= 22);
    for (const p of C6_PROVIDERS) assert.ok(evidence.sentPerProvider[p.id] <= C6_BUDGET[p.id]);
  }
});

test('B: the refusal is recorded per provider and becomes a false candidate, never a fallback', async () => {
  const seen = [];
  const inner = simulatedTransport(scenario('estimate-gas-refused-publicnode'));
  const { evidence } = await runCompatibility({ endpoints: endpoints(), now: SIM_NOW, transport: async (r) => { seen.push(r); return inner(r); } });
  const estimates = seen.filter((r) => JSON.parse(Buffer.from(r.body).toString('utf8')).method === 'eth_estimateGas');
  assert.equal(estimates.length, 2, 'one estimate per provider, no second form');
  for (const r of estimates) assert.equal(typeof JSON.parse(Buffer.from(r.body).toString('utf8')).params[1].blockHash, 'string');
  assert.deepEqual(evidence.compatibilityCandidate['sepolia-publicnode'], { eip1898AccountReads: true, estimateGasBlockHash: false });
  assert.deepEqual(evidence.compatibilityCandidate['sepolia-1rpc'], { eip1898AccountReads: true, estimateGasBlockHash: true });
  const s10 = evidence.exchanges.find((e) => e.id === 'S10');
  assert.equal(s10.outcome, 'RPC_ERROR');
  assert.equal(s10.rpcError.code, -32602);
  const http400 = (await run(scenario('estimate-gas-refused-http-400'))).evidence.exchanges.find((e) => e.id === 'S14');
  assert.deepEqual([http400.outcome, http400.httpStatus], ['RPC_ERROR', 400]);
});

test('dependencies: a missing head leaves the pins and pinned reads NOT_SENT; other reads still go out once', async () => {
  const { evidence } = await run(scenario('head-timeout-1rpc'));
  const by = (id) => evidence.exchanges.find((e) => e.id === id);
  assert.equal(by('S04').outcome, 'TIMEOUT');
  for (const id of ['S05', 'S06', 'S07', 'S08', 'S09', 'S10', 'S11', 'S12', 'S13', 'S14']) {
    assert.equal(by(id).outcome, 'NOT_SENT', id);
    assert.equal(by(id).request, null);
  }
  for (const id of ['S15', 'S16', 'S17', 'S18']) assert.notEqual(by(id).outcome, 'NOT_SENT', id);
  assert.equal(evidence.requestCount, 12);
  assert.equal(evidence.compatibilityCandidate['sepolia-1rpc'].eip1898AccountReads, null);
});

test('a malformed head or pin is BLOCKED evidence, never a crash, and the run still completes (C6 review 2)', async () => {
  for (const [S, value] of [['S03', null], ['S03', '0x1'], ['S04', 7], ['S05', null], ['S06', []]]) {
    const { evidence } = await run({ override: { [S]: { result: value } } });
    assert.equal(evidence.exchanges.length, 22);
    assert.equal(evidence.verdict.sepolia, 'BLOCKED', `${S} ${JSON.stringify(value)}`);
  }
});

test('the transport codes are recorded; a transport size refusal is TOO_LARGE (C6 review 7)', async () => {
  const { evidence } = await run(scenario('transport-too-large'));
  const s08 = evidence.exchanges.find((e) => e.id === 'S08');
  assert.deepEqual([s08.outcome, s08.transportCode], ['TOO_LARGE', 'RNLO_RESPONSE_TOO_LARGE']);
  const odd = await runCompatibility({ endpoints: endpoints(), now: SIM_NOW, transport: async () => { throw Object.assign(new Error('x'), { code: 'SECRET host 10.0.0.1' }); } });
  assert.ok(odd.evidence.exchanges.filter((e) => e.outcome !== 'NOT_SENT').every((e) => e.outcome === 'TRANSPORT_ERROR' && e.transportCode === null));
});

test('the manifest digest is the SHA-256 of its canonical bytes (C6 review 10)', () => {
  assert.equal(`sha256:${createHash('sha256').update(manifestBytes()).digest('hex')}`, C6_MANIFEST_SHA256);
  assert.match(read('docs/genesis/rn-net-03b2c6-provider-compatibility.md'), new RegExp(C6_MANIFEST_SHA256.slice('sha256:'.length)));
});

test('a provider on the wrong network gets nothing more', async () => {
  const { evidence } = await run(scenario('sepolia-wrong-chain-1rpc'));
  assert.equal(evidence.sentPerProvider['sepolia-1rpc'], 1);
  const x = await run(scenario('xrpl-wrong-network-labs'));
  assert.equal(x.evidence.sentPerProvider['xrpl-testnet-xrpl-labs'], 1);
});

test('error messages are sanitized: printable ASCII, URLs and IPv4 masked, at most 160 characters', async () => {
  const { evidence } = await run(scenario('error-message-sanitized'));
  const m = evidence.exchanges.find((e) => e.id === 'S10').rpcError.message;
  assert.ok(m.length <= 160);
  assert.match(m, /^[ -~]*$/);
  assert.ok(!/https?:|10\.0\.0\.7|192\.168/.test(m), m);
  assert.equal(sanitizeMessage('a\u00e9\u{1F600}b'), 'a??b');
  assert.equal(sanitizeMessage('dial internal-geth-3.prod.svc.cluster.local:8545 from 2001:db8:85a3::8a2e:370:7334 Bearer abcdefghijklmnopqrstuvwxyz0123456789ABCD'), 'dial <host> from <ip> Bearer <token>');
  assert.equal(sanitizeMessage(`hash 0x${'ab'.repeat(32)} unknown`), `hash 0x${'ab'.repeat(32)} unknown`);
  // C6 re-check N1: an IPv4-mapped IPv6 address is masked whole.
  assert.equal(sanitizeMessage('ip ::ffff:198.51.100.7 x'), 'ip <ip><ip> x');
  // C6 re-check N2: a long message is cut before masking (bounded time), with no partial run left.
  const started = Date.now();
  for (const s of ['a'.repeat(262_000), 'a.'.repeat(131_000), '1.'.repeat(131_000), `x ${'1.2.3.4'.repeat(100)}`]) assert.ok(sanitizeMessage(s).length <= 160);
  assert.ok(Date.now() - started < 2000, 'sanitizing is bounded');
  assert.ok(!/\d/.test(sanitizeMessage(`${'w '.repeat(250)}198.51.100.7`)), 'a cut address does not survive');
  assert.equal(sanitizeMessage(7), null);
});

test('refuses a bad time, transport or endpoint file before any request', async () => {
  let calls = 0;
  const transport = async () => { calls += 1; throw new Error('never'); };
  await assert.rejects(runCompatibility({ endpoints: endpoints(), transport, now: 0 }), /Unix seconds/);
  await assert.rejects(runCompatibility({ endpoints: { format: 'x' }, transport, now: SIM_NOW }), TypeError);
  await assert.rejects(runCompatibility({ endpoints: endpoints(), transport: null, now: SIM_NOW }), /transport/);
  assert.equal(calls, 0);
  assert.throws(() => requestBytes('evm:11155111', 'eth_sendRawTransaction', ['0x00']), /not an allowed read-only method/);
});

test('classification rules: ledger ranges, finality window bounds and branch combinations', () => {
  assert.deepEqual(parseLedgerRanges('1-5,7,9-12'), [[1, 5], [7, 7], [9, 12]]);
  for (const bad of ['empty', '', '5-1', 'a-b', '1,,2', null]) assert.equal(parseLedgerRanges(bad), null);
  const c = (id, status) => ({ id, status, detail: '' });
  assert.deepEqual(branches([c('sepolia.eip1898.nonce.p', 'PASS'), c('sepolia.estimate_gas.p', 'BLOCKED')], 'BLOCKED'), ['B']);
  assert.deepEqual(branches([c('sepolia.eip1898.nonce.p', 'BLOCKED'), c('sepolia.estimate_gas.p', 'BLOCKED')], 'BLOCKED'), ['E'], 'an estimate refusal with a refused account read is not B');
  assert.deepEqual(branches([c('sepolia.pin_agreement', 'BLOCKED'), c('sepolia.finality_window', 'BLOCKED')], 'BLOCKED'), ['C', 'D']);
  assert.deepEqual(branches([c('sepolia.head.p', 'UNRESOLVED')], 'UNRESOLVED'), ['UNRESOLVED']);
});

test('finality window: 64 blocks apart PASS, 65 to 192 UNRESOLVED, 193 BLOCKED', async () => {
  for (const [apart, status] of [[64, 'PASS'], [65, 'UNRESOLVED'], [192, 'UNRESOLVED'], [193, 'BLOCKED']]) {
    // PublicNode finalizes 9_500_000 - 70; 1RPC's head is 9_500_001, so its lag is apart + 71.
    const lag = apart + 71;
    const { evidence } = await run({ sepolia: { 'sepolia-1rpc': { finalizedLag: lag } } });
    const check = evidence.checks.find((x) => x.id === 'sepolia.finality_window');
    assert.equal(check.status, status, `apart ${apart}: ${check.detail}`);
  }
});

test('fixtures/compat-c6/cases.json is current, and every transcript replays to its evidence', async () => {
  const fixture = JSON.parse(read('fixtures/compat-c6/cases.json'));
  assert.equal(read('fixtures/compat-c6/cases.json'), fixtureText(await buildCases(endpoints())));
  for (const c of fixture.cases) {
    const { evidence } = await runCompatibility({ endpoints: endpoints(), transport: replayTranscript(c.transcript), now: c.now });
    assert.deepEqual(evidence, c.evidence, c.name);
    assert.deepEqual(classify(c.evidence).checks, c.evidence.checks, c.name);
  }
});
