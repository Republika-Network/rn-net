// RN-NET-03B2-C6-LIVE: the controlled read-only C6 entry point, DISABLED for live network access.
// Every test uses simulated providers (tools/compat/simulated.mjs) or a recording stub: nothing
// here builds a transport, and the offline preload refuses the network.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { canonicalBytes, canonicalize } from '../packages/canonical/src/index.mjs';
import { C6_BUDGET, C6_PROVIDERS, C6_REQUESTS, manifestBytes } from './compat/manifest.mjs';
import { SCENARIOS, SIM_NOW, simulatedTransport } from './compat/simulated.mjs';
import { compatAuthorizationDigest, readCompatAuthorization } from './compat-live/authorization.mjs';
import { buildRunFixture, FIXTURE_DIR, RUN_FIXTURES } from './compat-live/build-c6-live-fixtures.mjs';
import { COMPAT_EXIT, compatLive, LIVE_NETWORK_ACCESS, main } from './compat-live/compat-live.mjs';
import { AGREED_EVIDENCE_DIR, C6_MANIFEST_SHA256, COMPAT_FLAGS, CompatEntryCode, REVIEWED_ENDPOINTS_SHA256 } from './compat-live/entry.mjs';
import { createCompatPolicy, responseFileName } from './compat-live/policy.mjs';
import { reproduceRun } from './compat-live/report.mjs';
import { COMPAT_LIVE_TOOLS, COMPAT_TRANSPORT_JOINERS } from './guards/dependency-boundaries.mjs';

const ROOT = new URL('../', import.meta.url);
const read = (path) => readFileSync(new URL(path, ROOT), 'utf8');
const ENDPOINTS_PATH = new URL('config/rpc-endpoints.json', ROOT).pathname;
const endpoints = () => JSON.parse(read('config/rpc-endpoints.json'));
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const iso = (seconds) => new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');
const scenario = (name) => SCENARIOS.find((s) => s.name === name);
const NOT_AFTER = SIM_NOW + 1800;

function authorizationFor(dir, overrides = {}) {
  return {
    authorizationId: 'c6-test-run',
    evidenceDir: dir,
    format: 'rnnet.compat-authorization.v1',
    manifestSha256: C6_MANIFEST_SHA256,
    notAfter: iso(NOT_AFTER),
    providers: C6_PROVIDERS.map((p) => ({ id: p.id, requests: C6_BUDGET[p.id], url: p.url })),
    publication: 'none',
    requestBudget: 22,
    scope: 'C6 read-only compatibility check (test)',
    ...overrides,
  };
}

/** A private evidence directory (0700) and the authorization a run will be given (as a 0600 file). */
function setup(overrides = {}, { mode = 0o600, text = null } = {}) {
  const base = mkdtempSync(join(tmpdir(), 'rnnet-c6-live-test-'));
  chmodSync(base, 0o700);
  const dir = join(base, 'evidence');
  mkdirSync(dir, { mode: 0o700 });
  chmodSync(dir, 0o700);
  return { base, dir, a: authorizationFor(dir, overrides), mode, text };
}

async function run(ctx, { transport, approve, now = () => SIM_NOW, argv = null, agreed } = {}) {
  const { base, dir } = ctx;
  const authPath = join(base, `auth-${Math.random().toString(16).slice(2)}.json`);
  const text = ctx.text ?? `${canonicalize(ctx.a)}\n`;
  writeFileSync(authPath, text, { mode: ctx.mode });
  chmodSync(authPath, ctx.mode);
  let digest = null;
  try {
    digest = readCompatAuthorization(text).digest;
  } catch {
    // refused by the entry point
  }
  const calls = [];
  const inner = transport ?? simulatedTransport(scenario('all-compatible'));
  const counting = async (request) => {
    calls.push(request);
    return inner(request);
  };
  const prompts = [];
  const result = await compatLive({
    argv: argv ?? ['--authorization', authPath, '--endpoints', ENDPOINTS_PATH, '--evidence-dir', dir],
    deps: {
      agreed: agreed === undefined ? dir : agreed,
      transport: counting,
      now,
      getuid: () => process.getuid(),
      approve: approve ?? (async (prompt) => {
        prompts.push(prompt);
        return `c6 ${digest.slice(-16)}`;
      }),
      sleep: () => new Promise(() => {}),
    },
  });
  return { result, calls, prompts, digest };
}

const cleanup = (ctx) => rmSync(ctx.base, { recursive: true, force: true });

test('C6-LIVE is disabled: the command refuses, the guard keeps it off the network, no joiner is listed', () => {
  assert.equal(LIVE_NETWORK_ACCESS, false);
  assert.equal(AGREED_EVIDENCE_DIR, null);
  assert.deepEqual(COMPAT_TRANSPORT_JOINERS, []);
  assert.equal(COMPAT_LIVE_TOOLS, 'tools/compat-live/');
  const writes = [];
  const original = process.stderr.write;
  process.stderr.write = (text) => writes.push(text);
  try {
    assert.equal(main(), COMPAT_EXIT.LIVE_DISABLED);
  } finally {
    process.stderr.write = original;
  }
  assert.match(writes.join(''), /^RNCL_LIVE_DISABLED: live network access is disabled/);
  for (const name of readdirSync(new URL('tools/compat-live/', ROOT)).filter((n) => n.endsWith('.mjs'))) {
    const text = read(`tools/compat-live/${name}`);
    assert.ok(!/https-transport|node:https|node:http\b|node:net|node:tls|node:dns|node:child_process|\bfetch\(/.test(text), name);
    assert.ok(!/signer\/|txverify\/|keytool|chain-submit|tools\/submit|\.\.\/submit\/|tx-prepare|\.\.\/prepare\//.test(text.replace(/^\/\/.*$/gm, '')), name);
  }
  assert.deepEqual([...COMPAT_FLAGS], ['authorization', 'endpoints', 'evidence-dir']);
});

test('the pinned digests are the reviewed manifest and the reviewed endpoint file', () => {
  assert.equal(C6_MANIFEST_SHA256, 'sha256:2a45e37c0067e6e7e9aaa0705a298c712335b9a85060e332f794bac935088037');
  assert.equal(sha256(manifestBytes()), C6_MANIFEST_SHA256);
  assert.equal(sha256(canonicalBytes(endpoints())), REVIEWED_ENDPOINTS_SHA256);
});

test('one authorized run: 22 requests, private durable evidence, reproduced, PASS', async () => {
  const ctx = setup();
  try {
    const { result, calls, prompts } = await run(ctx);
    assert.equal(result.outcome, 'PASS', result.message);
    assert.equal(result.exitCode, 0);
    assert.equal(calls.length, 22);
    assert.deepEqual(calls.map((c) => c.providerId), C6_REQUESTS.map((e) => e.providerId));
    for (const c of calls) {
      assert.equal(c.url, C6_PROVIDERS.find((p) => p.id === c.providerId).url);
      assert.equal(c.timeoutMs, 10_000);
      assert.equal(c.maxResponseBytes, 262_144);
    }
    assert.equal(new Set(calls.map((c) => `${c.providerId} ${Buffer.from(c.body).toString('utf8')}`)).size, 22, 'no request repeated');
    // The prompt shows what the run is bound to.
    assert.equal(prompts.length, 1);
    for (const p of C6_PROVIDERS) assert.ok(prompts[0].includes(`${p.id} at ${p.url}: ${C6_BUDGET[p.id]} requests`), p.id);
    assert.ok(prompts[0].includes(C6_MANIFEST_SHA256) && prompts[0].includes('no publication') && prompts[0].includes('no retry'));
    const runDir = join(ctx.dir, 'c6-test-run');
    assert.equal(result.runDirectory, runDir);
    assert.equal(lstatSync(runDir).mode & 0o777, 0o700);
    const names = readdirSync(runDir).sort();
    assert.deepEqual(names, ['authorization.json', 'evidence.json', 'report.json', ...Array.from({ length: 22 }, (_, i) => responseFileName(i + 1)), 'transcript.json'].sort());
    for (const n of names) assert.equal(lstatSync(join(runDir, n)).mode & 0o777, 0o600, n);
    const report = JSON.parse(readFileSync(join(runDir, 'report.json'), 'utf8'));
    assert.equal(report.overall, 'PASS');
    assert.equal(report.forwardedRequests, 22);
    assert.equal(report.manifestSha256, C6_MANIFEST_SHA256);
    assert.equal(result.reportSha256, sha256(readFileSync(join(runDir, 'report.json'))));
    // The stored authorization is the founder's exact text.
    assert.equal(readFileSync(join(runDir, 'authorization.json'), 'utf8'), `${canonicalize(ctx.a)}\n`);
  } finally {
    cleanup(ctx);
  }
});

test('BLOCKED and UNRESOLVED runs exit with their own codes and keep their evidence', async () => {
  for (const [name, outcome] of [['estimate-gas-refused-both', 'BLOCKED'], ['xrpl-wrong-network-labs', 'BLOCKED'], ['head-timeout-1rpc', 'UNRESOLVED']]) {
    const ctx = setup();
    try {
      const { result } = await run(ctx, { transport: simulatedTransport(scenario(name)) });
      assert.equal(result.outcome, outcome, `${name}: ${result.message}`);
      assert.equal(result.exitCode, COMPAT_EXIT[outcome]);
      assert.ok(readdirSync(result.runDirectory).includes('report.json'));
    } finally {
      cleanup(ctx);
    }
  }
});

test('every refusal before the run sends nothing', async () => {
  const other = C6_PROVIDERS.map((p) => ({ id: p.id, requests: C6_BUDGET[p.id], url: p.url }));
  const cases = [
    ['manifest digest', { manifestSha256: `sha256:${'0'.repeat(64)}` }, CompatEntryCode.MANIFEST_MISMATCH],
    ['provider url substituted', { providers: other.map((p, i) => (i === 3 ? { ...p, url: 'https://sepolia.example.invalid/' } : p)) }, CompatEntryCode.AUTHORIZATION],
    ['provider substituted', { providers: other.map((p, i) => (i === 3 ? { ...p, id: 'sepolia-other' } : p)) }, CompatEntryCode.AUTHORIZATION],
    ['provider order', { providers: [other[1], other[0], other[2], other[3]] }, CompatEntryCode.AUTHORIZATION],
    ['per-provider budget moved', { providers: other.map((p, i) => (i === 2 ? { ...p, requests: 10 } : i === 3 ? { ...p, requests: 8 } : p)) }, CompatEntryCode.AUTHORIZATION],
    ['budget expanded', { providers: other.map((p, i) => (i === 3 ? { ...p, requests: 10 } : p)), requestBudget: 23 }, CompatEntryCode.AUTHORIZATION],
    ['budget not the sum', { requestBudget: 21 }, CompatEntryCode.AUTHORIZATION],
    ['publication', { publication: 'public' }, CompatEntryCode.AUTHORIZATION],
    ['another evidence directory', { evidenceDir: '/srv/elsewhere' }, CompatEntryCode.AUTHORIZATION],
    ['expired', { notAfter: iso(SIM_NOW - 1) }, CompatEntryCode.AUTHORIZATION_EXPIRED],
    ['too far ahead', { notAfter: iso(SIM_NOW + 3601) }, CompatEntryCode.AUTHORIZATION],
    ['extra field', { retry: true }, CompatEntryCode.AUTHORIZATION],
    ['not a real date', { notAfter: '2026-02-30T00:00:00Z' }, CompatEntryCode.AUTHORIZATION],
  ];
  for (const [label, overrides, code] of cases) {
    const ctx = setup(overrides);
    try {
      const { result, calls } = await run(ctx);
      assert.equal(result.outcome, 'REFUSED', label);
      assert.equal(result.code, code, `${label}: ${result.message}`);
      assert.equal(calls.length, 0, label);
      assert.deepEqual(readdirSync(ctx.dir), [], `${label}: no run directory`);
    } finally {
      cleanup(ctx);
    }
  }
});

test('flags, directory, file mode, endpoint file and approval refusals send nothing', async () => {
  const check = async (label, code, options, ctxOptions = {}) => {
    const ctx = setup({}, ctxOptions);
    try {
      const { result, calls } = await run(ctx, typeof options === 'function' ? options(ctx) : options);
      assert.equal(result.code, code, `${label}: ${result.message}`);
      assert.equal(calls.length, 0, label);
    } finally {
      cleanup(ctx);
    }
  };
  await check('a retry flag', CompatEntryCode.USAGE, (ctx) => ({ argv: ['--authorization', '/x', '--endpoints', ENDPOINTS_PATH, '--evidence-dir', ctx.dir, '--retry', '1'] }));
  await check('a provider flag instead', CompatEntryCode.USAGE, (ctx) => ({ argv: ['--authorization', '/x', '--provider', 'sepolia-1rpc', '--evidence-dir', ctx.dir] }));
  await check('no agreed directory', CompatEntryCode.DIRECTORY_NOT_AGREED, { agreed: null });
  await check('another directory', CompatEntryCode.DIRECTORY_NOT_AGREED, { agreed: '/srv/agreed' });
  await check('authorization readable by others', CompatEntryCode.FILE, {}, { mode: 0o644 });
  await check('authorization not canonical', CompatEntryCode.AUTHORIZATION, {}, { text: `${JSON.stringify(authorizationFor('/x'), null, 1)}\n` });
  await check('wrong approval', CompatEntryCode.APPROVAL_REFUSED, { approve: async () => 'c6 0000000000000000' });
  await check('approval on another network label', CompatEntryCode.APPROVAL_REFUSED, { approve: async () => 'xrpl:testnet 0000000000000000' });
  let t = 0;
  await check('expired during the approval', CompatEntryCode.AUTHORIZATION_EXPIRED, { now: () => (t++ === 0 ? SIM_NOW : NOT_AFTER + 1) });
  // A modified endpoint file: an extra provider, a changed URL, a changed note.
  for (const change of [
    (e) => e.providers.push({ ...e.providers[3], id: 'sepolia-extra' }),
    (e) => { e.providers[0].url = 'https://s.altnet.rippletest.net:51235/'; },
    (e) => { e.note = 'changed'; },
  ]) {
    const ctx = setup();
    try {
      const e = endpoints();
      change(e);
      const path = join(ctx.base, 'endpoints.json');
      writeFileSync(path, JSON.stringify(e));
      const auth = join(ctx.base, 'a.json');
      writeFileSync(auth, `${canonicalize(ctx.a)}\n`, { mode: 0o600 });
      const { result, calls } = await run(ctx, { argv: ['--authorization', auth, '--endpoints', path, '--evidence-dir', ctx.dir] });
      assert.equal(result.code, CompatEntryCode.ENDPOINTS_NOT_REVIEWED, result.message);
      assert.equal(calls.length, 0);
    } finally {
      cleanup(ctx);
    }
  }
});

test('an authorization runs once: a second run is refused before any request', async () => {
  const ctx = setup();
  try {
    assert.equal((await run(ctx)).result.outcome, 'PASS');
    const again = await run(ctx);
    assert.equal(again.result.code, CompatEntryCode.AUTHORIZATION_USED);
    assert.equal(again.calls.length, 0);
  } finally {
    cleanup(ctx);
  }
});

test('no automatic retry and no substitute provider: a failure is recorded once and nothing else is asked', async () => {
  const ctx = setup();
  try {
    const failing = async (request) => {
      if (request.providerId === 'sepolia-1rpc') throw Object.assign(new Error('down'), { code: 'RNLO_CONNECTION' });
      return simulatedTransport(scenario('all-compatible'))(request);
    };
    const { result, calls } = await run(ctx, { transport: failing });
    assert.equal(result.outcome, 'UNRESOLVED', result.message);
    // 1RPC is asked once (eth_chainId), fails, and is never asked again; no other provider is asked in its place.
    assert.equal(calls.filter((c) => c.providerId === 'sepolia-1rpc').length, 1);
    // PublicNode: chainId, head, the unknown hash and finalized; the pin needs both heads, so it and
    // the pinned reads are NOT_SENT.
    assert.equal(calls.filter((c) => c.providerId === 'sepolia-publicnode').length, 4);
    for (const id of ['xrpl-testnet-ripple', 'xrpl-testnet-xrpl-labs']) assert.equal(calls.filter((c) => c.providerId === id).length, 2);
    assert.equal(new Set(calls.map((c) => `${c.providerId} ${Buffer.from(c.body).toString('utf8')}`)).size, calls.length);
  } finally {
    cleanup(ctx);
  }
});

test('the request policy refuses what the manifest does not plan, and nothing passes after a violation', async () => {
  const providers = C6_PROVIDERS.map((p) => ({ id: p.id, requests: C6_BUDGET[p.id], url: p.url }));
  const make = (clock = () => SIM_NOW) => {
    const seen = [];
    const policy = createCompatPolicy({ providers, notAfter: NOT_AFTER, clock, keep: () => {}, sleep: () => new Promise(() => {}) });
    return { policy, seen, t: policy.wrap(async (r) => { seen.push(r); return { status: 200, body: Buffer.from('{}') }; }) };
  };
  const req = (providerId, body, extra = {}) => ({ providerId, url: providers.find((p) => p.id === providerId)?.url ?? 'https://x.invalid/', body: Buffer.from(JSON.stringify(body)), timeoutMs: 10_000, maxResponseBytes: 262_144, ...extra });
  const eth = (method, params = []) => ({ id: 1, jsonrpc: '2.0', method, params });
  for (const [label, request] of [
    ['write method', req('sepolia-publicnode', eth('eth_sendRawTransaction', ['0x00']))],
    ['xrpl submit', req('xrpl-testnet-ripple', { method: 'submit', params: [{}] })],
    ['unknown provider', req('sepolia-other', eth('eth_chainId'))],
    ['substituted url', req('sepolia-publicnode', eth('eth_chainId'), { url: 'https://public.1rpc.io/sepolia' })],
    ['longer deadline', req('sepolia-publicnode', eth('eth_chainId'), { timeoutMs: 60_000 })],
    ['larger limit', req('sepolia-publicnode', eth('eth_chainId'), { maxResponseBytes: 1 << 24 })],
    ['not JSON', { ...req('sepolia-publicnode', {}), body: Buffer.from('nope') }],
  ]) {
    const { policy, seen, t } = make();
    await assert.rejects(t(request), (e) => e.code === 'RNCL_REQUEST_POLICY', label);
    assert.equal(seen.length, 0, label);
    assert.notEqual(policy.violation, null, label);
    // Sticky: a valid request afterwards is refused too.
    await assert.rejects(t(req('sepolia-publicnode', eth('eth_chainId'))), (e) => e.code === 'RNCL_REQUEST_POLICY');
    assert.equal(seen.length, 0, label);
  }
  // Manifest order: a provider may skip ahead (a request whose dependency was not observed is
  // NOT_SENT), never go back.
  const ordered = make();
  await ordered.t(req('sepolia-publicnode', eth('eth_getCode', ['0x0', 'latest'])));
  await assert.rejects(ordered.t(req('sepolia-publicnode', eth('eth_chainId'))), (e) => e.code === 'RNCL_REQUEST_POLICY');
  assert.equal(ordered.seen.length, 1);
  // A provider's budget: XRPL Labs has 2 (server_info, tx); a third is refused.
  const { seen, t } = make();
  await t(req('xrpl-testnet-xrpl-labs', { method: 'server_info', params: [{}] }));
  await t(req('xrpl-testnet-xrpl-labs', { method: 'tx', params: [{}] }));
  await assert.rejects(t(req('xrpl-testnet-xrpl-labs', { method: 'server_info', params: [{}] })), (e) => e.code === 'RNCL_REQUEST_POLICY');
  assert.equal(seen.length, 2);
  // Expiry is checked before every request.
  let now = SIM_NOW;
  const timed = make(() => now);
  await timed.t(req('sepolia-publicnode', eth('eth_chainId')));
  now = NOT_AFTER + 1;
  await assert.rejects(timed.t(req('sepolia-1rpc', eth('eth_chainId'))), (e) => e.code === 'RNCL_REQUEST_POLICY');
  assert.equal(timed.seen.length, 1);
  assert.match(timed.policy.violation, /expired/);
});

test('the policy deadline and response limit hold whatever the transport does', async () => {
  const providers = C6_PROVIDERS.map((p) => ({ id: p.id, requests: C6_BUDGET[p.id], url: p.url }));
  const request = { providerId: 'sepolia-publicnode', url: providers[2].url, body: Buffer.from('{"id":1,"jsonrpc":"2.0","method":"eth_chainId","params":[]}'), timeoutMs: 10_000, maxResponseBytes: 262_144 };
  let asked = 0;
  const kept = [];
  const slept = [];
  const hang = createCompatPolicy({ providers, notAfter: NOT_AFTER, clock: () => SIM_NOW, keep: (n) => kept.push(n), sleep: (ms) => { slept.push(ms); return Promise.resolve(); } });
  await assert.rejects(hang.wrap(() => { asked += 1; return new Promise(() => {}); })(request), (e) => e.code === 'RNLO_TIMEOUT');
  assert.deepEqual(slept, [10_000]);
  assert.equal(asked, 1);
  const big = createCompatPolicy({ providers, notAfter: NOT_AFTER, clock: () => SIM_NOW, keep: (n) => kept.push(n), sleep: () => new Promise(() => {}) });
  await assert.rejects(big.wrap(async () => ({ status: 200, body: Buffer.alloc(262_145, 0x20) }))(request), (e) => e.code === 'RNLO_RESPONSE_TOO_LARGE');
  assert.deepEqual(kept, [], 'an oversized body is not stored');
  assert.equal(big.transcript().calls[0].error, 'RNLO_RESPONSE_TOO_LARGE');
});

test('the run fixtures are current, and a tampered run directory is not reproduced', async () => {
  const e = endpoints();
  for (const f of RUN_FIXTURES) {
    const built = await buildRunFixture(f, e);
    const dir = new URL(`${FIXTURE_DIR}/${f.name}/`, ROOT);
    assert.deepEqual(readdirSync(dir).sort(), [...built.keys()], f.name);
    for (const [name, bytes] of built) assert.ok(readFileSync(new URL(name, dir)).equals(bytes), `${f.name}/${name} is stale (node tools/compat-live/build-c6-live-fixtures.mjs)`);
    const ok = await reproduceRun({ files: built, endpoints: e, readAuthorization: readCompatAuthorization });
    assert.ok(ok.reproduced, `${f.name}: ${ok.problems.join('; ')}`);
  }
  const files = await buildRunFixture(RUN_FIXTURES[0], e);
  const tamper = async (name, change) => {
    const copy = new Map(files);
    copy.set(name, change(Buffer.from(copy.get(name))));
    return reproduceRun({ files: copy, endpoints: e, readAuthorization: readCompatAuthorization });
  };
  for (const [name, change] of [
    ['response-05.bin', (b) => Buffer.from(b.toString('utf8').replace('0xaa36a7', '0xaa36a8'))],
    ['report.json', (b) => Buffer.from(b.toString('utf8').replace('"overall":"PASS"', '"overall":"BLOCKED"'))],
    ['evidence.json', (b) => Buffer.from(b.toString('utf8').replace('"observedAt":', '"observedAt":1'))],
  ]) {
    const out = await tamper(name, change);
    assert.equal(out.reproduced, false, name);
  }
  const extra = new Map(files);
  extra.set('response-99.bin', Buffer.from('x'));
  assert.equal((await reproduceRun({ files: extra, endpoints: e, readAuthorization: readCompatAuthorization })).reproduced, false);
});

test('the fixture runs cover PASS, BLOCKED and UNRESOLVED, a policy stop and the deadline', () => {
  const report = (name) => JSON.parse(read(`${FIXTURE_DIR}/${name}/report.json`));
  const overalls = new Set(RUN_FIXTURES.map((f) => report(f.name).overall));
  assert.deepEqual([...overalls].sort(), ['BLOCKED', 'PASS', 'UNRESOLVED']);
  const stopped = report('authorization-expires-mid-run');
  assert.equal(stopped.forwardedRequests, 10);
  assert.match(stopped.policyViolation, /expired/);
  assert.equal(stopped.overall, 'UNRESOLVED');
  const transcript = JSON.parse(read(`${FIXTURE_DIR}/deadline-hang-1rpc-head/transcript.json`));
  assert.ok(transcript.calls.some((c) => c.providerId === 'sepolia-1rpc' && c.error === 'RNLO_TIMEOUT'));
  const depth = JSON.parse(read(`${FIXTURE_DIR}/json-depth-edges/evidence.json`)).exchanges;
  assert.deepEqual(['X02', 'S01', 'S02'].map((id) => depth.find((x) => x.id === id).outcome), ['INVALID_RESPONSE', 'OK', 'INVALID_RESPONSE']);
  assert.ok(compatAuthorizationDigest(JSON.parse(read(`${FIXTURE_DIR}/all-compatible/authorization.json`))).startsWith('sha256:'));
});
