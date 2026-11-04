// RN-NET-03B2-C6-LIVE: the controlled read-only C6 entry point, DISABLED for live network access.
// Every test uses simulated providers (tools/compat/simulated.mjs) or a recording stub: nothing
// here builds a transport, and the offline preload refuses the network. The flow is tested through
// flow.mjs; the command (compat-live.mjs), the only file joined to a transport, is not imported here
// (guard: compat-transport-join-transitive), and tools/broadcast/live-disabled.check.mjs runs it.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { canonicalBytes, canonicalize } from '../packages/canonical/src/index.mjs';
import { buildParams, C6_BUDGET, C6_PROVIDERS, C6_REQUESTS, entryBytes, manifestBytes } from './compat/manifest.mjs';
import { SCENARIOS, SIM_NOW, simulatedTransport } from './compat/simulated.mjs';
import { compatAuthorizationDigest, readCompatAuthorization } from './compat-live/authorization.mjs';
import { buildRunFixture, FIXTURE_DIR, RUN_FIXTURES } from './compat-live/build-c6-live-fixtures.mjs';
import { AGREED_EVIDENCE_DIR, C6_MANIFEST_SHA256, COMPAT_FLAGS, CompatEntryCode, REVIEWED_ENDPOINTS_SHA256 } from './compat-live/entry.mjs';
import { COMPAT_EXIT, compatLive } from './compat-live/flow.mjs';
import { createCompatPolicy, responseFileName } from './compat-live/policy.mjs';
import { reproduceRun } from './compat-live/report.mjs';
import { COMPAT_LIVE_NETWORK_FILES, COMPAT_LIVE_TOOLS, COMPAT_LIVE_TRANSPORT_FILE, COMPAT_TRANSPORT_JOINERS } from './guards/dependency-boundaries.mjs';

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

async function run(ctx, { transport, approve, now = () => SIM_NOW, argv = null, agreed, io } = {}) {
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
      minFreeBytes: 1,
      ...(io === undefined ? {} : { io }),
    },
  });
  return { result, calls, prompts, digest };
}

const cleanup = (ctx) => rmSync(ctx.base, { recursive: true, force: true });

test('C6 live access is disabled again after the H3 run: two locks, one listed joiner, one narrow transport file', () => {
  // Lock 1: the command refuses before reading anything (tools/broadcast/live-disabled.check.mjs runs it).
  // Restored by the post-run deactivation (docs/genesis/rn-net-03b2c6-h3-activation.md §5).
  const command = read('tools/compat-live/compat-live.mjs');
  assert.match(command, /^export const LIVE_NETWORK_ACCESS = false;$/m);
  assert.equal((command.match(/^[^/\n]*LIVE_NETWORK_ACCESS = /gm) ?? []).length, 1);
  assert.match(command, /if \(!LIVE_NETWORK_ACCESS\) \{\n\s+process\.stderr\.write\(`\$\{CompatEntryCode\.LIVE_DISABLED\}: live network access is disabled/);
  // Lock 2: no evidence directory is agreed, so even an enabled command refuses every run.
  assert.equal(AGREED_EVIDENCE_DIR, null);
  // The guard lists the command as the one joiner, and two files that may reach the transport.
  assert.deepEqual(COMPAT_TRANSPORT_JOINERS, ['tools/compat-live/compat-live.mjs']);
  assert.deepEqual(COMPAT_LIVE_NETWORK_FILES, ['tools/compat-live/compat-live.mjs', 'tools/compat-live/c6-transport.mjs']);
  assert.equal(COMPAT_LIVE_TRANSPORT_FILE, 'tools/compat-live/c6-transport.mjs');
  assert.equal(COMPAT_LIVE_TOOLS, 'tools/compat-live/');
  for (const name of readdirSync(new URL('tools/compat-live/', ROOT)).filter((n) => n.endsWith('.mjs'))) {
    const text = read(`tools/compat-live/${name}`);
    const code = text.replace(/^\s*\/\/.*$/gm, '');
    // Only c6-transport.mjs names the HTTPS transport; only the command names c6-transport.mjs, in
    // its enabled branch; nothing here names a network module or fetch.
    if (name !== 'c6-transport.mjs') assert.ok(!/https-transport|httpsTransport|createHttpsTransport/.test(code), name);
    if (name !== 'compat-live.mjs') assert.ok(!/c6-transport/.test(code), name);
    assert.ok(!/node:https|node:http\b|node:http2|node:net|node:tls|node:dns|node:dgram|node:child_process|node:worker_threads|\bfetch\(/.test(code), name);
    assert.ok(!/signer\/|txverify\/|keytool|chain-submit|tools\/submit|\.\.\/submit\/|tx-prepare|\.\.\/prepare\//.test(code), name);
  }
  assert.match(command, /await import\('\.\/c6-transport\.mjs'\)/);
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
    assert.deepEqual(names, ['authorization.json', 'evidence.json', 'journal.ndjson', 'report.json', ...Array.from({ length: 22 }, (_, i) => responseFileName(i + 1)), 'transcript.json'].sort());
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

/** The manifest bytes of entry `id`, with the observed values of `state`. */
const manifestBody = (id, state = {}) => {
  const e = C6_REQUESTS.find((x) => x.id === id);
  return Buffer.from(entryBytes(e, buildParams(e, state)));
};
const POLICY_PROVIDERS = C6_PROVIDERS.map((p) => ({ id: p.id, requests: C6_BUDGET[p.id], url: p.url }));
const preq = (id, extra = {}, state = {}) => {
  const e = C6_REQUESTS.find((x) => x.id === id);
  return { providerId: e.providerId, url: C6_PROVIDERS.find((p) => p.id === e.providerId).url, body: manifestBody(id, state), timeoutMs: 10_000, maxResponseBytes: 262_144, ...extra };
};
/** A policy over a recording transport and an in-memory evidence store. */
const makePolicy = ({ clock = () => SIM_NOW, sleep = () => new Promise(() => {}), respond = async () => ({ status: 200, body: Buffer.from('{}') }), evidence } = {}) => {
  const seen = [];
  const journal = [];
  const kept = [];
  const policy = createCompatPolicy({ providers: POLICY_PROVIDERS, notAfter: NOT_AFTER, clock, sleep, evidence: evidence ?? { journal: (r) => journal.push(r), keep: (n) => kept.push(n) } });
  return { policy, seen, journal, kept, t: policy.wrap(async (r) => { seen.push(r); return respond(r); }) };
};

test('the request policy refuses what the manifest does not plan, and nothing passes after a violation', async () => {
  const eth = (method, params = []) => Buffer.from(JSON.stringify({ id: 1, jsonrpc: '2.0', method, params }));
  for (const [label, request] of [
    ['write method', { ...preq('S01'), body: eth('eth_sendRawTransaction', ['0x00']) }],
    ['xrpl submit', { ...preq('X01'), body: Buffer.from(JSON.stringify({ method: 'submit', params: [{}] })) }],
    ['unknown provider', { ...preq('S01'), providerId: 'sepolia-other' }],
    ['substituted url', preq('S01', { url: 'https://public.1rpc.io/sepolia' })],
    ['longer deadline', preq('S01', { timeoutMs: 60_000 })],
    ['larger limit', preq('S01', { maxResponseBytes: 1 << 24 })],
    ['not JSON', { ...preq('S01'), body: Buffer.from('nope') }],
  ]) {
    const { policy, seen, journal, t } = makePolicy();
    await assert.rejects(t(request), (e) => e.code === 'RNCL_REQUEST_POLICY', label);
    assert.equal(seen.length, 0, label);
    assert.notEqual(policy.violation, null, label);
    // Sticky: a valid request afterwards is refused too, and neither was journaled as sent.
    await assert.rejects(t(preq('S01')), (e) => e.code === 'RNCL_REQUEST_POLICY');
    assert.equal(seen.length, 0, label);
    assert.deepEqual(journal.map((r) => r.event), ['refused', 'refused'], label);
  }
  // Manifest order: a provider may skip ahead (a request whose dependency was not observed is
  // NOT_SENT), never go back.
  const ordered = makePolicy();
  await ordered.t(preq('S15'));
  await assert.rejects(ordered.t(preq('S01')), (e) => e.code === 'RNCL_REQUEST_POLICY');
  assert.equal(ordered.seen.length, 1);
  // A provider's budget: XRPL Labs has 2 (server_info, tx); a third is refused.
  const budget = makePolicy();
  await budget.t(preq('X02'));
  await budget.t(preq('X04', {}, { validatedSeq: { 'xrpl-testnet-xrpl-labs': 5_000_000 } }));
  await assert.rejects(budget.t(preq('X02')), (e) => e.code === 'RNCL_REQUEST_POLICY');
  assert.equal(budget.seen.length, 2);
  // Expiry is checked before every request.
  let now = SIM_NOW;
  const timed = makePolicy({ clock: () => now });
  await timed.t(preq('S01'));
  now = NOT_AFTER + 1;
  await assert.rejects(timed.t(preq('S02')), (e) => e.code === 'RNCL_REQUEST_POLICY');
  assert.equal(timed.seen.length, 1);
  assert.match(timed.policy.violation, /expired/);
});

test('review F3: every request is the manifest request byte for byte; only observed values vary, each of its form', async () => {
  const hash = `0x${'ab'.repeat(32)}`;
  const cases = [
    ['an extra key', () => ({ ...preq('S01'), body: Buffer.from('{"id":1,"jsonrpc":"2.0","method":"eth_chainId","params":[],"x":1}') })],
    ['a duplicate key', () => ({ ...preq('S01'), body: Buffer.from('{"id":1,"jsonrpc":"2.0","method":"eth_chainId","method":"eth_chainId","params":[]}') })],
    ['another key order', () => ({ ...preq('S01'), body: Buffer.from('{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}') })],
    ['whitespace', () => ({ ...preq('S01'), body: Buffer.from('{"id":1, "jsonrpc":"2.0","method":"eth_chainId","params":[]}') })],
    ['another id', () => ({ ...preq('S01'), body: Buffer.from('{"id":2,"jsonrpc":"2.0","method":"eth_chainId","params":[]}') })],
    ['a head with full transactions', () => ({ ...preq('S03'), body: Buffer.from('{"id":1,"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",true]}') })],
    ['another address', () => ({ ...preq('S08', {}, { pinHash: { 'sepolia-publicnode': hash } }), body: Buffer.from(manifestBody('S08', { pinHash: { 'sepolia-publicnode': hash } }).toString('utf8').replace('0x57db', '0x57dc')) })],
    ['a block tag instead of a hash', () => ({ ...preq('S08'), body: Buffer.from(manifestBody('S08', { pinHash: { 'sepolia-publicnode': hash } }).toString('utf8').replace(hash, 'latest')) })],
    ['a short hash', () => preq('S08', {}, { pinHash: { 'sepolia-publicnode': '0xab' } })],
    ['a ledger range below 999', () => preq('X03', {}, { validatedSeq: { 'xrpl-testnet-ripple': 998 } })],
    ['a pin that is not a QUANTITY', () => preq('S05', {}, { pinNumber: '0x01' })],
  ];
  for (const [label, make] of cases) {
    const { seen, t } = makePolicy();
    await assert.rejects(t(make()), (e) => e.code === 'RNCL_REQUEST_POLICY', label);
    assert.equal(seen.length, 0, label);
  }
  // Skipping ahead to a later entry of the same method (S08 NOT_SENT, then S15) is allowed.
  const skip = makePolicy();
  await skip.t(preq('S15'));
  assert.equal(skip.seen.length, 1);
  // The pin is the same block number on both providers.
  const pin = makePolicy();
  await pin.t(preq('S03'));
  await pin.t(preq('S05', {}, { pinNumber: '0x10' }));
  await assert.rejects(pin.t(preq('S06', {}, { pinNumber: '0x11' })), (e) => e.code === 'RNCL_REQUEST_POLICY');
  const same = makePolicy();
  await same.t(preq('S05', {}, { pinNumber: '0x10' }));
  await same.t(preq('S04'));
  await same.t(preq('S06', {}, { pinNumber: '0x10' }));
  assert.equal(same.seen.length, 3);
  // The transport sees a fresh copy of exactly the checked request.
  const fresh = makePolicy();
  const r = preq('S01');
  await fresh.t(r);
  assert.ok(Object.isFrozen(fresh.seen[0]) && fresh.seen[0].body !== r.body && Buffer.from(fresh.seen[0].body).equals(r.body));
  assert.deepEqual(Object.keys(fresh.seen[0]).sort(), ['body', 'maxResponseBytes', 'providerId', 'timeoutMs', 'url']);
});

test('the policy deadline and response limit hold whatever the transport does', async () => {
  let asked = 0;
  const slept = [];
  const hang = makePolicy({ sleep: (ms) => { slept.push(ms); return Promise.resolve(); }, respond: () => { asked += 1; return new Promise(() => {}); } });
  await assert.rejects(hang.t(preq('S01')), (e) => e.code === 'RNLO_TIMEOUT');
  assert.deepEqual(slept, [12_000], 'the policy deadline is the request deadline plus its grace (review B1)');
  assert.equal(asked, 1);
  const big = makePolicy({ respond: async () => ({ status: 200, body: Buffer.alloc(262_145, 0x20) }) });
  await assert.rejects(big.t(preq('S01')), (e) => e.code === 'RNLO_RESPONSE_TOO_LARGE');
  assert.deepEqual(big.kept, [], 'an oversized body is not stored');
  assert.equal(big.policy.transcript().calls[0].error, 'RNLO_RESPONSE_TOO_LARGE');
});

test('the run fixtures are current, and a tampered run directory is not reproduced', async () => {
  const e = endpoints();
  for (const f of RUN_FIXTURES) {
    const built = await buildRunFixture(f, e);
    const dir = new URL(`${FIXTURE_DIR}/${f.name}/`, ROOT);
    assert.deepEqual(readdirSync(dir).sort(), [...built.keys()], f.name);
    for (const [name, bytes] of built) assert.ok(readFileSync(new URL(name, dir)).equals(bytes), `${f.name}/${name} is stale (node tools/compat-live/build-c6-live-fixtures.mjs)`);
    const ok = await reproduceRun({ files: built, endpoints: e, readAuthorization: readCompatAuthorization });
    // An incomplete run (N1) is never reproduced: it has no evidence.json and no report.json.
    if (built.has('report.json')) assert.ok(ok.reproduced, `${f.name}: ${ok.problems.join('; ')}`);
    else assert.deepEqual([ok.reproduced, built.has('evidence.json'), ok.problems], [false, false, ['a run file is missing']], f.name);
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

test('review F1: a response that cannot be stored stops the run, and the run carries no report (N1)', async () => {
  const names = readdirSync(new URL(`${FIXTURE_DIR}/response-storage-fails/`, ROOT));
  assert.ok(!names.includes('report.json') && !names.includes('evidence.json'), 'an incomplete run has no report');
  const calls = JSON.parse(read(`${FIXTURE_DIR}/response-storage-fails/transcript.json`)).calls;
  assert.equal(calls.filter((c) => c.policy === null).length, 6, 'nothing is sent after the failure');
  assert.deepEqual([calls[5].error, calls[5].status, calls[5].responseFile], ['RNCL_STORAGE', null, null]);
  assert.ok(calls.slice(6).every((c) => c.policy === 'evidence could not be stored at call 6 (EIO)'));
  // A file planted where a response goes (the reviewer's case K): the run stops at that call and the
  // run directory is NOT reproduced (the planted file is not a recorded response).
  const ctx = setup();
  try {
    const runDir = join(ctx.dir, 'c6-test-run');
    let n = 0;
    const planting = async (request) => {
      n += 1;
      if (n === 6) writeFileSync(join(runDir, 'response-06.bin'), 'planted', { mode: 0o600 });
      return simulatedTransport(scenario('all-compatible'))(request);
    };
    const { result, calls: sent } = await run(ctx, { transport: planting });
    assert.equal(result.outcome, 'REFUSED', result.message);
    assert.equal(result.code, CompatEntryCode.EVIDENCE);
    assert.equal(sent.length, 6);
    const t = JSON.parse(readFileSync(join(runDir, 'transcript.json'), 'utf8')).calls;
    assert.equal(t[5].error, 'RNCL_STORAGE');
    assert.equal(readFileSync(join(runDir, 'response-06.bin'), 'utf8'), 'planted', 'the planted file is not overwritten');
    assert.ok(!readdirSync(runDir).includes('report.json'));
  } finally {
    cleanup(ctx);
  }
  // A transcript with an unused call, or a failed call that claims a response, is not reproduced (review F2).
  const e = endpoints();
  const files = await buildRunFixture(RUN_FIXTURES[0], e);
  const extend = new Map(files);
  const tr = JSON.parse(Buffer.from(files.get('transcript.json')).toString('utf8'));
  tr.calls.push({ ...tr.calls[21], call: 23, responseFile: 'response-23.bin' });
  extend.set('transcript.json', Buffer.from(`${canonicalize(tr)}\n`));
  extend.set('response-23.bin', files.get('response-22.bin'));
  assert.equal((await reproduceRun({ files: extend, endpoints: e, readAuthorization: readCompatAuthorization })).reproduced, false);
  // The Python reference's own record does not make a run directory unverifiable (review F8).
  const recorded = new Map(files);
  recorded.set('python-reference.txt', Buffer.from('compat run reference: 15/15 checks agree; AGREES\n'));
  assert.equal((await reproduceRun({ files: recorded, endpoints: e, readAuthorization: readCompatAuthorization })).reproduced, true);
});

test('the fixture runs cover PASS, BLOCKED and UNRESOLVED, a policy stop, the deadline and incomplete runs', () => {
  const report = (name) => JSON.parse(read(`${FIXTURE_DIR}/${name}/report.json`));
  const complete = RUN_FIXTURES.filter((f) => readdirSync(new URL(`${FIXTURE_DIR}/${f.name}/`, ROOT)).includes('report.json'));
  assert.deepEqual(RUN_FIXTURES.filter((f) => !complete.includes(f)).map((f) => f.name), ['response-storage-fails', 'journal-fails-before-call-9']);
  const overalls = new Set(complete.map((f) => report(f.name).overall));
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
