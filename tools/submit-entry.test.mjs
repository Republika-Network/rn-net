// RN-NET-03B2-C2: the controlled live entry points, the request policy and the durable store,
// offline. Every run goes to an injected, simulated transport (the B3 fixtures' synthetic
// providers); nothing here can reach a network, and both commands refuse live use.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { canonicalize } from '../packages/canonical/src/index.mjs';
import { BroadcastCode, BroadcastError, entryDigest, Outcome, readAuthorization } from '../packages/chain-submit/src/index.mjs';
import { FILE, withLog } from './broadcast/build-b3-fixtures.mjs';
import { replayTextTransport } from './broadcast/simulated.mjs';
import { runBroadcast } from './submit/broadcaster.mjs';
import { EntryCode, readPrivateText, REVIEWED_PROVIDERS, reviewedEndpoints } from './submit/entry.mjs';
import { createReadOnlyPolicy, createRequestPolicy, SUBMIT_READ_PLAN, SUBMIT_RUN_REQUESTS } from './submit/policy.mjs';
import { LIVE_NETWORK_ACCESS as SUBMIT_LIVE, main as submitMain, SUBMIT_EXIT, SUBMIT_FLAGS, submitAnchor } from './submit/submit-anchor.mjs';
import { LIVE_NETWORK_ACCESS as STATUS_LIVE, STATUS_EXIT, statusCheck } from './submit/status-check.mjs';
import { appendEntry, readLog, writeNewFile } from './submit/store.mjs';

const fixtures = JSON.parse(readFileSync(FILE, 'utf8'));
const reviewed = fixtures.endpoints.providers.map(({ id, network, url }) => ({ id, network, url }));
const submitCase = (id) => structuredClone(fixtures.submit.find((c) => c.id === id));
const statusCase = (id) => structuredClone(fixtures.statusChecks.find((c) => c.id === id));
const digestOf = (text) => readAuthorization(text).digest;
const withAuthorizationId = (text, id) => text.replace(/"authorizationId":"[^"]+"/, `"authorizationId":"${id}"`);

/** A spy around a transport: counts every request and every write method it is asked to send. */
function spy(inner) {
  const seen = [];
  const transport = async (request) => {
    seen.push(JSON.parse(Buffer.from(request.body).toString('utf8')).method);
    return inner(request);
  };
  transport.seen = seen;
  return transport;
}

/** The argv and readText of a submit run over a fixture case. */
function submitRun(c, dirs, overrides = {}) {
  const files = {
    '/f/authorization.json': c.inputs.authorization,
    '/f/intent.json': `${c.inputs.intent}\n`,
    '/f/signed.txt': `${c.inputs.signedTransaction}\n`,
    '/f/endpoints.json': JSON.stringify(fixtures.endpoints),
    ...overrides.files,
  };
  const args = {
    network: JSON.parse(c.inputs.authorization).network,
    authorization: '/f/authorization.json',
    intent: '/f/intent.json',
    'approved-digest': c.inputs.approvedDigest,
    'signed-transaction': '/f/signed.txt',
    endpoints: '/f/endpoints.json',
    'log-dir': dirs.logDir,
    'evidence-dir': dirs.evidenceDir,
    ...overrides.args,
  };
  const argv = overrides.argv ?? SUBMIT_FLAGS.flatMap((f) => [`--${f}`, args[f]]);
  const readText = (path) => {
    if (!Object.hasOwn(files, path)) throw Object.assign(new Error('no such file'), { code: 'ENOENT' });
    return files[path];
  };
  const transport = spy(overrides.transport ?? replayTextTransport(c.exchanges));
  const network = JSON.parse(files['/f/authorization.json']).network ?? args.network;
  const approve = overrides.approve ?? (async () => `${network} ${digestOf(files['/f/authorization.json'].trimEnd()).slice(-16)}`);
  // The fixtures' clock advances by clockStepPerRequest for every request sent.
  const now = () => c.now + (c.clockStepPerRequest ?? 0) * transport.seen.length;
  return { argv, transport, deps: { readText, transport, referenceVerifier: () => structuredClone(c.referenceRecord), now, approve, reviewed } };
}

test('C2: both entry points are disabled for live network access and refuse as commands', () => {
  assert.equal(SUBMIT_LIVE, false);
  assert.equal(STATUS_LIVE, false);
  const written = [];
  const original = process.stderr.write;
  process.stderr.write = (text) => written.push(text);
  try {
    assert.equal(submitMain(), SUBMIT_EXIT.LIVE_DISABLED);
  } finally {
    process.stderr.write = original;
  }
  assert.match(written.join(''), /RNSA_LIVE_DISABLED/);
});

test('C2: the reviewed provider list is exactly the committed endpoint configuration', () => {
  const config = JSON.parse(readFileSync(new URL('../config/rpc-endpoints.json', import.meta.url), 'utf8'));
  assert.deepEqual(config.providers.map(({ id, network, url }) => ({ id, network, url })), REVIEWED_PROVIDERS.map((p) => ({ ...p })));
  for (const network of ['xrpl:testnet', 'evm:11155111']) assert.equal(reviewedEndpoints(config, network), config);
  for (const change of [
    (c) => (c.providers[0].url = 'https://s.altnet.rippletest.net:51233/'),
    (c) => (c.providers[3].id = 'sepolia-other'),
    (c) => c.providers.pop(),
    (c) => c.providers.push({ id: 'xrpl-mainnet', network: 'xrpl:testnet', url: 'https://xrplcluster.com/', operator: 'x', source: 'https://x.example/' }),
  ]) {
    const copy = structuredClone(config);
    change(copy);
    assert.throws(() => reviewedEndpoints(copy, 'xrpl:testnet') && reviewedEndpoints(copy, 'evm:11155111'), (e) => e.code === EntryCode.ENDPOINTS_NOT_REVIEWED);
  }
});

test('C2: simulated XRPL and Sepolia success, with exactly the planned requests and one write', async () => {
  for (const [id, network, write] of [['xrpl-accepted', 'xrpl:testnet', 'submit'], ['sepolia-accepted', 'evm:11155111', 'eth_sendRawTransaction']]) {
    const c = submitCase(id);
    await withLog([], async (dirs) => {
      const run = submitRun(c, dirs);
      const out = await submitAnchor(run);
      assert.equal(out.exitCode, SUBMIT_EXIT.ACCEPTED_PROVISIONAL, id);
      assert.equal(out.result.outcome, Outcome.ACCEPTED_PROVISIONAL);
      assert.match(out.message, /not proof of inclusion/);
      assert.equal(out.result.requests, SUBMIT_RUN_REQUESTS[network]);
      assert.equal(out.result.writes, 1);
      assert.equal(run.transport.seen.length, SUBMIT_RUN_REQUESTS[network]);
      assert.deepEqual(run.transport.seen.filter((m) => m === write).length, 1);
      assert.equal(run.transport.seen.at(-1), write);
      assert.deepEqual(readLog(dirs.logDir).map((e) => e.kind), ['RUN_STARTED', 'ATTEMPTING', 'RESULT']);
      assert.deepEqual(readdirSync(out.result.runDirectory).sort(), ['attempt.json', 'capture.json', 'submission-record.json']);
    });
  }
});

test('C2: unauthorized runs are refused before anything is consumed or sent', async () => {
  const c = submitCase('xrpl-accepted');
  const cases = [
    ['wrong approval text', { approve: async () => 'xrpl:testnet 0000000000000000' }, EntryCode.APPROVAL_REFUSED],
    ['approval for the other network', { approve: async (prompt) => `evm:11155111 ${/digest: sha256:([0-9a-f]{64})/.exec(prompt)[1].slice(-16)}` }, EntryCode.APPROVAL_REFUSED],
    ['approval prompt fails', { approve: async () => { throw new Error('no terminal'); } }, EntryCode.APPROVAL_REFUSED],
    ['no approval route', { approve: null }, EntryCode.APPROVAL_REFUSED],
    ['missing authorization file', { files: { '/f/authorization.json': undefined } }, null],
    ['authorization not canonical', { files: { '/f/authorization.json': `${c.inputs.authorization.replace(':', ': ')}\n` } }, EntryCode.AUTHORIZATION],
    ['a status authorization instead', { files: { '/f/authorization.json': statusCase('status-xrpl-included').inputs.authorization } }, EntryCode.AUTHORIZATION],
    ['--network differs from the authorization', { args: { network: 'evm:11155111' } }, EntryCode.NETWORK_MISMATCH],
    ['a mainnet', { args: { network: 'xrpl:mainnet' } }, EntryCode.NETWORK_NOT_ALLOWED],
    ['an EVM mainnet', { args: { network: 'evm:1' } }, EntryCode.NETWORK_NOT_ALLOWED],
    ['endpoints not reviewed', { files: { '/f/endpoints.json': JSON.stringify({ ...fixtures.endpoints, providers: fixtures.endpoints.providers.map((p, i) => (i === 0 ? { ...p, url: 'https://evil.fixture.invalid/' } : p)) }) } }, EntryCode.ENDPOINTS_NOT_REVIEWED],
    ['a retry option', { argv: [...SUBMIT_FLAGS.flatMap((f) => [`--${f}`, 'x']).slice(0, -2), '--retry', '3'] }, EntryCode.USAGE],
    ['a flag twice', { argv: [...SUBMIT_FLAGS.flatMap((f) => [`--${f}`, 'x']).slice(0, -2), '--network', 'xrpl:testnet'] }, EntryCode.USAGE],
    ['no arguments', { argv: [] }, EntryCode.USAGE],
  ];
  for (const [label, overrides, code] of cases) {
    if (overrides.files && Object.values(overrides.files).includes(undefined)) {
      // A missing file: the reader throws, and nothing at all happens.
      await withLog([], async (dirs) => {
        const run = submitRun(c, dirs);
        const readText = (p) => (p === '/f/authorization.json' ? readPrivateText('/nonexistent/authorization.json') : run.deps.readText(p));
        const out = await submitAnchor({ argv: run.argv, deps: { ...run.deps, readText } });
        assert.equal(out.code, EntryCode.FILE, label);
        assert.equal(run.transport.seen.length, 0, label);
        assert.deepEqual(readLog(dirs.logDir), [], label);
      });
      continue;
    }
    await withLog([], async (dirs) => {
      const run = submitRun(c, dirs, overrides);
      if (overrides.approve === null) run.deps.approve = undefined;
      const out = await submitAnchor(run);
      assert.equal(out.exitCode, SUBMIT_EXIT.REFUSED, label);
      assert.equal(out.code, code, `${label}: ${out.message}`);
      assert.equal(run.transport.seen.length, 0, label);
      assert.deepEqual(readLog(dirs.logDir), [], `${label}: nothing consumed`);
    });
  }
});

test('C2: wrong payload, modified signed bytes, fees above the cap and expiry send nothing', async () => {
  const flip = (hex) => hex.slice(0, -2) + (hex.slice(-2) === '00' ? '01' : '00');
  const xrpl = submitCase('xrpl-accepted');
  const sepolia = submitCase('sepolia-accepted');
  const cases = [
    ['XRPL signed bytes modified', xrpl, { files: { '/f/signed.txt': flip(xrpl.inputs.signedTransaction).toUpperCase() } }],
    ['Sepolia signed bytes modified', sepolia, { files: { '/f/signed.txt': flip(sepolia.inputs.signedTransaction) } }],
    ['a different intent (payload)', xrpl, { files: { '/f/intent.json': sepolia.inputs.intent } }],
    ['the approved digest of another intent', xrpl, { args: { 'approved-digest': sepolia.inputs.approvedDigest } }],
  ];
  for (const [label, c, overrides] of cases) {
    await withLog([], async (dirs) => {
      const run = submitRun(c, dirs, overrides);
      run.deps.referenceVerifier = () => ({ ...structuredClone(c.referenceRecord), outcome: 'FAIL' });
      const out = await submitAnchor(run);
      assert.equal(out.result.outcome, Outcome.NOT_SENT, label);
      assert.equal(out.result.writes, 0, label);
      assert.equal(run.transport.seen.length, 0, `${label}: no request at all`);
    });
  }
  // The committed fixtures hold the rest, each refused before any write: fee above the cap in the
  // bytes and in the intent, an expired Sepolia authorization, one that expires during the reads,
  // and an XRPL ledger margin of 4 or fewer ledgers.
  for (const id of ['bytes-xrpl-fee-above-cap', 'bytes-xrpl-intent-fee-above-cap', 'bytes-sepolia-intent-fee-above-cap', 'sepolia-authorization-expired', 'sepolia-authorization-expires-during-reads', 'xrpl-read-ledger-margin']) {
    const c = submitCase(id);
    await withLog(c.logBefore, async (dirs) => {
      const out = await submitAnchor(submitRun(c, dirs));
      assert.equal(out.result.outcome, Outcome.NOT_SENT, id);
      assert.equal(out.result.writes, 0, id);
      assert.equal(out.code, c.expected.code, id);
    });
  }
});

test('C2: a repeated attempt is refused, and an expired or missing XRPL margin is never retried', async () => {
  const c = submitCase('xrpl-accepted');
  await withLog([], async (dirs) => {
    const first = await submitAnchor(submitRun(c, dirs));
    assert.equal(first.result.writes, 1);
    const again = submitRun(c, dirs);
    const second = await submitAnchor(again);
    assert.equal(second.code, BroadcastCode.AUTHORIZATION_USED);
    assert.equal(second.result.writes, 0);
    assert.equal(again.transport.seen.length, 0);
    // A new authorization for the same attempt number is refused by the log too.
    const third = submitRun(c, dirs, { files: { '/f/authorization.json': withAuthorizationId(c.inputs.authorization, 'xrpl-accepted-again') } });
    const out = await submitAnchor(third);
    assert.equal(out.code, BroadcastCode.LOG_ATTEMPT_NUMBER);
    assert.equal(third.transport.seen.length, 0);
  });
});

test('C2: a write timeout and an unknown response are UNCERTAIN, never retried, and block the next attempt', async () => {
  for (const [id, answer] of [
    ['timeout', () => Promise.reject(Object.assign(new Error('timeout'), { code: 'RNLO_TIMEOUT' }))],
    ['connection reset', () => Promise.reject(Object.assign(new Error('reset'), { code: 'RNLO_CONNECTION' }))],
    ['an unknown result shape', async () => ({ status: 200, body: new Uint8Array(Buffer.from('{"result":{"status":"success","engine_result":"tesSOMETHING"}}')) })],
    ['no engine_result', async () => ({ status: 200, body: new Uint8Array(Buffer.from('{"result":{"status":"success"}}')) })],
    // B3 review N5: a transport that claims the harness refused it, after sending, is UNCERTAIN.
    ['a transport pretending NOT_SENT_HARNESS', () => Promise.reject(new BroadcastError(BroadcastCode.NOT_SENT_HARNESS, 'lie'))],
    ['a thrown non-error', () => Promise.reject('string')],
  ]) {
    const c = submitCase('xrpl-accepted');
    const replay = replayTextTransport(c.exchanges.slice(0, -1));
    let writes = 0;
    const transport = async (request) => {
      if (replay.remaining() > 0) return replay(request);
      writes += 1;
      return answer();
    };
    await withLog([], async (dirs) => {
      const out = await submitAnchor(submitRun(c, dirs, { transport }));
      assert.equal(out.result.outcome, Outcome.UNCERTAIN, id);
      assert.equal(out.exitCode, SUBMIT_EXIT.UNCERTAIN, id);
      assert.match(out.message, /Do not resend/);
      assert.equal(writes, 1, `${id}: exactly one write, no retry`);
      const log = readLog(dirs.logDir);
      assert.deepEqual(log.map((e) => e.kind), ['RUN_STARTED', 'ATTEMPTING', 'RESULT']);
      // The next attempt (a resend, attempt 2) is refused until a status check resolves the first.
      const resend = JSON.parse(c.inputs.authorization);
      Object.assign(resend, { authorizationId: `resend-${id.replace(/[^a-z]+/g, '-')}`, attempt: 2, kind: 'resend', previousAttempt: entryDigest(log[2]) });
      const run = submitRun(c, dirs, { files: { '/f/authorization.json': canonicalize(resend) } });
      const next = await submitAnchor(run);
      assert.equal(next.code, BroadcastCode.LOG_CASE_NOT_PERMITTED, id);
      assert.equal(run.transport.seen.length, 0, id);
    });
  }
});

test('C2: concurrent runs on one log send at most one write, and a stopped write blocks the log', async () => {
  const c = submitCase('xrpl-accepted');
  await withLog([], async (dirs) => {
    const runs = ['concurrent-a', 'concurrent-b', 'concurrent-c'].map((id) => submitRun(c, dirs, { files: { '/f/authorization.json': withAuthorizationId(c.inputs.authorization, id) } }));
    const results = await Promise.all(runs.map((run) => submitAnchor(run)));
    const writes = results.reduce((n, r) => n + (r.result?.writes ?? 0), 0);
    assert.equal(writes, 1);
    for (const r of results.filter((x) => x.result.writes === 0)) assert.ok([BroadcastCode.LOG_CONFLICT, BroadcastCode.LOG_ATTEMPT_NUMBER, BroadcastCode.LOG_UNRESOLVED_ATTEMPT].includes(r.code), r.code);
    const log = readLog(dirs.logDir);
    assert.equal(log.filter((e) => e.kind === 'ATTEMPTING').length, 1);
    assert.equal(log.filter((e) => e.kind === 'RUN_STARTED').length, 3);
  });
  // A temporary name left by a stopped write refuses every later run (nothing is consumed).
  await withLog([], async (dirs) => {
    writeFileSync(join(dirs.logDir, '.000000.json.tmp'), '{', { mode: 0o600 });
    const run = submitRun(c, dirs);
    const out = await submitAnchor(run);
    assert.equal(out.code, BroadcastCode.LOG_CONFLICT);
    assert.equal(run.transport.seen.length, 0);
    rmSync(join(dirs.logDir, '.000000.json.tmp'));
  });
});

test('C2 N4: entries and evidence are created through a temporary name, exclusively, and nothing is left behind', () => {
  const root = mkdtempSync(join(tmpdir(), 'rnnet-c2-store-'));
  try {
    chmodSync(root, 0o700);
    writeNewFile(join(root, 'a.json'), 'one\n');
    assert.deepEqual(readdirSync(root), ['a.json']);
    assert.throws(() => writeNewFile(join(root, 'a.json'), 'two\n'), (e) => e.code === 'EEXIST');
    assert.equal(readFileSync(join(root, 'a.json'), 'utf8'), 'one\n');
    // Another writer's temporary name is never reused or removed.
    writeFileSync(join(root, '.b.json.tmp'), 'partial', { mode: 0o600 });
    assert.throws(() => writeNewFile(join(root, 'b.json'), 'x\n'), (e) => e.code === 'EEXIST');
    assert.deepEqual(readdirSync(root).sort(), ['.b.json.tmp', 'a.json']);
    // A temporary name that is a symbolic link is refused (O_NOFOLLOW | O_EXCL).
    symlinkSync(join(root, 'a.json'), join(root, '.c.json.tmp'));
    assert.throws(() => writeNewFile(join(root, 'c.json'), 'x\n'));
    assert.equal(readFileSync(join(root, 'a.json'), 'utf8'), 'one\n');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('C2 N5: an oversized blob is refused at input, before RUN_STARTED', async () => {
  const c = submitCase('xrpl-accepted');
  await withLog([], async (dirs) => {
    const environment = { endpoints: fixtures.endpoints, now: () => c.now, referenceVerifier: () => structuredClone(c.referenceRecord), transport: spy(replayTextTransport(c.exchanges)), logDir: dirs.logDir, evidenceDir: dirs.evidenceDir };
    const result = await runBroadcast({ inputs: { ...c.inputs, signedTransaction: 'AB'.repeat(4097) }, environment });
    assert.equal(result.code, BroadcastCode.INPUT_INVALID);
    assert.deepEqual(readLog(dirs.logDir), []);
    assert.equal(environment.transport.seen.length, 0);
    const ok = await runBroadcast({ inputs: { ...c.inputs, signedTransaction: 42 }, environment });
    assert.equal(ok.code, BroadcastCode.INPUT_INVALID);
  });
});

test('C2: the request policy admits exactly the planned reads, then one write to the authorized provider', async () => {
  const providers = fixtures.endpoints.providers.filter((p) => p.network === 'xrpl:testnet');
  const body = (method) => new Uint8Array(Buffer.from(JSON.stringify({ method, params: [{}] })));
  const ok = async () => ({ status: 200, body: new Uint8Array() });
  const fresh = () => createRequestPolicy('xrpl:testnet', providers, providers[0].id);
  const readAll = async (policy) => {
    const reads = policy.reads(ok);
    for (const p of providers) for (const [method, n] of Object.entries(SUBMIT_READ_PLAN['xrpl:testnet'])) for (let i = 0; i < n; i++) await reads({ providerId: p.id, url: p.url, body: body(method) });
  };
  const refusedRead = async (policy, request) => assert.rejects(() => policy.reads(ok)(request), (e) => e.code === 'RNBC_REQUEST_POLICY');
  await refusedRead(fresh(), { providerId: providers[0].id, url: providers[0].url, body: body('submit') });
  await refusedRead(fresh(), { providerId: providers[0].id, url: providers[0].url, body: body('ledger') });
  await refusedRead(fresh(), { providerId: providers[0].id, url: 'https://elsewhere.fixture.invalid/', body: body('server_info') });
  await refusedRead(fresh(), { providerId: 'fixture-sepolia-a', url: fixtures.endpoints.providers[2].url, body: body('server_info') });
  await refusedRead(fresh(), { providerId: providers[0].id, url: providers[0].url, body: new Uint8Array(Buffer.from('[{"method":"server_info"}]')) });
  const twice = fresh();
  await twice.reads(ok)({ providerId: providers[0].id, url: providers[0].url, body: body('server_info') });
  await refusedRead(twice, { providerId: providers[0].id, url: providers[0].url, body: body('server_info') });
  // The write: not before every planned read, only the write method, only the authorized provider, once.
  const early = fresh();
  assert.match(early.admitWrite({ providerId: providers[0].id, url: providers[0].url, body: body('submit') }), /planned pre-submit read/);
  const policy = fresh();
  await readAll(policy);
  assert.match(policy.admitWrite({ providerId: providers[1].id, url: providers[1].url, body: body('submit') }), /only/);
  const other = fresh();
  await readAll(other);
  assert.match(other.admitWrite({ providerId: providers[0].id, url: providers[0].url, body: body('server_info') }), /not the write method/);
  const good = fresh();
  await readAll(good);
  assert.equal(good.admitWrite({ providerId: providers[0].id, url: providers[0].url, body: body('submit') }), null);
  assert.match(good.admitWrite({ providerId: providers[0].id, url: providers[0].url, body: body('submit') }), /second write/);
  assert.throws(() => createRequestPolicy('xrpl:mainnet', providers, providers[0].id), TypeError);
  assert.throws(() => createRequestPolicy('xrpl:testnet', providers.slice(0, 1), providers[0].id), TypeError);
});

test('C2: status verification is separately read-only, and works on simulated providers', async () => {
  for (const id of ['status-xrpl-included', 'status-sepolia-included', 'status-xrpl-expired-after-crash', 'status-sepolia-pending', 'status-xrpl-not-searched-all']) {
    const c = statusCase(id);
    await withLog(c.logBefore, async (dirs) => {
      const files = { '/f/authorization.json': c.inputs.authorization, '/f/intent.json': `${c.inputs.intent}\n`, '/f/endpoints.json': JSON.stringify(fixtures.endpoints) };
      const network = JSON.parse(c.inputs.authorization).network;
      const transport = spy(replayTextTransport(c.exchanges));
      const argv = ['--network', network, '--authorization', '/f/authorization.json', '--intent', '/f/intent.json', '--endpoints', '/f/endpoints.json', '--log-dir', dirs.logDir, '--evidence-dir', dirs.evidenceDir];
      const approve = async (prompt) => `${network} ${/digest: sha256:([0-9a-f]{64})/.exec(prompt)[1].slice(-16)}`;
      const out = await statusCheck({ argv, deps: { readText: (p) => files[p], transport, now: () => c.now, approve, reviewed } });
      assert.equal(out.finding, c.expected.finding, id);
      assert.equal(out.exitCode, out.finding === 'UNRESOLVED' ? STATUS_EXIT.UNRESOLVED : STATUS_EXIT.RESOLVED, id);
      assert.ok(!transport.seen.some((m) => m === 'submit' || m === 'eth_sendRawTransaction'), id);
      // A refused approval reads nothing.
      const refused = spy(replayTextTransport(c.exchanges));
      const no = await statusCheck({ argv, deps: { readText: (p) => files[p], transport: refused, now: () => c.now, approve: async () => 'no', reviewed } });
      assert.equal(no.code, EntryCode.APPROVAL_REFUSED);
      assert.equal(refused.seen.length, 0);
    });
  }
  // The read-only policy refuses every write method and anything not a read.
  const providers = fixtures.endpoints.providers.filter((p) => p.network === 'evm:11155111');
  const policy = createReadOnlyPolicy('evm:11155111', providers);
  const wrapped = policy.wrap(async () => ({ status: 200, body: new Uint8Array() }));
  for (const method of ['eth_sendRawTransaction', 'eth_sendTransaction', 'eth_sign', 'debug_traceTransaction']) {
    await assert.rejects(() => wrapped({ providerId: providers[0].id, url: providers[0].url, body: new Uint8Array(Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: [] }))) }), (e) => e.code === 'RNBC_REQUEST_POLICY', method);
  }
  assert.match(policy.violation, /not a read-only method/);
});

test('C2: private input files: absolute, regular, 0600, owned, bounded; never a symbolic link', () => {
  const root = mkdtempSync(join(tmpdir(), 'rnnet-c2-files-'));
  try {
    const file = join(root, 'a.json');
    writeFileSync(file, 'text', { mode: 0o600 });
    assert.equal(readPrivateText(file), 'text');
    chmodSync(file, 0o644);
    assert.throws(() => readPrivateText(file), (e) => e.code === EntryCode.FILE);
    chmodSync(file, 0o600);
    symlinkSync(file, join(root, 'link.json'));
    assert.throws(() => readPrivateText(join(root, 'link.json')), (e) => e.code === EntryCode.FILE);
    assert.throws(() => readPrivateText('a.json'), (e) => e.code === EntryCode.FILE);
    assert.throws(() => readPrivateText(root), (e) => e.code === EntryCode.FILE);
    writeFileSync(join(root, 'big.json'), 'x'.repeat(70_000), { mode: 0o600 });
    assert.throws(() => readPrivateText(join(root, 'big.json')), (e) => e.code === EntryCode.FILE);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('C2: an existing log entry blocks the same index, whatever writes it', () => {
  const root = mkdtempSync(join(tmpdir(), 'rnnet-c2-log-'));
  try {
    chmodSync(root, 0o700);
    const entry = { authorizationDigest: `sha256:${'a'.repeat(64)}`, format: 'rnnet.submission-log-entry.v1', index: 0, kind: 'RUN_STARTED', mode: 'submit', network: 'xrpl:testnet', sender: 'r', sequence: '1' };
    appendEntry(root, entry);
    assert.throws(() => appendEntry(root, entry), (e) => e.code === BroadcastCode.LOG_CONFLICT);
    assert.deepEqual(readdirSync(root), ['000000.json']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
