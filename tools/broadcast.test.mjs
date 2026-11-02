// RN-NET-03B2-B3: the keyless broadcaster, offline. Every committed case is replayed through
// tools/submit/ from its recorded exchanges alone; the write path, the log, the evidence files and
// the isolation rules are tested directly. Simulated providers only: no network, no key.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { canonicalize } from '../packages/canonical/src/index.mjs';
import { READ_ONLY_METHODS, requestBytes } from '../packages/chain-readonly/src/index.mjs';
import {
  BroadcastCode,
  classifySubmitResponse,
  decideAttempt,
  entryDigest,
  makeEntry,
  Outcome,
  readAuthorization,
  submitRequestBytes,
  utcSeconds,
  WRITE_METHODS,
} from '../packages/chain-submit/src/index.mjs';
import { build, FILE, withLog } from './broadcast/build-b3-fixtures.mjs';
import { replayTextTransport } from './broadcast/simulated.mjs';
import { createWriteGate, runBroadcast } from './submit/broadcaster.mjs';
import { appendEntry, checkPrivateDirectory, readLog, writeNewFile } from './submit/store.mjs';
import { runStatusCheck } from './submit/status.mjs';

const fixtures = JSON.parse(readFileSync(FILE, 'utf8'));
const canon = (v) => canonicalize(v);

test('the committed broadcaster fixtures are exactly what the generator builds', async () => {
  assert.ok(readFileSync(FILE).equals(await build()));
});

test('every submit case replays to its recorded outcome, code, counts, record and log entries', async () => {
  assert.ok(fixtures.submit.length >= 150);
  for (const c of fixtures.submit) {
    const replay = replayTextTransport(c.exchanges);
    let sent = 0;
    const transport = async (request) => {
      sent += 1;
      return replay(request);
    };
    transport.remaining = replay.remaining;
    const { result, log } = await withLog(c.logBefore, (dirs) => runBroadcast({
      inputs: c.inputs,
      environment: { endpoints: fixtures.endpoints, now: () => c.now + c.clockStepPerRequest * sent, referenceVerifier: () => structuredClone(c.referenceRecord), transport, logDir: dirs.logDir, evidenceDir: dirs.evidenceDir, ...c.environmentExtra },
    }));
    const e = c.expected;
    assert.equal(result.outcome, e.outcome, c.id);
    assert.equal(result.code, e.code, c.id);
    assert.equal(result.requests, e.requests, `${c.id} requests`);
    assert.equal(result.writes, e.writes, `${c.id} writes`);
    assert.equal(canon(result.record), canon(e.record), `${c.id} record`);
    assert.equal(result.recordDigest, e.recordDigest, c.id);
    assert.equal(canon(log.slice(c.logBefore.length)), canon(e.appended), `${c.id} log`);
    assert.equal(transport.remaining(), 0, `${c.id}: every recorded exchange was used`);
    assert.ok(e.writes <= 1, `${c.id}: at most one write`);
    // Nothing is written to the network unless the run reached its write.
    if (e.writes === 0) assert.ok(!c.exchanges.some((x) => /"method":"(?:submit|eth_sendRawTransaction)"/.test(x.request)), `${c.id}: no write request`);
  }
});

test('every status case replays to its finding, record and log entries', async () => {
  for (const c of fixtures.statusChecks) {
    const transport = replayTextTransport(c.exchanges);
    const { result, log } = await withLog(c.logBefore, (dirs) => runStatusCheck({
      inputs: c.inputs, environment: { endpoints: fixtures.endpoints, now: () => c.now, transport, logDir: dirs.logDir, evidenceDir: dirs.evidenceDir },
    }));
    assert.equal(result.finding, c.expected.finding, c.id);
    assert.equal(result.code, c.expected.code, c.id);
    assert.equal(canon(result.record), canon(c.expected.record), c.id);
    assert.equal(canon(log.slice(c.logBefore.length)), canon(c.expected.appended), c.id);
    assert.equal(transport.remaining(), 0, c.id);
    assert.ok(!c.exchanges.some((x) => /"method":"(?:submit|eth_sendRawTransaction)"/.test(x.request)), `${c.id}: a status check never writes`);
  }
});

test('the design §8 scenarios are all present', () => {
  const ids = new Set([...fixtures.submit, ...fixtures.statusChecks].map((c) => c.id));
  for (const id of [
    'xrpl-input-secret', 'xrpl-input-seed', 'xrpl-input-key-type', 'xrpl-input-keyfile', 'xrpl-input-passphrase', 'xrpl-authorization-blob-differs',
    'xrpl-read-ledger-margin', 'sepolia-authorization-expired', 'xrpl-authorization-reused', 'xrpl-resend-wrong-link', 'xrpl-resend-skips-attempt',
    'xrpl-provider-unknown', 'xrpl-provider-other-network', 'bytes-xrpl-trailing-byte', 'bytes-xrpl-network-id-added', 'bytes-sepolia-type-1',
    'bytes-sepolia-high-s', 'bytes-sepolia-y-parity-2', 'bytes-sepolia-signature-from-another-key', 'bytes-xrpl-key-and-signature-substituted',
    'xrpl-supplied-record-other-bytes', 'xrpl-supplied-records-differ', 'xrpl-python-disagrees', 'sepolia-read-wrong-chain', 'xrpl-read-sequence-moved',
    'xrpl-read-already-known', 'sepolia-read-nonce-pending', 'sepolia-read-base-fee', 'sepolia-read-balance', 'xrpl-read-invalid-json', 'xrpl-read-timeout',
    'xrpl-write-timeout', 'xrpl-write-connection-lost', 'xrpl-write-blocked-address', 'xrpl-http-500', 'xrpl-http-429', 'xrpl-hash-differs', 'xrpl-ter-queued',
    'xrpl-tem', 'xrpl-tel-insuf-fee', 'xrpl-tel-can-not-queue', 'xrpl-tef-already', 'xrpl-tef-past-seq', 'xrpl-tec', 'xrpl-accepted-false',
    'xrpl-broadcast-false', 'sepolia-error-already-known', 'xrpl-after-crash', 'xrpl-dry-run-reused', 'xrpl-resend-after-rejected', 'xrpl-after-included',
    'sepolia-authorization-expires-during-reads', 'sepolia-authorization-valid-through-reads', 'status-xrpl-not-searched-all', 'status-xrpl-sequence-used', 'status-xrpl-expired-after-crash', 'status-sepolia-pending',
  ]) assert.ok(ids.has(id), id);
});

test('the write allowlist is disjoint from the read allowlist, and chain-readonly cannot build a write', () => {
  for (const network of Object.keys(WRITE_METHODS)) {
    assert.deepEqual(WRITE_METHODS[network].filter((m) => READ_ONLY_METHODS[network].includes(m)), []);
    for (const method of [...WRITE_METHODS[network], 'sign', 'sign_for', 'submit_multisigned', 'wallet_propose', 'eth_sendTransaction', 'eth_sign', 'eth_signTransaction', 'personal_sign']) {
      assert.throws(() => requestBytes(network, method, {}), TypeError, method);
    }
  }
  assert.deepEqual(WRITE_METHODS, { 'xrpl:testnet': ['submit'], 'evm:11155111': ['eth_sendRawTransaction'] });
});

test('the write requests are exact and take only the signed bytes', () => {
  assert.equal(Buffer.from(submitRequestBytes('xrpl:testnet', 'ABCD')).toString(), '{"method":"submit","params":[{"fail_hard":true,"tx_blob":"ABCD"}]}');
  assert.equal(Buffer.from(submitRequestBytes('evm:11155111', '0xabcd')).toString(), '{"id":1,"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xabcd"]}');
  for (const [network, blob] of [['xrpl:testnet', 'abcd'], ['xrpl:testnet', 'ABC'], ['evm:11155111', 'abcd'], ['evm:11155111', '0xABCD'], ['xrpl:mainnet', 'ABCD'], ['evm:1', '0xab']]) {
    assert.throws(() => submitRequestBytes(network, blob), TypeError, `${network} ${blob}`);
  }
  assert.throws(() => submitRequestBytes('xrpl:testnet', 'AB'.repeat(4097)), TypeError);
  assert.equal(submitRequestBytes.length, 2);
});

test('the harness lets exactly one write through per run', async () => {
  const gate = createWriteGate();
  let sent = 0;
  await gate.send(async () => (sent += 1));
  assert.throws(() => gate.send(async () => (sent += 1)), (e) => e.code === BroadcastCode.NOT_SENT_HARNESS);
  assert.equal(sent, 1);
  assert.equal(classifySubmitResponse('xrpl:testnet', { harnessRefused: BroadcastCode.NOT_SENT_HARNESS }, {}).outcome, Outcome.NOT_SENT);
});

test('only a harness refusal or a blocked address is NOT_SENT; every other transport failure is UNCERTAIN', () => {
  for (const code of ['RNLO_TIMEOUT', 'RNLO_CONNECTION', 'RNLO_REDIRECT', 'RNLO_RESPONSE_TOO_LARGE', 'RNLO_ANYTHING', undefined]) {
    for (const network of ['xrpl:testnet', 'evm:11155111']) assert.equal(classifySubmitResponse(network, { transportError: code }, {}).outcome, Outcome.UNCERTAIN, String(code));
  }
  assert.equal(classifySubmitResponse('evm:11155111', { transportError: 'RNLO_BLOCKED_ADDRESS' }, {}).outcome, Outcome.NOT_SENT);
  assert.equal(classifySubmitResponse('evm:11155111', null, {}).outcome, Outcome.UNCERTAIN);
});

test('a response larger than the limit, or not bytes, is UNCERTAIN and not parsed', async () => {
  const base = fixtures.submit.find((c) => c.id === 'xrpl-accepted');
  for (const [label, answer] of [['too large', { status: 200, body: new Uint8Array(262_145) }], ['not bytes', { status: 200, body: 'text' }]]) {
    const replay = replayTextTransport(base.exchanges.slice(0, -1));
    const transport = async (request) => (replay.remaining() > 0 ? replay(request) : answer);
    const { result } = await withLog([], (dirs) => runBroadcast({
      inputs: { ...base.inputs, authorization: base.inputs.authorization.replace('"authorizationId":"xrpl-accepted"', `"authorizationId":"oversized-${label.replace(' ', '-')}"`) },
      environment: { endpoints: fixtures.endpoints, now: () => base.now, referenceVerifier: () => structuredClone(base.referenceRecord), transport, logDir: dirs.logDir, evidenceDir: dirs.evidenceDir },
    }));
    assert.equal(result.outcome, Outcome.UNCERTAIN, label);
    assert.equal(result.writes, 1);
  }
});

test('RUN_STARTED is written before any read, ATTEMPTING before the write, RESULT after it', async () => {
  const base = fixtures.submit.find((c) => c.id === 'xrpl-accepted');
  const seen = [];
  const replay = replayTextTransport(base.exchanges);
  await withLog([], async (dirs) => {
    const transport = async (request) => {
      seen.push([Buffer.from(request.body).toString().includes('"submit"') ? 'write' : 'read', readLog(dirs.logDir).map((e) => e.kind)]);
      return replay(request);
    };
    await runBroadcast({ inputs: base.inputs, environment: { endpoints: fixtures.endpoints, now: () => base.now, referenceVerifier: () => structuredClone(base.referenceRecord), transport, logDir: dirs.logDir, evidenceDir: dirs.evidenceDir } });
    assert.deepEqual(readLog(dirs.logDir).map((e) => e.kind), ['RUN_STARTED', 'ATTEMPTING', 'RESULT']);
  });
  assert.deepEqual(seen[0], ['read', ['RUN_STARTED']]);
  assert.deepEqual(seen.at(-1), ['write', ['RUN_STARTED', 'ATTEMPTING']]);
  assert.equal(seen.filter(([k]) => k === 'write').length, 1);
});

test('a crash after the write leaves the attempt unresolved, and every later run is refused until RESOLVED', () => {
  const c = fixtures.submit.find((x) => x.id === 'xrpl-after-crash');
  assert.equal(c.expected.code, BroadcastCode.LOG_UNRESOLVED_ATTEMPT);
  assert.ok(c.logBefore.some((e) => e.kind === 'ATTEMPTING') && !c.logBefore.some((e) => e.kind === 'RESULT'));
  const after = fixtures.submit.find((x) => x.id === 'xrpl-replacement-after-expired');
  assert.equal(after.expected.outcome, Outcome.ACCEPTED_PROVISIONAL);
  assert.ok(after.logBefore.some((e) => e.kind === 'RESOLVED' && e.finding === 'EXPIRED'));
});

test('the log store: wx, mode 0600, contiguous canonical entries, never overwritten', () => {
  const root = mkdtempSync(join(tmpdir(), 'rnnet-b3-store-'));
  try {
    chmodSync(root, 0o700);
    const entry = makeEntry(0, 'RUN_STARTED', { authorizationDigest: `sha256:${'1'.repeat(64)}`, network: 'xrpl:testnet', sender: 'r', sequence: '1', mode: 'submit' });
    appendEntry(root, entry);
    assert.equal(lstatSync(join(root, '000000.json')).mode & 0o777, 0o600);
    assert.throws(() => appendEntry(root, entry), (e) => e.code === BroadcastCode.LOG_CONFLICT);
    assert.throws(() => writeNewFile(join(root, '000000.json'), 'x'), (e) => e.code === 'EEXIST');
    assert.equal(canon(readLog(root)), canon([entry]));
    writeFileSync(join(root, 'notes.txt'), 'x', { mode: 0o600 });
    assert.throws(() => readLog(root), (e) => e.code === BroadcastCode.LOG_INVALID);
    rmSync(join(root, 'notes.txt'));
    writeFileSync(join(root, '000002.json'), '{}\n', { mode: 0o600 });
    assert.throws(() => readLog(root), (e) => e.code === BroadcastCode.LOG_INVALID, 'a gap');
    rmSync(join(root, '000002.json'));
    writeFileSync(join(root, '000001.json'), '{"a": 1}\n', { mode: 0o600 });
    assert.throws(() => readLog(root), (e) => e.code === BroadcastCode.LOG_INVALID, 'not canonical');
    chmodSync(join(root, '000001.json'), 0o644);
    assert.throws(() => readLog(root), (e) => e.code === BroadcastCode.LOG_INVALID, 'mode');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('private directories: absolute, real, mode 0700, never inside a git worktree', () => {
  const root = mkdtempSync(join(tmpdir(), 'rnnet-b3-dir-'));
  try {
    chmodSync(root, 0o700);
    checkPrivateDirectory(root, BroadcastCode.LOG_DIRECTORY);
    const refused = (dir) => assert.throws(() => checkPrivateDirectory(dir, BroadcastCode.LOG_DIRECTORY), (e) => e.code === BroadcastCode.LOG_DIRECTORY, dir);
    refused('relative/dir');
    refused(join(root, 'missing'));
    refused(`${root}/.`);
    chmodSync(root, 0o750);
    refused(root);
    chmodSync(root, 0o700);
    mkdirSync(join(root, 'repo', '.git'), { recursive: true });
    mkdirSync(join(root, 'repo', 'log'), { mode: 0o700 });
    refused(join(root, 'repo', 'log'));
    // The repository itself is a git worktree.
    refused(new URL('..', import.meta.url).pathname.replace(/\/$/, ''));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('evidence: a run directory 0700 with the record and capture 0600, outside the log', async () => {
  const base = fixtures.submit.find((c) => c.id === 'sepolia-accepted');
  await withLog([], async (dirs) => {
    const result = await runBroadcast({
      inputs: base.inputs,
      environment: { endpoints: fixtures.endpoints, now: () => base.now, referenceVerifier: () => structuredClone(base.referenceRecord), transport: replayTextTransport(base.exchanges), logDir: dirs.logDir, evidenceDir: dirs.evidenceDir },
    });
    assert.equal(lstatSync(result.runDirectory).mode & 0o777, 0o700);
    // attempt.json is written, durably, before the write (C2): the exact request and the reads.
    assert.deepEqual(readdirSync(result.runDirectory).sort(), ['attempt.json', 'capture.json', 'submission-record.json']);
    const attempt = JSON.parse(readFileSync(join(result.runDirectory, 'attempt.json'), 'utf8'));
    assert.equal(attempt.format, 'rnnet.submission-attempt.v1');
    assert.equal(attempt.requestSha256, result.record.requestSha256);
    assert.equal(attempt.presubmitExchanges, 12);
    assert.equal(attempt.attemptEntry, entryDigest(readLog(dirs.logDir)[1]));
    for (const name of readdirSync(result.runDirectory)) assert.equal(lstatSync(join(result.runDirectory, name)).mode & 0o777, 0o600);
    assert.equal(readFileSync(join(result.runDirectory, 'submission-record.json'), 'utf8'), `${canon(result.record)}\n`);
    const capture = JSON.parse(readFileSync(join(result.runDirectory, 'capture.json'), 'utf8'));
    assert.equal(capture.exchanges.length, 13);
    assert.ok(!existsSync(join(dirs.logDir, 'capture.json')));
  });
});

test('authorization digests and validity times', () => {
  const c = fixtures.submit.find((x) => x.id === 'xrpl-accepted');
  const { digest, authorization } = readAuthorization(c.inputs.authorization);
  assert.equal(digest, c.expected.record.authorizationDigest);
  assert.ok(Object.isFrozen(authorization));
  assert.equal(utcSeconds('2026-11-01T00:00:00Z'), 1_793_491_200);
  for (const bad of ['2026-02-29T00:00:00Z', '2026-11-01T24:00:00Z', '2026-11-01T00:00:00.000Z', '2026-11-01 00:00:00Z', 20261101]) assert.equal(utcSeconds(bad), null, String(bad));
});

test('log decisions: fail closed after uncertainty, and nothing after inclusion', () => {
  const uncertain = fixtures.submit.find((x) => x.id === 'xrpl-write-timeout');
  const log = [...uncertain.logBefore, ...uncertain.expected.appended];
  const result = log.at(-1);
  const auth = { ...readAuthorization(uncertain.inputs.authorization).authorization, authorizationId: 'next', attempt: 2, kind: 'resend', previousAttempt: entryDigest(result) };
  assert.throws(() => decideAttempt(log, auth), (e) => e.code === BroadcastCode.LOG_CASE_NOT_PERMITTED);
  assert.throws(() => decideAttempt(log, { ...auth, kind: 'replacement', blobSha256: `sha256:${'2'.repeat(64)}` }), (e) => e.code === BroadcastCode.LOG_CASE_NOT_PERMITTED);
});
