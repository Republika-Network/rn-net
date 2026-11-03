// RN-NET-03B2-C6-LIVE-ENABLE: the pre-live corrections and the enabling code, offline.
//   - N1: evidence durability under a failing disk (every write, fsync and link of a run, in
//     turn), a killed process, a full or unwritable evidence directory, and concurrent runs;
//   - F4: hostile and oversized responses are never stored or parsed;
//   - the command wiring (command.mjs) and the terminal approval (tty-approval.mjs).
// Every transport here is simulated, and the offline preload refuses the network. The command
// itself (compat-live.mjs) and the C6 transport are not imported here: see c6-transport.test.mjs
// and tools/broadcast/live-disabled.check.mjs.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { canonicalize } from '../packages/canonical/src/index.mjs';
import { C6_BUDGET, C6_PROVIDERS } from './compat/manifest.mjs';
import { SCENARIOS, SIM_NOW, simulatedTransport } from './compat/simulated.mjs';
import { readCompatAuthorization } from './compat-live/authorization.mjs';
import { runCommand } from './compat-live/command.mjs';
import { C6_MANIFEST_SHA256, CompatEntryCode, JOURNAL_FILE, MIN_FREE_BYTES, NODE_IO, RUN_LOCK } from './compat-live/entry.mjs';
import { compatLive, COMPAT_EXIT, describeSummary } from './compat-live/flow.mjs';
import { readResponse } from './compat-live/policy.mjs';
import { createTtyApproval, MAX_ANSWER_BYTES, TTY_PATH } from './compat-live/tty-approval.mjs';

const ROOT = new URL('../', import.meta.url);
const ENDPOINTS_PATH = new URL('config/rpc-endpoints.json', ROOT).pathname;
const iso = (seconds) => new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const NOT_AFTER = SIM_NOW + 1800;
const allCompatible = () => simulatedTransport(SCENARIOS.find((s) => s.name === 'all-compatible'));

function setup(id = 'c6-enable-test') {
  const base = mkdtempSync(join(tmpdir(), 'rnnet-c6-enable-'));
  chmodSync(base, 0o700);
  const dir = join(base, 'evidence');
  mkdirSync(dir, { mode: 0o700 });
  chmodSync(dir, 0o700);
  return { base, dir, id };
}
const cleanup = (ctx) => rmSync(ctx.base, { recursive: true, force: true });

function authorizationFile(ctx, id = ctx.id) {
  const a = {
    authorizationId: id,
    evidenceDir: ctx.dir,
    format: 'rnnet.compat-authorization.v1',
    manifestSha256: C6_MANIFEST_SHA256,
    notAfter: iso(NOT_AFTER),
    providers: C6_PROVIDERS.map((p) => ({ id: p.id, requests: C6_BUDGET[p.id], url: p.url })),
    publication: 'none',
    requestBudget: 22,
    scope: 'C6 read-only compatibility check (enable test)',
  };
  const text = `${canonicalize(a)}\n`;
  const path = join(ctx.base, `auth-${id}.json`);
  writeFileSync(path, text, { mode: 0o600 });
  chmodSync(path, 0o600);
  return { path, digest: readCompatAuthorization(text).digest };
}

/** One run through the flow; `transport` defaults to the all-compatible simulation. */
async function run(ctx, { id = ctx.id, transport = allCompatible(), io, minFreeBytes = 1, sleep = () => new Promise(() => {}) } = {}) {
  const { path, digest } = authorizationFile(ctx, id);
  const calls = [];
  const result = await compatLive({
    argv: ['--authorization', path, '--endpoints', ENDPOINTS_PATH, '--evidence-dir', ctx.dir],
    deps: {
      agreed: ctx.dir,
      transport: async (r) => {
        calls.push(r);
        return transport(r);
      },
      now: () => SIM_NOW,
      getuid: () => process.getuid(),
      approve: async () => `c6 ${digest.slice(-16)}`,
      sleep,
      minFreeBytes,
      ...(io === undefined ? {} : { io }),
    },
  });
  return { result, calls, runDir: join(ctx.dir, id) };
}

/** The complete records of a journal on disk (a torn last line is not a record). */
function journalOnDisk(runDir) {
  const path = join(runDir, JOURNAL_FILE);
  if (!existsSync(path)) return [];
  const lines = readFileSync(path, 'utf8').split('\n');
  return lines.slice(0, -1).map((l) => JSON.parse(l));
}

/**
 * NODE_IO with one failure: the `nth` call of `op` (counted over the whole run) fails with `code`,
 * or, for writeSync with `short`, writes nothing.
 */
function failingIo(op, nth, code, { short = false } = {}) {
  let n = 0;
  return {
    ...NODE_IO,
    [op]: (...args) => {
      n += 1;
      if (n === nth) {
        if (short) return 0;
        throw Object.assign(new Error(`simulated ${code}`), { code });
      }
      return NODE_IO[op](...args);
    },
  };
}
function countingIo() {
  const counts = { writeSync: 0, fsyncSync: 0, linkSync: 0, openSync: 0 };
  const io = { ...NODE_IO };
  for (const op of Object.keys(counts)) io[op] = (...args) => { counts[op] += 1; return NODE_IO[op](...args); };
  return { io, counts };
}

/** The N1 invariants of any run directory after any failure. */
function assertDurable(label, { result, calls, runDir }) {
  const names = existsSync(runDir) ? readdirSync(runDir) : [];
  assert.ok(!names.some((n) => n.startsWith('.')), `${label}: no partially written file is left (${names.filter((n) => n.startsWith('.'))})`);
  if (result.outcome !== 'REFUSED') {
    // A failure that touched no evidence (the lock's removal) leaves a complete, reproduced run.
    assert.ok(names.includes('report.json') && result.reportSha256 === sha256(readFileSync(join(runDir, 'report.json'))), `${label}: ${result.message}`);
    return;
  }
  assert.ok(!names.includes('report.json'), `${label}: an incomplete run never carries a report`);
  const records = journalOnDisk(runDir);
  const sends = records.filter((r) => r.event === 'send').map((r) => r.call);
  // Every request that reached the transport was durably journaled before it was sent, and
  // nothing reached the transport after the failure. The journal may hold ONE more "send" than was
  // sent: the record whose fsync failed (its bytes may be on disk), whose request was then not sent.
  // On the disk alone it reads as "possibly sent", never the other way round; the transcript, when
  // stored, says it was refused.
  assert.ok(sends.length === calls.length || sends.length === calls.length + 1, `${label}: ${calls.length} sent, ${sends.length} journaled as sent`);
  assert.deepEqual(sends, sends.map((_, i) => sends[0] + i), label);
  if (sends.length === calls.length + 1) {
    assert.equal(records[records.length - 1].event, 'send', `${label}: only the last record can be the unsent one`);
    assert.ok(result.summary.notSent.includes(sends[sends.length - 1]), `${label}: the flow knows it was not sent`);
    if (names.includes('transcript.json')) assert.notEqual(JSON.parse(readFileSync(join(runDir, 'transcript.json'), 'utf8')).calls[sends.length - 1].policy, null, label);
  }
  if (result.summary) {
    const s = result.summary;
    assert.equal(s.recorded.length + s.sentUnrecorded.length, calls.length, `${label}: ${describeSummary(s)}`);
    const outcomes = new Map(records.filter((r) => r.event === 'outcome').map((r) => [r.call, r]));
    for (const c of s.recorded) {
      const o = outcomes.get(c);
      assert.ok(o, `${label}: recorded call ${c} has its outcome on disk`);
      if (o.responseFile !== null) assert.equal(sha256(readFileSync(join(runDir, o.responseFile))), o.responseSha256, `${label}: call ${c}`);
    }
    assert.match(result.message, /SENT BUT NOT DURABLY RECORDED/);
  }
  if (calls.length === 0) assert.ok(names.every((n) => ['authorization.json', JOURNAL_FILE, 'transcript.json'].includes(n)), `${label}: nothing sent: no response, evidence or report (${names})`);
}

test('N1: a clean run journals every request before sending it, and its journal reproduces', async () => {
  const ctx = setup();
  try {
    const { result, calls, runDir } = await run(ctx);
    assert.equal(result.outcome, 'PASS', result.message);
    const records = journalOnDisk(runDir);
    assert.deepEqual(records[0], { authorizationDigest: readCompatAuthorization(readFileSync(join(runDir, 'authorization.json'), 'utf8')).digest, authorizationId: ctx.id, format: 'rnnet.provider-compat-journal.v1' });
    assert.equal(records.filter((r) => r.event === 'send').length, 22);
    assert.equal(records.filter((r) => r.event === 'outcome').length, 22);
    assert.equal(calls.length, 22);
    assert.deepEqual(result.summary, { recorded: Array.from({ length: 22 }, (_, i) => i + 1), sentUnrecorded: [], notSent: [], notReached: 0, forwarded: 22 });
    assert.ok(!existsSync(join(ctx.dir, RUN_LOCK)), 'the lock is released');
    assert.deepEqual(readdirSync(ctx.dir), [ctx.id], 'no probe or temporary file is left');
  } finally {
    cleanup(ctx);
  }
});

test('N1: a disk that fails at ANY write, fsync or link of a run fails closed and keeps what was sent on record', async () => {
  const counter = setup();
  let counts;
  try {
    const counted = countingIo();
    assert.equal((await run(counter, { io: counted.io })).result.outcome, 'PASS');
    counts = counted.counts;
  } finally {
    cleanup(counter);
  }
  assert.ok(counts.writeSync > 60 && counts.fsyncSync > 60 && counts.linkSync > 20, JSON.stringify(counts));
  const variants = [];
  for (let k = 1; k <= counts.writeSync; k += 1) variants.push(['writeSync', k, 'ENOSPC', {}]);
  for (let k = 1; k <= counts.writeSync; k += 7) variants.push(['writeSync', k, 'EIO', { short: true }]);
  for (let k = 1; k <= counts.fsyncSync; k += 1) variants.push(['fsyncSync', k, 'EIO', {}]);
  for (let k = 1; k <= counts.linkSync; k += 1) variants.push(['linkSync', k, 'ENOSPC', {}]);
  for (let k = 1; k <= counts.openSync; k += 3) variants.push(['openSync', k, 'EMFILE', {}]);
  const outcomes = new Map();
  for (const [op, k, code, options] of variants) {
    const ctx = setup();
    try {
      const label = `${op} #${k} ${code}${options.short ? ' (short write)' : ''}`;
      const out = await run(ctx, { io: failingIo(op, k, code, options) });
      assertDurable(label, out);
      outcomes.set(`${out.result.outcome} ${out.result.code}`, (outcomes.get(`${out.result.outcome} ${out.result.code}`) ?? 0) + 1);
      // A failed run never leaves the lock held, unless removing it is what failed.
      if (!(op === 'fsyncSync' && out.result.outcome === 'PASS')) assert.ok(!existsSync(join(ctx.dir, RUN_LOCK)) || out.result.code !== null, label);
    } finally {
      cleanup(ctx);
    }
  }
  assert.ok(outcomes.get(`REFUSED ${CompatEntryCode.EVIDENCE}`) > variants.length / 2, JSON.stringify([...outcomes]));
  assert.ok(![...outcomes.keys()].some((k) => /^(BLOCKED|UNRESOLVED)/.test(k)), 'a storage failure is never reported as a provider finding');
});

test('N1: a run killed mid-request leaves a journal that tells sent-but-unrecorded from never-sent', async () => {
  const ctx = setup();
  try {
    let n = 0;
    let hangRelease;
    const transport = async (r) => {
      n += 1;
      if (n === 6) return new Promise((_, reject) => { hangRelease = () => reject(Object.assign(new Error('x'), { code: 'RNLO_CONNECTION' })); });
      return allCompatible()(r);
    };
    const pending = run(ctx, { transport });
    while (hangRelease === undefined) await new Promise((r) => setImmediate(r));
    // The state on disk at this moment is what a killed process leaves.
    const runDir = join(ctx.dir, ctx.id);
    const records = journalOnDisk(runDir);
    assert.deepEqual(records.filter((r) => r.event === 'send').map((r) => r.call), [1, 2, 3, 4, 5, 6]);
    assert.deepEqual(records.filter((r) => r.event === 'outcome').map((r) => r.call), [1, 2, 3, 4, 5]);
    assert.ok(!existsSync(join(runDir, 'transcript.json')) && !existsSync(join(runDir, 'report.json')));
    assert.ok(existsSync(join(ctx.dir, RUN_LOCK)), 'the lock is held while the run is active');
    // Call 6 is SENT BUT NOT RECORDED; calls 7 to 22 were never sent (no "send" record).
    hangRelease();
    const { result } = await pending;
    assert.equal(result.outcome, 'UNRESOLVED', result.message);
  } finally {
    cleanup(ctx);
  }
});

test('N1: no room, no durable probe, or a held lock: refused before any request and before the run directory', async () => {
  const cases = [
    ['too little free space', { minFreeBytes: MIN_FREE_BYTES, io: { ...NODE_IO, statfsSync: () => ({ bavail: 10n, bsize: 4096n }) } }],
    ['free space unreadable', { io: { ...NODE_IO, statfsSync: () => { throw Object.assign(new Error('x'), { code: 'ENOSYS' }); } } }],
    ['probe cannot be created', { io: { ...NODE_IO, openSync: (p, ...rest) => { if (String(p).includes('durability-probe')) throw Object.assign(new Error('x'), { code: 'EROFS' }); return NODE_IO.openSync(p, ...rest); } } }],
    ['probe cannot be linked', { io: { ...NODE_IO, linkSync: (a, ...rest) => { if (String(a).includes('durability-probe')) throw Object.assign(new Error('x'), { code: 'EPERM' }); return NODE_IO.linkSync(a, ...rest); } } }],
  ];
  for (const [label, options] of cases) {
    const ctx = setup();
    try {
      const { result, calls } = await run(ctx, options);
      assert.equal(result.code, CompatEntryCode.EVIDENCE, `${label}: ${result.message}`);
      assert.equal(calls.length, 0, label);
      assert.deepEqual(readdirSync(ctx.dir), [], `${label}: nothing left in the evidence directory`);
    } finally {
      cleanup(ctx);
    }
  }
  // The default requirement is 64 MiB: a real directory with less is refused.
  assert.equal(MIN_FREE_BYTES, 64 * 1024 * 1024);
  const stale = setup();
  try {
    writeFileSync(join(stale.dir, RUN_LOCK), 'killed-run\n', { mode: 0o600 });
    const { result, calls } = await run(stale);
    assert.equal(result.code, CompatEntryCode.EVIDENCE);
    assert.match(result.message, /another C6 run holds/);
    assert.equal(calls.length, 0);
    assert.ok(!existsSync(join(stale.dir, stale.id)));
  } finally {
    cleanup(stale);
  }
});

test('N1: concurrent runs: while one runs, no other run in the evidence directory sends anything', async () => {
  const ctx = setup('c6-first');
  try {
    let release;
    let n = 0;
    const slow = async (r) => {
      n += 1;
      if (n === 1) await new Promise((ok) => { release = ok; });
      return allCompatible()(r);
    };
    const first = run(ctx, { transport: slow });
    while (release === undefined) await new Promise((r) => setImmediate(r));
    const second = await run(ctx, { id: 'c6-second' });
    assert.equal(second.result.code, CompatEntryCode.EVIDENCE, second.result.message);
    assert.equal(second.calls.length, 0);
    const same = await run(ctx, { id: 'c6-first' });
    assert.ok([CompatEntryCode.EVIDENCE, CompatEntryCode.AUTHORIZATION_USED].includes(same.result.code), same.result.message);
    assert.equal(same.calls.length, 0);
    // Started at the same moment: exactly one of two runs sends.
    release();
    assert.equal((await first).result.outcome, 'PASS');
    const [a, b] = await Promise.all([run(ctx, { id: 'c6-third' }), run(ctx, { id: 'c6-fourth' })]);
    assert.deepEqual([a.result.outcome, b.result.outcome].sort(), ['PASS', 'REFUSED']);
    assert.equal(a.calls.length + b.calls.length, 22);
    // After the lock is released, the next authorization runs.
    assert.equal((await run(ctx, { id: 'c6-fifth' })).result.outcome, 'PASS');
  } finally {
    cleanup(ctx);
  }
});

test('F4: hostile and oversized responses are read once, never stored and never parsed', async () => {
  // readResponse itself.
  let reads = 0;
  const getter = { status: 200, get body() { reads += 1; return reads === 1 ? Buffer.alloc(300_000) : Buffer.from('{}'); } };
  assert.equal(readResponse(getter).error, 'RNLO_RESPONSE_TOO_LARGE');
  assert.equal(reads, 1, 'the body is read once');
  let statusReads = 0;
  assert.equal(readResponse({ get status() { statusReads += 1; return 200; }, body: Buffer.from('{}') }).error, null);
  assert.equal(statusReads, 1);
  class Lying extends Uint8Array {
    get length() { return 2; }
  }
  const proxyLength = { calls: 0 };
  const proxy = new Proxy(new Uint8Array(4), { get: (t, k) => (k === 'length' ? (proxyLength.calls += 1, proxyLength.calls === 1 ? 4 : 1e9) : t[k]) });
  const own = Buffer.from('{}');
  Object.defineProperty(own, 'length', { value: 1 });
  for (const [label, response, error] of [
    ['a subclass that lies about its length', { status: 200, body: new Lying(300_000) }, 'TRANSPORT_ERROR'],
    ['a Proxy whose length changes', { status: 200, body: proxy }, 'TRANSPORT_ERROR'],
    ['an own length property', { status: 200, body: own }, 'TRANSPORT_ERROR'],
    ['a typed array of another kind', { status: 200, body: new Uint16Array(4) }, 'TRANSPORT_ERROR'],
    ['a status of 2**60 (F6)', { status: 2 ** 60, body: Buffer.from('{}') }, 'TRANSPORT_ERROR'],
    ['a status of 99', { status: 99, body: Buffer.from('{}') }, 'TRANSPORT_ERROR'],
    ['a string body', { status: 200, body: '{}' }, 'TRANSPORT_ERROR'],
    ['one byte over', { status: 200, body: Buffer.alloc(262_145) }, 'RNLO_RESPONSE_TOO_LARGE'],
    ['16 MiB', { status: 200, body: new Uint8Array(16 << 20) }, 'RNLO_RESPONSE_TOO_LARGE'],
  ]) assert.equal(readResponse(response).error, error, label);
  assert.ok(proxyLength.calls <= 1, 'the proxy is refused before its length is read twice');
  const ok = readResponse({ status: 200, body: Buffer.alloc(262_144, 0x20) });
  assert.equal(ok.body.length, 262_144);
  assert.equal(Object.getPrototypeOf(ok.body), Uint8Array.prototype);

  // Through a whole run: S10 answers with each hostile body; nothing of it is stored or parsed.
  for (const [label, hostile] of [
    ['oversized', () => ({ status: 200, body: Buffer.alloc(262_145, 0x7b) })],
    ['changing getter', () => { let k = 0; return { status: 200, get body() { k += 1; return k === 1 ? Buffer.alloc(300_000, 0x7b) : Buffer.from('{"jsonrpc":"2.0","id":1,"result":"0x5208"}'); } }; }],
    ['lying subclass', () => ({ status: 200, body: new Lying(300_000) })],
  ]) {
    const ctx = setup();
    try {
      const inner = allCompatible();
      const transport = async (r) => (JSON.parse(Buffer.from(r.body).toString()).method === 'eth_estimateGas' && r.providerId === 'sepolia-publicnode' ? hostile() : inner(r));
      const { result, runDir } = await run(ctx, { transport });
      assert.equal(result.outcome, 'UNRESOLVED', `${label}: ${result.message}`);
      const t = JSON.parse(readFileSync(join(runDir, 'transcript.json'), 'utf8')).calls;
      const bad = t.find((c) => c.error !== null);
      assert.ok(['RNLO_RESPONSE_TOO_LARGE', 'TRANSPORT_ERROR'].includes(bad.error), label);
      assert.equal(bad.responseFile, null, label);
      assert.ok(readdirSync(runDir).every((n) => !n.endsWith('.bin') || readFileSync(join(runDir, n)).length <= 262_144), label);
    } finally {
      cleanup(ctx);
    }
  }
});

test('the command wiring: the environment is checked first, the default evidence directory refuses, a wired run passes', async () => {
  const ctx = setup();
  try {
    const { path, digest } = authorizationFile(ctx);
    const argv = ['--authorization', path, '--endpoints', ENDPOINTS_PATH, '--evidence-dir', ctx.dir];
    const written = [];
    let built = 0;
    const base = { argv, env: { PATH: '/usr/bin' }, execArgv: [], now: () => SIM_NOW, getuid: () => process.getuid(), write: (t) => written.push(t), io: undefined };
    // A refused environment: exit 2 before anything is read or approved.
    let asked = 0;
    const refusing = () => { built += 1; throw Object.assign(new Error('RNCL_TRANSPORT_ENVIRONMENT: unset HTTPS_PROXY before a C6 run'), { code: 'RNCL_TRANSPORT_ENVIRONMENT' }); };
    assert.equal(await runCommand({ ...base, createTransport: refusing, approve: async () => { asked += 1; return ''; } }), COMPAT_EXIT.REFUSED);
    assert.equal(asked, 0);
    assert.match(written.join(''), /RNCL_TRANSPORT_ENVIRONMENT: unset HTTPS_PROXY/);
    // The environment and Node.js options are what reach createTransport.
    const calls = [];
    const createTransport = ({ env, execArgv }) => {
      built += 1;
      assert.deepEqual([env, execArgv], [base.env, []]);
      return async (r) => { calls.push(r); return allCompatible()(r); };
    };
    // AGREED_EVIDENCE_DIR is null: refused, nothing sent, nothing approved.
    assert.equal(await runCommand({ ...base, createTransport, approve: async () => { asked += 1; return ''; } }), COMPAT_EXIT.REFUSED);
    assert.equal(asked, 0);
    assert.equal(calls.length, 0);
    assert.match(written.join(''), /RNCL_DIRECTORY_NOT_AGREED/);
    // Agreed (as the enabling change would set it) and approved: the whole run.
    const code = await runCommand({ ...base, agreed: ctx.dir, createTransport, approve: async (prompt) => { assert.match(prompt, /type: c6 <last 16 hex digits/); return `c6 ${digest.slice(-16)}`; } });
    assert.equal(code, COMPAT_EXIT.PASS, written.join(''));
    assert.equal(calls.length, 22);
    assert.equal(built, 3);
  } finally {
    cleanup(ctx);
  }
});

test('the approval is typed on the terminal: never read from standard input, one bounded line, no terminal no approval', async () => {
  const fakeTty = ({ tty = true, input = 'c6 0123456789abcdef\n', chunk = 1 } = {}) => {
    const seen = { opened: [], written: '', closed: 0 };
    let pos = 0;
    const bytes = Buffer.from(input, 'utf8');
    return {
      seen,
      io: {
        openSync: (path) => { seen.opened.push(path); return 42; },
        isatty: (fd) => fd === 42 && tty,
        writeSync: (fd, b, off, len) => { seen.written += Buffer.from(b).subarray(off, off + len).toString(); return len; },
        readSync: (fd, buf, off, len) => {
          const n = Math.min(chunk, len, bytes.length - pos);
          bytes.copy(buf, off, pos, pos + n);
          pos += n;
          return n;
        },
        closeSync: () => { seen.closed += 1; },
      },
    };
  };
  const ok = fakeTty();
  assert.equal(await createTtyApproval(ok.io)('PROMPT'), 'c6 0123456789abcdef');
  assert.deepEqual(ok.seen.opened, [TTY_PATH]);
  assert.equal(TTY_PATH, '/dev/tty');
  assert.match(ok.seen.written, /^PROMPT\n> $/);
  assert.equal(ok.seen.closed, 1);
  assert.equal(await createTtyApproval(fakeTty({ input: 'c6 0123456789abcdef\r\n', chunk: 64 }).io)('P'), 'c6 0123456789abcdef');
  for (const [label, options] of [['not a terminal', { tty: false }], ['no answer', { input: '' }], ['an endless line', { input: 'c'.repeat(MAX_ANSWER_BYTES + 10) }]]) {
    const f = fakeTty(options);
    await assert.rejects(createTtyApproval(f.io)('P'), Error, label);
    assert.equal(f.seen.closed, 1, label);
  }
  const noTty = { ...fakeTty().io, openSync: () => { throw Object.assign(new Error('x'), { code: 'ENXIO' }); } };
  await assert.rejects(createTtyApproval(noTty)('P'));
  // The module never touches standard input.
  const source = readFileSync(new URL('tools/compat-live/tty-approval.mjs', ROOT), 'utf8').replace(/^\s*\/\/.*$/gm, '');
  assert.ok(!/stdin|process\.|readline/.test(source));
});
