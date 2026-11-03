// RN-NET-03B2-C6-H3: the activation branch's negative controls, offline. LIVE_NETWORK_ACCESS is
// true and AGREED_EVIDENCE_DIR is set on this branch, so these tests drive the ENABLED wiring
// (command.mjs, flow.mjs, the /dev/tty approval) with a fake transport and a fake terminal, and:
//   - never import or run tools/compat-live/compat-live.mjs (the guard also forbids it here);
//   - never touch the real agreed evidence directory: the one test that names it uses a file
//     system that refuses every call under it, so even on the founder's machine nothing is read,
//     created or written there;
//   - run under the offline preload and the network namespace (tools/ci/offline-checks.sh).
import assert from 'node:assert/strict';
import { chmodSync, constants, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { canonicalize } from '../packages/canonical/src/index.mjs';
import { C6_BUDGET, C6_PROVIDERS } from './compat/manifest.mjs';
import { SCENARIOS, SIM_NOW, simulatedTransport } from './compat/simulated.mjs';
import { readCompatAuthorization } from './compat-live/authorization.mjs';
import { runCommand } from './compat-live/command.mjs';
import { AGREED_EVIDENCE_DIR, C6_MANIFEST_SHA256, CompatEntryCode, NODE_IO, RUN_LOCK } from './compat-live/entry.mjs';
import { compatLive, COMPAT_EXIT } from './compat-live/flow.mjs';
import { createTtyApproval } from './compat-live/tty-approval.mjs';

const ROOT = new URL('../', import.meta.url);
const ENDPOINTS = new URL('config/rpc-endpoints.json', ROOT).pathname;
const iso = (s) => new Date(s * 1000).toISOString().replace('.000Z', 'Z');
const allCompatible = () => simulatedTransport(SCENARIOS.find((s) => s.name === 'all-compatible'));
const SCOPE = 'One founder-authorized, read-only C6 provider compatibility check for RN-NET Genesis Proof 01 against XRPL Testnet and Ethereum Sepolia. Exactly 22 authorized RPC requests maximum. No transaction signing, no broadcast, no account funding, no publication and no retry.';

function setup() {
  const base = mkdtempSync(join(tmpdir(), 'rnnet-c6-h3-'));
  chmodSync(base, 0o700);
  const dir = join(base, 'evidence');
  mkdirSync(dir, { mode: 0o700 });
  chmodSync(dir, 0o700);
  return { base, dir };
}
function authorization(ctx, overrides = {}) {
  const a = {
    authorizationId: 'c6-h3-test',
    evidenceDir: ctx.dir,
    format: 'rnnet.compat-authorization.v1',
    manifestSha256: C6_MANIFEST_SHA256,
    notAfter: iso(SIM_NOW + 1800),
    providers: C6_PROVIDERS.map((p) => ({ id: p.id, requests: C6_BUDGET[p.id], url: p.url })),
    publication: 'none',
    requestBudget: 22,
    scope: SCOPE,
    ...overrides,
  };
  const text = overrides.__text ?? `${canonicalize(a)}\n`;
  const path = join(ctx.base, `auth-${Math.random().toString(16).slice(2)}.json`);
  writeFileSync(path, text, { mode: 0o600 });
  chmodSync(path, 0o600);
  let digest = null;
  try {
    digest = readCompatAuthorization(text).digest;
  } catch {
    // refused by the flow
  }
  return { path, digest };
}
/** A fake terminal: `answer` is typed after the prompt; `tty` false means there is none. */
function terminal({ answer = '', tty = true, open = true } = {}) {
  const seen = { prompted: 0 };
  let pos = 0;
  const bytes = Buffer.from(answer, 'utf8');
  const io = {
    openSync: (path, flags) => {
      assert.equal(path, '/dev/tty');
      if (!open) throw Object.assign(new Error('no tty'), { code: 'ENXIO' });
      return (flags & constants.O_NONBLOCK) ? 43 : 42;
    },
    isatty: () => tty,
    writeSync: (fd, b, off, len) => { seen.prompted += 1; return len; },
    readSync: (fd, buf, off, len) => {
      if (fd === 43) throw Object.assign(new Error('EAGAIN'), { code: 'EAGAIN' });
      const n = Math.min(len, bytes.length - pos);
      bytes.copy(buf, off, pos, pos + n);
      pos += n;
      return n;
    },
    closeSync: () => {},
  };
  return { approve: createTtyApproval(io), seen };
}
/** The enabled command, injected; returns { code, calls, output }. */
async function command(ctx, { auth, approve, transport = allCompatible(), agreed = ctx.dir, evidenceDir = ctx.dir, now = () => SIM_NOW, io } = {}) {
  const calls = [];
  const output = [];
  const code = await runCommand({
    argv: ['--authorization', auth.path, '--endpoints', ENDPOINTS, '--evidence-dir', evidenceDir],
    env: { PATH: '/usr/bin' },
    execArgv: [],
    createTransport: () => async (r) => { calls.push(r); return transport(r); },
    approve,
    now,
    getuid: () => process.getuid(),
    write: (t) => output.push(t),
    agreed,
    ...(io === undefined ? {} : { io }),
  });
  return { code, calls, output: output.join('') };
}
const right = (auth) => terminal({ answer: `c6 ${auth.digest.slice(-16)}\n` });
/** The H3 directory of the reviewed activation; AGREED_EVIDENCE_DIR is it while activated, null once deactivated. */
const H3_DIR = '/home/vicvalch/rn-net-private/c6-evidence';

test('H3: the agreed evidence directory is the proposed private WSL path (or null once deactivated), and no fixture or test authorization names it', () => {
  // Activated: the H3 directory. Deactivated (docs/genesis/rn-net-03b2c6-h3-activation.md §5): null.
  assert.ok(AGREED_EVIDENCE_DIR === H3_DIR || AGREED_EVIDENCE_DIR === null, String(AGREED_EVIDENCE_DIR));
  assert.match(H3_DIR, /^\/[A-Za-z0-9._/-]{1,255}$/);
  assert.ok(!H3_DIR.startsWith('/mnt/') && !H3_DIR.split('/').some((s) => s === '..' || s === '.'));
  assert.ok(!H3_DIR.startsWith(new URL('.', ROOT).pathname.replace(/\/$/, '')), 'outside this repository');
  // No stored authorization in the repository can authorize the real run: none names the agreed
  // directory, and every one expired long ago (SIM_NOW is in 2026-10; notAfter is SIM_NOW + 30 min).
  const base = new URL('fixtures/compat-c6-live/', ROOT);
  for (const name of readdirSync(base)) {
    const a = JSON.parse(readFileSync(new URL(`${name}/authorization.json`, base), 'utf8'));
    assert.notEqual(a.evidenceDir, H3_DIR, name);
    assert.ok(Date.parse(a.notAfter) < Date.parse('2026-11-04T00:00:00Z'), name);
  }
});

test('H3 negative controls: each refuses before any request, and before the terminal is asked unless noted', async () => {
  const cases = [
    ['an invalid (non-canonical) authorization', { __text: '{"format": "rnnet.compat-authorization.v1"}\n' }, CompatEntryCode.AUTHORIZATION],
    ['an expired authorization', { notAfter: iso(SIM_NOW - 1) }, CompatEntryCode.AUTHORIZATION_EXPIRED],
    ['an authorization more than 60 minutes ahead', { notAfter: iso(SIM_NOW + 3601) }, CompatEntryCode.AUTHORIZATION],
    ['another manifest digest', { manifestSha256: `sha256:${'0'.repeat(64)}` }, CompatEntryCode.MANIFEST_MISMATCH],
    ['a mismatched provider URL', { providers: C6_PROVIDERS.map((p, i) => ({ id: p.id, requests: C6_BUDGET[p.id], url: i === 2 ? 'https://sepolia.example.org/' : p.url })) }, CompatEntryCode.AUTHORIZATION],
    ['a moved budget', { providers: C6_PROVIDERS.map((p, i) => ({ id: p.id, requests: C6_BUDGET[p.id] + (i === 2 ? 1 : i === 3 ? -1 : 0), url: p.url })) }, CompatEntryCode.AUTHORIZATION],
    ['publication', { publication: 'public' }, CompatEntryCode.AUTHORIZATION],
    ['the authorization names another evidence directory', { evidenceDir: '/srv/elsewhere' }, CompatEntryCode.AUTHORIZATION],
  ];
  for (const [label, overrides, code] of cases) {
    const ctx = setup();
    try {
      const auth = authorization(ctx, overrides);
      const tty = terminal({ answer: 'c6 0000000000000000\n' });
      const out = await command(ctx, { auth, approve: tty.approve });
      assert.equal(out.code, COMPAT_EXIT.REFUSED, label);
      assert.match(out.output, new RegExp(code), `${label}: ${out.output}`);
      assert.equal(out.calls.length, 0, label);
      assert.equal(tty.seen.prompted, 0, `${label}: the terminal is not asked`);
      assert.deepEqual(readdirSync(ctx.dir), [], label);
    } finally {
      rmSync(ctx.base, { recursive: true, force: true });
    }
  }
  // --evidence-dir is not the agreed directory.
  const ctx = setup();
  try {
    const auth = authorization(ctx);
    const out = await command(ctx, { auth, approve: right(auth).approve, agreed: H3_DIR });
    assert.match(out.output, /RNCL_DIRECTORY_NOT_AGREED/);
    assert.equal(out.calls.length, 0);
  } finally {
    rmSync(ctx.base, { recursive: true, force: true });
  }
});

test('H3: the real agreed directory, unavailable or unwritable, refuses with nothing sent (and is never touched by tests)', async () => {
  const ctx = setup();
  try {
    // The real agreed path, with a file system that refuses every call under it.
    const touched = [];
    const guard = (fn) => (path, ...rest) => {
      if (String(path).startsWith(H3_DIR)) {
        touched.push(String(path));
        throw Object.assign(new Error('EACCES'), { code: 'EACCES' });
      }
      return fn(path, ...rest);
    };
    const io = { ...NODE_IO };
    for (const k of ['openSync', 'lstatSync', 'statfsSync', 'mkdirSync', 'linkSync', 'unlinkSync']) io[k] = guard(NODE_IO[k]);
    const real = { base: ctx.base, dir: H3_DIR };
    const auth = authorization(real);
    const out = await command(real, { auth, approve: right(auth).approve, agreed: H3_DIR, evidenceDir: H3_DIR, io });
    assert.equal(out.code, COMPAT_EXIT.REFUSED);
    assert.match(out.output, /RNCL_EVIDENCE/);
    assert.equal(out.calls.length, 0);
    assert.ok(touched.length > 0 && touched.every((p) => p === H3_DIR), `only refused calls on the agreed path: ${touched}`);
    // An unwritable (0500) directory of the right owner.
    chmodSync(ctx.dir, 0o500);
    const ro = authorization(ctx);
    const out2 = await command(ctx, { auth: ro, approve: right(ro).approve });
    assert.match(out2.output, /RNCL_EVIDENCE/);
    assert.equal(out2.calls.length, 0);
    chmodSync(ctx.dir, 0o700);
  } finally {
    chmodSync(ctx.dir, 0o700);
    rmSync(ctx.base, { recursive: true, force: true });
  }
});

test('H3: no terminal means no run; a refusal at the terminal means zero requests', async () => {
  for (const [label, tty] of [['no controlling terminal', terminal({ open: false })], ['not a terminal', terminal({ tty: false })], ['typed "no"', terminal({ answer: 'no\n' })], ['typed a wrong digest', terminal({ answer: 'c6 0123456789abcdef\n' })], ['nothing typed', terminal({ answer: '' })]]) {
    const ctx = setup();
    try {
      const auth = authorization(ctx);
      const out = await command(ctx, { auth, approve: tty.approve });
      assert.equal(out.code, COMPAT_EXIT.REFUSED, label);
      assert.match(out.output, /RNCL_APPROVAL_REFUSED/, label);
      assert.equal(out.calls.length, 0, label);
      assert.deepEqual(readdirSync(ctx.dir), [], `${label}: no run directory, the authorization is not used`);
    } finally {
      rmSync(ctx.base, { recursive: true, force: true });
    }
  }
});

test('H3: an approved simulated run sends exactly 22 requests, never more; a second run of the same authorization sends none', async () => {
  const ctx = setup();
  try {
    const auth = authorization(ctx);
    const out = await command(ctx, { auth, approve: right(auth).approve });
    assert.equal(out.code, COMPAT_EXIT.PASS, out.output);
    assert.equal(out.calls.length, 22);
    const again = await command(ctx, { auth, approve: right(auth).approve });
    assert.match(again.output, /RNCL_AUTHORIZATION_USED/);
    assert.equal(again.calls.length, 0);
  } finally {
    rmSync(ctx.base, { recursive: true, force: true });
  }
});

test('H3: an interrupted run is never replayed or retried', async () => {
  const ctx = setup();
  try {
    const auth = authorization(ctx);
    let n = 0;
    let reached = 0;
    const hanging = async (r) => {
      n += 1;
      reached = n;
      if (n === 5) return new Promise(() => {}); // the process is "killed" here: never answers
      return allCompatible()(r);
    };
    // The first run is left hanging at call 5 (as a killed process leaves it).
    const first = command(ctx, { auth, approve: right(auth).approve, transport: hanging });
    while (reached < 5) await new Promise((ok) => setImmediate(ok));
    // The same authorization again: refused by the lock, nothing sent.
    const second = await command(ctx, { auth, approve: right(auth).approve });
    assert.match(second.output, /RNCL_EVIDENCE.*another C6 run holds/s);
    assert.equal(second.calls.length, 0);
    // After the founder removes the stale lock: the authorization is used, nothing sent.
    rmSync(join(ctx.dir, RUN_LOCK));
    const third = await command(ctx, { auth, approve: right(auth).approve });
    assert.match(third.output, /RNCL_AUTHORIZATION_USED/);
    assert.equal(third.calls.length, 0);
    assert.equal(reached, 5, 'nothing was retried or replayed');
    void first;
  } finally {
    rmSync(ctx.base, { recursive: true, force: true });
  }
});

test('H3: the flow without the command wiring still refuses an unagreed directory by default', async () => {
  const ctx = setup();
  try {
    const auth = authorization(ctx);
    const r = await compatLive({ argv: ['--authorization', auth.path, '--endpoints', ENDPOINTS, '--evidence-dir', ctx.dir], deps: { transport: async () => assert.fail('sent'), now: () => SIM_NOW, approve: async () => assert.fail('asked') } });
    assert.equal(r.code, CompatEntryCode.DIRECTORY_NOT_AGREED);
  } finally {
    rmSync(ctx.base, { recursive: true, force: true });
  }
});
