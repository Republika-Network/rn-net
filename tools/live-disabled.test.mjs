// RN-NET-03B2-C6-H3, review R1: the dual-mode decision of the live-disabled check
// (tools/broadcast/live-disabled.mjs), with fake sources and a fake runner that records what would
// be started. Nothing is started here: the runner is a function, and the offline preload refuses
// subprocesses anyway. The real check (tools/broadcast/live-disabled.check.mjs) runs in
// tools/ci/offline-checks.sh, inside the network namespace.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { C6_COMMAND, C6_ENTRY_POINT, C6_STATE, c6State, H3_EVIDENCE_DIR, liveDisabledCheck, OTHER_ENTRY_POINTS } from './broadcast/live-disabled.mjs';

const command = (value) => `import x from 'y';\n/** doc */\nexport const LIVE_NETWORK_ACCESS = ${value};\nexport async function main() {}\n`;
const entry = (value) => `export const C6_MANIFEST_SHA256 = 'x';\nexport const AGREED_EVIDENCE_DIR = ${value};\nexport const MAX_AUTHORIZATION_AHEAD_SECONDS = 3600;\n`;
const H3 = `'${H3_EVIDENCE_DIR}'`;
/** A fake runner: every entry point refuses as required, unless `override(entry)` says otherwise. */
function runner(override = () => null) {
  const started = [];
  const run = (e) => {
    started.push(e.path);
    const o = override(e);
    if (o !== null) return o;
    const r = { status: 3, stdout: '', stderr: `${e.code}: live network access is disabled. (fake)` };
    return e === C6_ENTRY_POINT ? { ...r, networkModules: [], evidenceUntouched: true } : r;
  };
  return { run, started };
}

test('R1 activated pair: passes, C6 is NEVER started, and the result says C6 is ACTIVATED, not 5/5', () => {
  const r = runner();
  const out = liveDisabledCheck({ commandSource: command('true'), entrySource: entry(H3), run: r.run });
  assert.equal(out.state, C6_STATE.ACTIVATED);
  assert.equal(out.exitCode, 0);
  assert.ok(!r.started.includes(C6_COMMAND), 'C6 not started');
  assert.deepEqual(r.started, OTHER_ENTRY_POINTS.map((e) => e.path));
  assert.equal(out.refusing, 4);
  const text = out.lines.join('\n');
  assert.match(text, /4\/4 other entry points refuse; C6 is ACTIVATED: NOT all live entry points are disabled/);
  assert.match(text, /ACTIVATED .*NOT executed, NOT disabled/);
  assert.ok(!/5\/5/.test(text), 'never reports five');
  assert.ok(!/\(C6 disabled\)/.test(text));
});

test('R1 disabled pair: passes only once C6 is started and refuses; 5/5 is reported only then', () => {
  const r = runner();
  const out = liveDisabledCheck({ commandSource: command('false'), entrySource: entry('null'), run: r.run });
  assert.equal(out.state, C6_STATE.DISABLED);
  assert.equal(out.exitCode, 0);
  assert.deepEqual(r.started, [...OTHER_ENTRY_POINTS.map((e) => e.path), C6_COMMAND]);
  assert.equal(out.refusing, 5);
  assert.match(out.lines.join('\n'), /live-disabled check: 5\/5 entry points refuse \(C6 disabled\)/);
  assert.match(out.lines.join('\n'), /network modules loaded: none; evidence directory untouched: true/);
});

test('R1 mixed or unexpected pairs: UNREVIEWED CONFIGURATION, fail, and start nothing at all', () => {
  const cases = [
    ['true with null', command('true'), entry('null')],
    ['false with the H3 directory', command('false'), entry(H3)],
    ['true with another directory', command('true'), entry("'/home/vicvalch/elsewhere'")],
    ['false with another directory', command('false'), entry("'/srv/c6'")],
    ['the H3 directory with a trailing slash', command('true'), entry(`'${H3_EVIDENCE_DIR}/'`)],
    ['the switch missing', 'export const OTHER = 1;\n', entry('null')],
    ['the directory missing', command('false'), 'export const OTHER = 1;\n'],
    ['the switch exported twice', `${command('false')}export const LIVE_NETWORK_ACCESS = true;\n`, entry('null')],
    ['the directory exported twice', command('false'), `${entry('null')}export const AGREED_EVIDENCE_DIR = ${H3};\n`],
    ['a computed switch', 'export const LIVE_NETWORK_ACCESS = !0;\n', entry('null')],
    ['a let switch', 'export let LIVE_NETWORK_ACCESS = false;\n', entry('null')],
    ['a commented-out reviewed line beside a computed one', `// export const LIVE_NETWORK_ACCESS = false;\nexport const LIVE_NETWORK_ACCESS = Boolean(1);\n`, entry('null')],
    ['no source', undefined, undefined],
  ];
  for (const [label, commandSource, entrySource] of cases) {
    const r = runner();
    const out = liveDisabledCheck({ commandSource, entrySource, run: r.run });
    assert.equal(out.state, C6_STATE.UNREVIEWED, label);
    assert.equal(out.exitCode, 1, label);
    assert.deepEqual(r.started, [], `${label}: nothing started`);
    assert.match(out.lines.join('\n'), /UNREVIEWED CONFIGURATION/, label);
    assert.ok(!/refuse \(|other entry points refuse/.test(out.lines.join('\n')), `${label}: no count reported`);
  }
});

test('R1 a failing disabled C6 check fails the whole check, and the counts say so', () => {
  const failures = [
    ['C6 exits 0', { status: 0, stdout: '', stderr: '', networkModules: [], evidenceUntouched: true }],
    ['C6 exits 2 (it read an argument)', { status: 2, stdout: 'REFUSED RNCL_FILE', stderr: '', networkModules: [], evidenceUntouched: true }],
    ['C6 another code', { status: 3, stdout: '', stderr: 'RNCL_OTHER: x', networkModules: [], evidenceUntouched: true }],
    ['C6 prints on stdout', { status: 3, stdout: 'x', stderr: 'RNCL_LIVE_DISABLED: live network access is disabled', networkModules: [], evidenceUntouched: true }],
    ['C6 loaded node:https', { status: 3, stdout: '', stderr: 'RNCL_LIVE_DISABLED: live network access is disabled', networkModules: ['https', 'tls'], evidenceUntouched: true }],
    ['no probe record', { status: 3, stdout: '', stderr: 'RNCL_LIVE_DISABLED: live network access is disabled', networkModules: null, evidenceUntouched: true }],
    ['C6 wrote in the evidence directory', { status: 3, stdout: '', stderr: 'RNCL_LIVE_DISABLED: live network access is disabled', networkModules: [], evidenceUntouched: false }],
    ['the runner throws (timeout, spawn failure)', 'throw'],
  ];
  for (const [label, result] of failures) {
    const r = runner((e) => {
      if (e !== C6_ENTRY_POINT) return null;
      if (result === 'throw') throw new Error('spawn failed');
      return result;
    });
    const out = liveDisabledCheck({ commandSource: command('false'), entrySource: entry('null'), run: r.run });
    assert.equal(out.exitCode, 1, label);
    assert.equal(out.refusing, 4, label);
    assert.match(out.lines.join('\n'), /live-disabled check: FAILED: 4\/5 entry points refuse/, label);
    assert.ok(!/5\/5/.test(out.lines.join('\n')), label);
  }
  // Another entry point failing, in either mode.
  for (const [mode, c, e] of [['disabled', command('false'), entry('null')], ['activated', command('true'), entry(H3)]]) {
    const r = runner((x) => (x.path === 'submit/submit-anchor.mjs' ? { status: 0, stdout: '', stderr: '' } : null));
    const out = liveDisabledCheck({ commandSource: c, entrySource: e, run: r.run });
    assert.equal(out.exitCode, 1, mode);
    assert.match(out.lines.join('\n'), /FAILED/, mode);
  }
});

test('R1 the repository itself: this branch is in exactly one reviewed state, read without starting anything', () => {
  const src = (p) => readFileSync(new URL(`./${p}`, import.meta.url), 'utf8');
  const s = c6State(src(C6_COMMAND), src('compat-live/entry.mjs'));
  assert.ok([C6_STATE.ACTIVATED, C6_STATE.DISABLED].includes(s.state), JSON.stringify(s));
  // The check script imports nothing of the entry points and starts the C6 command only in the
  // DISABLED branch of the decision.
  const script = src('broadcast/live-disabled.check.mjs').replace(/^\s*\/\/.*$/gm, '');
  assert.ok(!/from '\.\.\/(?:compat-live|prepare|submit)\//.test(script));
  assert.ok(!/LIVE_NETWORK_ACCESS|AGREED_EVIDENCE_DIR/.test(script), 'the script does not decide by itself');
});
