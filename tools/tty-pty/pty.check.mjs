// The C6 typed approval on a REAL pseudo-terminal (RN-NET-03B2-C6-H3, TTY approval review).
// Run by tools/ci/offline-checks.sh inside the network namespace, without the test preload (which
// refuses subprocesses):
//   node tools/tty-pty/pty.check.mjs <python3>
//
// The unit tests (tools/compat-live-enable.test.mjs, tools/compat-h3.test.mjs) replace the terminal
// with a fake. This check instead runs the production createTtyApproval() and requireApproval()
// (tools/tty-pty/probe.mjs, with a synthetic digest) on a pseudo-terminal that a Python driver
// (tools/tty-pty/driver.py) types into as a terminal emulator would, so the kernel's line
// discipline (canonical mode, echo, Ctrl-U, ICRNL, O_NONBLOCK reads) is the real one. After every
// scenario that finishes on a terminal it also checks what is left in the terminal's input queue,
// which is what the shell would read (and run) next: nothing.
//
// It never starts the C6 command: the only program started is python3 with the driver, which
// starts only node with the probe; both paths are fixed below and the probe's imports are checked.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const python = process.argv[2];
if (typeof python !== 'string' || !python.startsWith('/')) {
  process.stderr.write('usage: node tools/tty-pty/pty.check.mjs <absolute path of python3>\n');
  process.exit(2);
}
const DRIVER = fileURLToPath(new URL('./driver.py', import.meta.url));
const PROBE = fileURLToPath(new URL('./probe.mjs', import.meta.url));
const RIGHT = 'c6 0123456789abcdef';
const CTRL_U = '\x15';

// The probe reaches only the approval: exactly these two imports, and no command, authorization,
// endpoints, evidence or network name anywhere in it.
const probeSource = readFileSync(PROBE, 'utf8');
const imports = [...probeSource.matchAll(/^import\s.*?from\s+'([^']+)';$/gm)].map((m) => m[1]);
assert.deepEqual(imports, ['../compat-live/entry.mjs', '../compat-live/tty-approval.mjs'], 'probe imports');
const code = probeSource.replace(/^\s*\/\/.*$/gm, '');
assert.ok(!/compat-live\.mjs|command\.mjs|c6-transport|runCommand|authorization\.mjs|readFileSync|node:(?:https?|http2|net|tls|dns|dgram|child_process)|fetch\(/.test(code), 'probe stays the approval alone');

function run(label, scenario) {
  const child = spawnSync(python, ['-I', '-B', DRIVER, process.execPath, PROBE, JSON.stringify(scenario)], { encoding: 'utf8', env: {}, timeout: 30_000 });
  assert.equal(child.status, 0, `${label}: driver failed: ${child.stderr}`);
  const out = JSON.parse(child.stdout);
  return { label, ...out };
}

const scenarios = [
  // 1. A correct confirmation typed by hand after the prompt is accepted.
  ['typed after the prompt', { mode: 'cooked', steps: [['send', `${RIGHT}\r`]] }, { approved: true, answer: RIGHT }],
  ['Ctrl-U, then typed (the documented procedure)', { mode: 'cooked', steps: [['send', CTRL_U], ['sleep', 0.2], ['send', `${RIGHT}\r`]] }, { approved: true, answer: RIGHT }],
  ['typed one key at a time', { mode: 'cooked', steps: [...`${CTRL_U}${RIGHT}\r`].flatMap((k) => [['send', k], ['sleep', 0.03]]) }, { approved: true, answer: RIGHT }],
  ['corrected with Backspace', { mode: 'cooked', steps: [['send', `${RIGHT.slice(0, -1)}X\x7f${RIGHT.slice(-1)}\r`]] }, { approved: true, answer: RIGHT }],
  ['Enter sent as CR LF', { mode: 'cooked', steps: [['send', `${RIGHT}\r\n`]] }, { approved: true, answer: RIGHT }],
  // 2. An empty answer is refused.
  ['empty answer (Enter only)', { mode: 'cooked', steps: [['send', '\r']] }, { approved: false, answer: '', code: 'RNCL_APPROVAL_REFUSED' }],
  ['Ctrl-U, then Enter only', { mode: 'cooked', steps: [['send', CTRL_U], ['sleep', 0.2], ['send', '\r']] }, { approved: false, answer: '', code: 'RNCL_APPROVAL_REFUSED' }],
  // 3. A wrong digest is refused.
  ['wrong digest', { mode: 'cooked', steps: [['send', 'c6 0123456789abcdee\r']] }, { approved: false, answer: 'c6 0123456789abcdee', code: 'RNCL_APPROVAL_REFUSED' }],
  ['the full digest instead of its last 16 digits', { mode: 'cooked', steps: [['send', `c6 ${'0'.repeat(48)}0123456789abcdef\r`]] }, { approved: false, error: 'answer too long', code: 'RNCL_APPROVAL_REFUSED' }],
  ['answer longer than 64 bytes', { mode: 'cooked', steps: [['send', `${'c'.repeat(70)}\r`]] }, { approved: false, error: 'answer too long', code: 'RNCL_APPROVAL_REFUSED' }],
  // 4. No terminal is refused.
  ['no controlling terminal', { mode: 'none' }, { approved: false, answer: null, code: 'RNCL_APPROVAL_REFUSED', error: true }],
  // 5. Type-ahead is not accepted as approval.
  ['right answer typed ahead with Enter, then "no"', { mode: 'cooked', ahead: `${RIGHT}\r`, steps: [['send', 'no\r']] }, { approved: false, answer: 'no', code: 'RNCL_APPROVAL_REFUSED' }],
  ['right answer typed ahead with Enter, nothing after', { mode: 'cooked', ahead: `${RIGHT}\r`, steps: [['sleep', 1]], timeout: 4 }, { blocked: true }],
  ['empty lines typed ahead, then the answer', { mode: 'cooked', ahead: '\r\r\n', steps: [['send', `${RIGHT}\r`]] }, { approved: true, answer: RIGHT }],
  // 6. Ctrl-U clears a line typed ahead without Enter.
  ['right answer typed ahead WITHOUT Enter, Ctrl-U, then "no"', { mode: 'cooked', ahead: RIGHT, steps: [['send', CTRL_U], ['sleep', 0.2], ['send', 'no\r']] }, { approved: false, answer: 'no', code: 'RNCL_APPROVAL_REFUSED' }],
  ['garbage typed ahead without Enter, Ctrl-U, then the answer', { mode: 'cooked', ahead: 'garbage', steps: [['send', CTRL_U], ['sleep', 0.2], ['send', `${RIGHT}\r`]] }, { approved: true, answer: RIGHT }],
  // ...and without Ctrl-U it stays in front of the answer (the accepted residual, round-2 review F1).
  ['garbage typed ahead without Enter, no Ctrl-U, then the answer', { mode: 'cooked', ahead: 'xx', steps: [['send', `${RIGHT}\r`]] }, { approved: false, answer: `xx${RIGHT}`, code: 'RNCL_APPROVAL_REFUSED' }],
  // A terminal left in raw mode: Enter ("\r") ends no line, so nothing is approved (the reader waits).
  ['terminal in raw mode', { mode: 'raw', steps: [['send', `${RIGHT}\r`], ['sleep', 1]], timeout: 4 }, { blocked: true }],
  // 7. An answer longer than 64 bytes is refused and discarded WHOLE: nothing of it (or of what was
  // pasted with it) is left on the terminal for the shell to run once the program exits.
  ['65 bytes then Enter (only the Enter would be left)', { mode: 'cooked', steps: [['send', `${'c'.repeat(65)}\r`]] }, { approved: false, error: 'answer too long', code: 'RNCL_APPROVAL_REFUSED' }],
  ['64 bytes then Enter (the longest answer read; wrong, so refused)', { mode: 'cooked', steps: [['send', `${'c'.repeat(64)}\r`]] }, { approved: false, answer: 'c'.repeat(64), code: 'RNCL_APPROVAL_REFUSED' }],
  ['over-long line ending in a shell command', { mode: 'cooked', steps: [['send', `${'x'.repeat(65)}; echo RNNET-INJECTED\r`]] }, { approved: false, error: 'answer too long', code: 'RNCL_APPROVAL_REFUSED' }],
  ['the right answer padded past 64 bytes', { mode: 'cooked', steps: [['send', `${RIGHT}${' '.repeat(60)}touch /tmp/RNNET-INJECTED\r`]] }, { approved: false, error: 'answer too long', code: 'RNCL_APPROVAL_REFUSED' }],
  ['a 3000-byte line', { mode: 'cooked', steps: [['send', `${'y'.repeat(3000)}\r`]] }, { approved: false, error: 'answer too long', code: 'RNCL_APPROVAL_REFUSED' }],
  ['over-long line, then more lines in the same paste', { mode: 'cooked', steps: [['send', `${'z'.repeat(80)}\recho RNNET-INJECTED\rid\r`]] }, { approved: false, error: 'answer too long', code: 'RNCL_APPROVAL_REFUSED' }],
  ['over-long line ended by Ctrl-D instead of Enter', { mode: 'cooked', steps: [['send', `${'w'.repeat(70)}echo RNNET-INJECTED\x04`]] }, { approved: false, error: 'answer too long', code: 'RNCL_APPROVAL_REFUSED' }],
  // 8. Lines pasted after the answer line never reach the shell (the first line alone is the answer).
  ['wrong answer, then a pasted command line', { mode: 'cooked', steps: [['send', 'no\recho RNNET-INJECTED\r']] }, { approved: false, answer: 'no', code: 'RNCL_APPROVAL_REFUSED' }],
  ['right answer, then a pasted command line', { mode: 'cooked', steps: [['send', `${RIGHT}\recho RNNET-INJECTED\r`]] }, { approved: true, answer: RIGHT }],
  // 9. Review R2: a partial line (no Enter) typed after the answer, before the program exits, sits
  // in the kernel's canonical line buffer, invisible to a non-blocking read. It must not reach the
  // shell: neither when Enter is pressed after the shell resumes, nor when the shell's line editor
  // turns canonical mode off. Typed in the same write as the answer, so the order is deterministic.
  ['R2: right answer, then a partial line; Enter after exit', { mode: 'cooked', steps: [['send', `${RIGHT}\recho RNNET-INJECTED`]], after: '\r' }, { approved: true, answer: RIGHT, pending: '\n' }],
  ['R2: right answer, then a partial line; line editor resumes', { mode: 'cooked', steps: [['send', `${RIGHT}\recho RNNET-INJECTED`]], reveal: 'noncanonical' }, { approved: true, answer: RIGHT }],
  ['R2: wrong answer, then a partial line', { mode: 'cooked', steps: [['send', 'no\recho RNNET-INJECTED']], after: '\r' }, { approved: false, answer: 'no', code: 'RNCL_APPROVAL_REFUSED', pending: '\n' }],
  ['R2: over-long line, then a partial line', { mode: 'cooked', steps: [['send', `${'x'.repeat(80)}\recho RNNET-INJECTED`]], reveal: 'noncanonical' }, { approved: false, error: 'answer too long', code: 'RNCL_APPROVAL_REFUSED' }],
  ['R2: over-long line, more lines, then a partial line', { mode: 'cooked', steps: [['send', `${'x'.repeat(80)}\rid\recho RNNET-INJECTED`]], after: '\r' }, { approved: false, error: 'answer too long', code: 'RNCL_APPROVAL_REFUSED', pending: '\n' }],
  // Controls: a partial line typed once the program has exited is invisible to a plain non-blocking
  // read (why R2 exists), and IS seen once the line editor resumes (so the R2 checks above mean it).
  ['control: partial line typed after exit is invisible without a reveal', { mode: 'cooked', steps: [['send', `${RIGHT}\r`]], after: 'echo later' }, { approved: true, answer: RIGHT, pending: '' }],
  ['control: partial line typed after exit, line editor resumes', { mode: 'cooked', steps: [['send', `${RIGHT}\r`]], after: 'echo later', reveal: 'noncanonical' }, { approved: true, answer: RIGHT, pending: 'echo later' }],
  // Control: input typed once the program has exited IS seen as pending, so "nothing pending" above means it.
  ['control: typed after the program exited is pending', { mode: 'cooked', steps: [['send', `${RIGHT}\r`]], after: 'echo later\r' }, { approved: true, answer: RIGHT, pending: 'echo later\n' }],
];

let failures = 0;
for (const [label, scenario, expected] of scenarios) {
  const got = run(label, scenario);
  try {
    if (expected.blocked) {
      assert.equal(got.blocked, true, `${label}: expected the reader to still be waiting`);
      assert.equal(got.result, null, `${label}: no record`);
    } else {
      assert.equal(got.blocked, false, `${label}: the probe produced no record`);
      const r = got.result;
      assert.equal(r.approved, expected.approved, `${label}: approved`);
      if ('answer' in expected) assert.equal(r.answer, expected.answer, `${label}: answer`);
      if ('code' in expected) assert.equal(r.code, expected.code, `${label}: code`);
      if (expected.error === true) assert.ok(r.error, `${label}: an error`);
      else if ('error' in expected) assert.equal(r.error, expected.error, `${label}: error`);
      if (!expected.approved) assert.notEqual(r.code, null, `${label}: refused`);
      // What the shell would read next from this terminal: nothing, unless the scenario typed it later.
      if (scenario.mode !== 'none') assert.equal(got.pending, expected.pending ?? '', `${label}: input left on the terminal for the shell`);
      // The approval leaves the terminal's settings exactly as it found them (R2 switches modes).
      if (scenario.mode !== 'none') assert.equal(got.restored, true, `${label}: terminal settings restored`);
    }
    process.stdout.write(`ok   ${label}\n`);
  } catch (failure) {
    failures += 1;
    process.stdout.write(`FAIL ${label}: ${failure.message}\n     record: ${JSON.stringify(got.result)}\n     transcript: ${JSON.stringify(got.transcript.slice(-400))}\n`);
  }
}
if (failures) {
  process.stdout.write(`tty-pty: ${failures} of ${scenarios.length} scenarios failed\n`);
  process.exit(1);
}
process.stdout.write(`tty-pty: ${scenarios.length}/${scenarios.length} scenarios on a real pseudo-terminal; the C6 command was not started\n`);
