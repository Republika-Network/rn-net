// The offline dual-chain CLI: explicit paths, documented exit codes, no fixture echo.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { EXIT, main } from './verify-anchors.mjs';

const dual = JSON.parse(readFileSync(fileURLToPath(new URL('../vectors/anchor/dual.json', import.meta.url)), 'utf8')).vectors;
const byId = (id) => dual.find((v) => v.id === id);

function run(argv, files) {
  const out = { stdout: '', stderr: '', written: new Map(), read: [] };
  const code = main(argv, {
    readFile: (path) => {
      out.read.push(path);
      if (!Object.hasOwn(files, path)) throw Object.assign(new Error('missing'), { code: 'ENOENT' });
      return new TextEncoder().encode(files[path]);
    },
    writeFile: (path, data) => out.written.set(path, new TextDecoder().decode(data)),
    stdout: (text) => (out.stdout += text),
    stderr: (text) => (out.stderr += text),
  });
  return { code, ...out };
}

test('prints the canonical report and exits by outcome', () => {
  for (const [id, exit] of [['same-commitment-both', EXIT.PASS], ['one-unsuccessful', EXIT.FAIL], ['unsupported-anchor-version', EXIT.UNSUPPORTED]]) {
    const v = byId(id);
    const result = run(['--commitment', v.expectedCommitment, '--xrpl', 'x.json', '--evm', 'e.json'], { 'x.json': v.xrpl, 'e.json': v.evm });
    assert.equal(result.code, exit, id);
    assert.equal(result.stdout, `${v.expectedReport}\n`);
    assert.deepEqual(result.read, ['x.json', 'e.json']);
    assert.ok(!result.stdout.includes('rSyntheticAnchorTestAccount1111".') && !result.stdout.includes('close_time_iso'));
  }
});

test('writes only to an explicit output path', () => {
  const v = byId('same-commitment-both');
  const result = run(['--commitment', v.expectedCommitment, '--xrpl', 'x', '--evm', 'e', '--output', 'r.json'], { x: v.xrpl, e: v.evm });
  assert.equal(result.stdout, '');
  assert.deepEqual([...result.written], [['r.json', `${v.expectedReport}\n`]]);
});

test('an output file that cannot be created has its own exit code', () => {
  const v = byId('same-commitment-both');
  const code = main(['--commitment', v.expectedCommitment, '--xrpl', 'x', '--evm', 'e', '--output', 'r.json'], {
    readFile: (path) => new TextEncoder().encode({ x: v.xrpl, e: v.evm }[path]),
    writeFile: () => {
      throw Object.assign(new Error('exists'), { code: 'EEXIST' });
    },
    stdout: () => {},
    stderr: () => {},
  });
  assert.equal(code, EXIT.CANNOT_CREATE);
});

test('usage errors and unreadable inputs', () => {
  const c = `sha256:${'ab'.repeat(32)}`;
  for (const argv of [[], ['--commitment', c, '--xrpl', 'x'], ['--commitment', 'sha256:x', '--xrpl', 'x', '--evm', 'e'], ['--commitment', c, '--xrpl', 'x', '--evm', 'e', '--url', 'https://example.org'], ['--commitment', c, '--xrpl', 'x', '--evm']]) {
    assert.equal(run(argv, {}).code, EXIT.USAGE, JSON.stringify(argv));
  }
  assert.equal(run(['--commitment', c, '--xrpl', 'x', '--evm', 'e'], {}).code, EXIT.NO_INPUT);
});
