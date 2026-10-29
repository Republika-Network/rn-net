// The command-line verifier: same verifier, documented exit codes, explicit paths only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { EXIT, main } from './verify-evidence.mjs';

const vectors = JSON.parse(readFileSync(fileURLToPath(new URL('../vectors/evidence/evidence.json', import.meta.url)), 'utf8')).vectors;
const byId = (id) => vectors.find((v) => v.id === id);
const encode = (text) => new TextEncoder().encode(text);

function run(argv, files) {
  const out = { stdout: '', stderr: '', written: new Map(), read: [] };
  const code = main(argv, {
    readFile: (path) => {
      out.read.push(path);
      if (!Object.hasOwn(files, path)) throw Object.assign(new Error('missing'), { code: 'ENOENT' });
      return encode(files[path]);
    },
    writeFile: (path, data) => out.written.set(path, new TextDecoder().decode(data)),
    stdout: (text) => (out.stdout += text),
    stderr: (text) => (out.stderr += text),
  });
  return { code, ...out };
}

test('prints the canonical report and exits by outcome', () => {
  for (const [id, exit] of [['valid-one-signature', EXIT.PASS], ['tampered-outcome', EXIT.FAIL], ['unsupported-format', EXIT.UNSUPPORTED]]) {
    const vector = byId(id);
    const result = run(['evidence.json'], { 'evidence.json': vector.input });
    assert.equal(result.code, exit, id);
    assert.equal(result.stdout, `${vector.expectedReport}\n`);
    assert.deepEqual(result.read, ['evidence.json']);
    assert.equal(result.written.size, 0);
  }
});

test('checks a commitment and writes only to an explicit output path', () => {
  const vector = byId('valid-with-commitment');
  const result = run(['e.json', '--commitment', 'c.json', '--commitment-digest', vector.commitment.digest, '--output', 'r.json'], {
    'e.json': vector.input,
    'c.json': vector.commitment.envelope,
  });
  assert.equal(result.code, EXIT.PASS);
  assert.equal(result.stdout, '');
  assert.deepEqual([...result.written], [['r.json', `${vector.expectedReport}\n`]]);
});

test('usage errors and unreadable inputs have their own exit codes', () => {
  for (const argv of [[], ['a', 'b'], ['a', '--commitment', 'c'], ['a', '--commitment-digest', 'd'], ['a', '--key', 'k'], ['a', '--output']]) {
    assert.equal(run(argv, {}).code, EXIT.USAGE, JSON.stringify(argv));
  }
  const missing = run(['nowhere.json'], {});
  assert.equal(missing.code, EXIT.NO_INPUT);
  assert.match(missing.stderr, /ENOENT/);
});
