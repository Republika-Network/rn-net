import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { check } from './secret-shapes.mjs';

// Samples are assembled at runtime so this file never contains a matching literal.
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const base58 = (n) => Array.from(randomBytes(n), (b) => BASE58[b % 58]).join('');
const hex64 = () => randomBytes(32).toString('hex');
const file = (content, path = 'sample.txt') => [{ path, content }];
const rulesHit = (content) => check(file(content)).map((f) => f.rule);

test('detects each credential shape', () => {
  const cases = {
    'pem-private-key': ['-----BEGIN ', 'PRIVATE KEY-----'].join(''),
    'xrpl-seed': `seed is ${'s' + base58(28)}`,
    'hex-private-key': `private_key: 0x${hex64()}`,
    'github-token': ['gh', 'p_', 'A'.repeat(36)].join(''),
    'npm-token': ['np', 'm_', 'b'.repeat(36)].join(''),
    'aws-access-key': ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join(''),
    'slack-token': ['xo', 'xb-', '1234567890-abc'].join(''),
    'secret-assignment': ['ANCHOR_', 'SEED=', 'abcdefghij'].join(''),
  };
  for (const [rule, content] of Object.entries(cases)) {
    assert.ok(rulesHit(content).includes(rule), `${rule} not detected`);
  }
});

test('detects an XRPL ed25519 seed and an OpenSSH key block', () => {
  assert.ok(rulesHit('sEd' + base58(28)).includes('xrpl-seed'));
  assert.ok(rulesHit(['-----BEGIN OPENSSH ', 'PRIVATE KEY-----'].join('')).includes('pem-private-key'));
});

test('ignores public values RN-NET will legitimately publish', () => {
  const benign = [
    `tx hash 0x${hex64()}`,
    `evidenceDigest sha256:${hex64()}`,
    '-----BEGIN PUBLIC KEY-----',
    'Secrets are never committed; see SECURITY.md.',
    'GITHUB_TOKEN permissions are read-only.',
  ];
  for (const content of benign) assert.deepEqual(rulesHit(content), [], content);
});

test('reports path and line without echoing the secret', () => {
  const [finding] = check(file(['line one', ['gh', 'p_', 'C'.repeat(40)].join('')].join('\n'), 'a/b.md'));
  assert.deepEqual(finding, { path: 'a/b.md', line: 2, rule: 'github-token' });
});

test('skips binary content', () => {
  assert.deepEqual(check([{ path: 'blob.bin', content: null }]), []);
});
