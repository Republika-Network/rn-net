import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from './forbidden-paths.mjs';

const rulesFor = (path) => check([{ path, content: '' }]).map((f) => f.rule);

test('rejects key material and packed artifacts by path', () => {
  const cases = {
    '.env': 'env-file',
    'apps/anchor/.env.local': 'env-file',
    'issuer.pem': 'key-file',
    'deep/dir/anchor.KEY': 'key-file',
    'wallet.keystore': 'key-file',
    'testnet.seed': 'key-file',
    'id_ed25519': 'ssh-key',
    'home/id_rsa.pub': 'ssh-key',
    'keys/anchor.json': 'key-directory',
    'apps/x/.secrets/a': 'key-directory',
    'vendor/protocol-0.1.0.tgz': 'packed-artifact',
  };
  for (const [path, rule] of Object.entries(cases)) {
    assert.ok(rulesFor(path).includes(rule), `${path} should hit ${rule}`);
  }
});

test('allows ordinary repository paths', () => {
  for (const path of ['README.md', '.github/workflows/ci.yml', 'docs/adr/README.md', 'spec/keys.md', 'monkeys/a.md', '.envrc.md']) {
    assert.deepEqual(rulesFor(path), [], path);
  }
});
