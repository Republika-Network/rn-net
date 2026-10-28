import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { check, DENIED_TOKEN_HASHES } from './upstream-content.mjs';

const rules = (content, path = 'doc.md') => check([{ path, content }]).map((f) => f.rule);
const join = (...parts) => parts.join('');

test('flags public upstream identifiers', () => {
  assert.ok(rules(join('import x from "@aoc-', 'enterprise/runtime"')).includes('upstream-package'));
  assert.ok(rules(join('see src/', 'enterprise/host.ts')).includes('upstream-path'));
  assert.ok(rules(join('per SEC', '-INV-12')).includes('upstream-invariant'));
  assert.ok(rules(join('fron', 'tera:executor-receipt:v1')).includes('upstream-signing-domain'));
});

test('flags a denied name by hash, case-insensitively, inside text', () => {
  // A synthetic name, registered for this test only.
  const name = join('zz-test-', 'denied-name');
  const hash = createHash('sha256').update(name).digest('hex');
  DENIED_TOKEN_HASHES.add(hash);
  try {
    assert.deepEqual(rules(`Built for ${name.toUpperCase()} in 2026.`), ['denied-name']);
    assert.deepEqual(rules('Built for someone else.'), []);
  } finally {
    DENIED_TOKEN_HASHES.delete(hash);
  }
});

test('allows nominative references to upstream projects', () => {
  for (const content of ['RN-NET is downstream of Soberanía Protocol and Frontera.', 'enterprise customers', 'frontera is a word']) {
    assert.deepEqual(rules(content), [], content);
  }
});

test('every denied hash is a SHA-256 hex digest', () => {
  for (const hash of DENIED_TOKEN_HASHES) assert.match(hash, /^[0-9a-f]{64}$/);
});
