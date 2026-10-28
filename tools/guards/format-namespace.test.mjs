import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from './format-namespace.mjs';

const rules = (content, path = 'doc.md') => check([{ path, content }]).map((f) => f.rule);
const RN = ['r', 'n.'].join('');

test('rejects identifiers in the reserved short namespace', () => {
  assert.deepEqual(rules(`format ${RN}evidence-commitment.v1`), ['rn-prefix']);
  assert.deepEqual(rules(`"${RN}sv"`), ['rn-prefix']);
});

test('accepts rnnet identifiers and ordinary words', () => {
  for (const content of ['rnnet.evidence-commitment.v1', 'the turn.next step', 'Return.value', 'learn.md']) {
    assert.deepEqual(rules(content), [], content);
  }
});

test('JSON format fields must be rnnet or registered external formats', () => {
  assert.deepEqual(rules('{"format": "rnnet.evidence-commitment.v1"}', 'v.json'), []);
  assert.deepEqual(rules('{"format": "vendor.bundle.v1"}', 'v.json'), ['unregistered-format']);
  assert.deepEqual(rules('{"format": "vendor.bundle.v1"}', 'v.md'), [], 'only JSON files are checked');
});
