import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalBytes, canonicalizeText, parse } from '../../canonical/src/index.mjs';
import { inputBytes, loadVectors } from '../src/vectors.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const valid = loadVectors('canonical/valid.json');
const invalid = loadVectors('canonical/invalid.json');

test('vector files declare the canonical profile', () => {
  assert.equal(valid.profile, 'rnnet.canonical-json.v1');
  assert.equal(invalid.profile, 'rnnet.canonical-json.v1');
});

for (const vector of valid.vectors) {
  test(`canonical valid: ${vector.id}`, () => {
    const bytes = inputBytes(vector);
    assert.equal(canonicalizeText(bytes), vector.expected);
    const out = canonicalBytes(parse(bytes));
    assert.equal(sha256(out), vector.expectedSha256);
    // Canonical output is a fixed point: canonicalizing it again changes nothing.
    assert.equal(canonicalizeText(out), vector.expected);
  });
}

for (const vector of invalid.vectors) {
  test(`canonical invalid: ${vector.id} -> ${vector.expectedError}`, () => {
    // parse() is public, so it must enforce every input rule on its own, without relying on
    // the serializer's defensive re-checks.
    assert.throws(() => parse(inputBytes(vector)), { name: 'CanonicalError', code: vector.expectedError });
    assert.throws(() => canonicalizeText(inputBytes(vector)), { name: 'CanonicalError', code: vector.expectedError });
  });
}

test('equivalent inputs share one canonical form and hash', () => {
  const byExpected = new Map();
  for (const v of valid.vectors) byExpected.set(v.expected, [...(byExpected.get(v.expected) ?? []), v.id]);
  const groups = [...byExpected.values()].filter((ids) => ids.length > 1);
  assert.ok(groups.some((ids) => ids.includes('non-ascii-escaped') && ids.includes('non-ascii-literal')));
});
