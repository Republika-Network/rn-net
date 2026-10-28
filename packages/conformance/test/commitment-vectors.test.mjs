import { test } from 'node:test';
import assert from 'node:assert/strict';
import { commitmentFromBytes, computeCommitment, verifyCommitment } from '../../commitment/src/index.mjs';
import { inputBytes, loadVectors } from '../src/vectors.mjs';

const valid = loadVectors('commitment/valid.json');
const invalid = loadVectors('commitment/invalid.json');
const tamper = loadVectors('tamper/commitment-tamper.json');

for (const vector of valid.vectors) {
  test(`commitment valid: ${vector.id}`, () => {
    const result = commitmentFromBytes(inputBytes(vector));
    assert.equal(result.canonical, vector.expectedCanonical);
    assert.equal(result.digest, vector.expectedCommitment);
    assert.equal(verifyCommitment(inputBytes(vector), vector.expectedCommitment).valid, true);
  });
}

for (const vector of invalid.vectors) {
  test(`commitment invalid: ${vector.id} -> ${vector.expectedError}`, () => {
    let error;
    try {
      commitmentFromBytes(inputBytes(vector));
    } catch (caught) {
      error = caught;
    }
    assert.ok(error, 'expected a failure');
    assert.equal(error.code, vector.expectedError);
    assert.equal(error.field, vector.expectedField);
  });
}

test('the tamper base envelope matches its recorded commitment', () => {
  assert.equal(computeCommitment(tamper.base.envelope).digest, tamper.base.commitment);
});

for (const vector of tamper.vectors) {
  test(`tamper: ${vector.id}`, () => {
    const result = verifyCommitment(inputBytes(vector), vector.presentedDigest);
    assert.equal(result.valid, vector.expected.valid);
    if (!vector.expected.valid) assert.equal(result.code, vector.expected.code);
  });
}

test('at least twelve tamper scenarios are rejected', () => {
  assert.ok(tamper.vectors.filter((v) => !v.expected.valid).length >= 12);
});
