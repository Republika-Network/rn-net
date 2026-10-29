// RN-NET-02: every evidence vector reproduces its expected report byte for byte.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeReport, verifyEvidence } from '../../verifier/src/index.mjs';
import { inputBytes, loadVectors } from '../src/vectors.mjs';

const file = loadVectors('evidence/evidence.json');
const encoder = new TextEncoder();

test('the evidence vectors cover passes, failures and unsupported inputs', () => {
  const outcomes = new Set(file.vectors.map((v) => v.expectedOutcome));
  assert.deepEqual([...outcomes].sort(), ['FAIL', 'PASS', 'UNSUPPORTED']);
  assert.equal(new Set(file.vectors.map((v) => v.id)).size, file.vectors.length);
});

for (const vector of file.vectors) {
  test(`evidence: ${vector.id} -> ${vector.expectedOutcome}`, () => {
    const options = vector.commitment
      ? { commitment: { envelope: encoder.encode(vector.commitment.envelope), digest: vector.commitment.digest } }
      : {};
    const report = verifyEvidence(inputBytes(vector), options);
    assert.equal(report.outcome, vector.expectedOutcome);
    assert.deepEqual(report.findings.map((f) => f.code), vector.expectedFindings);
    assert.equal(new TextDecoder().decode(encodeReport(report)), vector.expectedReport);
    // No report ever claims more than the taxonomy allows in RN-NET-02.
    assert.ok(!report.statements.some((s) => s.classification === 'THIRD_PARTY_ATTESTED'));
    if (report.outcome !== 'PASS') assert.ok(report.findings.length > 0);
  });
}
