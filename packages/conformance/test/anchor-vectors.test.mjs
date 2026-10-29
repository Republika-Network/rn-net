// RN-NET-03A: every anchor vector reproduces its expected result, byte for byte where recorded.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeAnchorPayload, encodeAnchorPayload, encodeAnchorReport, verifyDualAnchor, verifyEvmObservation, verifyXrplObservation } from '../../anchor/src/index.mjs';
import { loadVectors } from '../src/vectors.mjs';

const encode = (text) => new TextEncoder().encode(text);
const decode = (bytes) => new TextDecoder().decode(bytes);

for (const vector of loadVectors('anchor/payload.json').vectors) {
  test(`anchor payload: ${vector.id}`, () => {
    const data = Uint8Array.from(Buffer.from(vector.payloadHex, 'hex'));
    if (vector.expectedError) {
      assert.throws(() => decodeAnchorPayload(data), { code: vector.expectedError });
    } else {
      assert.equal(decodeAnchorPayload(data), vector.expectedCommitment);
      assert.equal(Buffer.from(encodeAnchorPayload(vector.expectedCommitment)).toString('hex'), vector.payloadHex);
    }
  });
}

for (const [name, verify] of [['xrpl', verifyXrplObservation], ['evm', verifyEvmObservation]]) {
  for (const vector of loadVectors(`anchor/${name}.json`).vectors) {
    test(`anchor ${name}: ${vector.id} -> ${vector.expectedOutcome}`, () => {
      const record = verify(encode(vector.input), vector.expectedCommitment);
      assert.equal(record.outcome, vector.expectedOutcome);
      assert.deepEqual(record.findings.map((f) => f.code), vector.expectedFindings);
      assert.equal(decode(encodeAnchorReport(record)), vector.expectedRecord);
    });
  }
}

for (const vector of loadVectors('anchor/dual.json').vectors) {
  test(`anchor dual: ${vector.id} -> ${vector.expectedOutcome}`, () => {
    const inputs = {};
    for (const slot of ['xrpl', 'evm']) if (vector[slot] !== undefined) inputs[slot] = encode(vector[slot]);
    const report = verifyDualAnchor(inputs, vector.expectedCommitment);
    assert.equal(report.outcome, vector.expectedOutcome);
    assert.deepEqual(report.conclusions, vector.expectedConclusions);
    assert.ok(!report.conclusions.includes('CHAIN_PROVEN'));
    assert.equal(decode(encodeAnchorReport(report)), vector.expectedReport);
  });
}
