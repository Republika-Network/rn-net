// The committed evidence vectors are exactly what the generator builds from public test-key
// labels: fixture construction is reproducible.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildEvidenceVectors, OUTPUT, serialize } from './vectors/evidence-vectors.mjs';

test('vectors/evidence/evidence.json is reproducible from tools/vectors/evidence-vectors.mjs', () => {
  assert.equal(readFileSync(OUTPUT, 'utf8'), serialize(buildEvidenceVectors()));
});
