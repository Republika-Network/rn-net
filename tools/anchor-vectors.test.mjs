// The committed anchor vectors are exactly what the generator builds: fixtures are reproducible.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildAnchorVectors, OUT, serialize } from './vectors/anchor-vectors.mjs';

test('vectors/anchor/ is reproducible from tools/vectors/anchor-vectors.mjs', () => {
  for (const [name, value] of Object.entries(buildAnchorVectors())) assert.equal(readFileSync(OUT(name), 'utf8'), serialize(value), name);
});
