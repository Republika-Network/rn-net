// Loads the conformance vectors in vectors/ (format rnnet.conformance-vectors.v1).
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = new URL('../../../vectors/', import.meta.url);

/** @param {string} name path relative to vectors/, e.g. 'canonical/valid.json' */
export function loadVectors(name) {
  const file = JSON.parse(readFileSync(fileURLToPath(new URL(name, ROOT)), 'utf8'));
  if (file.format !== 'rnnet.conformance-vectors.v1') throw new Error(`${name}: unexpected vector file format`);
  return file;
}

/**
 * The exact input bytes of a vector: inputHex when present; inputPattern (prefix + repeat ×
 * count + suffix, UTF-8) for inputs too large to store literally; otherwise UTF-8 of input.
 */
export function inputBytes(vector) {
  if (Object.hasOwn(vector, 'inputHex')) return Uint8Array.from(Buffer.from(vector.inputHex, 'hex'));
  if (Object.hasOwn(vector, 'inputPattern')) {
    const { prefix, repeat, count, suffix } = vector.inputPattern;
    return new TextEncoder().encode(prefix + repeat.repeat(count) + suffix);
  }
  return new TextEncoder().encode(vector.input);
}

/** The expected canonical text of a valid vector: expectedPattern when present, otherwise expected. */
export function expectedText(vector) {
  if (Object.hasOwn(vector, 'expectedPattern')) {
    const { prefix, repeat, count, suffix } = vector.expectedPattern;
    return prefix + repeat.repeat(count) + suffix;
  }
  return vector.expected;
}
