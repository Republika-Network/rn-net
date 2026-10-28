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

/** The exact input bytes of a vector: inputHex when present, otherwise UTF-8 of input. */
export function inputBytes(vector) {
  if (Object.hasOwn(vector, 'inputHex')) return Uint8Array.from(Buffer.from(vector.inputHex, 'hex'));
  return new TextEncoder().encode(vector.input);
}
