// Behaviour that the JSON vector files cannot express: values built in code, limits, and
// cross-checks against the platform's JSON implementation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalBytes, canonicalize, CanonicalErrorCode as E, LIMITS, parse, PROFILE } from '../src/index.mjs';

const rejects = (fn, code) => assert.throws(fn, { name: 'CanonicalError', code });

test('profile identifier', () => {
  assert.equal(PROFILE, 'rnnet.canonical-json.v1');
});

test('values built in code follow the same rules as parsed input', () => {
  assert.equal(canonicalize({ b: [1, 'x'], a: { d: null, c: true } }), '{"a":{"c":true,"d":null},"b":[1,"x"]}');
  rejects(() => canonicalize(-0), E.NEGATIVE_ZERO);
  rejects(() => canonicalize(1.5), E.NUMBER_NOT_INTEGER);
  rejects(() => canonicalize(2 ** 53), E.NUMBER_OUT_OF_RANGE);
  rejects(() => canonicalize(Number.NaN), E.UNSUPPORTED_VALUE);
  rejects(() => canonicalize(Number.POSITIVE_INFINITY), E.UNSUPPORTED_VALUE);
  rejects(() => canonicalize('\ud800'), E.LONE_SURROGATE);
  rejects(() => canonicalize({ ['\udc00']: 1 }), E.LONE_SURROGATE);
});

test('unsupported JavaScript values are rejected, never coerced', () => {
  const unsupported = [
    undefined,
    { a: undefined },
    [undefined],
    () => 1,
    Symbol('s'),
    10n,
    new Date(0),
    new Map(),
    new Uint8Array(1),
    new (class Point {})(),
    { [Symbol('k')]: 1 },
    Object.defineProperty({}, 'a', { get: () => 1, enumerable: true }),
    Object.defineProperty({}, 'a', { value: 1, enumerable: false }),
    // eslint-disable-next-line no-sparse-arrays
    [1, , 3],
  ];
  for (const value of unsupported) rejects(() => canonicalize(value), E.UNSUPPORTED_VALUE);
});

test('parse returns null-prototype objects, so __proto__ cannot pollute', () => {
  const value = parse('{"__proto__":{"polluted":true}}');
  assert.equal(Object.getPrototypeOf(value), null);
  assert.deepEqual(Object.keys(value), ['__proto__']);
  assert.equal({}.polluted, undefined);
});

test('string escaping matches JSON.stringify for every BMP code unit except lone surrogates', () => {
  for (let unit = 0; unit <= 0xffff; unit++) {
    if (unit >= 0xd800 && unit <= 0xdfff) continue;
    const s = `a${String.fromCharCode(unit)}b`;
    assert.equal(canonicalize(s), JSON.stringify(s));
  }
});

test('key order is by UTF-16 code unit, not by code point', () => {
  // U+1F600 is encoded as D83D DE00, which sorts before U+FFFD.
  assert.equal(canonicalize({ '�': 1, '\u{1f600}': 2 }), '{"\u{1f600}":2,"�":1}');
});

test('depth limit applies to serialization as well as parsing', () => {
  let ok = [];
  for (let i = 1; i < LIMITS.maxDepth; i++) ok = [ok];
  assert.equal(canonicalize(ok).length, LIMITS.maxDepth * 2);
  rejects(() => canonicalize([ok]), E.DEPTH_EXCEEDED);
});

test('size limit is enforced on bytes and strings', () => {
  const big = `"${'a'.repeat(LIMITS.maxBytes)}"`;
  rejects(() => parse(new TextEncoder().encode(big)), E.SIZE_EXCEEDED);
  rejects(() => parse(big), E.SIZE_EXCEEDED);
  const atLimit = `"${'a'.repeat(LIMITS.maxBytes - 2)}"`;
  assert.equal(parse(atLimit).length, LIMITS.maxBytes - 2);
});

test('string input with a byte order mark or lone surrogate is rejected', () => {
  rejects(() => parse('﻿{}'), E.BOM);
  rejects(() => parse('"\ud800"'), E.LONE_SURROGATE);
});

test('non-byte, non-string input is rejected', () => {
  rejects(() => parse(42), E.UNSUPPORTED_VALUE);
  rejects(() => parse([0x7b, 0x7d]), E.UNSUPPORTED_VALUE);
});

test('errors carry an offset into the input', () => {
  assert.throws(() => parse('{"a":1,"a":2}'), (error) => error.code === E.DUPLICATE_KEY && error.offset === 7);
});

test('canonicalBytes is the UTF-8 encoding of canonicalize', () => {
  const value = { k: 'é\u{1f600}' };
  assert.deepEqual(canonicalBytes(value), new TextEncoder().encode(canonicalize(value)));
});

test('canonicalization is deterministic across insertion orders', () => {
  const keys = Array.from({ length: 50 }, (_, i) => `k${(i * 37) % 50}`);
  const forward = Object.fromEntries(keys.map((k) => [k, k]));
  const backward = Object.fromEntries([...keys].reverse().map((k) => [k, k]));
  assert.equal(canonicalize(forward), canonicalize(backward));
});
