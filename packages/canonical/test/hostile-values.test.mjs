// RN-NET-01H: constructed values are read once (F1), and string input follows the byte-input
// check order without paying for an oversized string (F8).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize, CanonicalErrorCode as E, LIMITS, parse } from '../src/index.mjs';

const rejects = (fn, code) => assert.throws(fn, { name: 'CanonicalError', code });

test('F1: an accessor array element is rejected, not read twice', () => {
  let reads = 0;
  const array = [];
  Object.defineProperty(array, 0, { enumerable: true, configurable: true, get: () => ++reads });
  rejects(() => canonicalize(array), E.UNSUPPORTED_VALUE);
  assert.equal(reads, 0);
});

test('F1: non-enumerable indices, extra named properties and symbol properties on arrays are rejected', () => {
  const nonEnumerable = [1, 2];
  Object.defineProperty(nonEnumerable, 1, { value: 2, enumerable: false });
  rejects(() => canonicalize(nonEnumerable), E.UNSUPPORTED_VALUE);

  const extra = [1];
  extra.extra = 'x';
  rejects(() => canonicalize(extra), E.UNSUPPORTED_VALUE);

  const symbol = [1];
  symbol[Symbol('s')] = 1;
  rejects(() => canonicalize(symbol), E.UNSUPPORTED_VALUE);

  // eslint-disable-next-line no-sparse-arrays
  rejects(() => canonicalize([1, , 3]), E.UNSUPPORTED_VALUE);
});

test('F1: hostile nested values are rejected wherever they appear', () => {
  const getter = Object.defineProperty({}, 'a', { enumerable: true, get: () => 1 });
  rejects(() => canonicalize({ outer: [getter] }), E.UNSUPPORTED_VALUE);
  rejects(() => canonicalize([[{ ok: 1 }, getter]]), E.UNSUPPORTED_VALUE);
});

test('F1: a Proxy is serialized from one snapshot of its descriptors', () => {
  let calls = 0;
  const proxy = new Proxy([1, 2], {
    get: (target, key) => (key === 'length' ? 99 : Reflect.get(target, key)),
    getOwnPropertyDescriptor(target, key) {
      calls += 1;
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
  // The get trap lies about length; the descriptors (one call per property) do not.
  assert.equal(canonicalize(proxy), '[1,2]');
  assert.equal(calls, 3); // indices 0 and 1, and length, exactly once each
});

test('F1: an object Proxy that changes its descriptor answers is read once per key', () => {
  let calls = 0;
  const proxy = new Proxy(
    { a: 1 },
    {
      getOwnPropertyDescriptor(target, key) {
        const descriptor = Reflect.getOwnPropertyDescriptor(target, key);
        descriptor.value = ++calls;
        return descriptor;
      },
    },
  );
  assert.equal(canonicalize(proxy), '{"a":1}');
  assert.equal(calls, 1);
});

test('F8: string input checks size, then byte order mark, then well-formedness', () => {
  rejects(() => parse(`﻿${'a'.repeat(LIMITS.maxBytes)}`), E.SIZE_EXCEEDED);
  rejects(() => parse('﻿"\ud800"'), E.BOM);
  rejects(() => parse('"\ud800"'), E.LONE_SURROGATE);
});

test('F8: string size is the UTF-8 length, counted exactly at the limit', () => {
  const twoByte = (n) => `"${'é'.repeat(n)}"`; // 2 + 2n bytes
  assert.equal(parse(twoByte((LIMITS.maxBytes - 2) / 2)).length, (LIMITS.maxBytes - 2) / 2);
  rejects(() => parse(twoByte((LIMITS.maxBytes - 2) / 2 + 1)), E.SIZE_EXCEEDED);
  // Supplementary characters: 4 UTF-8 bytes for 2 UTF-16 units; ASCII padding fills the rest.
  const astral = Math.floor((LIMITS.maxBytes - 2) / 4);
  const pad = LIMITS.maxBytes - 2 - astral * 4;
  const atLimit = `"${'\u{1f600}'.repeat(astral)}${'a'.repeat(pad)}"`;
  assert.equal(parse(atLimit).length, astral * 2 + pad);
  rejects(() => parse(`"${'\u{1f600}'.repeat(astral)}${'a'.repeat(pad + 1)}"`), E.SIZE_EXCEEDED);
});

test('F8: an oversized string is rejected by its length before any encoding work', () => {
  const huge = 'a'.repeat(64 * LIMITS.maxBytes);
  const started = process.hrtime.bigint();
  rejects(() => parse(huge), E.SIZE_EXCEEDED);
  // A length comparison, not a 64 MiB encode: generous bound to avoid flakiness.
  assert.ok(process.hrtime.bigint() - started < 50_000_000n);
});

test('bytes at exactly the size limit are accepted, one more byte is not', () => {
  const at = new TextEncoder().encode(`"${'a'.repeat(LIMITS.maxBytes - 2)}"`);
  assert.equal(at.length, LIMITS.maxBytes);
  assert.equal(parse(at).length, LIMITS.maxBytes - 2);
  rejects(() => parse(new TextEncoder().encode(`"${'a'.repeat(LIMITS.maxBytes - 1)}"`)), E.SIZE_EXCEEDED);
});
