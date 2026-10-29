// RN-NET-01H, finding F1: an envelope given as a JavaScript value must be read once. Getters
// and Proxies must not be able to show one value to validation and another to hashing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { commitmentFromBytes, computeCommitment, FORMAT, validateEnvelope, verifyCommitment } from '../src/index.mjs';

const valid = Object.freeze({
  format: FORMAT,
  sourceFormat: 'example.evidence-bundle.v1',
  sourceCanonicalization: 'rnnet.canonical-json.v1',
  sourceEvidenceDigest: `sha256:${'a'.repeat(64)}`,
  sourceFileSha256: `sha256:${'b'.repeat(64)}`,
  sourceRef: 'example:hostile/1',
});
const encode = (text) => new TextEncoder().encode(text);

/** A getter that answers `first` for the first `n` reads, then `later`. */
function shifting(field, first, later, n = 2) {
  let reads = 0;
  const value = { ...valid };
  Object.defineProperty(value, field, { enumerable: true, configurable: true, get: () => (++reads <= n ? first : later) });
  return value;
}

/** A Proxy whose get trap answers `later` for `field` after the first `n` reads. */
function shiftingProxy(field, later, n = 2) {
  let reads = 0;
  return new Proxy({ ...valid }, { get: (target, key) => (key === field && ++reads > n ? later : target[key]) });
}

/** A Proxy whose descriptor trap answers `first`, then `later`, for `field`. */
function shiftingDescriptorProxy(field, first, later) {
  let calls = 0;
  return new Proxy(
    { ...valid },
    {
      getOwnPropertyDescriptor(target, key) {
        const descriptor = Reflect.getOwnPropertyDescriptor(target, key);
        if (key === field) descriptor.value = ++calls === 1 ? first : later;
        return descriptor;
      },
    },
  );
}

const hostile = {
  'getter: sourceRef becomes invalid on the third read': shifting('sourceRef', 'x:y', 'not a valid ref with spaces'),
  'getter: sourceEvidenceDigest becomes a number': shifting('sourceEvidenceDigest', valid.sourceEvidenceDigest, 12345),
  'getter: format becomes v2': shifting('format', FORMAT, 'rnnet.evidence-commitment.v2'),
  'getter: always valid (still an accessor)': shifting('sourceRef', 'x:y', 'x:y'),
  'proxy get trap: format becomes v2': shiftingProxy('format', 'rnnet.evidence-commitment.v2'),
  'proxy get trap: sourceRef becomes invalid': shiftingProxy('sourceRef', 'bad ref'),
  'proxy descriptor trap: valid first, invalid later': shiftingDescriptorProxy('sourceRef', 'x:y', 'bad ref'),
  'proxy descriptor trap: invalid first, valid later': shiftingDescriptorProxy('sourceRef', 'bad ref', 'x:y'),
  'non-enumerable field': Object.defineProperty({ ...valid }, 'sourceRef', { value: 'x:y', enumerable: false }),
  'symbol-keyed extra': { ...valid, [Symbol('extra')]: 'x' },
  'class instance with the six fields': Object.assign(new (class Envelope {})(), valid),
};

for (const [name, value] of Object.entries(hostile)) {
  test(`F1 invariant: ${name}`, () => {
    let result;
    try {
      result = computeCommitment(value);
    } catch (error) {
      // Rejected with a defined code: acceptable.
      assert.match(error.code, /^RN(CJ|EC)_/);
      return;
    }
    // Accepted: the digest must cover exactly the validated envelope, and the byte-level
    // verifier must accept the commitment over the canonical bytes it was computed from.
    assert.deepEqual(validateEnvelope(result.envelope), result.envelope);
    assert.equal(computeCommitment(result.envelope).digest, result.digest);
    assert.equal(commitmentFromBytes(encode(result.canonical)).digest, result.digest);
    assert.equal(verifyCommitment(encode(result.canonical), result.digest).valid, true);
  });
}

test('F1: every accessor is rejected, even one that always returns a valid value', () => {
  for (const name of Object.keys(hostile).filter((n) => n.startsWith('getter'))) {
    assert.throws(() => computeCommitment(hostile[name]), { code: 'RNCJ_UNSUPPORTED_VALUE' }, name);
    assert.throws(() => validateEnvelope(hostile[name]), { code: 'RNCJ_UNSUPPORTED_VALUE' }, name);
  }
});

test('F1: the reproduced attacks no longer yield a commitment over an invalid envelope', () => {
  const { digest, canonical, envelope } = computeCommitment(shiftingProxy('format', 'rnnet.evidence-commitment.v2'));
  assert.equal(envelope.format, FORMAT);
  assert.ok(canonical.includes(`"format":"${FORMAT}"`));
  assert.equal(verifyCommitment(encode(canonical), digest).valid, true);
});

test('F1: a polluted Object.prototype.value does not let an accessor pass as data', () => {
  const value = shifting('sourceRef', 'x:y', 'x:y');
  Object.prototype.value = 'polluted';
  try {
    assert.throws(() => computeCommitment(value), { code: 'RNCJ_UNSUPPORTED_VALUE' });
  } finally {
    delete Object.prototype.value;
  }
});

test('the returned envelope cannot be changed after the digest was computed', () => {
  const result = computeCommitment({ ...valid });
  assert.throws(() => {
    'use strict';
    result.envelope.sourceRef = 'example:changed';
  }, TypeError);
  assert.equal(result.envelope.sourceRef, valid.sourceRef);
});

test('commitmentFromBytes accepts bytes only', () => {
  assert.throws(() => commitmentFromBytes(JSON.stringify(valid)), { code: 'RNCJ_UNSUPPORTED_VALUE' });
  assert.throws(() => commitmentFromBytes([123, 125]), { code: 'RNCJ_UNSUPPORTED_VALUE' });
});
