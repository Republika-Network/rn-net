import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
  Classification as C,
  computeCommitment,
  DOMAIN_SEPARATOR,
  DOMAIN_TAG,
  FIELDS,
  FORMAT,
  sha256Digest,
  validateEnvelope,
  verifyCommitment,
} from '../src/index.mjs';

const sourceFile = new TextEncoder().encode('synthetic source file for unit tests');
const envelope = Object.freeze({
  format: FORMAT,
  sourceFormat: 'example.evidence-bundle.v1',
  sourceCanonicalization: 'rnnet.canonical-json.v1',
  sourceEvidenceDigest: sha256Digest(new TextEncoder().encode('synthetic evidence')),
  sourceFileSha256: sha256Digest(sourceFile),
  sourceRef: 'example:unit-test/1',
});
const text = (value) => JSON.stringify(value);

test('domain separator is the ASCII tag followed by one zero byte', () => {
  assert.equal(DOMAIN_TAG, 'rnnet:evidence-commitment:v1');
  assert.deepEqual([...DOMAIN_SEPARATOR], [...Buffer.from('rnnet:evidence-commitment:v1\0', 'latin1')]);
});

test('commitment = SHA-256(domain separator || canonical envelope)', () => {
  const { canonical, digest, digestBytes } = computeCommitment(envelope);
  const expected = createHash('sha256').update(DOMAIN_SEPARATOR).update(canonical, 'utf8').digest();
  assert.equal(digest, `sha256:${expected.toString('hex')}`);
  assert.deepEqual(Buffer.from(digestBytes), expected);
  assert.equal(digestBytes.length, 32);
});

test('every bound field changes the commitment', () => {
  const base = computeCommitment(envelope).digest;
  const changed = {
    sourceFormat: 'example.evidence-bundle.v2',
    sourceCanonicalization: 'example-canonical/1',
    sourceEvidenceDigest: `sha256:${'1'.repeat(64)}`,
    sourceFileSha256: `sha256:${'2'.repeat(64)}`,
    sourceRef: 'example:unit-test/2',
  };
  for (const [field, value] of Object.entries(changed)) {
    assert.notEqual(computeCommitment({ ...envelope, [field]: value }).digest, base, field);
  }
});

test('validateEnvelope returns exactly the six fields in specification order', () => {
  assert.deepEqual(Object.keys(validateEnvelope({ ...envelope })), FIELDS);
});

test('validateEnvelope rejects non-plain objects', () => {
  assert.throws(() => validateEnvelope(new (class Envelope {})()), { code: 'RNEC_NOT_OBJECT' });
});

test('successful verification classifies each statement conservatively', () => {
  const { digest } = computeCommitment(envelope);
  const result = verifyCommitment(text(envelope), digest);
  assert.equal(result.valid, true);
  const bySubject = Object.fromEntries(result.statements.map((s) => [s.subject, s.classification]));
  assert.deepEqual(bySubject, {
    commitment: C.VERIFIED,
    sourceFormat: C.CLAIMED,
    sourceCanonicalization: C.CLAIMED,
    sourceEvidenceDigest: C.CLAIMED,
    sourceFileSha256: C.CLAIMED,
    sourceRef: C.UNRESOLVED,
  });
});

test('a supplied source file upgrades only sourceFileSha256 to VERIFIED', () => {
  const { digest } = computeCommitment(envelope);
  const result = verifyCommitment(text(envelope), digest, { sourceFile });
  assert.equal(result.valid, true);
  const file = result.statements.find((s) => s.subject === 'sourceFileSha256');
  assert.equal(file.classification, C.VERIFIED);
  assert.equal(result.statements.find((s) => s.subject === 'sourceEvidenceDigest').classification, C.CLAIMED);
});

test('a different source file is reported as a mismatch', () => {
  const { digest } = computeCommitment(envelope);
  const result = verifyCommitment(text(envelope), digest, { sourceFile: new TextEncoder().encode('other file') });
  assert.equal(result.valid, false);
  assert.equal(result.code, 'RNEC_SOURCE_FILE_MISMATCH');
});

test('verifyCommitment returns codes instead of throwing on bad input', () => {
  const { digest } = computeCommitment(envelope);
  assert.equal(verifyCommitment('{', digest).code, 'RNCJ_SYNTAX');
  assert.equal(verifyCommitment(text({ ...envelope, extra: 'x' }), digest).code, 'RNEC_UNKNOWN_FIELD');
  assert.equal(verifyCommitment(text(envelope), 'sha256:xyz').code, 'RNEC_INVALID_COMMITMENT_DIGEST');
  assert.equal(verifyCommitment(text(envelope), undefined).code, 'RNEC_INVALID_COMMITMENT_DIGEST');
});

test('verification statements never claim more than RN-NET-01 checks', () => {
  const { digest } = computeCommitment(envelope);
  const { statements } = verifyCommitment(text(envelope), digest);
  const verified = statements.filter((s) => s.classification === C.VERIFIED).map((s) => s.subject);
  assert.deepEqual(verified, ['commitment']);
  for (const s of statements) assert.ok(Object.values(C).includes(s.classification));
});
