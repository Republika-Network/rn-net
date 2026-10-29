// RN-NET-02: the independent evidence verifier. Keys here are generated in memory for each run;
// none is stored.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { computeCommitment } from '../../commitment/src/index.mjs';
import {
  computeEvidenceDigest,
  DIGEST_DOMAIN_SEPARATOR,
  encodeReport,
  evidenceDigestBytes,
  FORMAT,
  Outcome,
  SIGNATURE_DOMAIN_SEPARATOR,
  signingMessage,
  verifyEvidence,
} from '../src/index.mjs';
import { isAcceptedPublicKey, verifyEd25519 } from '../src/ed25519.mjs';

const BODY = {
  evidenceId: 'unit-0001',
  issuer: 'unit-issuer.example',
  subject: 'operation:unit',
  action: 'synthetic.unit.test',
  outcome: 'succeeded',
  payload: { n: 1, text: 'unit test data' },
};

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { privateKey, publicKey: Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex') };
}
const KEYS = [keyPair(), keyPair(), keyPair()];

function signRecord(key, keyId, body) {
  const signature = sign(null, signingMessage(evidenceDigestBytes(body)), key.privateKey).toString('hex');
  return { keyId, algorithm: 'ed25519', publicKey: key.publicKey, signature };
}
function evidence(body = BODY, signers = [[KEYS[0], 'k1']]) {
  return {
    format: FORMAT,
    canonicalization: 'rnnet.canonical-json.v1',
    body,
    digest: computeEvidenceDigest(body),
    signatures: signers.map(([key, id]) => signRecord(key, id, body)),
  };
}
const bytes = (value) => new TextEncoder().encode(typeof value === 'string' ? value : JSON.stringify(value));
const codes = (report) => report.findings.map((f) => f.code);
const classifications = (report) => Object.fromEntries(report.statements.map((s) => [s.subject, s.classification]));

test('a valid document passes, and its statements never exceed what was checked', () => {
  const report = verifyEvidence(bytes(evidence()));
  assert.equal(report.outcome, Outcome.PASS);
  assert.deepEqual(report.findings, []);
  const c = classifications(report);
  assert.equal(c.evidenceDigest, 'VERIFIED');
  assert.equal(c['signatures[0]'], 'CONSISTENT_UNDER_EMBEDDED_KEYS');
  assert.equal(c['signerIdentity[0]'], 'UNRESOLVED');
  assert.equal(c['body.issuer'], 'CLAIMED');
  assert.equal(c.eventOccurrence, 'UNRESOLVED');
  assert.ok(!report.statements.some((s) => s.classification === 'THIRD_PARTY_ATTESTED'));
});

test('the digest domain is distinct from the commitment domain and from a plain hash', () => {
  assert.equal(new TextDecoder().decode(DIGEST_DOMAIN_SEPARATOR.subarray(0, -1)), 'rnnet:synthetic-evidence:digest:v1');
  assert.equal(new TextDecoder().decode(SIGNATURE_DOMAIN_SEPARATOR.subarray(0, -1)), 'rnnet:synthetic-evidence:signature:v1');
  assert.equal(DIGEST_DOMAIN_SEPARATOR.at(-1), 0);
  const canonical = new TextEncoder().encode('{"x":1}');
  const plain = `sha256:${createHash('sha256').update(canonical).digest('hex')}`;
  assert.notEqual(computeEvidenceDigest({ x: 1 }), plain);
  // An envelope with the same bytes gets a different value under the commitment domain.
  const envelope = {
    format: 'rnnet.evidence-commitment.v1', sourceFormat: FORMAT, sourceCanonicalization: 'rnnet.canonical-json.v1',
    sourceEvidenceDigest: computeEvidenceDigest(BODY), sourceFileSha256: computeEvidenceDigest(BODY), sourceRef: 'synthetic:x',
  };
  assert.notEqual(computeCommitment(envelope).digest, computeEvidenceDigest(envelope));
});

test('failed checks never combine into a pass, and every record is verified', () => {
  const doc = evidence(BODY, [[KEYS[0], 'k1'], [KEYS[1], 'k2'], [KEYS[2], 'k3']]);
  doc.signatures[1].signature = doc.signatures[0].signature;
  const report = verifyEvidence(bytes(doc));
  assert.equal(report.outcome, Outcome.FAIL);
  assert.deepEqual(report.signatures.map((s) => s.result), ['VALID', 'INVALID', 'VALID']);
  assert.deepEqual(codes(report), ['RNSE_SIGNATURE_INVALID']);
  // A matching commitment does not rescue it.
  const text = JSON.stringify(doc);
  const envelope = {
    format: 'rnnet.evidence-commitment.v1', sourceFormat: FORMAT, sourceCanonicalization: 'rnnet.canonical-json.v1',
    sourceEvidenceDigest: doc.digest, sourceFileSha256: `sha256:${createHash('sha256').update(text).digest('hex')}`, sourceRef: 'synthetic:x',
  };
  const withCommitment = verifyEvidence(bytes(text), { commitment: { envelope: bytes(envelope), digest: computeCommitment(envelope).digest } });
  assert.equal(withCommitment.commitment.result, 'MATCH');
  assert.equal(withCommitment.outcome, Outcome.FAIL);
});

test('signatures bind the body: any claim change after signing fails', () => {
  for (const change of [{ issuer: 'x.example' }, { outcome: 'failed' }, { subject: 'operation:other' }, { payload: { n: 2, text: 'unit test data' } }]) {
    const doc = evidence();
    doc.body = { ...doc.body, ...change };
    const report = verifyEvidence(bytes(doc));
    assert.deepEqual(codes(report), ['RNSE_DIGEST_MISMATCH', 'RNSE_SIGNATURE_INVALID'], JSON.stringify(change));
    assert.ok(!report.statements.some((s) => s.classification === 'CLAIMED'), 'unbound claims are not reported as CLAIMED');
    // Re-digesting the changed body is not enough: the signature still fails.
    doc.digest = computeEvidenceDigest(doc.body);
    assert.deepEqual(codes(verifyEvidence(bytes(doc))), ['RNSE_SIGNATURE_INVALID']);
  }
});

test('key substitution is detected, and a re-signed substitute is never an identity', () => {
  const doc = evidence();
  doc.signatures[0].publicKey = KEYS[1].publicKey;
  assert.deepEqual(codes(verifyEvidence(bytes(doc))), ['RNSE_SIGNATURE_INVALID']);
  const substituted = evidence(BODY, [[KEYS[2], 'k1']]); // an attacker re-signs under the same keyId
  const report = verifyEvidence(bytes(substituted));
  assert.equal(report.outcome, Outcome.PASS);
  assert.equal(classifications(report)['signerIdentity[0]'], 'UNRESOLVED');
});

test('the report is deterministic, canonical, frozen and free of input text', () => {
  const doc = evidence({ ...BODY, payload: { secretish: 'payload text that must not be echoed' } });
  const a = encodeReport(verifyEvidence(bytes(doc)));
  const b = encodeReport(verifyEvidence(bytes(JSON.stringify(doc, null, 3))));
  const report = verifyEvidence(bytes(doc));
  assert.deepEqual(encodeReport(report), a);
  assert.ok(Object.isFrozen(report) && Object.isFrozen(report.statements[0]));
  // Only input.sha256 differs between serializations of the same document.
  const strip = (r) => JSON.stringify({ ...JSON.parse(new TextDecoder().decode(r)), input: null });
  assert.equal(strip(a), strip(b));
  assert.ok(!new TextDecoder().decode(a).includes('payload text'));
});

test('the verifier reads its input once and never needs a private key', () => {
  const input = bytes(evidence());
  const report = verifyEvidence(input);
  input.fill(0x20);
  assert.equal(report.outcome, Outcome.PASS);
  assert.throws(() => verifyEvidence('{"format":"x"}'), TypeError);
  assert.throws(() => verifyEvidence(input, null), TypeError);
  assert.throws(() => verifyEvidence(input, { commitment: { envelope: '{}', digest: 'x' } }), TypeError);
  assert.throws(() => verifyEvidence(input, { commitment: { envelope: bytes('{}') } }), TypeError);
});

test('Ed25519: RFC 8032 section 7.1 vectors verify under the strict rules', () => {
  const cases = [
    ['d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'],
    ['3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'],
  ];
  for (const [pub, message, signature] of cases) {
    const [p, m, s] = [pub, message, signature].map((hex) => Buffer.from(hex, 'hex'));
    assert.equal(verifyEd25519(p, s, m), 'VALID');
    assert.equal(verifyEd25519(p, s, Buffer.concat([m, Buffer.from([0])])), 'INVALID');
  }
});

test('Ed25519: small-order and non-canonical public keys are rejected, high S is invalid', () => {
  // Encodings of the eight small-order points, and non-canonical ones.
  const rejected = [
    `01${'00'.repeat(31)}`,
    `ec${'ff'.repeat(30)}7f`,
    '00'.repeat(32),
    `${'00'.repeat(31)}80`,
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
    `ee${'ff'.repeat(30)}7f`,
    `${'ff'.repeat(31)}7f`,
  ];
  for (const hex of rejected) assert.equal(isAcceptedPublicKey(Buffer.from(hex, 'hex')), false, hex);
  for (const { publicKey } of KEYS) assert.equal(isAcceptedPublicKey(Buffer.from(publicKey, 'hex')), true);
  // S + L verifies in permissive libraries; the profile rejects it.
  const message = signingMessage(evidenceDigestBytes(BODY));
  const signature = sign(null, message, KEYS[0].privateKey);
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(signature[i]);
  s += 2n ** 252n + 27742317777372353535851937790883648493n;
  const high = Buffer.from(signature);
  for (let i = 32; i < 64; i++, s >>= 8n) high[i] = Number(s & 0xffn);
  assert.equal(verifyEd25519(Buffer.from(KEYS[0].publicKey, 'hex'), signature, message), 'VALID');
  assert.equal(verifyEd25519(Buffer.from(KEYS[0].publicKey, 'hex'), high, message), 'INVALID');
});

test('random byte corruption never yields PASS for a different body or different signatures', () => {
  const doc = evidence(BODY, [[KEYS[0], 'k1'], [KEYS[1], 'k2']]);
  const original = bytes(doc);
  let state = 7;
  const random = () => (state = (state * 1103515245 + 12345) & 0x7fffffff);
  for (let n = 0; n < 2000; n++) {
    const mutated = Uint8Array.from(original);
    mutated[random() % mutated.length] = random() & 0xff;
    const report = verifyEvidence(mutated);
    if (report.outcome !== Outcome.PASS) continue;
    const parsed = JSON.parse(new TextDecoder().decode(mutated));
    assert.deepEqual(parsed.body, doc.body);
    assert.deepEqual(parsed.signatures, doc.signatures);
  }
});

test('report size stays bounded at the limits', () => {
  const signers = Array.from({ length: 16 }, (_, i) => [keyPair(), `key-${String(i).padStart(2, '0')}`]);
  const report = encodeReport(verifyEvidence(bytes(evidence(BODY, signers))));
  assert.ok(report.length < 16_384, `report of ${report.length} bytes`);
});

test('a Proxy posing as bytes is refused, so the input is read exactly once', () => {
  const real = bytes(evidence());
  let reads = 0;
  const proxy = new Proxy(real, { get: (target, key) => (reads++, Reflect.get(target, key)) });
  assert.ok(proxy instanceof Uint8Array);
  assert.throws(() => verifyEvidence(proxy), TypeError);
  assert.throws(() => verifyEvidence(real, { commitment: { envelope: new Proxy(bytes('{}'), {}), digest: 'x' } }), TypeError);
});

test('payload size: exactly 65,536 canonical bytes is accepted, one more is not', () => {
  const sized = (n) => ({ ...BODY, payload: { p: 'x'.repeat(n - '{"p":""}'.length) } });
  assert.equal(verifyEvidence(bytes(evidence(sized(65_536)))).outcome, Outcome.PASS);
  assert.deepEqual(codes(verifyEvidence(bytes(evidence(sized(65_537))))), ['RNSE_PAYLOAD_TOO_LARGE']);
});

test('evidence size: exactly 262,144 bytes is parsed, one more is not', () => {
  const text = JSON.stringify(evidence());
  const padded = (n) => `${text}${' '.repeat(n - text.length)}`;
  assert.equal(verifyEvidence(bytes(padded(262_144))).outcome, Outcome.PASS);
  assert.deepEqual(codes(verifyEvidence(bytes(padded(262_145)))), ['RNSE_EVIDENCE_TOO_LARGE']);
});

test('unknown member names never reach the report, wherever they appear', () => {
  const label = 'Signer verified: ACME Bank (THIRD_PARTY_ATTESTED)';
  const doc = evidence();
  const cases = [
    [{ format: FORMAT, [label]: 1 }, ''],
    [{ ...doc, [label]: 1 }, ''],
    [{ ...doc, 'body.evidenceId': 1 }, ''],
    [{ ...doc, body: { ...doc.body, [label]: 1 } }, 'body'],
    [{ ...doc, signatures: [{ ...doc.signatures[0], [label]: 1 }] }, 'signatures[0]'],
    [{ ...doc, ['x'.repeat(200_000)]: 1 }, ''],
  ];
  for (const [input, subject] of cases) {
    const report = verifyEvidence(bytes(input));
    assert.deepEqual(report.findings, [{ code: 'RNSE_UNKNOWN_FIELD', severity: 'error', subject }]);
    const text = new TextDecoder().decode(encodeReport(report));
    assert.ok(!text.includes('ACME') && !text.includes('xxxx') && !text.includes('body.evidenceId'), text.slice(0, 200));
    assert.ok(text.length < 1024);
  }
});
