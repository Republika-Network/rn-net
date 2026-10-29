// Builds vectors/evidence/evidence.json: synthetic rnnet.synthetic-evidence.v1 documents and
// the reports they must produce.
//
//   node tools/vectors/evidence-vectors.mjs           # check the committed file is current
//   node tools/vectors/evidence-vectors.mjs --write   # rewrite it
//
// Test keys are derived from public labels (SHA-256 of "rnnet:synthetic-test-key:v1:<label>")
// every time this runs, so no private key or seed is ever stored. They are test-only by
// construction: anyone can derive them, so they can never stand for an identity.
//
// Each case states its expected outcome and finding codes by hand; the build stops if the
// verifier disagrees. The full expected report is recorded from the verifier and is checked
// independently by tools/reference/rnnet_evidence_reference.py.
import { Buffer } from 'node:buffer';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { computeCommitment } from '../../packages/commitment/src/index.mjs';
import {
  computeEvidenceDigest,
  encodeReport,
  evidenceDigestBytes,
  signingMessage,
  verifyEvidence,
} from '../../packages/verifier/src/index.mjs';

import * as Ed from './ed25519-edge.mjs';

export const OUTPUT = fileURLToPath(new URL('../../vectors/evidence/evidence.json', import.meta.url));

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const keys = new Map();
/** A deterministic, publicly derivable test key pair for a label. */
function testKey(label) {
  if (!keys.has(label)) {
    const derived = createHash('sha256').update(`rnnet:synthetic-test-key:v1:${label}`).digest();
    const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, derived]), format: 'der', type: 'pkcs8' });
    const publicKey = Buffer.from(createPublicKey(privateKey).export({ format: 'jwk' }).x, 'base64url').toString('hex');
    keys.set(label, { privateKey, publicKey });
  }
  return keys.get(label);
}

const BODY = Object.freeze({
  evidenceId: 'synthetic-0001',
  issuer: 'synthetic-issuer.example',
  subject: 'operation:demo-42',
  action: 'synthetic.transfer.simulated',
  outcome: 'succeeded',
  payload: {
    amount: 1250,
    currency: 'TEST',
    note: 'Synthetic test data. It describes no real operation.',
    steps: ['requested', 'approved', 'simulated'],
  },
});
const body = (changes = {}) => ({ ...structuredClone(BODY), ...changes });

/** A signature record by the test key `label` over a body (or explicit message bytes). */
function record(label, keyId, signed, { message } = {}) {
  const key = testKey(label);
  const bytes = message ?? signingMessage(evidenceDigestBytes(signed));
  return { keyId, algorithm: 'ed25519', publicKey: key.publicKey, signature: sign(null, bytes, key.privateKey).toString('hex') };
}

function evidence(b, signatures, overrides = {}) {
  return { format: 'rnnet.synthetic-evidence.v1', canonicalization: 'rnnet.canonical-json.v1', body: b, digest: computeEvidenceDigest(b), signatures, ...overrides };
}
const json = (value) => JSON.stringify(value);
const sha256 = (text) => `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`;

function envelopeFor(evidenceText, changes = {}) {
  const parsed = JSON.parse(evidenceText);
  const envelope = {
    format: 'rnnet.evidence-commitment.v1',
    sourceFormat: 'rnnet.synthetic-evidence.v1',
    sourceCanonicalization: 'rnnet.canonical-json.v1',
    sourceEvidenceDigest: computeEvidenceDigest(parsed.body),
    sourceFileSha256: sha256(evidenceText),
    sourceRef: 'synthetic:fixtures/evidence-0001',
    ...changes,
  };
  return { envelope: json(envelope), digest: computeCommitment(envelope).digest };
}

const nested = (depth) => (depth === 0 ? 'leaf' : { level: nested(depth - 1) });
const signed = (b = body()) => evidence(b, [record('key-a', 'issuer-key-1', b)]);
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

// Ed25519 edge cases (spec §5.3), built with explicit curve arithmetic from label-derived scalars.
function edgeCases() {
  const edgeBody = (n) => body({ payload: { edge: n } });
  const message = (b) => signingMessage(evidenceDigestBytes(b));
  const recordOf = (A, R, S) => ({ keyId: 'edge-key', algorithm: 'ed25519', publicKey: Buffer.from(A).toString('hex'), signature: Buffer.concat([Buffer.from(R), Ed.littleEndian(S)]).toString('hex') });
  const doc = (b, A, R, S) => json(evidence(b, [recordOf(A, R, S)]));
  const primeKey = (label) => {
    const a = Ed.scalar(label);
    return { a, A: Ed.encode(Ed.multiply(a, Ed.BASE)) };
  };
  const offCurveY = (() => { for (let y = 2n; ; y++) if (Ed.xFor(y, 0) === null) return y; })();
  const smallOnCurveY = (() => { for (let y = 2n; y < 19n; y++) if (Ed.xFor(y, 0) !== null) return y; throw new Error('none'); })();
  const out = [];
  const add = (id, description, input, outcome, codes) => out.push({ id, description, input, outcome, codes });

  { // Mixed-order key, R with a torsion part that cancels kT: the cofactorless equation holds.
    const b = edgeBody(1);
    let found;
    for (let t = 0; !found; t++) {
      const a = Ed.scalar(`mixed-valid-a-${t}`);
      const A = Ed.encode(Ed.add(Ed.multiply(a, Ed.BASE), Ed.TORSION8));
      const r = Ed.scalar(`mixed-valid-r-${t}`);
      for (let i = 1n; i < 8n && !found; i++) {
        const torsion = Ed.multiply(i, Ed.TORSION8);
        const R = Ed.encode(Ed.add(Ed.multiply(r, Ed.BASE), torsion));
        const k = Ed.challenge(R, A, message(b));
        if (Ed.equal(Ed.add(torsion, Ed.multiply(k, Ed.TORSION8)), Ed.IDENTITY)) found = { A, R, S: (r + k * a) % Ed.L };
      }
    }
    add('ed25519-mixed-order-key-cofactorless-valid', 'A key with a torsion component and an R whose torsion part cancels it: valid under the cofactorless equation the profile requires.', doc(b, found.A, found.R, found.S), 'PASS', []);
  }
  { // Mixed-order key, honest R: only a cofactored check accepts it.
    const b = edgeBody(2);
    let found;
    for (let t = 0; !found; t++) {
      const a = Ed.scalar(`mixed-cofactored-a-${t}`);
      const A = Ed.encode(Ed.add(Ed.multiply(a, Ed.BASE), Ed.TORSION8));
      const r = Ed.scalar(`mixed-cofactored-r-${t}`);
      const R = Ed.encode(Ed.multiply(r, Ed.BASE));
      const k = Ed.challenge(R, A, message(b));
      if (!Ed.equal(Ed.multiply(k, Ed.TORSION8), Ed.IDENTITY)) found = { A, R, S: (r + k * a) % Ed.L };
    }
    add('ed25519-mixed-order-key-cofactored-only', 'A signature that only a cofactored check accepts (mixed-order key): invalid under this profile.', doc(b, found.A, found.R, found.S), 'FAIL', ['RNSE_SIGNATURE_INVALID']);
  }
  { // Prime-order key, R with a torsion component: only a cofactored check accepts it.
    const b = edgeBody(3);
    const { a, A } = primeKey('torsion-r-key');
    const r = Ed.scalar('torsion-r-nonce');
    const R = Ed.encode(Ed.add(Ed.multiply(r, Ed.BASE), Ed.TORSION8));
    const k = Ed.challenge(R, A, message(b));
    add('ed25519-torsion-r-cofactored-only', 'R carries a torsion component: only a cofactored check accepts it; invalid under this profile.', doc(b, A, R, (r + k * a) % Ed.L), 'FAIL', ['RNSE_SIGNATURE_INVALID']);
  }
  { // R = identity: canonical encoding is valid, non-canonical and negative-zero encodings are not.
    const { a, A } = primeKey('identity-r-key');
    const forms = [
      ['ed25519-r-identity-canonical', 'R is the identity, canonically encoded, with S = k*a: valid under the cofactorless equation.', Ed.littleEndian(1n), 'PASS', []],
      ['ed25519-r-identity-non-canonical', 'R is the identity encoded with y = p + 1: rejected, though a permissive decoder would reduce it and accept.', Ed.littleEndian(Ed.P + 1n), 'FAIL', ['RNSE_SIGNATURE_INVALID']],
      ['ed25519-r-identity-negative-zero', 'R is the identity with the sign bit set (x = 0): not a valid encoding.', (() => { const r = Ed.littleEndian(1n); r[31] |= 0x80; return r; })(), 'FAIL', ['RNSE_SIGNATURE_INVALID']],
    ];
    forms.forEach(([id, description, R, outcome, codes], i) => {
      const b = edgeBody(10 + i);
      add(id, description, doc(b, A, R, (Ed.challenge(R, A, message(b)) * a) % Ed.L), outcome, codes);
    });
  }
  {
    const b = edgeBody(20);
    const { A } = primeKey('off-curve-r-key');
    add('ed25519-r-off-curve', 'R is not a point on the curve.', doc(b, A, Ed.littleEndian(offCurveY), 1n), 'FAIL', ['RNSE_SIGNATURE_INVALID']);
  }
  const R = Ed.encode(Ed.BASE);
  const keyCases = [
    ['ed25519-key-negative-zero', 'Public key with x = 0 and the sign bit set.', (() => { const k = Ed.littleEndian(1n); k[31] |= 0x80; return k; })()],
    ['ed25519-key-off-curve', 'Public key not on the curve.', Ed.littleEndian(offCurveY)],
    ['ed25519-key-non-canonical-on-curve', 'An on-curve public key encoded with y + p.', Ed.littleEndian(Ed.P + smallOnCurveY)],
    ['ed25519-key-order-8', 'A public key of order 8.', Ed.encode(Ed.TORSION8)],
  ];
  keyCases.forEach(([id, description, A], i) => add(id, description, doc(edgeBody(30 + i), A, R, 1n), 'FAIL', ['RNSE_PUBLIC_KEY_REJECTED']));
  return out;
}

function cases() {
  const base = signed();
  const baseText = json(base);
  const multi = body();
  const nfc = body({ payload: { note: 'caf\u00e9' } });
  const nfd = body({ payload: { note: 'cafe\u0301' } });
  const tamper = (changes) => json({ ...base, body: body(changes) });
  const withRecord = (changes) => json({ ...base, signatures: [{ ...base.signatures[0], ...changes }] });
  const high = (() => {
    const signature = Buffer.from(base.signatures[0].signature, 'hex');
    let s = 0n;
    for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(signature[i]);
    s += L;
    for (let i = 32; i < 64; i++, s >>= 8n) signature[i] = Number(s & 0xffn);
    return signature.toString('hex');
  })();
  const badSignature = json({ ...base, signatures: [record('key-a', 'issuer-key-1', body({ outcome: 'failed' }))] });
  const seventeen = Array.from({ length: 17 }, (_, i) => record(`bulk-${i}`, `key-${String(i).padStart(2, '0')}`, body()));

  return [
    // --- valid ----------------------------------------------------------------------------
    { id: 'valid-one-signature', description: 'One Ed25519 signature; signer identity stays UNRESOLVED.', input: baseText, outcome: 'PASS', codes: [] },
    {
      id: 'valid-multiple-signatures',
      description: 'Three signatures in keyId order; several self-asserted keys are still not an identity.',
      input: json(evidence(multi, [record('key-a', 'issuer-key-1', multi), record('key-b', 'issuer-key-2', multi), record('key-c', 'witness-key', multi)])),
      outcome: 'PASS',
      codes: [],
    },
    { id: 'valid-no-signatures', description: 'No signatures: integrity only; nothing is known about the producer.', input: json(evidence(body(), [])), outcome: 'PASS', codes: [] },
    {
      id: 'valid-equivalent-serialization',
      description: 'The same document with other member order and whitespace: same digest and signature results.',
      input: `{ "signatures": ${JSON.stringify(base.signatures, null, 2)},\n "digest": "${base.digest}", "body": {"payload": ${json(BODY.payload)}, "outcome": "succeeded", "action": "synthetic.transfer.simulated", "subject": "operation:demo-42", "issuer": "synthetic-issuer.example", "evidenceId": "synthetic-0001"},\n "canonicalization": "rnnet.canonical-json.v1", "format": "rnnet.synthetic-evidence.v1" }\n`,
      outcome: 'PASS',
      codes: [],
    },
    {
      id: 'valid-nested-payload',
      description: 'A payload nested to the depth the canonical profile allows, with null, arrays and Unicode text.',
      input: json(signed(body({ payload: { tree: nested(55), list: [3, 1, 2, null, true], text: 'Gr\u00fc\u00dfe \u{1F600}' } }))),
      outcome: 'PASS',
      codes: [],
    },
    { id: 'valid-payload-nfc', description: 'Payload text in NFC.', input: json(signed(nfc)), outcome: 'PASS', codes: [] },
    { id: 'valid-payload-nfd', description: 'The same text in NFD: valid, with a different digest; no normalization is applied.', input: json(signed(nfd)), outcome: 'PASS', codes: [] },
    { id: 'valid-with-commitment', description: 'A matching rnnet.evidence-commitment.v1 commitment.', input: baseText, commitment: envelopeFor(baseText), outcome: 'PASS', codes: [] },
    {
      id: 'valid-signer-substitution',
      description: 'An attacker re-signs the same digest under its own key and reuses the keyId: the signature is consistent under the attacker key, and signer identity stays UNRESOLVED.',
      input: json(evidence(body(), [record('attacker', 'issuer-key-1', body())])),
      outcome: 'PASS',
      codes: [],
    },

    // --- tampering and signature failures ---------------------------------------------------
    { id: 'tampered-payload', description: 'Payload changed after signing.', input: tamper({ payload: { ...BODY.payload, amount: 999999 } }), outcome: 'FAIL', codes: ['RNSE_DIGEST_MISMATCH', 'RNSE_SIGNATURE_INVALID'] },
    { id: 'tampered-outcome', description: 'Claimed outcome changed after signing.', input: tamper({ outcome: 'failed' }), outcome: 'FAIL', codes: ['RNSE_DIGEST_MISMATCH', 'RNSE_SIGNATURE_INVALID'] },
    { id: 'tampered-issuer', description: 'Issuer claim changed after signing.', input: tamper({ issuer: 'other-issuer.example' }), outcome: 'FAIL', codes: ['RNSE_DIGEST_MISMATCH', 'RNSE_SIGNATURE_INVALID'] },
    {
      id: 'tampered-payload-normalization',
      description: 'Payload text re-normalized from NFC to NFD under the NFC digest and signature.',
      input: json({ ...signed(nfc), body: nfd }),
      outcome: 'FAIL',
      codes: ['RNSE_DIGEST_MISMATCH', 'RNSE_SIGNATURE_INVALID'],
    },
    {
      id: 'incorrect-digest',
      description: 'A well-formed but wrong digest over an intact body: the signature still verifies over the recomputed digest, and the document fails.',
      input: json({ ...base, digest: sha256('something else') }),
      outcome: 'FAIL',
      codes: ['RNSE_DIGEST_MISMATCH'],
    },
    {
      id: 'digest-over-whole-document',
      description: 'A digest computed over the whole document instead of the body.',
      input: json({ ...base, digest: sha256(json({ ...base, digest: '' })) }),
      outcome: 'FAIL',
      codes: ['RNSE_DIGEST_MISMATCH'],
    },
    {
      id: 'wrong-signing-domain',
      description: 'Signed over the commitment domain separator instead of the signature domain.',
      input: json(evidence(body(), [record('key-a', 'issuer-key-1', null, { message: Uint8Array.from([...Buffer.from('rnnet:evidence-commitment:v1\0', 'latin1'), ...evidenceDigestBytes(body())]) })])),
      outcome: 'FAIL',
      codes: ['RNSE_SIGNATURE_INVALID'],
    },
    {
      id: 'signature-over-plain-digest',
      description: 'Signed over the raw digest bytes with no domain separator (cross-protocol replay).',
      input: json(evidence(body(), [record('key-a', 'issuer-key-1', null, { message: evidenceDigestBytes(body()) })])),
      outcome: 'FAIL',
      codes: ['RNSE_SIGNATURE_INVALID'],
    },
    { id: 'wrong-public-key', description: 'Signature by key-a, presented with key-b.', input: withRecord({ publicKey: testKey('key-b').publicKey }), outcome: 'FAIL', codes: ['RNSE_SIGNATURE_INVALID'] },
    { id: 'wrong-signature', description: 'A signature over a different body.', input: badSignature, outcome: 'FAIL', codes: ['RNSE_SIGNATURE_INVALID'] },
    { id: 'signature-s-not-reduced', description: 'The valid signature with L added to S (malleability).', input: withRecord({ signature: high }), outcome: 'FAIL', codes: ['RNSE_SIGNATURE_INVALID'] },
    { id: 'public-key-small-order', description: 'The neutral element as public key.', input: withRecord({ publicKey: `01${'00'.repeat(31)}` }), outcome: 'FAIL', codes: ['RNSE_PUBLIC_KEY_REJECTED'] },
    { id: 'public-key-non-canonical', description: 'A public key whose y is not reduced modulo p.', input: withRecord({ publicKey: `ee${'ff'.repeat(30)}7f` }), outcome: 'FAIL', codes: ['RNSE_PUBLIC_KEY_REJECTED'] },
    {
      id: 'one-of-two-signatures-invalid',
      description: 'A valid and an invalid signature: the invalid one is reported, and the document fails.',
      input: json(evidence(multi, [record('key-a', 'issuer-key-1', multi), { ...record('key-b', 'issuer-key-2', multi), signature: base.signatures[0].signature }])),
      outcome: 'FAIL',
      codes: ['RNSE_SIGNATURE_INVALID'],
    },

    // --- malformed and unsupported ------------------------------------------------------------
    { id: 'truncated-signature', description: 'A signature of 63 bytes.', input: withRecord({ signature: base.signatures[0].signature.slice(0, 126) }), outcome: 'FAIL', codes: ['RNSE_INVALID_SIGNATURE_ENCODING'] },
    { id: 'public-key-uppercase-hex', description: 'Public key in uppercase hex.', input: withRecord({ publicKey: base.signatures[0].publicKey.toUpperCase() }), outcome: 'FAIL', codes: ['RNSE_INVALID_PUBLIC_KEY_ENCODING'] },
    {
      id: 'duplicate-key-id',
      description: 'Two records with the same keyId.',
      input: json(evidence(multi, [record('key-a', 'issuer-key-1', multi), record('key-b', 'issuer-key-1', multi)])),
      outcome: 'FAIL',
      codes: ['RNSE_DUPLICATE_KEY_ID'],
    },
    {
      id: 'duplicate-public-key',
      description: 'The same public key under two keyIds.',
      input: json(evidence(multi, [record('key-a', 'issuer-key-1', multi), record('key-a', 'issuer-key-2', multi)])),
      outcome: 'FAIL',
      codes: ['RNSE_DUPLICATE_PUBLIC_KEY'],
    },
    {
      id: 'signatures-reordered',
      description: 'Valid records in descending keyId order.',
      input: json(evidence(multi, [record('key-b', 'issuer-key-2', multi), record('key-a', 'issuer-key-1', multi)])),
      outcome: 'FAIL',
      codes: ['RNSE_SIGNATURES_NOT_SORTED'],
    },
    { id: 'too-many-signatures', description: 'Seventeen signature records.', input: json(evidence(body(), seventeen)), outcome: 'FAIL', codes: ['RNSE_TOO_MANY_SIGNATURES'] },
    {
      id: 'duplicate-json-keys',
      description: 'The body has two issuer members.',
      input: baseText.replace('"issuer":"synthetic-issuer.example"', '"issuer":"synthetic-issuer.example","issuer":"other-issuer.example"'),
      outcome: 'FAIL',
      codes: ['RNCJ_DUPLICATE_KEY'],
    },
    { id: 'unsupported-signature-algorithm', description: 'A record declaring another algorithm.', input: withRecord({ algorithm: 'ecdsa-p256' }), outcome: 'UNSUPPORTED', codes: ['RNSE_UNSUPPORTED_SIGNATURE_ALGORITHM'] },
    { id: 'unsupported-canonicalization', description: 'Another canonicalization profile.', input: json({ ...base, canonicalization: 'rfc8785' }), outcome: 'UNSUPPORTED', codes: ['RNSE_UNSUPPORTED_CANONICALIZATION'] },
    { id: 'unsupported-format', description: 'Another source format.', input: json({ ...base, format: 'example.evidence-bundle.v1' }), outcome: 'UNSUPPORTED', codes: ['RNSE_UNSUPPORTED_FORMAT'] },
    {
      id: 'unsupported-version',
      description: 'A later version with a member v1 does not know: the version is reported, not the member.',
      input: json({ ...base, format: 'rnnet.synthetic-evidence.v2', timestamp: 'claimed' }),
      outcome: 'UNSUPPORTED',
      codes: ['RNSE_UNSUPPORTED_VERSION'],
    },
    { id: 'unsupported-digest-algorithm', description: 'A sha512 digest.', input: json({ ...base, digest: `sha512:${'ab'.repeat(64)}` }), outcome: 'UNSUPPORTED', codes: ['RNSE_UNSUPPORTED_DIGEST_ALGORITHM'] },
    { id: 'invalid-digest-uppercase', description: 'Digest in uppercase hex.', input: json({ ...base, digest: base.digest.toUpperCase().replace('SHA256', 'sha256') }), outcome: 'FAIL', codes: ['RNSE_INVALID_DIGEST'] },
    {
      id: 'oversized-evidence',
      description: 'A document of more than 262,144 bytes.',
      inputPattern: { prefix: baseText.slice(0, -1) + ',"padding":"', repeat: 'x', count: 262_144, suffix: '"}' },
      outcome: 'FAIL',
      codes: ['RNSE_EVIDENCE_TOO_LARGE'],
    },
    { id: 'payload-too-large', description: 'A payload over 65,536 canonical bytes.', input: json(signed(body({ payload: { blob: 'x'.repeat(70_000) } }))), outcome: 'FAIL', codes: ['RNSE_PAYLOAD_TOO_LARGE'] },
    { id: 'excessive-nesting', description: 'Payload nested beyond the canonical depth limit.', input: json({ ...base, body: body({ payload: { tree: nested(70) } }) }), outcome: 'FAIL', codes: ['RNCJ_DEPTH_EXCEEDED'] },
    {
      id: 'missing-outcome',
      description: 'body.outcome absent.',
      input: json({ ...base, body: Object.fromEntries(Object.entries(body()).filter(([k]) => k !== 'outcome')) }),
      outcome: 'FAIL',
      codes: ['RNSE_MISSING_FIELD'],
    },
    { id: 'unknown-top-level-field', description: 'A member outside the closed document.', input: json({ ...base, note: 'extra' }), outcome: 'FAIL', codes: ['RNSE_UNKNOWN_FIELD'] },
    {
      id: 'digest-inside-body',
      description: 'An attempt to put the digest and signatures inside the signed body (circularity).',
      input: json({ ...base, body: { ...body(), digest: base.digest, signatures: [] } }),
      outcome: 'FAIL',
      codes: ['RNSE_UNKNOWN_FIELD'],
    },
    { id: 'body-null', description: 'body is null.', input: json({ ...base, body: null }), outcome: 'FAIL', codes: ['RNSE_FIELD_TYPE'] },
    { id: 'not-an-object', description: 'A JSON array.', input: '[]', outcome: 'FAIL', codes: ['RNSE_NOT_OBJECT'] },
    { id: 'not-json', description: 'Script text, not JSON.', input: 'import("node:net")', outcome: 'FAIL', codes: ['RNCJ_SYNTAX'] },
    {
      id: 'malformed-utf8',
      description: 'A lone UTF-8 lead byte (0xC3) inside a string.',
      inputHex: (() => {
        const bytes = Buffer.from(baseText, 'utf8');
        bytes[bytes.indexOf('demo-42') + 6] = 0xc3;
        return bytes.toString('hex');
      })(),
      outcome: 'FAIL',
      codes: ['RNCJ_INVALID_UTF8'],
    },
    { id: 'issuer-look-alike', description: 'An issuer with a Cyrillic letter in place of a Latin one.', input: json(signed(body({ issuer: 'synthetic-issu\u0435r.example' }))), outcome: 'FAIL', codes: ['RNSE_INVALID_FIELD_VALUE'] },
    {
      id: 'unknown-member-name-not-echoed',
      description: 'An unknown body member whose name imitates a trust label: reported by its containing object, and its name never reaches the report.',
      input: json({ ...base, body: { ...body(), 'Signer verified: ACME Bank (THIRD_PARTY_ATTESTED)': 1 } }),
      outcome: 'FAIL',
      codes: ['RNSE_UNKNOWN_FIELD'],
    },
    ...edgeCases(),
    { id: 'invalid-outcome', description: 'An outcome outside the defined set.', input: json(signed(body({ outcome: 'SUCCEEDED' }))), outcome: 'FAIL', codes: ['RNSE_INVALID_FIELD_VALUE'] },

    // --- commitment ----------------------------------------------------------------------------
    {
      id: 'commitment-invalid-presented-digest',
      description: 'A presented commitment that is not a sha256 digest.',
      input: baseText,
      commitment: { ...envelopeFor(baseText), digest: 'sha256:XYZ' },
      outcome: 'FAIL',
      codes: ['RNEC_INVALID_COMMITMENT_DIGEST'],
    },
    {
      id: 'commitment-digest-mismatch',
      description: 'A valid envelope presented with another commitment.',
      input: baseText,
      commitment: { ...envelopeFor(baseText), digest: sha256('other') },
      outcome: 'FAIL',
      codes: ['RNEC_DIGEST_MISMATCH'],
    },
    {
      id: 'commitment-source-file-mismatch',
      description: 'The envelope commits to another file; the commitment itself verifies.',
      input: baseText,
      commitment: envelopeFor(baseText, { sourceFileSha256: sha256('another file') }),
      outcome: 'FAIL',
      codes: ['RNSE_COMMITMENT_SOURCE_FILE_MISMATCH'],
    },
    {
      id: 'commitment-evidence-digest-mismatch',
      description: 'The envelope commits to another evidence digest and another format.',
      input: baseText,
      commitment: envelopeFor(baseText, { sourceEvidenceDigest: sha256('other'), sourceFormat: 'example.evidence-bundle.v1' }),
      outcome: 'FAIL',
      codes: ['RNSE_COMMITMENT_SOURCE_FORMAT_MISMATCH', 'RNSE_COMMITMENT_EVIDENCE_DIGEST_MISMATCH'],
    },
    {
      id: 'commitment-to-stale-declared-digest',
      description: 'Tampered evidence with a commitment to its declared (stale) digest: the commitment is compared with the recomputed digest, not the declared one.',
      input: tamper({ outcome: 'failed' }),
      commitment: envelopeFor(tamper({ outcome: 'failed' }), { sourceEvidenceDigest: base.digest }),
      outcome: 'FAIL',
      codes: ['RNSE_DIGEST_MISMATCH', 'RNSE_SIGNATURE_INVALID', 'RNSE_COMMITMENT_EVIDENCE_DIGEST_MISMATCH'],
    },
    {
      id: 'commitment-matches-signature-fails',
      description: 'The commitment matches the evidence exactly, and the signature still fails.',
      input: badSignature,
      commitment: envelopeFor(badSignature),
      outcome: 'FAIL',
      codes: ['RNSE_SIGNATURE_INVALID'],
    },
    {
      id: 'commitment-envelope-malformed',
      description: 'An envelope that is not JSON.',
      input: baseText,
      commitment: { envelope: '{"format":', digest: sha256('x') },
      outcome: 'FAIL',
      codes: ['RNCJ_SYNTAX'],
    },
    {
      id: 'commitment-untrusted-source-ref',
      description: 'A sourceRef that looks executable: reported as given, UNRESOLVED, never dereferenced.',
      input: baseText,
      commitment: envelopeFor(baseText, { sourceRef: 'javascript:alert(document.cookie)' }),
      outcome: 'PASS',
      codes: [],
    },
    {
      id: 'commitment-source-ref-invalid',
      description: 'A sourceRef with a space, rejected by the commitment format.',
      input: baseText,
      commitment: (() => {
        const envelope = JSON.parse(envelopeFor(baseText).envelope);
        envelope.sourceRef = 'synthetic:has space';
        return { envelope: json(envelope), digest: sha256('x') };
      })(),
      outcome: 'FAIL',
      codes: ['RNEC_INVALID_SOURCE_REF'],
    },
  ];
}

/** The exact bytes of a vector's input. */
export function vectorInputBytes(vector) {
  if (Object.hasOwn(vector, 'inputHex')) return Uint8Array.from(Buffer.from(vector.inputHex, 'hex'));
  if (Object.hasOwn(vector, 'inputPattern')) {
    const { prefix, repeat, count, suffix } = vector.inputPattern;
    return new TextEncoder().encode(prefix + repeat.repeat(count) + suffix);
  }
  return new TextEncoder().encode(vector.input);
}

export function buildEvidenceVectors() {
  const vectors = cases().map(({ outcome, codes, commitment, ...vector }) => {
    const options = commitment ? { commitment: { envelope: new TextEncoder().encode(commitment.envelope), digest: commitment.digest } } : {};
    const report = verifyEvidence(vectorInputBytes(vector), options);
    const found = report.findings.map((f) => f.code);
    if (report.outcome !== outcome || JSON.stringify(found) !== JSON.stringify(codes)) {
      throw new Error(`${vector.id}: expected ${outcome} ${codes}, verifier gave ${report.outcome} ${found}`);
    }
    return {
      ...vector,
      ...(commitment ? { commitment } : {}),
      expectedOutcome: outcome,
      expectedFindings: codes,
      expectedReport: new TextDecoder().decode(encodeReport(report)),
    };
  });
  return {
    format: 'rnnet.conformance-vectors.v1',
    profile: 'rnnet.synthetic-evidence.v1',
    kind: 'evidence-verification',
    vectors,
  };
}

const serialize = (file) => `${JSON.stringify(file, null, 2)}\n`;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = serialize(buildEvidenceVectors());
  if (process.argv.includes('--write')) writeFileSync(OUTPUT, text);
  else if (readFileSync(OUTPUT, 'utf8') !== text) {
    console.error('vectors/evidence/evidence.json is out of date; run with --write');
    process.exitCode = 1;
  }
}
export { serialize };
