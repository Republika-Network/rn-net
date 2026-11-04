// RN-NET-03B2-B1: public known-answer vectors, the committed signing fixtures and their altered
// copies, the broadcaster hand-off interface, and the isolation rules. Offline only.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  addressFromPublicKey,
  decodeAddress,
  decodeEip1559Signed,
  encodeAddress,
  encodeEip1559Unsigned,
  encodeNativeAmount,
  encodeVL,
  fieldHeader,
  TxError,
  XRPL_FIELD_CODES,
  xrplTxHash,
} from '../packages/tx-intent/src/index.mjs';
import { createHash } from 'node:crypto';
import { checkHandoff } from '../packages/broadcast-handoff/src/index.mjs';
import { canonicalBytes } from '../packages/canonical/src/index.mjs';
import { INTENT_DIGEST_DOMAIN } from '../packages/tx-intent/src/index.mjs';
import { createSigner } from '../signer/src/sign.mjs';
import { fixtureKey } from '../signer/test/fixture-keys.mjs';
import { cases as s1Cases } from './s1/build-s1-cases.mjs';
import { keccak256, secp256k1RecoverAddress, secp256k1SignDigest } from '../signer/src/crypto.mjs';
import { verifySignedTransaction } from '../txverify/src/index.mjs';
import { check } from './guards/dependency-boundaries.mjs';
import { build, DIR, FILES } from './signing/build-b1-fixtures.mjs';

const kat = JSON.parse(readFileSync(new URL('../vectors/signing/known-answers.json', import.meta.url), 'utf8'));
const golden = JSON.parse(readFileSync(`${DIR}golden.json`, 'utf8'));
const intentOf = (name) => JSON.parse(readFileSync(DIR + golden.signed[name].intentFile, 'utf8'));
const code = (fn) => {
  try {
    fn();
  } catch (error) {
    assert.ok(error instanceof TxError, `not a TxError: ${error}`);
    return error.code;
  }
  return null;
};
const big = (hex) => BigInt(hex);

test('the committed signing fixtures are exactly what the generator builds', () => {
  const built = build();
  for (const name of FILES) assert.ok(readFileSync(DIR + name).equals(built[name]), name);
});

test('Keccak-256 known answers (and it is not SHA3-256)', () => {
  for (const v of kat.keccak256) assert.equal(keccak256(Buffer.from(v.input, 'utf8')).toString('hex'), v.expected);
  assert.notEqual(keccak256(Buffer.alloc(0)).toString('hex'), 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
});

test('EIP-155 known answer: signing hash, deterministic r and s, recovery id and sender', () => {
  const e = kat.eip155;
  const digest = keccak256(Buffer.from(e.signingDataHex.slice(2), 'hex'));
  assert.equal(`0x${digest.toString('hex')}`, e.signingHash);
  const key = Uint8Array.from(Buffer.from(e.keyByteRepeated32.repeat(32), 'hex'));
  const sig = secp256k1SignDigest(key, digest);
  assert.equal(sig.r, big(e.r));
  assert.equal(sig.s, big(e.s));
  assert.equal(sig.yParity, BigInt(e.recoveryId));
  assert.equal(e.v, 35 + 2 * 1 + e.recoveryId);
  assert.equal(secp256k1RecoverAddress(digest, sig), e.sender);
});

test('EIP-1559 known answers (ethers): decode, unsigned preimage, signature and sender', () => {
  for (const v of kat.eip1559) {
    const { transaction, signature, unsigned } = decodeEip1559Signed(Buffer.from(v.signedHex.slice(2), 'hex'));
    assert.deepEqual(transaction, v.transaction, v.id);
    assert.equal(`0x${unsigned.toString('hex')}`, v.unsignedHex, v.id);
    assert.equal(`0x${encodeEip1559Unsigned(v.transaction).toString('hex')}`, v.unsignedHex, v.id);
    assert.deepEqual(signature, { yParity: BigInt(v.signature.yParity), r: big(v.signature.r), s: big(v.signature.s) }, v.id);
    assert.equal(secp256k1RecoverAddress(keccak256(unsigned), signature), v.sender, v.id);
  }
});

test('EIP-1559 invalid vectors (ethereum/tests): leading zeros are refused', () => {
  for (const v of kat.eip1559Invalid) assert.equal(code(() => decodeEip1559Signed(Buffer.from(v.txbytes.slice(2), 'hex'))), v.expectedCode, v.id);
});

test('XRPL official fixtures (ripple-binary-codec): field codes, headers, amounts, addresses', () => {
  for (const h of kat.xrplFieldHeaders) {
    assert.deepEqual(XRPL_FIELD_CODES[h.field].slice(0, 2), [h.type, h.nth], h.field);
    assert.equal(fieldHeader(h.type, h.nth).toString('hex').toUpperCase(), h.expectedHex, h.field);
  }
  for (const a of kat.xrplNativeAmounts) assert.equal(encodeNativeAmount(a.drops).toString('hex').toUpperCase(), a.expectedHex);
  for (const a of kat.xrplAddresses) {
    assert.equal(decodeAddress(a.address).toString('hex').toUpperCase(), a.accountIdHex);
    assert.equal(encodeAddress(Buffer.from(a.accountIdHex, 'hex')), a.address);
  }
});

test('XRPL official signing blob and transaction hash (ripple-binary-codec) from the codec primitives', () => {
  const v = kat.xrplSigningBlob;
  const codes = { ...Object.fromEntries(Object.entries(XRPL_FIELD_CODES).map(([k, c]) => [k, c.slice(0, 2)])), ...v.extraFields };
  const parts = [Buffer.from('53545800', 'hex')];
  for (const [name, value] of v.fields) {
    const head = fieldHeader(...codes[name]);
    if (name === 'Account' || name === 'Destination') parts.push(head, encodeVL(20), decodeAddress(value));
    else if (name === 'SigningPubKey') parts.push(head, encodeVL(value.length / 2), Buffer.from(value, 'hex'));
    else parts.push(head, Buffer.from(value, 'hex'));
  }
  assert.equal(Buffer.concat(parts).toString('hex').toUpperCase(), v.expectedHex);
  assert.equal(addressFromPublicKey(Buffer.from(v.json.SigningPubKey, 'hex')), v.json.Account);
  assert.equal(xrplTxHash(Buffer.from(kat.xrplTxHash.blobHex, 'hex')), kat.xrplTxHash.expectedHash);
});

test('both committed signed transactions verify (PASS) and match their records', () => {
  for (const name of ['xrpl', 'sepolia']) {
    const s = golden.signed[name];
    const record = verifySignedTransaction({ intent: intentOf(name), approvedDigest: s.intentDigest, signedTransaction: s.signedTransaction });
    assert.deepEqual(record, s.verification);
    assert.equal(record.outcome, 'PASS');
  }
  assert.ok(golden.status.startsWith('SYNTHETIC'));
});

test('every altered transaction fails with its stated code, and the record matches', () => {
  assert.ok(golden.negative.length >= 40);
  const needed = ['RNTX_WRONG_CHAIN', 'RNTX_NONCE_MISMATCH', 'RNTX_FEE_MISMATCH', 'RNTX_PAYLOAD_MISMATCH', 'RNTX_FIELD_MISMATCH', 'RNTX_SENDER_MISMATCH', 'RNTX_SIGNATURE_INVALID', 'RNTX_HIGH_S', 'RNTX_INTENT_DIGEST_MISMATCH'];
  for (const c of needed) assert.ok(golden.negative.some((n) => n.expectedCode === c), c);
  for (const n of golden.negative) {
    const record = verifySignedTransaction({ intent: n.intent, approvedDigest: n.approvedDigest, signedTransaction: n.signedTransaction });
    assert.equal(record.code, n.expectedCode, n.id);
    assert.deepEqual(record, n.expectedVerification, n.id);
  }
});

test('the broadcaster hand-off accepts only the verified blob with two identical PASS records', () => {
  for (const name of ['xrpl', 'sepolia']) {
    const s = golden.signed[name];
    const base = { intent: intentOf(name), approvedDigest: s.intentDigest, signedTransaction: s.signedTransaction, verifications: [s.verification, { ...s.verification }] };
    assert.equal(checkHandoff(base).blobSha256, s.blobSha256);
    assert.equal(code(() => checkHandoff({ ...base, verifications: [s.verification] })), 'RNTX_HANDOFF_INVALID');
    assert.equal(code(() => checkHandoff({ ...base, verifications: [s.verification, { ...s.verification, transactionHash: 'x' }] })), 'RNTX_HANDOFF_INVALID');
    const failed = { ...s.verification, outcome: 'FAIL', code: 'RNTX_SIGNATURE_INVALID' };
    assert.equal(code(() => checkHandoff({ ...base, verifications: [failed, failed] })), 'RNTX_HANDOFF_NOT_PASS');
    const other = golden.negative.find((n) => n.id.startsWith(name === 'xrpl' ? 'xrpl-fee-changed' : 'sepolia-nonce-changed'));
    assert.equal(code(() => checkHandoff({ ...base, signedTransaction: other.signedTransaction })), 'RNTX_HANDOFF_BLOB_MISMATCH');
    // A forged record for the altered blob still fails: the hand-off decodes and compares itself.
    const forged = { ...s.verification, blobSha256: other.expectedVerification.blobSha256 };
    assert.equal(code(() => checkHandoff({ ...base, signedTransaction: other.signedTransaction, verifications: [forged, forged] })), other.expectedCode);
    assert.equal(code(() => checkHandoff({ ...base, approvedDigest: other.expectedVerification.intentDigest.replace(/.$/, '0') })), 'RNTX_INTENT_DIGEST_MISMATCH');
  }
});

const rules = (path, content) => check([{ path, content }]).map((f) => f.rule);

test('isolation: the signer cannot reach the network, the live transport, files or a CLI', () => {
  assert.deepEqual(rules('signer/src/x.mjs', "import { httpsTransport } from '../../tools/live/https-transport.mjs';"), ['signer-import-not-allowed:tools/live/https-transport.mjs']);
  assert.deepEqual(rules('signer/src/x.mjs', "import { call } from '../../packages/chain-readonly/src/index.mjs';"), ['signer-import-not-allowed:packages/chain-readonly/src/index.mjs']);
  for (const mod of ['node:https', 'node:net', 'node:fs', 'node:readline', 'node:child_process']) {
    assert.ok(rules('signer/src/x.mjs', `import x from '${mod}';`).includes(`builtin-not-allowed:${mod}`), mod);
  }
  assert.ok(rules('signer/src/x.mjs', 'const a = process.argv;').includes('process-access'));
  assert.ok(rules('signer/src/x.mjs', "const r = await fetch('https://example.org');").length > 0);
  assert.deepEqual(rules('signer/src/x.mjs', "import { keccak_256 } from '@noble/hashes/sha3.js';"), []);
  assert.deepEqual(rules('signer/src/x.mjs', "import { x } from '@noble/hashes/legacy.js';"), ['third-party-import:@noble/hashes/legacy.js']);
  assert.deepEqual(rules('signer/package.json', JSON.stringify({ dependencies: { '@noble/curves': '2.4.0', '@noble/hashes': '2.4.0' }, bin: { s: 'x' } })), ['signer-manifest-field-not-allowed:bin']);
});

test('isolation: the broadcaster and packages cannot reach the signer or its libraries', () => {
  assert.deepEqual(rules('packages/broadcast-handoff/src/x.mjs', "import { createSigner } from '../../../signer/src/sign.mjs';"), ['import-outside-packages']);
  assert.deepEqual(rules('packages/broadcast-handoff/src/x.mjs', "import { sign } from 'node:crypto';"), ['builtin-export-not-allowed:node:crypto#sign']);
  assert.deepEqual(rules('packages/broadcast-handoff/src/x.mjs', "import { createPrivateKey } from 'node:crypto';"), ['builtin-export-not-allowed:node:crypto#createPrivateKey']);
  assert.deepEqual(rules('packages/tx-intent/src/x.mjs', "import { secp256k1 } from '@noble/curves/secp256k1.js';"), ['third-party-import:@noble/curves/secp256k1.js']);
  assert.deepEqual(rules('tools/live/x.mjs', "import { createSigner } from '../../signer/src/sign.mjs';"), ['signer-importer-not-allowed']);
  // A bare library specifier in tools/ also makes the file network-capable (RN-NET-03B2-C2).
  assert.deepEqual(rules('tools/verify-live-anchor.mjs', "import { keccak_256 } from '@noble/hashes/sha3.js';"), ['signer-library-outside-signer', 'network-capable-file-not-allowed:module-bare:@noble/hashes/sha3.js']);
  assert.deepEqual(rules('tools/signing/build-b1-fixtures.mjs', "import { createSigner } from '../../signer/src/sign.mjs';"), []);
});

test('RN-NET S1: the signer refuses an unsupported preparation, with a correctly recomputed digest, before any signature', () => {
  const s1 = Object.fromEntries(s1Cases().map((c) => [c.id, c]));
  const base = intentOf('sepolia');
  const raw = (intent) => `sha256:${createHash('sha256').update(INTENT_DIGEST_DOMAIN).update(canonicalBytes(intent)).digest('hex')}`;
  const key = fixtureKey('evm:11155111', 'rn-net-03b2b1-sepolia-1');
  for (const id of ['v2-record', 'v9-record', 'v1-with-gas', 'synthetic-with-format']) {
    const intent = { ...base, preparation: s1[id].preparation };
    assert.equal(code(() => createSigner().sign(intent, raw(intent), key)), 'RNTX_INTENT_INVALID', id);
  }
  // The historical synthetic intent still signs to its golden bytes.
  assert.equal(createSigner().sign(base, golden.signed.sepolia.intentDigest, key).signedTransaction, golden.signed.sepolia.signedTransaction);
});

test('RN-NET WP3-R1: the signer refuses a v2 candidate as itself and relabelled as an intent', () => {
  const v2 = JSON.parse(readFileSync(new URL('../fixtures/preparation-v2/cases.json', import.meta.url), 'utf8'));
  const { candidate, digest } = v2.preparations.find((c) => c.id === 'amsterdam-pass-estimate-14847').expected;
  const raw = (value) => `sha256:${createHash('sha256').update(INTENT_DIGEST_DOMAIN).update(canonicalBytes(value)).digest('hex')}`;
  const key = fixtureKey('evm:11155111', 'rn-net-03b2b1-sepolia-1');
  const relabelled = { ...candidate, format: 'rnnet.unsigned-tx-intent.v1' };
  assert.equal(code(() => createSigner().sign(candidate, digest, key)), 'RNTX_INTENT_INVALID');
  assert.equal(code(() => createSigner().sign(relabelled, raw(relabelled), key)), 'RNTX_INTENT_INVALID');
});
