// txverify/ (RN-NET-03B2-B3, ADR-RN-019 §3): verification only. Checked against the public
// known-answer vectors and every B1 golden and altered transaction. Offline; no key is used.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { decodeEip1559Signed, decodeXrplTx, TxError } from '../../packages/tx-intent/src/index.mjs';
import { ed25519Verify, keccak256, secp256k1RecoverAddress, transactionHash, verifySepoliaSignature, verifySignedTransaction, verifyXrplSignature } from '../src/index.mjs';

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const kat = read('../../vectors/signing/known-answers.json');
const golden = read('../../fixtures/signing-b1/golden.json');
const intentOf = (name) => read(`../../fixtures/signing-b1/${golden.signed[name].intentFile}`);
const codeOf = (fn) => {
  try {
    fn();
  } catch (error) {
    assert.ok(error instanceof TxError, String(error));
    return error.code;
  }
  return null;
};

test('Keccak-256 known answers', () => {
  for (const v of kat.keccak256) assert.equal(keccak256(Buffer.from(v.input, 'utf8')).toString('hex'), v.expected);
});

test('secp256k1 recovery: the EIP-155 and EIP-1559 known answers', () => {
  const e = kat.eip155;
  const digest = keccak256(Buffer.from(e.signingDataHex.slice(2), 'hex'));
  assert.equal(secp256k1RecoverAddress(digest, { yParity: BigInt(e.recoveryId), r: BigInt(e.r), s: BigInt(e.s) }), e.sender);
  for (const v of kat.eip1559) {
    const bytes = Buffer.from(v.signedHex.slice(2), 'hex');
    const { sender, transactionHash: hash } = verifySepoliaSignature(bytes);
    assert.equal(sender, v.sender, v.id);
    assert.equal(hash, `0x${keccak256(bytes).toString('hex')}`);
  }
});

test('the B1 golden transactions verify, with the same records and hashes', () => {
  for (const [name, signed] of Object.entries(golden.signed)) {
    const record = verifySignedTransaction({ intent: intentOf(name), approvedDigest: signed.intentDigest, signedTransaction: signed.signedTransaction });
    assert.deepEqual(record, signed.verification, name);
  }
  const s = golden.signed.sepolia;
  const bytes = Buffer.from(s.signedTransaction.slice(2), 'hex');
  assert.deepEqual(verifySepoliaSignature(bytes), { sender: intentOf('sepolia').transaction.from, transactionHash: s.transactionHash });
  assert.equal(transactionHash('evm:11155111', bytes), s.transactionHash);
  const x = golden.signed.xrpl;
  assert.equal(codeOf(() => verifyXrplSignature(decodeXrplTx(Buffer.from(x.signedTransaction, 'hex')))), null);
  assert.equal(transactionHash('xrpl:testnet', Buffer.from(x.signedTransaction, 'hex')), x.transactionHash);
});

test('every altered B1 transaction gives its hand-stated record', () => {
  assert.ok(golden.negative.length >= 40);
  for (const n of golden.negative) {
    assert.deepEqual(verifySignedTransaction({ intent: n.intent, approvedDigest: n.approvedDigest, signedTransaction: n.signedTransaction }), n.expectedVerification, n.id);
  }
});

test('signature checks alone: flipped bits, high s, y-parity 2 and malformed keys are refused', () => {
  const x = Buffer.from(golden.signed.xrpl.signedTransaction, 'hex');
  const decoded = decodeXrplTx(x);
  const flipped = { ...decoded, TxnSignature: `${decoded.TxnSignature.slice(0, -1)}${decoded.TxnSignature.endsWith('0') ? '1' : '0'}` };
  assert.equal(codeOf(() => verifyXrplSignature(flipped)), 'RNTX_SIGNATURE_INVALID');
  const { TxnSignature, ...unsigned } = decoded;
  assert.equal(codeOf(() => verifyXrplSignature(unsigned)), 'RNTX_SIGNATURE_INVALID');
  assert.equal(ed25519Verify(Buffer.alloc(31), Buffer.alloc(0), Buffer.alloc(64)), false);
  for (const id of ['sepolia-high-s', 'sepolia-y-parity-2', 'sepolia-r-zero', 'sepolia-signature-s-changed']) {
    const n = golden.negative.find((c) => c.id === id);
    const bytes = Buffer.from(n.signedTransaction.slice(2), 'hex');
    decodeEip1559Signed(bytes);
    const code = codeOf(() => {
      const { sender } = verifySepoliaSignature(bytes);
      if (sender !== n.intent.transaction.from) throw new TxError('RNTX_SENDER_MISMATCH');
    });
    assert.equal(code, n.expectedCode, id);
  }
});

test('txverify exports nothing that signs or derives a key', async () => {
  const api = await import('../src/index.mjs');
  for (const name of Object.keys(api)) assert.ok(!/sign(?!ed|ature)|secret|private|keygen|random|getPublicKey/i.test(name.replace(/Signature|signedBytes|SignedTransaction/g, '')), name);
});
