// signer/ (RN-NET-03B2-B1): signing, key binding, the in-memory sign log, verification and the
// in-memory key-file format. Label-derived test keys only; offline.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { test } from 'node:test';
import {
  decodeEip1559Signed,
  encodeEip1559Signed,
  INTENT_FORMAT,
  intentDigest,
  SECP256K1_N,
  sepoliaAnchorTemplate,
  sepoliaMaxFee,
  TxError,
  xrplAnchorTemplate,
} from '../../packages/tx-intent/src/index.mjs';
import { keccak256, secp256k1RecoverAddress, secp256k1SignDigest } from '../src/crypto.mjs';
import { decryptKeyFile, encryptKeyFile, KEY_FILE_FORMAT } from '../src/keyfile.mjs';
import { bindKey } from '../src/keys.mjs';
import { createSigner } from '../src/sign.mjs';
import { verifySignedTransaction } from '../src/verify.mjs';
import { fixtureKey } from './fixture-keys.mjs';

const C = 'sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7';
const XK = fixtureKey('xrpl:testnet', 'signer-test-xrpl');
const EK = fixtureKey('evm:11155111', 'signer-test-sepolia');
const X = bindKey(XK);
const E = bindKey(EK);
// A test passphrase for in-memory key-file tests only; no file is ever written.
const PASSPHRASE = 'rn-net b1 in-memory test passphrase';
const SALT = Uint8Array.from(Buffer.alloc(16, 0x11));
const IV = Uint8Array.from(Buffer.alloc(12, 0x22));

const xrplIntent = (change = {}, key = X) => ({
  format: INTENT_FORMAT,
  network: 'xrpl:testnet',
  purpose: 'genesis-proof-01',
  commitment: C,
  preparation: { source: 'synthetic' },
  transaction: { ...xrplAnchorTemplate(C, { Account: key.address, Sequence: 7, LastLedgerSequence: 27, SigningPubKey: key.publicKey }), ...change },
});
const sepoliaIntent = (change = {}, key = E) => ({
  format: INTENT_FORMAT,
  network: 'evm:11155111',
  purpose: 'genesis-proof-01',
  commitment: C,
  preparation: { source: 'synthetic' },
  transaction: { ...sepoliaAnchorTemplate(C, { from: key.address, nonce: '0x3', maxFeePerGas: sepoliaMaxFee('0x11') }), ...change },
});
const code = (fn) => {
  try {
    fn();
  } catch (error) {
    assert.ok(error instanceof TxError, `not a TxError: ${error}`);
    return error.code;
  }
  return null;
};

test('signs an approved intent on each network and the output verifies', () => {
  for (const [intent, key] of [[xrplIntent(), XK], [sepoliaIntent(), EK]]) {
    const digest = intentDigest(intent);
    const out = createSigner().sign(intent, digest, key);
    assert.equal(out.verification.outcome, 'PASS');
    assert.equal(out.intentDigest, digest);
    assert.deepEqual(verifySignedTransaction({ intent, approvedDigest: digest, signedTransaction: out.signedTransaction }), out.verification);
  }
});

test('signing is deterministic (RFC 8032 and RFC 6979): the same intent gives the same bytes', () => {
  const intent = sepoliaIntent();
  const digest = intentDigest(intent);
  assert.equal(createSigner().sign(intent, digest, EK).signedTransaction, createSigner().sign(intent, digest, EK).signedTransaction);
});

test('the signer refuses before signing, each with its code', () => {
  const s = createSigner();
  const intent = sepoliaIntent();
  const digest = intentDigest(intent);
  assert.equal(code(() => s.sign(intent, intentDigest(sepoliaIntent({ nonce: '0x4' })), EK)), 'RNTX_INTENT_DIGEST_MISMATCH');
  assert.equal(code(() => s.sign(sepoliaIntent({ chainId: '0x1' }), digest, EK)), 'RNTX_INTENT_INVALID');
  assert.equal(code(() => s.sign(intent, digest, XK)), 'RNTX_KEY_NETWORK_MISMATCH');
  assert.equal(code(() => s.sign(intent, digest, { ...EK, purpose: 'other' })), 'RNTX_KEY_INVALID');
  assert.equal(code(() => s.sign(intent, digest, fixtureKey('evm:11155111', 'another-key'))), 'RNTX_SENDER_MISMATCH');
  assert.equal(code(() => s.sign(intent, digest, { ...EK, secretKey: new Uint8Array(32) })), 'RNTX_KEY_INVALID');
  assert.equal(code(() => s.sign(intent, digest, { ...EK, secretKey: new Uint8Array(31) })), 'RNTX_KEY_INVALID');
  const n = Buffer.from(SECP256K1_N.toString(16), 'hex');
  assert.equal(code(() => s.sign(intent, digest, { ...EK, secretKey: Uint8Array.from(n) })), 'RNTX_KEY_INVALID');
  const xi = xrplIntent();
  assert.equal(code(() => s.sign(xi, intentDigest(xi), fixtureKey('xrpl:testnet', 'another-key'))), 'RNTX_SENDER_MISMATCH');
});

test('the in-memory sign log: the same intent again, or another intent with the same key, is refused', () => {
  const s = createSigner();
  const first = sepoliaIntent();
  s.sign(first, intentDigest(first), EK);
  assert.equal(code(() => s.sign(first, intentDigest(first), EK)), 'RNTX_ALREADY_SIGNED');
  const replacement = sepoliaIntent({ maxFeePerGas: '0x3b9aca30' }); // same nonce, other fee
  assert.equal(code(() => s.sign(replacement, intentDigest(replacement), EK)), 'RNTX_SEQUENCE_UNRESOLVED');
  const next = sepoliaIntent({ nonce: '0x4' });
  assert.equal(code(() => s.sign(next, intentDigest(next), EK)), 'RNTX_SEQUENCE_UNRESOLVED');
  const xi = xrplIntent();
  s.sign(xi, intentDigest(xi), XK); // another key and network: its own entry
  const xNext = xrplIntent({ Sequence: 8 });
  assert.equal(code(() => s.sign(xNext, intentDigest(xNext), XK)), 'RNTX_SEQUENCE_UNRESOLVED');
});

test('the recovery byte is y-parity: recovering with it gives the signer, with the other parity it does not', () => {
  for (let i = 0; i < 8; i++) {
    const digest = keccak256(Buffer.from(`digest-${i}`));
    const sig = secp256k1SignDigest(EK.secretKey, digest);
    assert.ok(sig.yParity === 0n || sig.yParity === 1n);
    assert.ok(sig.s <= SECP256K1_N / 2n);
    assert.equal(secp256k1RecoverAddress(digest, sig), E.address);
    assert.notEqual(secp256k1RecoverAddress(digest, { ...sig, yParity: sig.yParity ^ 1n }), E.address);
  }
});

test('signature substitution and malleability are refused by the verifier', () => {
  const intent = sepoliaIntent();
  const digest = intentDigest(intent);
  const out = createSigner().sign(intent, digest, EK);
  const { transaction, signature, unsigned } = decodeEip1559Signed(Buffer.from(out.signedTransaction.slice(2), 'hex'));
  const tx = { ...transaction, from: E.address };
  const v = (sig) => verifySignedTransaction({ intent, approvedDigest: digest, signedTransaction: `0x${encodeEip1559Signed(tx, sig).toString('hex')}` }).code;
  assert.equal(v({ yParity: signature.yParity ^ 1n, r: signature.r, s: SECP256K1_N - signature.s }), 'RNTX_HIGH_S');
  assert.equal(v(secp256k1SignDigest(fixtureKey('evm:11155111', 'other').secretKey, keccak256(unsigned))), 'RNTX_SENDER_MISMATCH');
  assert.equal(v({ ...signature, s: 0n }), 'RNTX_SIGNATURE_INVALID');
  assert.equal(v({ ...signature, r: SECP256K1_N }), 'RNTX_SIGNATURE_INVALID');
  assert.equal(v({ ...signature, yParity: 2n }), 'RNTX_BAD_Y_PARITY');
});

test('key file: encrypts and decrypts in memory, bound to network, purpose and public key', () => {
  for (const key of [XK, EK]) {
    const file = encryptKeyFile(key, PASSPHRASE, { salt: SALT, iv: IV, createdAt: '2026-11-01T00:00:00Z' });
    assert.equal(file.format, KEY_FILE_FORMAT);
    assert.equal(file.kdf.N, 131_072);
    assert.equal(file.cipher.iv.length, 24);
    assert.equal(file.cipher.tag.length, 32);
    assert.ok(!JSON.stringify(file).includes(Buffer.from(key.secretKey).toString('hex')), 'the secret never appears in clear');
    const back = decryptKeyFile(file, PASSPHRASE);
    assert.ok(Buffer.from(back.secretKey).equals(Buffer.from(key.secretKey)));
    assert.equal(back.network, key.network);
  }
});

test('key file: a wrong passphrase or any changed field fails; a malformed file is invalid', () => {
  const file = encryptKeyFile(EK, PASSPHRASE, { salt: SALT, iv: IV, createdAt: '2026-11-01T00:00:00Z' });
  const dec = (f, p = PASSPHRASE) => code(() => decryptKeyFile(f, p));
  assert.equal(dec(file, `${PASSPHRASE}!`), 'RNTX_KEYFILE_DECRYPT');
  assert.equal(dec({ ...file, purpose: 'genesis-proof-01', network: 'xrpl:testnet' }), 'RNTX_KEYFILE_DECRYPT');
  assert.equal(dec({ ...file, createdAt: '2026-11-02T00:00:00Z' }), 'RNTX_KEYFILE_DECRYPT');
  assert.equal(dec({ ...file, address: X.address }), 'RNTX_KEYFILE_DECRYPT');
  assert.equal(dec({ ...file, publicKey: X.publicKey }), 'RNTX_KEYFILE_DECRYPT');
  assert.equal(dec({ ...file, cipher: { ...file.cipher, tag: '00'.repeat(16) } }), 'RNTX_KEYFILE_DECRYPT');
  const flipped = `${file.ciphertext.slice(0, -1)}${file.ciphertext.endsWith('0') ? '1' : '0'}`;
  assert.equal(dec({ ...file, ciphertext: flipped }), 'RNTX_KEYFILE_DECRYPT');
  assert.equal(dec({ ...file, kdf: { ...file.kdf, N: 16_384 } }), 'RNTX_KEYFILE_INVALID');
  assert.equal(dec({ ...file, format: 'rnnet.testnet-key-file.v2' }), 'RNTX_KEYFILE_INVALID');
  assert.equal(dec({ ...file, extra: 1 }), 'RNTX_KEYFILE_INVALID');
  assert.equal(dec(file, 'short'), 'RNTX_KEYFILE_INVALID');
  assert.equal(code(() => encryptKeyFile(EK, PASSPHRASE, { salt: SALT.subarray(1), iv: IV, createdAt: '2026-11-01T00:00:00Z' })), 'RNTX_KEYFILE_INVALID');
  assert.equal(code(() => encryptKeyFile(EK, PASSPHRASE, { salt: SALT, iv: IV.subarray(1), createdAt: '2026-11-01T00:00:00Z' })), 'RNTX_KEYFILE_INVALID');
});

test('a key from a key file signs only for its own network', () => {
  const key = decryptKeyFile(encryptKeyFile(XK, PASSPHRASE, { salt: SALT, iv: IV, createdAt: '2026-11-01T00:00:00Z' }), PASSPHRASE);
  const intent = sepoliaIntent();
  assert.equal(code(() => createSigner().sign(intent, intentDigest(intent), key)), 'RNTX_KEY_NETWORK_MISMATCH');
  const xi = xrplIntent();
  assert.equal(createSigner().sign(xi, intentDigest(xi), key).verification.outcome, 'PASS');
});
