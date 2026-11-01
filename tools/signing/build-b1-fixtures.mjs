// Builds fixtures/signing-b1/: synthetic signed transactions for RN-NET-03B2-B1 and a corpus of
// altered transactions, each with the error code it must produce.
//
//   node tools/signing/build-b1-fixtures.mjs           # check the committed files are current
//   node tools/signing/build-b1-fixtures.mjs --write   # write them (refuses to overwrite)
//
// Everything is synthetic and offline. The keys are derived from public labels
// (signer/test/fixture-keys.mjs), so anyone can recompute them: they are test keys, never
// identities, and their addresses must never be funded. The intents use the Genesis Proof 01
// commitment with made-up Sequence, ledger and nonce values; nothing here was, or can be, submitted
// to a network. Expected codes are stated by hand below; the JavaScript verifier and
// tools/reference/rnnet_tx_reference.py must both reproduce every record.
import { Buffer } from 'node:buffer';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalBytes } from '../../packages/canonical/src/index.mjs';
import {
  decodeEip1559Signed,
  decodeXrplTx,
  encodeEip1559Signed,
  encodeEip1559Unsigned,
  encodeUint,
  encodeXrplTx,
  fieldHeader,
  INTENT_FORMAT,
  intentDigest,
  rlpEncode,
  SECP256K1_N,
  sepoliaAnchorTemplate,
  sepoliaMaxFee,
  xrplAnchorTemplate,
  xrplSigningPreimage,
} from '../../packages/tx-intent/src/index.mjs';
import { ed25519Sign, keccak256, secp256k1SignDigest } from '../../signer/src/crypto.mjs';
import { bindKey } from '../../signer/src/keys.mjs';
import { createSigner } from '../../signer/src/sign.mjs';
import { verifySignedTransaction } from '../../signer/src/verify.mjs';
import { fixtureKey } from '../../signer/test/fixture-keys.mjs';

export const DIR = fileURLToPath(new URL('../../fixtures/signing-b1/', import.meta.url));
export const FILES = ['xrpl-intent.json', 'sepolia-intent.json', 'golden.json'];
export const COMMITMENT = 'sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7';
export const LABELS = Object.freeze({
  xrpl: 'rn-net-03b2b1-xrpl-1',
  xrplOther: 'rn-net-03b2b1-xrpl-2',
  sepolia: 'rn-net-03b2b1-sepolia-1',
  sepoliaOther: 'rn-net-03b2b1-sepolia-2',
});
const XRPL_NET = 'xrpl:testnet';
const SEP_NET = 'evm:11155111';
const PREPARATION = { source: 'synthetic', note: 'RN-NET-03B2-B1 fixture: made-up Sequence, ledger and nonce; never submitted' };

const keys = () => ({
  xrpl: fixtureKey(XRPL_NET, LABELS.xrpl),
  xrplOther: fixtureKey(XRPL_NET, LABELS.xrplOther),
  sepolia: fixtureKey(SEP_NET, LABELS.sepolia),
  sepoliaOther: fixtureKey(SEP_NET, LABELS.sepoliaOther),
});

export function intents() {
  const k = keys();
  const x = bindKey(k.xrpl);
  const e = bindKey(k.sepolia);
  const xrpl = {
    format: INTENT_FORMAT,
    network: XRPL_NET,
    purpose: 'genesis-proof-01',
    commitment: COMMITMENT,
    preparation: PREPARATION,
    transaction: xrplAnchorTemplate(COMMITMENT, { Account: x.address, Sequence: 1_000_001, LastLedgerSequence: 1_000_020, SigningPubKey: x.publicKey }),
  };
  const sepolia = {
    format: INTENT_FORMAT,
    network: SEP_NET,
    purpose: 'genesis-proof-01',
    commitment: COMMITMENT,
    preparation: PREPARATION,
    transaction: sepoliaAnchorTemplate(COMMITMENT, { from: e.address, nonce: '0x0', maxFeePerGas: sepoliaMaxFee('0x11') }),
  };
  return { xrpl, sepolia };
}

const upperHex = (bytes) => Buffer.from(bytes).toString('hex').toUpperCase();
const evmHex = (bytes) => `0x${Buffer.from(bytes).toString('hex')}`;
const withTx = (intent, change) => ({ ...intent, transaction: { ...intent.transaction, ...change } });

/** Altered XRPL transactions: [id, intent, approvedDigest, signedTransaction, expected code]. */
function xrplCases(intent, signed, k) {
  const digest = intentDigest(intent);
  const blob = Buffer.from(signed, 'hex');
  const tx = decodeXrplTx(blob);
  const reencode = (change) => upperHex(encodeXrplTx({ ...tx, ...change }));
  const sig = Buffer.from(tx.TxnSignature, 'hex');
  const flipped = Buffer.from(sig);
  flipped[0] ^= 0x01;
  const memo = tx.Memos[0].Memo;
  const otherData = memo.MemoData.slice(0, -2) + (memo.MemoData.endsWith('00') ? '01' : '00');
  const other = bindKey(k.xrplOther);
  const otherSig = (t) => upperHex(ed25519Sign(other.secretKey, xrplSigningPreimage(t)));
  // Raw edits around the serialized fields: TransactionType (3 bytes), Sequence (5),
  // LastLedgerSequence (6) come first in canonical order.
  const head = blob.subarray(0, 3);
  const seq = blob.subarray(3, 8);
  const lls = blob.subarray(8, 14);
  const rest = blob.subarray(14);
  const memoFormat = Buffer.concat([fieldHeader(7, 14), Buffer.of(1), Buffer.of(0x41)]);
  const end = blob.length - 2; // before 0xE1 (end of memo) and 0xF1 (end of array)
  const withMemoFormat = Buffer.concat([blob.subarray(0, end), memoFormat, blob.subarray(end)]);
  return [
    ['xrpl-signature-bit-flip', intent, digest, reencode({ TxnSignature: upperHex(flipped) }), 'RNTX_SIGNATURE_INVALID'],
    ['xrpl-signature-from-another-key', intent, digest, reencode({ TxnSignature: otherSig(tx) }), 'RNTX_SIGNATURE_INVALID'],
    ['xrpl-key-and-signature-substituted', intent, digest, reencode({ SigningPubKey: other.publicKey, TxnSignature: otherSig({ ...tx, SigningPubKey: other.publicKey }) }), 'RNTX_SENDER_MISMATCH'],
    ['xrpl-fee-changed', intent, digest, reencode({ Fee: '13' }), 'RNTX_FEE_MISMATCH'],
    ['xrpl-fee-above-cap', intent, digest, reencode({ Fee: '1001' }), 'RNTX_FEE_MISMATCH'],
    ['xrpl-sequence-changed', intent, digest, reencode({ Sequence: tx.Sequence + 1 }), 'RNTX_NONCE_MISMATCH'],
    ['xrpl-payload-changed', intent, digest, reencode({ Memos: [{ Memo: { ...memo, MemoData: otherData } }] }), 'RNTX_PAYLOAD_MISMATCH'],
    ['xrpl-second-memo', intent, digest, reencode({ Memos: [...tx.Memos, ...tx.Memos] }), 'RNTX_PAYLOAD_MISMATCH'],
    ['xrpl-last-ledger-changed', intent, digest, reencode({ LastLedgerSequence: tx.LastLedgerSequence + 1 }), 'RNTX_FIELD_MISMATCH'],
    ['xrpl-flags-nonzero', intent, digest, reencode({ Flags: 1 }), 'RNTX_FIELD_MISMATCH'],
    ['xrpl-network-id-added', intent, digest, upperHex(Buffer.concat([head, fieldHeader(2, 1), Buffer.from('00000001', 'hex'), blob.subarray(3)])), 'RNTX_WRONG_CHAIN'],
    ['xrpl-unknown-field', intent, digest, upperHex(Buffer.concat([head, seq, lls, fieldHeader(2, 33), Buffer.from('00000001', 'hex'), rest])), 'RNTX_UNKNOWN_FIELD'],
    ['xrpl-memo-format-added', intent, digest, upperHex(withMemoFormat), 'RNTX_UNKNOWN_FIELD'],
    ['xrpl-fields-out-of-order', intent, digest, upperHex(Buffer.concat([head, lls, seq, rest])), 'RNTX_NONCANONICAL_ENCODING'],
    // Field IDs below 16 written in the extended forms: other encodings of the same fields.
    ['xrpl-header-long-form-field', intent, digest, `1002${signed.slice(2)}`, 'RNTX_NONCANONICAL_ENCODING'],
    ['xrpl-header-long-form-both', intent, digest, `000102${signed.slice(2)}`, 'RNTX_NONCANONICAL_ENCODING'],
    ['xrpl-header-long-form-account', intent, digest, signed.replace(/8114/, '800114'), 'RNTX_NONCANONICAL_ENCODING'],
    ['xrpl-trailing-byte', intent, digest, `${signed}00`, 'RNTX_TRAILING_BYTES'],
    ['xrpl-truncated', intent, digest, signed.slice(0, -2), 'RNTX_DECODE'],
    ['xrpl-lower-case-hex', intent, digest, signed.toLowerCase(), 'RNTX_DECODE'],
    ['xrpl-approved-digest-mismatch', intent, intentDigest(withTx(intent, { LastLedgerSequence: 1_000_021 })), signed, 'RNTX_INTENT_DIGEST_MISMATCH'],
    ['xrpl-intent-fee-above-cap', withTx(intent, { Fee: '1001' }), digest, signed, 'RNTX_INTENT_INVALID'],
    ['xrpl-intent-network-id', withTx(intent, { NetworkID: 1 }), digest, signed, 'RNTX_INTENT_INVALID'],
    ['xrpl-intent-account-not-key', withTx(intent, { Account: other.address }), digest, signed, 'RNTX_INTENT_INVALID'],
  ];
}

/** Altered Sepolia transactions. */
function sepoliaCases(intent, signed, k) {
  const digest = intentDigest(intent);
  const bytes = Buffer.from(signed.slice(2), 'hex');
  const { transaction, signature } = decodeEip1559Signed(bytes);
  const tx = { ...transaction };
  const reencode = (change, sig = signature) => evmHex(encodeEip1559Signed({ ...tx, ...change }, sig));
  const items = (change = {}, sig = signature) => {
    const t = { ...tx, ...change };
    const u = (name) => encodeUint(BigInt(t[name]));
    return [u('chainId'), u('nonce'), u('maxPriorityFeePerGas'), u('maxFeePerGas'), u('gas'), Buffer.from(t.to.slice(2), 'hex'), u('value'), Buffer.from(t.input.slice(2), 'hex'), t.accessListItems ?? [], encodeUint(sig.yParity), encodeUint(sig.r), encodeUint(sig.s)];
  };
  const typed = (list) => evmHex(Buffer.concat([Buffer.of(2), rlpEncode(list)]));
  const other = bindKey(k.sepoliaOther);
  const otherSignature = secp256k1SignDigest(other.secretKey, keccak256(encodeEip1559Unsigned(tx)));
  const sFlip = { ...signature, s: signature.s ^ 1n };
  const highS = { yParity: signature.yParity ^ 1n, r: signature.r, s: SECP256K1_N - signature.s };
  const accessList = items({ accessListItems: [[Buffer.from(tx.to.slice(2), 'hex'), []]] });
  const nonCanonicalNonce = items();
  nonCanonicalNonce[1] = Buffer.of(0); // nonce 0 written as one zero byte instead of the empty string
  const legacy = evmHex(rlpEncode([encodeUint(0n), encodeUint(1n), encodeUint(30_000n), Buffer.from(tx.to.slice(2), 'hex'), encodeUint(0n), Buffer.from(tx.input.slice(2), 'hex'), encodeUint(37n), encodeUint(signature.r), encodeUint(signature.s)]));
  return [
    ['sepolia-signature-s-changed', intent, digest, reencode({}, sFlip), 'RNTX_SENDER_MISMATCH'],
    ['sepolia-signature-from-another-key', intent, digest, reencode({}, otherSignature), 'RNTX_SENDER_MISMATCH'],
    ['sepolia-high-s', intent, digest, reencode({}, highS), 'RNTX_HIGH_S'],
    ['sepolia-y-parity-2', intent, digest, reencode({}, { ...signature, yParity: 2n }), 'RNTX_BAD_Y_PARITY'],
    ['sepolia-r-zero', intent, digest, reencode({}, { ...signature, r: 0n }), 'RNTX_SIGNATURE_INVALID'],
    ['sepolia-wrong-chain', intent, digest, reencode({ chainId: '0x1' }), 'RNTX_WRONG_CHAIN'],
    ['sepolia-nonce-changed', intent, digest, reencode({ nonce: '0x1' }), 'RNTX_NONCE_MISMATCH'],
    ['sepolia-max-fee-changed', intent, digest, reencode({ maxFeePerGas: '0x4a817c800' }), 'RNTX_FEE_MISMATCH'],
    ['sepolia-priority-fee-changed', intent, digest, reencode({ maxPriorityFeePerGas: '0x3b9aca01' }), 'RNTX_FEE_MISMATCH'],
    ['sepolia-gas-changed', intent, digest, reencode({ gas: '0x7531' }), 'RNTX_FEE_MISMATCH'],
    ['sepolia-payload-changed', intent, digest, reencode({ input: `${tx.input.slice(0, -2)}${tx.input.endsWith('00') ? '01' : '00'}` }), 'RNTX_PAYLOAD_MISMATCH'],
    ['sepolia-to-changed', intent, digest, reencode({ to: other.address }), 'RNTX_FIELD_MISMATCH'],
    ['sepolia-value-changed', intent, digest, reencode({ value: '0x1' }), 'RNTX_FIELD_MISMATCH'],
    ['sepolia-access-list-added', intent, digest, typed(accessList), 'RNTX_FIELD_MISMATCH'],
    ['sepolia-type-1', intent, digest, `0x01${signed.slice(4)}`, 'RNTX_WRONG_TX_TYPE'],
    ['sepolia-legacy-encoding', intent, digest, legacy, 'RNTX_WRONG_TX_TYPE'],
    ['sepolia-nonce-leading-zero', intent, digest, typed(nonCanonicalNonce), 'RNTX_NONCANONICAL_ENCODING'],
    ['sepolia-trailing-byte', intent, digest, `${signed}00`, 'RNTX_TRAILING_BYTES'],
    ['sepolia-truncated', intent, digest, signed.slice(0, -2), 'RNTX_DECODE'],
    ['sepolia-upper-case-hex', intent, digest, `0x${signed.slice(2).toUpperCase()}`, 'RNTX_DECODE'],
    ['sepolia-approved-digest-mismatch', intent, intentDigest(withTx(intent, { nonce: '0x1' })), signed, 'RNTX_INTENT_DIGEST_MISMATCH'],
    ['sepolia-intent-chain-1', withTx(intent, { chainId: '0x1' }), digest, signed, 'RNTX_INTENT_INVALID'],
    ['sepolia-intent-fee-above-cap', withTx(intent, { maxFeePerGas: '0x4a817c801' }), digest, signed, 'RNTX_INTENT_INVALID'],
    ['sepolia-intent-not-self-send', withTx(intent, { to: other.address }), digest, signed, 'RNTX_INTENT_INVALID'],
    ['sepolia-intent-nonce-2-pow-64', withTx(intent, { nonce: '0x10000000000000000' }), digest, signed, 'RNTX_INTENT_INVALID'],
    ['sepolia-access-list-nested-too-deep', intent, digest, typed(items({ accessListItems: [[[[[]]]]] })), 'RNTX_DECODE'],
  ];
}

const text = (value) => `${Buffer.from(canonicalBytes(value)).toString('utf8')}\n`;

/** The fixture files as bytes, built from scratch. Throws if any expectation fails. */
export function build() {
  const k = keys();
  const { xrpl, sepolia } = intents();
  const signer = createSigner();
  const out = {};
  const golden = {
    format: 'rnnet.signing-b1-fixtures.v1',
    status: 'SYNTHETIC TEST FIXTURES: label-derived test keys, made-up sequence values; never submitted and must never be funded',
    keys: [],
    signed: {},
    negative: [],
  };
  for (const [name, intent, key, label] of [['xrpl', xrpl, k.xrpl, LABELS.xrpl], ['sepolia', sepolia, k.sepolia, LABELS.sepolia]]) {
    const bound = bindKey(key);
    golden.keys.push({ network: bound.network, label, derivation: 'SHA-256("rnnet:synthetic-test-key:v1:" + label); secp256k1: modulo n', publicKey: bound.publicKey, address: bound.address });
    const digest = intentDigest(intent);
    const result = signer.sign(intent, digest, key);
    if (result.verification.outcome !== 'PASS') throw new Error(`${name}: did not verify`);
    golden.signed[name] = { intentFile: `${name}-intent.json`, intentDigest: digest, signedTransaction: result.signedTransaction, blobSha256: result.blobSha256, transactionHash: result.transactionHash, verification: result.verification };
    out[`${name}-intent.json`] = text(intent);
    const cases = name === 'xrpl' ? xrplCases(intent, result.signedTransaction, k) : sepoliaCases(intent, result.signedTransaction, k);
    for (const [id, caseIntent, approvedDigest, signedTransaction, expectedCode] of cases) {
      const verification = verifySignedTransaction({ intent: caseIntent, approvedDigest, signedTransaction });
      if (verification.outcome !== 'FAIL' || verification.code !== expectedCode) throw new Error(`${id}: expected ${expectedCode}, got ${verification.outcome} ${verification.code}`);
      golden.negative.push({ id, intent: caseIntent, approvedDigest, signedTransaction, expectedCode, expectedVerification: verification });
    }
  }
  out['golden.json'] = text(golden);
  return Object.fromEntries(FILES.map((name) => [name, Buffer.from(out[name], 'utf8')]));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const built = build();
  if (process.argv.includes('--write')) {
    for (const name of FILES) writeFileSync(DIR + name, built[name], { flag: 'wx' });
    console.log(`wrote ${FILES.join(', ')}`);
  } else {
    const stale = FILES.filter((name) => !existsSync(DIR + name) || !readFileSync(DIR + name).equals(built[name]));
    if (stale.length) {
      console.error(`stale or missing: ${stale.join(', ')}`);
      process.exit(1);
    }
    console.log('signing-b1 fixtures are current');
  }
}
