// packages/tx-intent (RN-NET-03B2-B1): intent, digest, codecs and comparison. Offline, no keys.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { test } from 'node:test';
import {
  approvedIntent,
  compareSepolia,
  compareXrpl,
  decodeEip1559Signed,
  decodeUint,
  decodeXrplTx,
  encodeEip1559Signed,
  encodeEip1559Unsigned,
  encodeUint,
  encodeVL,
  encodeXrplTx,
  fieldHeader,
  INTENT_FORMAT,
  intentDigest,
  makeIntent,
  rlpDecode,
  rlpEncode,
  sepoliaAnchorTemplate,
  sepoliaMaxFee,
  TxError,
  xrplAnchorTemplate,
  xrplSigningPreimage,
} from '../src/index.mjs';

const C = 'sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7';
// A public example key (ED + 32 bytes) and the address it controls, computed by the codec and
// cross-checked by tools/reference/rnnet_tx_reference.py through the B1 fixtures.
const PUB = 'ED5F5AC8B98974A3CA843326D9B88CEBD0560177B973EE0B149F782CFAA06DC66A';
const ACCOUNT = 'r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ';
const FROM = '0x57db031993583fe0cbbf42dbfcf6489e0fb70b86';

const code = (fn) => {
  try {
    fn();
  } catch (error) {
    assert.ok(error instanceof TxError, `not a TxError: ${error}`);
    return error.code;
  }
  return null;
};
const xrplIntent = (change = {}) => ({
  format: INTENT_FORMAT,
  network: 'xrpl:testnet',
  purpose: 'genesis-proof-01',
  commitment: C,
  preparation: { source: 'synthetic' },
  transaction: { ...xrplAnchorTemplate(C, { Account: ACCOUNT, Sequence: 5, LastLedgerSequence: 25, SigningPubKey: PUB }), ...change },
});
const sepoliaIntent = (change = {}) => ({
  format: INTENT_FORMAT,
  network: 'evm:11155111',
  purpose: 'genesis-proof-01',
  commitment: C,
  preparation: { source: 'synthetic' },
  transaction: { ...sepoliaAnchorTemplate(C, { from: FROM, nonce: '0x0', maxFeePerGas: sepoliaMaxFee('0x11') }), ...change },
});

test('makeIntent returns a deeply frozen canonical copy; changing the input later changes nothing', () => {
  const input = xrplIntent();
  const checked = makeIntent(input);
  assert.ok(Object.isFrozen(checked) && Object.isFrozen(checked.transaction) && Object.isFrozen(checked.transaction.Memos[0].Memo));
  const digest = intentDigest(input);
  input.transaction.Fee = '999';
  assert.equal(intentDigest(checked), digest);
  assert.notEqual(intentDigest(input), digest);
  assert.match(digest, /^sha256:[0-9a-f]{64}$/);
});

test('the intent digest is domain-separated and changes with every field', () => {
  const base = intentDigest(sepoliaIntent());
  for (const change of [{ nonce: '0x1' }, { maxFeePerGas: '0x3b9aca23' }, { gas: '0x752f' }]) assert.notEqual(intentDigest(sepoliaIntent(change)), base);
  assert.notEqual(intentDigest({ ...sepoliaIntent(), preparation: { source: 'other' } }), base);
});

test('intents are refused with RNTX_INTENT_INVALID', () => {
  const cases = [
    xrplIntent({ Fee: '1001' }),
    xrplIntent({ NetworkID: 1 }),
    xrplIntent({ Flags: 1 }),
    xrplIntent({ Sequence: null }),
    xrplIntent({ Account: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh' }), // not the key's address
    { ...xrplIntent(), transaction: (({ SigningPubKey, ...t }) => t)(xrplIntent().transaction) },
    sepoliaIntent({ chainId: '0x1' }),
    sepoliaIntent({ to: '0x0000000000000000000000000000000000000001' }),
    sepoliaIntent({ maxFeePerGas: '0x4a817c801' }),
    sepoliaIntent({ input: '0x00' }),
    sepoliaIntent({ nonce: null }),
    { ...sepoliaIntent(), network: 'evm:1' },
    { ...sepoliaIntent(), purpose: 'other' },
    { ...sepoliaIntent(), format: 'rnnet.unsigned-tx-intent.v2' },
    { ...sepoliaIntent(), extra: 1 },
  ];
  for (const intent of cases) assert.equal(code(() => makeIntent(intent)), 'RNTX_INTENT_INVALID', JSON.stringify(intent).slice(0, 120));
});

test('non-plain intents (Proxy, getter, inherited field) are refused', () => {
  const proxy = new Proxy(sepoliaIntent(), {});
  const getter = sepoliaIntent();
  Object.defineProperty(getter.transaction, 'nonce', { get: () => '0x0', enumerable: true });
  const inherited = Object.assign(Object.create({ purpose: 'genesis-proof-01' }), (({ purpose, ...rest }) => rest)(sepoliaIntent()));
  for (const intent of [proxy, getter, inherited]) assert.equal(code(() => makeIntent(intent)), 'RNTX_INTENT_INVALID');
});

test('approvedIntent requires exactly the approved digest', () => {
  const intent = sepoliaIntent();
  assert.equal(code(() => approvedIntent(intent, intentDigest(intent))), null);
  assert.equal(code(() => approvedIntent(intent, intentDigest(sepoliaIntent({ nonce: '0x1' })))), 'RNTX_INTENT_DIGEST_MISMATCH');
  assert.equal(code(() => approvedIntent(intent, 'sha256:00')), 'RNTX_INTENT_DIGEST_MISMATCH');
  assert.equal(code(() => approvedIntent(intent, undefined)), 'RNTX_INTENT_DIGEST_MISMATCH');
});

test('XRPL: the AccountSet round-trips, and the preimage is STX + the fields without TxnSignature', () => {
  const tx = { ...makeIntent(xrplIntent()).transaction, TxnSignature: 'AB'.repeat(64) };
  const blob = encodeXrplTx(tx);
  assert.deepEqual(decodeXrplTx(blob), tx);
  const pre = xrplSigningPreimage(tx);
  assert.equal(pre.subarray(0, 4).toString('hex'), '53545800');
  const { TxnSignature, ...unsigned } = tx;
  assert.ok(pre.subarray(4).equals(encodeXrplTx(unsigned)));
});

test('XRPL: field headers and length prefixes for every header form', () => {
  assert.equal(fieldHeader(1, 2).toString('hex'), '12');
  assert.equal(fieldHeader(2, 27).toString('hex'), '201b');
  assert.equal(fieldHeader(16, 1).toString('hex'), '0110');
  assert.equal(fieldHeader(16, 17).toString('hex'), '001011');
  assert.equal(encodeVL(192).toString('hex'), 'c0');
  assert.equal(encodeVL(193).toString('hex'), 'c100');
  assert.equal(encodeVL(12_481).toString('hex'), 'f10000');
});

test('XRPL decoding refuses what ADR-RN-016 does not allow, each with its code', () => {
  const blob = encodeXrplTx({ ...makeIntent(xrplIntent()).transaction, TxnSignature: 'AB'.repeat(64) });
  const at = (bytes) => code(() => decodeXrplTx(bytes));
  assert.equal(at(Buffer.concat([blob, Buffer.of(0)])), 'RNTX_TRAILING_BYTES');
  assert.equal(at(blob.subarray(0, blob.length - 1)), 'RNTX_DECODE');
  assert.equal(at(Buffer.concat([blob.subarray(0, 3), Buffer.from('2100000001', 'hex'), blob.subarray(3)])), 'RNTX_WRONG_CHAIN');
  assert.equal(at(Buffer.concat([Buffer.from('2100000001', 'hex'), blob])), 'RNTX_WRONG_CHAIN');
  assert.equal(at(Buffer.concat([blob.subarray(3, 8), blob.subarray(0, 3), blob.subarray(8)])), 'RNTX_NONCANONICAL_ENCODING');
  assert.equal(at(Buffer.concat([blob.subarray(0, 3), blob.subarray(0, 3), blob.subarray(3)])), 'RNTX_NONCANONICAL_ENCODING');
  assert.equal(at(Buffer.from('6140000000000003E8', 'hex')), 'RNTX_UNKNOWN_FIELD'); // Amount (6/1) is not allowed
  assert.equal(at(Buffer.from('68C000000000000001', 'hex')), 'RNTX_DECODE'); // a non-XRP amount as Fee
  assert.equal(at(Buffer.from('680000000000000001', 'hex')), 'RNTX_DECODE'); // a negative amount
});

test('RLP: canonical round trip, and every non-canonical form is refused', () => {
  const items = [Buffer.alloc(0), Buffer.of(0x7f), Buffer.of(0x80), Buffer.alloc(56, 1), [Buffer.of(1), [Buffer.alloc(60, 2)]]];
  const encoded = rlpEncode(items);
  assert.ok(rlpEncode(rlpDecode(encoded)).equals(encoded));
  const at = (hex) => code(() => rlpDecode(Buffer.from(hex, 'hex')));
  assert.equal(at('817f'), 'RNTX_NONCANONICAL_ENCODING'); // single byte below 0x80 with a prefix
  assert.equal(at('b80101'), 'RNTX_NONCANONICAL_ENCODING'); // long form for a short string
  assert.equal(at(`b90038${'01'.repeat(56)}`), 'RNTX_NONCANONICAL_ENCODING'); // length with a leading zero
  assert.equal(at('f800'), 'RNTX_NONCANONICAL_ENCODING');
  assert.equal(at('8301'), 'RNTX_DECODE');
  assert.equal(at('0101'), 'RNTX_TRAILING_BYTES');
  assert.equal(code(() => decodeUint(Buffer.of(0, 1), 'n')), 'RNTX_NONCANONICAL_ENCODING');
  assert.equal(code(() => decodeUint(Buffer.alloc(33, 1), 'n')), 'RNTX_NONCANONICAL_ENCODING');
  assert.equal(encodeUint(0n).length, 0);
});

test('EIP-1559: signed bytes decode back to the transaction, and the unsigned preimage is re-derived', () => {
  const tx = makeIntent(sepoliaIntent()).transaction;
  const signature = { yParity: 1n, r: 5n, s: 7n };
  const signed = encodeEip1559Signed(tx, signature);
  const decoded = decodeEip1559Signed(signed);
  const { from, ...fields } = tx;
  assert.deepEqual(decoded.transaction, fields);
  assert.deepEqual(decoded.signature, signature);
  assert.ok(decoded.unsigned.equals(encodeEip1559Unsigned(tx)));
  assert.equal(signed[0], 0x02);
  assert.equal(code(() => decodeEip1559Signed(Buffer.concat([Buffer.of(1), signed.subarray(1)]))), 'RNTX_WRONG_TX_TYPE');
  assert.equal(code(() => decodeEip1559Signed(signed.subarray(1))), 'RNTX_WRONG_TX_TYPE');
});

test('comparison reports the first difference in a fixed order', () => {
  const xtx = makeIntent(xrplIntent()).transaction;
  assert.equal(compareXrpl(xtx, { ...xtx, TxnSignature: 'AA' }), null);
  assert.equal(compareXrpl(xtx, { ...xtx, Sequence: 6, Fee: '13' }).code, 'RNTX_NONCE_MISMATCH');
  assert.equal(compareXrpl(xtx, { ...xtx, Fee: '13' }).code, 'RNTX_FEE_MISMATCH');
  assert.equal(compareXrpl(xtx, { ...xtx, Memos: [] }).code, 'RNTX_PAYLOAD_MISMATCH');
  assert.equal(compareXrpl(xtx, { ...xtx, Flags: 0 }).code, 'RNTX_FIELD_MISMATCH');
  const etx = makeIntent(sepoliaIntent()).transaction;
  const { from, ...efields } = etx;
  assert.equal(compareSepolia(etx, efields), null);
  assert.equal(compareSepolia(etx, { ...efields, chainId: '0x1', nonce: '0x1' }).code, 'RNTX_WRONG_CHAIN');
  assert.equal(compareSepolia(etx, { ...efields, maxFeePerGas: '0x1' }).code, 'RNTX_FEE_MISMATCH');
  assert.equal(compareSepolia(etx, { ...efields, input: '0x' }).code, 'RNTX_PAYLOAD_MISMATCH');
});
