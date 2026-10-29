// RN-NET-03A: offline anchor payloads and supplied-record checks. Everything here is synthetic.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ANCHOR_MEMO_TYPE,
  Conclusion,
  decodeAnchorPayload,
  encodeAnchorPayload,
  encodeAnchorReport,
  MAGIC,
  verifyDualAnchor,
  verifyEvmObservation,
  verifyXrplObservation,
} from '../src/index.mjs';

const COMMITMENT = `sha256:${'ab'.repeat(32)}`;
const OTHER = `sha256:${'cd'.repeat(32)}`;
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const bytes = (value) => new TextEncoder().encode(JSON.stringify(value));
const codes = (record) => record.findings.map((f) => f.code);

const xrpl = (payloadHex = hex(encodeAnchorPayload(COMMITMENT)), changes = {}) => ({
  format: 'rnnet.anchor-observation.v1',
  network: 'xrpl:testnet',
  tx: {
    hash: 'A'.repeat(64), ledger_index: 100, ledger_hash: 'B'.repeat(64), validated: true,
    meta: { TransactionResult: 'tesSUCCESS' },
    tx_json: { TransactionType: 'AccountSet', Account: 'rSyntheticAnchorTestAccount1111', Memos: [{ Memo: { MemoType: ANCHOR_MEMO_TYPE, MemoData: payloadHex.toUpperCase() } }] },
    ...changes,
  },
});
const evm = (input = `0x${hex(encodeAnchorPayload(COMMITMENT))}`, receiptChanges = {}) => {
  const transaction = {
    hash: `0x${'1'.repeat(64)}`, chainId: '0xaa36a7', type: '0x2', from: `0x${'2'.repeat(40)}`, to: `0x${'2'.repeat(40)}`, input,
    blockHash: `0x${'3'.repeat(64)}`, blockNumber: '0x10', transactionIndex: '0x0',
  };
  const receipt = {
    transactionHash: transaction.hash, blockHash: transaction.blockHash, blockNumber: '0x10', transactionIndex: '0x0',
    from: transaction.from, to: transaction.to, status: '0x1', contractAddress: null, ...receiptChanges,
  };
  return { format: 'rnnet.anchor-observation.v1', network: 'evm:11155111', transaction, receipt };
};

test('the payload is exactly magic, version, format code and the digest bytes', () => {
  const payload = encodeAnchorPayload(COMMITMENT);
  assert.equal(payload.length, 42);
  assert.deepEqual([...payload.subarray(0, 8)], [...MAGIC]);
  assert.equal(new TextDecoder().decode(payload.subarray(0, 8)), 'RNNETANC');
  assert.deepEqual([payload[8], payload[9]], [1, 1]);
  assert.equal(hex(payload.subarray(10)), 'ab'.repeat(32));
  assert.equal(decodeAnchorPayload(payload), COMMITMENT);
  for (const bad of ['sha256:AB', `SHA256:${'ab'.repeat(32)}`, `sha256:${'AB'.repeat(32)}`, `sha512:${'ab'.repeat(32)}`, 7]) {
    assert.throws(() => encodeAnchorPayload(bad), TypeError);
  }
});

test('payload decoding: prefix, byte order and length confusion are rejected', () => {
  const payload = encodeAnchorPayload(COMMITMENT);
  const fails = (data, code) => assert.throws(() => decodeAnchorPayload(Uint8Array.from(data)), { code });
  fails([...payload].reverse(), 'RNAP_NOT_ANCHOR_PAYLOAD');
  fails([...new TextEncoder().encode('rnnet:evidence-commitment:v1'), 0, ...payload.subarray(10)], 'RNAP_NOT_ANCHOR_PAYLOAD');
  fails([0, ...payload], 'RNAP_NOT_ANCHOR_PAYLOAD');
  fails([...payload.subarray(0, 41)], 'RNAP_INVALID_LENGTH');
  fails([...payload, 0], 'RNAP_INVALID_LENGTH');
  fails([...payload.subarray(0, 8)], 'RNAP_INVALID_LENGTH');
});

test('a fake record can never be more than consistent with supplied data', () => {
  // Entirely fabricated but internally consistent data reaches level 2 and nothing more.
  for (const record of [verifyXrplObservation(bytes(xrpl()), COMMITMENT), verifyEvmObservation(bytes(evm()), COMMITMENT)]) {
    assert.equal(record.outcome, 'PASS');
    assert.equal(record.assurance, 'CONSISTENT_WITH_SUPPLIED_DATA');
    const classes = Object.fromEntries(record.statements.map((s) => [s.subject, s.classification]));
    assert.equal(classes.anchorPayload, 'VERIFIED');
    for (const subject of ['network', 'transactionStatus', 'inclusion', 'submitter']) assert.equal(classes[subject], 'CLAIMED');
    assert.equal(classes.transactionHash, 'UNRESOLVED');
  }
  const report = verifyDualAnchor({ xrpl: bytes(xrpl()), evm: bytes(evm()) }, COMMITMENT);
  assert.equal(report.outcome, 'PASS');
  assert.ok(!report.conclusions.includes(Conclusion.CHAIN_PROVEN));
  assert.ok(report.conclusions.includes(Conclusion.CHAIN_INCLUSION_UNVERIFIED));
  assert.ok(!JSON.stringify(report).includes('THIRD_PARTY_ATTESTED'));
});

test('spoofed status values never pass', () => {
  for (const validated of ['true', 1, null, false]) {
    const record = verifyXrplObservation(bytes(xrpl(undefined, { validated })), COMMITMENT);
    assert.notEqual(record.outcome, 'PASS', String(validated));
  }
  for (const TransactionResult of ['tesSUCCESS ', 'TESSUCCESS', 'tecCLAIM', undefined]) {
    const observation = xrpl();
    observation.tx.meta = { TransactionResult };
    assert.notEqual(verifyXrplObservation(bytes(observation), COMMITMENT).outcome, 'PASS', String(TransactionResult));
  }
  for (const status of ['0x01', '1', '0x2', 'success', '0x0']) {
    assert.notEqual(verifyEvmObservation(bytes(evm(undefined, { status })), COMMITMENT).outcome, 'PASS', status);
  }
});

test('the commitment must match exactly, on both networks', () => {
  assert.deepEqual(codes(verifyXrplObservation(bytes(xrpl()), OTHER)), ['RNAP_COMMITMENT_MISMATCH']);
  assert.deepEqual(codes(verifyEvmObservation(bytes(evm()), OTHER)), ['RNAP_COMMITMENT_MISMATCH']);
  const report = verifyDualAnchor({ xrpl: bytes(xrpl()), evm: bytes(evm(`0x${hex(encodeAnchorPayload(OTHER))}`)) }, COMMITMENT);
  assert.equal(report.outcome, 'FAIL');
  assert.deepEqual(report.conclusions, [Conclusion.CHAIN_INCLUSION_UNVERIFIED]);
  assert.ok(report.findings.some((f) => f.code === 'RNAD_PAYLOAD_DIFFERS'));
});

test('cross-chain substitution: each slot accepts only its own network', () => {
  const report = verifyDualAnchor({ xrpl: bytes(evm()), evm: bytes(xrpl()) }, COMMITMENT);
  assert.equal(report.records.xrpl.findings[0].code, 'RNAO_WRONG_NETWORK');
  assert.equal(report.records.evm.findings[0].code, 'RNAO_WRONG_NETWORK');
  assert.equal(report.outcome, 'FAIL');
});

test('records carry no input text and stay small', () => {
  const observation = xrpl();
  observation.tx.tx_json.Memos.push({ Memo: { MemoType: Buffer.from('Verified on two blockchains').toString('hex').toUpperCase(), MemoData: '00' } });
  observation.tx.close_time_iso = 'CHAIN_PROVEN';
  const text = new TextDecoder().decode(encodeAnchorReport(verifyXrplObservation(bytes(observation), COMMITMENT)));
  assert.ok(!/two blockchains|CHAIN_PROVEN|close_time/.test(text));
  const big = xrpl();
  big.tx.padding = 'x'.repeat(60_000);
  assert.ok(encodeAnchorReport(verifyXrplObservation(bytes(big), COMMITMENT)).length < 4096);
});

test('records are deterministic and frozen; inputs are copied and Proxies refused', () => {
  const input = bytes(evm());
  const a = encodeAnchorReport(verifyEvmObservation(input, COMMITMENT));
  const record = verifyEvmObservation(input, COMMITMENT);
  input.fill(0x20);
  assert.deepEqual(encodeAnchorReport(record), a);
  assert.ok(Object.isFrozen(record) && Object.isFrozen(record.statements));
  assert.throws(() => verifyEvmObservation(new Proxy(bytes(evm()), {}), COMMITMENT), TypeError);
  assert.throws(() => verifyEvmObservation(JSON.stringify(evm()), COMMITMENT), TypeError);
  assert.throws(() => verifyDualAnchor(null, COMMITMENT), TypeError);
  assert.throws(() => verifyDualAnchor({}, 'sha256:x'), TypeError);
});
