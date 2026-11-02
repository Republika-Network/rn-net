// Genesis Proof 01 preflight (RN-NET-03B2-A): the committed fixture and golden values, and the
// offline preparation checks of the intended XRPL Testnet and Sepolia transactions. Offline only.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { verifyCommitment } from '../packages/commitment/src/index.mjs';
import { verifyEvidence } from '../packages/verifier/src/index.mjs';
import { decodeAnchorPayload, encodeAnchorReport, verifyDualAnchor, verifyEvmObservation, verifyXrplObservation } from '../packages/anchor/src/index.mjs';
import { build, DIR, FILES } from './genesis/build-genesis-01.mjs';
import {
  checkSepoliaAnchorTx,
  checkXrplAnchorTx,
  intrinsicGas,
  memosSerializedLength,
  PREFLIGHT_LAST_LEDGER_OFFSET,
  rehearsalObservations,
  rehearsalTransactions,
  SEPOLIA,
  sepoliaAnchorTemplate,
  sepoliaMaxFee,
  XRPL,
  xrplAnchorTemplate,
} from './genesis/prepare.mjs';

const read = (name) => new Uint8Array(readFileSync(DIR + name));
const golden = JSON.parse(readFileSync(`${DIR}golden.json`, 'utf8'));
const COMMITMENT = golden.envelope.commitment;
const OTHER = 'sha256:7082efeb67d3252191c9a1b7d59c757ed82382b943460cc512c16859ba5e59ff';

test('the committed Genesis fixture is exactly what the generator builds', () => {
  const built = build();
  for (const name of FILES) assert.ok(Buffer.from(read(name)).equals(Buffer.from(built[name])), name);
});

test('the immutable golden file keeps its preflight offset; preparation binds + 80 (ADR-RN-016 Amendment C1)', () => {
  // RN-NET-03B2-C3 changed the binding offset, not the Genesis evidence, commitment or payload.
  assert.equal(PREFLIGHT_LAST_LEDGER_OFFSET, 20);
  assert.equal(golden.xrpl.lastLedgerOffset, PREFLIGHT_LAST_LEDGER_OFFSET);
  assert.equal(XRPL.lastLedgerOffset, 80);
  assert.equal(golden.envelope.commitment, 'sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7');
  assert.equal(golden.anchorPayload.length, 42);
});

test('the golden values are pinned', () => {
  assert.equal(COMMITMENT, 'sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7');
  assert.equal(golden.anchorPayload.hex, '524e4e4554414e430101a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7');
  assert.equal(golden.evidence.fileSha256, 'sha256:4a94ce939193dce631b1c0059c46dbfcbd7249885fe2e4ca330c87730ba6532f');
  assert.equal(golden.evidence.evidenceDigest, 'sha256:1551cf374a3abcdbd849663cc0b85033afc5b9a7e045ca211b6e724595f412f8');
});

test('RN-NET-02 verifies the evidence and its commitment; one changed byte fails', () => {
  const evidence = read('evidence.json');
  const envelope = read('envelope.json');
  const report = verifyEvidence(evidence, { commitment: { envelope, digest: COMMITMENT } });
  assert.equal(report.outcome, 'PASS');
  assert.deepEqual(report.findings, []);
  assert.equal(new TextDecoder().decode(encodeAnchorReport(report)), golden.evidence.verification.report);
  const tampered = Uint8Array.from(evidence);
  tampered[tampered.indexOf(0x31)] = 0x32; // the first "1" becomes "2"
  assert.notEqual(verifyEvidence(tampered, { commitment: { envelope, digest: COMMITMENT } }).outcome, 'PASS');
});

test('the RN-NET-01 commitment recomputes from the envelope bytes', () => {
  assert.deepEqual(verifyCommitment(read('envelope.json'), COMMITMENT).valid, true);
  assert.equal(verifyCommitment(read('envelope.json'), OTHER).valid, false);
});

test('the 42-byte payload decodes to the commitment', () => {
  const bytes = Buffer.from(golden.anchorPayload.hex, 'hex');
  assert.equal(bytes.length, 42);
  assert.equal(bytes.subarray(0, 10).toString('hex'), '524e4e4554414e430101');
  assert.equal(decodeAnchorPayload(bytes), COMMITMENT);
  assert.equal(golden.xrpl.memoData, golden.anchorPayload.hex.toUpperCase());
  assert.equal(golden.sepolia.input, `0x${golden.anchorPayload.hex}`);
});

// --- XRPL -------------------------------------------------------------------------------------

const xrplOk = () => rehearsalTransactions(COMMITMENT).xrpl;
const memoOf = (fields) => [{ Memo: fields }];
const { MemoType, MemoData } = xrplOk().Memos[0].Memo;

test('XRPL: the completed Genesis AccountSet passes; the unbound template does not', () => {
  assert.deepEqual(checkXrplAnchorTx(xrplOk(), COMMITMENT), []);
  assert.ok(checkXrplAnchorTx(xrplAnchorTemplate(COMMITMENT), COMMITMENT).length >= 3);
});

test('XRPL: every deviation from the intended construction is refused', () => {
  const cases = {
    'NetworkID present': { NetworkID: 1 },
    'Payment instead of AccountSet': { TransactionType: 'Payment' },
    'a settings field': { SetFlag: 8 },
    'a Domain': { Domain: '6578616D706C65' },
    'non-zero Flags': { Flags: 0x00010000 },
    'fee over the cap': { Fee: '1001' },
    'numeric fee': { Fee: 12 },
    'fee with a leading zero': { Fee: '012' },
    'no expiry': { LastLedgerSequence: undefined },
    'zero sequence': { Sequence: 0 },
    'secp256k1 signing key': { SigningPubKey: `02${'AB'.repeat(32)}` },
    'bad account': { Account: 'r0OIl' },
    'no memos': { Memos: [] },
    'two memos': { Memos: [...memoOf({ MemoType, MemoData }), ...memoOf({ MemoType, MemoData })] },
    'a MemoFormat': { Memos: memoOf({ MemoType, MemoData, MemoFormat: '746578742F706C61696E' }) },
    'lowercase MemoData': { Memos: memoOf({ MemoType, MemoData: MemoData.toLowerCase() }) },
    'another commitment': { Memos: memoOf({ MemoType, MemoData: `524E4E4554414E430101${OTHER.slice(7).toUpperCase()}` }) },
    'payload with trailing byte': { Memos: memoOf({ MemoType, MemoData: `${MemoData}00` }) },
    'memo wrapper with extra member': { Memos: [{ Memo: { MemoType, MemoData }, Extra: 1 }] },
  };
  for (const [name, change] of Object.entries(cases)) {
    const tx = { ...xrplOk(), ...change };
    for (const key of Object.keys(change)) if (change[key] === undefined) delete tx[key];
    assert.notDeepEqual(checkXrplAnchorTx(tx, COMMITMENT), [], name);
  }
  assert.notDeepEqual(checkXrplAnchorTx(xrplOk(), OTHER), [], 'checked against another commitment');
});

test('XRPL: the Memos field serializes to 73 bytes, under the 1 KB limit', () => {
  assert.equal(memosSerializedLength([[23, 42]]), 73);
  assert.equal(golden.xrpl.memosSerializedBytes, 73);
});

test('both checks refuse anything but plain JSON data (inherited fields, getters, proxies)', () => {
  const x = xrplOk();
  const e = rehearsalTransactions(COMMITMENT).evm;
  const xrplCases = {
    'every field inherited': Object.create(x),
    'inherited NetworkID': Object.assign(Object.create({ NetworkID: 0 }), x),
    'inherited memo': { ...x, Memos: [Object.create(x.Memos[0])] },
    'getter memo': { ...x, Memos: [Object.defineProperty({}, 'Memo', { get: () => x.Memos[0].Memo, enumerable: true })] },
    'proxy memo': { ...x, Memos: [new Proxy(x.Memos[0], {})] },
    'proxy transaction': new Proxy(x, {}),
    'symbol key': { ...x, [Symbol('extra')]: 1 },
  };
  for (const [name, tx] of Object.entries(xrplCases)) {
    assert.deepEqual(checkXrplAnchorTx(tx, COMMITMENT), ['transaction must be plain JSON data (no inherited fields, accessors or proxies)'], name);
  }
  const evmCases = {
    'inherited gasPrice': Object.assign(Object.create({ gasPrice: '0x1' }), e),
    'getter input': Object.defineProperty({ ...e }, 'input', { get: () => e.input, enumerable: true }),
    'proxy access list': { ...e, accessList: new Proxy([], {}) },
  };
  for (const [name, tx] of Object.entries(evmCases)) {
    assert.deepEqual(checkSepoliaAnchorTx(tx, COMMITMENT), ['transaction must be plain JSON data (no inherited fields, accessors or proxies)'], name);
  }
  // A JSON round trip of the accepted transactions is still accepted.
  assert.deepEqual(checkXrplAnchorTx(JSON.parse(JSON.stringify(x)), COMMITMENT), []);
  assert.deepEqual(checkSepoliaAnchorTx(JSON.parse(JSON.stringify(e)), COMMITMENT), []);
});

// --- Sepolia ----------------------------------------------------------------------------------

const evmOk = () => rehearsalTransactions(COMMITMENT).evm;

test('Sepolia: the completed Genesis transaction passes; the unbound template does not', () => {
  assert.deepEqual(checkSepoliaAnchorTx(evmOk(), COMMITMENT), []);
  assert.ok(checkSepoliaAnchorTx(sepoliaAnchorTemplate(COMMITMENT), COMMITMENT).length >= 3);
});

test('Sepolia: every deviation from the intended construction is refused', () => {
  const ok = evmOk();
  const cases = {
    'mainnet chainId': { chainId: '0x1' },
    'legacy type': { type: '0x0' },
    'blob type': { type: '0x3' },
    'contract creation': { to: null },
    'third-party recipient': { to: `0x${'11'.repeat(20)}` },
    'uppercase address': { from: ok.from.toUpperCase().replace('0X', '0x'), to: ok.from.toUpperCase().replace('0X', '0x') },
    'non-zero value': { value: '0x1' },
    'input with trailing byte': { input: `${ok.input}00` },
    'empty input': { input: '0x' },
    'another commitment': { input: `0x524e4e4554414e430101${OTHER.slice(7)}` },
    'non-empty access list': { accessList: [{ address: ok.from, storageKeys: [] }] },
    'gas below intrinsic': { gas: '0x5208' },
    'gas above limit': { gas: '0x7531' },
    'maxFee over cap': { maxFeePerGas: `0x${(SEPOLIA.maxFeePerGasCapWei + 1n).toString(16)}` },
    'priority above maxFee': { maxFeePerGas: '0x1', maxPriorityFeePerGas: '0x2' },
    'quantity with leading zero': { nonce: '0x00' },
    'unexpected data field': { data: ok.input },
    'missing nonce': { nonce: undefined },
  };
  for (const [name, change] of Object.entries(cases)) {
    const tx = { ...ok, ...change };
    for (const key of Object.keys(change)) if (change[key] === undefined) delete tx[key];
    assert.notDeepEqual(checkSepoliaAnchorTx(tx, COMMITMENT), [], name);
  }
});

test('Sepolia: intrinsic gas under Prague rules', () => {
  assert.deepEqual(intrinsicGas(Buffer.from(golden.anchorPayload.hex, 'hex')), { zeroBytes: 0, nonzeroBytes: 42, tokens: 168, standard: 21672, floor: 22680, gasUsed: 22680 });
  assert.equal(intrinsicGas(new Uint8Array(0)).gasUsed, 21000);
  assert.equal(intrinsicGas(new Uint8Array(10)).gasUsed, 21100); // ten zero bytes: floor 10 per token
  assert.ok(intrinsicGas(Buffer.from(golden.anchorPayload.hex, 'hex')).gasUsed < Number(SEPOLIA.gasLimit));
});

test('Sepolia: maxFeePerGas is 2 × base fee + tip, capped at 20 gwei', () => {
  assert.equal(sepoliaMaxFee('0x11'), `0x${(34n + 1_000_000_000n).toString(16)}`);
  assert.equal(sepoliaMaxFee(`0x${(100n * 1_000_000_000n).toString(16)}`), `0x${SEPOLIA.maxFeePerGasCapWei.toString(16)}`);
  assert.throws(() => sepoliaMaxFee('17'), TypeError);
});

// --- rehearsal --------------------------------------------------------------------------------

test('rehearsal: the intended transactions, as included, PASS the existing checks; never CHAIN_PROVEN', () => {
  const obs = rehearsalObservations(COMMITMENT);
  assert.equal(obs.xrpl, golden.rehearsal.xrplObservation);
  assert.equal(obs.evm, golden.rehearsal.evmObservation);
  const xrpl = verifyXrplObservation(Buffer.from(obs.xrpl), COMMITMENT);
  const evm = verifyEvmObservation(Buffer.from(obs.evm), COMMITMENT);
  assert.equal(xrpl.outcome, 'PASS');
  assert.equal(evm.outcome, 'PASS');
  assert.equal(evm.statements.find((s) => s.subject === 'finality').classification, 'UNRESOLVED');
  const dual = verifyDualAnchor({ xrpl: Buffer.from(obs.xrpl), evm: Buffer.from(obs.evm) }, COMMITMENT);
  assert.deepEqual(dual.conclusions, ['PAYLOAD_MATCH', 'RECORDS_CONSISTENT', 'CHAIN_INCLUSION_UNVERIFIED']);
  assert.equal(new TextDecoder().decode(encodeAnchorReport(dual)), golden.rehearsal.expectedReport);
  assert.equal(verifyDualAnchor({ xrpl: Buffer.from(obs.xrpl), evm: Buffer.from(obs.evm) }, OTHER).outcome, 'FAIL');
});

test('rehearsal values are labelled synthetic and the golden file holds no key material', () => {
  const text = readFileSync(`${DIR}golden.json`, 'utf8');
  assert.match(golden.synthetic, /synthetic/);
  assert.doesNotMatch(text, /privateKey|"seed"|mnemonic|TxnSignature|"secret"/i);
  assert.equal(golden.status, 'PREFLIGHT: not signed, not submitted, not anchored');
});
