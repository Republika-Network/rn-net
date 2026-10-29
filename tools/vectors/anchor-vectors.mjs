// Builds vectors/anchor/{payload,xrpl,evm,dual}.json: synthetic anchor payloads and synthetic
// XRPL Testnet and Ethereum Sepolia transaction records.
//
//   node tools/vectors/anchor-vectors.mjs           # check the committed files are current
//   node tools/vectors/anchor-vectors.mjs --write   # rewrite them
//
// Every transaction record here is SYNTHETIC. Hashes, ledger and block references and accounts
// are derived from labels ("rnnet:synthetic-...") and do not refer to anything on any network.
// No key is used and nothing is signed. Each case states its expected outcome and codes by hand;
// the build stops if the implementation disagrees. tools/reference/rnnet_anchor_reference.py
// rebuilds every expected record and report independently.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  ANCHOR_MEMO_TYPE,
  decodeAnchorPayload,
  encodeAnchorPayload,
  encodeAnchorReport,
  verifyDualAnchor,
  verifyEvmObservation,
  verifyXrplObservation,
} from '../../packages/anchor/src/index.mjs';

const OUT = (name) => fileURLToPath(new URL(`../../vectors/anchor/${name}.json`, import.meta.url));
const label = (text) => createHash('sha256').update(`rnnet:synthetic-${text}`).digest('hex');
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const json = (value) => JSON.stringify(value);
const text = (report) => new TextDecoder().decode(encodeAnchorReport(report));

// The commitment of the RN-NET-02 vector "valid-with-commitment", and a different one.
const COMMITMENT = 'sha256:ff8cc6f9c6d9c71c8f25c7c5c7d89deb089922c347f9eba499888773eacbfffd';
const OTHER = 'sha256:7082efeb67d3252191c9a1b7d59c757ed82382b943460cc512c16859ba5e59ff';
const PAYLOAD = hex(encodeAnchorPayload(COMMITMENT));
const withByte = (payloadHex, offset, value) => payloadHex.slice(0, offset * 2) + value + payloadHex.slice(offset * 2 + 2);

// --- payload ---------------------------------------------------------------------------------
function payloadCases() {
  return [
    { id: 'valid', payloadHex: PAYLOAD, expectedCommitment: COMMITMENT },
    { id: 'valid-other-commitment', payloadHex: hex(encodeAnchorPayload(OTHER)), expectedCommitment: OTHER },
    { id: 'wrong-version', payloadHex: withByte(PAYLOAD, 8, '02'), expectedError: 'RNAP_UNSUPPORTED_VERSION' },
    { id: 'version-zero', payloadHex: withByte(PAYLOAD, 8, '00'), expectedError: 'RNAP_UNSUPPORTED_VERSION' },
    { id: 'wrong-magic', payloadHex: `524e4e4554414e44${PAYLOAD.slice(16)}`, expectedError: 'RNAP_NOT_ANCHOR_PAYLOAD' },
    { id: 'lowercase-magic', payloadHex: `726e6e6574616e63${PAYLOAD.slice(16)}`, expectedError: 'RNAP_NOT_ANCHOR_PAYLOAD' },
    { id: 'empty', payloadHex: '', expectedError: 'RNAP_NOT_ANCHOR_PAYLOAD' },
    { id: 'magic-only', payloadHex: PAYLOAD.slice(0, 16), expectedError: 'RNAP_INVALID_LENGTH' },
    { id: 'truncated', payloadHex: PAYLOAD.slice(0, 82), expectedError: 'RNAP_INVALID_LENGTH' },
    { id: 'extra-bytes', payloadHex: `${PAYLOAD}00`, expectedError: 'RNAP_INVALID_LENGTH' },
    { id: 'payload-twice', payloadHex: PAYLOAD + PAYLOAD, expectedError: 'RNAP_INVALID_LENGTH' },
    { id: 'digest-of-31-bytes', payloadHex: PAYLOAD.slice(0, -2), expectedError: 'RNAP_INVALID_LENGTH' },
    { id: 'digest-of-33-bytes', payloadHex: `${PAYLOAD}ff`, expectedError: 'RNAP_INVALID_LENGTH' },
    { id: 'unsupported-commitment-format', payloadHex: withByte(PAYLOAD, 9, '02'), expectedError: 'RNAP_UNSUPPORTED_COMMITMENT_FORMAT' },
    { id: 'version-2-other-length', payloadHex: `${withByte(PAYLOAD, 8, '02')}0000`, expectedError: 'RNAP_UNSUPPORTED_VERSION' },
    { id: 'digest-reversed-byte-order', payloadHex: PAYLOAD.slice(0, 20) + Buffer.from(PAYLOAD.slice(20), 'hex').reverse().toString('hex'), expectedCommitment: `sha256:${Buffer.from(COMMITMENT.slice(7), 'hex').reverse().toString('hex')}` },
  ].map((v) => {
    let result;
    try {
      result = { commitment: decodeAnchorPayload(Buffer.from(v.payloadHex, 'hex')) };
    } catch (error) {
      result = { error: error.code };
    }
    const ok = v.expectedError ? result.error === v.expectedError : result.commitment === v.expectedCommitment;
    if (!ok) throw new Error(`payload ${v.id}: ${JSON.stringify(result)}`);
    return v;
  });
}

// --- XRPL ------------------------------------------------------------------------------------
const XRPL_LEDGER = 4242424;
const XRPL_TX_INDEX = 3;
const ctid = (ledger, index, network) => `C${((BigInt(ledger) << 32n) | (BigInt(index) << 16n) | BigInt(network)).toString(16).toUpperCase().padStart(15, '0')}`;
const memo = (fields) => ({ Memo: fields });
const anchorMemo = (payloadHex = PAYLOAD) => memo({ MemoType: ANCHOR_MEMO_TYPE, MemoData: payloadHex.toUpperCase() });

function xrplTx(changes = {}, jsonChanges = {}, metaChanges = {}) {
  return {
    hash: label('xrpl-tx-1').toUpperCase(),
    ledger_index: XRPL_LEDGER,
    ledger_hash: label('xrpl-ledger-4242424').toUpperCase(),
    validated: true,
    ctid: ctid(XRPL_LEDGER, XRPL_TX_INDEX, 1),
    close_time_iso: '2026-10-29T00:00:00Z',
    meta: { TransactionIndex: XRPL_TX_INDEX, TransactionResult: 'tesSUCCESS', ...metaChanges },
    tx_json: {
      TransactionType: 'AccountSet',
      Account: 'rSyntheticAnchorTestAccount1111',
      Fee: '12',
      Sequence: 7,
      Memos: [anchorMemo()],
      ...jsonChanges,
    },
    ...changes,
  };
}
const xrplObservation = (tx, changes = {}) => json({ format: 'rnnet.anchor-observation.v1', network: 'xrpl:testnet', tx, ...changes });
const without = (object, key) => Object.fromEntries(Object.entries(object).filter(([k]) => k !== key));

function xrplCases() {
  const unrelated = memo({ MemoType: Buffer.from('example/note').toString('hex').toUpperCase(), MemoData: '48656C6C6F' });
  return [
    ['valid', 'A validated, successful AccountSet with one anchor memo.', xrplObservation(xrplTx()), COMMITMENT, 'PASS', []],
    ['valid-with-unrelated-memos', 'The anchor memo among unrelated memos.', xrplObservation(xrplTx({}, { Memos: [unrelated, anchorMemo(), unrelated] })), COMMITMENT, 'PASS', []],
    ['valid-without-ctid', 'No ctid: nothing to cross-check.', xrplObservation(without(xrplTx(), 'ctid')), COMMITMENT, 'PASS', []],
    ['missing-memo', 'No Memos field.', xrplObservation(xrplTx({}, { Memos: undefined })), COMMITMENT, 'FAIL', ['RNAX_MISSING_ANCHOR']],
    ['only-unrelated-memos', 'Memos, but none of the anchor MemoType.', xrplObservation(xrplTx({}, { Memos: [unrelated] })), COMMITMENT, 'FAIL', ['RNAX_MISSING_ANCHOR']],
    ['wrong-memo-type', 'The payload under another MemoType (a v2 name).', xrplObservation(xrplTx({}, { Memos: [memo({ MemoType: Buffer.from('rnnet.anchor-payload.v2').toString('hex').toUpperCase(), MemoData: PAYLOAD.toUpperCase() })] })), COMMITMENT, 'FAIL', ['RNAX_MISSING_ANCHOR']],
    ['memo-type-lowercase-hex', 'The anchor MemoType in lowercase hex.', xrplObservation(xrplTx({}, { Memos: [memo({ MemoType: ANCHOR_MEMO_TYPE.toLowerCase(), MemoData: PAYLOAD.toUpperCase() })] })), COMMITMENT, 'FAIL', ['RNAX_MALFORMED_MEMO']],
    ['duplicate-anchor-memos', 'Two identical anchor memos: ambiguous.', xrplObservation(xrplTx({}, { Memos: [anchorMemo(), anchorMemo()] })), COMMITMENT, 'FAIL', ['RNAX_DUPLICATE_ANCHOR']],
    ['conflicting-anchor-memos', 'Two anchor memos for different commitments.', xrplObservation(xrplTx({}, { Memos: [anchorMemo(), anchorMemo(hex(encodeAnchorPayload(OTHER)))] })), COMMITMENT, 'FAIL', ['RNAX_DUPLICATE_ANCHOR']],
    ['memo-format-present', 'The anchor memo with a MemoFormat.', xrplObservation(xrplTx({}, { Memos: [memo({ MemoType: ANCHOR_MEMO_TYPE, MemoData: PAYLOAD.toUpperCase(), MemoFormat: '746578742F706C61696E' })] })), COMMITMENT, 'FAIL', ['RNAX_MALFORMED_MEMO']],
    ['memo-data-invalid-hex', 'MemoData with a non-hex character.', xrplObservation(xrplTx({}, { Memos: [memo({ MemoType: ANCHOR_MEMO_TYPE, MemoData: `${PAYLOAD.toUpperCase().slice(0, -1)}G` })] })), COMMITMENT, 'FAIL', ['RNAX_MALFORMED_MEMO']],
    ['memo-data-odd-length', 'MemoData with an odd number of hex digits.', xrplObservation(xrplTx({}, { Memos: [memo({ MemoType: ANCHOR_MEMO_TYPE, MemoData: PAYLOAD.toUpperCase().slice(0, -1) })] })), COMMITMENT, 'FAIL', ['RNAX_MALFORMED_MEMO']],
    ['memo-data-lowercase', 'MemoData in lowercase hex.', xrplObservation(xrplTx({}, { Memos: [memo({ MemoType: ANCHOR_MEMO_TYPE, MemoData: PAYLOAD })] })), COMMITMENT, 'FAIL', ['RNAX_MALFORMED_MEMO']],
    ['memo-extra-member', 'A memo with a member outside the memo schema.', xrplObservation(xrplTx({}, { Memos: [memo({ MemoType: ANCHOR_MEMO_TYPE, MemoData: PAYLOAD.toUpperCase(), MemoNote: '00' })] })), COMMITMENT, 'FAIL', ['RNAX_MALFORMED_MEMO']],
    ['too-many-memos', 'Thirty-three memos.', xrplObservation(xrplTx({}, { Memos: [anchorMemo(), ...Array(32).fill(unrelated)] })), COMMITMENT, 'FAIL', ['RNAX_MALFORMED_MEMO']],
    ['memo-not-anchor-payload', 'An anchor memo whose data is not an anchor payload.', xrplObservation(xrplTx({}, { Memos: [anchorMemo('48656c6c6f')] })), COMMITMENT, 'FAIL', ['RNAP_NOT_ANCHOR_PAYLOAD']],
    ['memo-payload-trailing-bytes', 'The payload followed by extra bytes.', xrplObservation(xrplTx({}, { Memos: [anchorMemo(`${PAYLOAD}00`)] })), COMMITMENT, 'FAIL', ['RNAP_INVALID_LENGTH']],
    ['incorrect-commitment', 'A well-formed anchor for another commitment.', xrplObservation(xrplTx()), OTHER, 'FAIL', ['RNAP_COMMITMENT_MISMATCH']],
    ['unsupported-payload-version', 'A version 2 payload.', xrplObservation(xrplTx({}, { Memos: [anchorMemo(withByte(PAYLOAD, 8, '02'))] })), COMMITMENT, 'UNSUPPORTED', ['RNAP_UNSUPPORTED_VERSION']],
    ['unvalidated-ledger', 'validated: false; the payload is correct.', xrplObservation(xrplTx({ validated: false })), COMMITMENT, 'FAIL', ['RNAX_NOT_VALIDATED']],
    ['unsuccessful-transaction', 'TransactionResult tecNO_PERMISSION; the payload is correct.', xrplObservation(xrplTx({}, {}, { TransactionResult: 'tecNO_PERMISSION' })), COMMITMENT, 'FAIL', ['RNAX_TRANSACTION_NOT_SUCCESSFUL']],
    ['unvalidated-and-wrong-commitment', 'Two independent findings: the anchor and the status.', xrplObservation(xrplTx({ validated: false })), OTHER, 'FAIL', ['RNAP_COMMITMENT_MISMATCH', 'RNAX_NOT_VALIDATED']],
    ['invalid-transaction-hash-lowercase', 'The transaction hash in lowercase hex.', xrplObservation(xrplTx({ hash: label('xrpl-tx-1') })), COMMITMENT, 'FAIL', ['RNAX_INVALID_HASH']],
    ['invalid-transaction-hash-short', 'A 63-digit transaction hash.', xrplObservation(xrplTx({ hash: label('xrpl-tx-1').toUpperCase().slice(1) })), COMMITMENT, 'FAIL', ['RNAX_INVALID_HASH']],
    ['missing-hash', 'No transaction hash.', xrplObservation(without(xrplTx(), 'hash')), COMMITMENT, 'FAIL', ['RNAX_MISSING_FIELD']],
    ['wrong-network-network-id', 'A NetworkID field (21338): not XRPL Testnet.', xrplObservation(xrplTx({}, { NetworkID: 21338 })), COMMITMENT, 'FAIL', ['RNAX_WRONG_NETWORK']],
    ['wrong-network-ctid', 'A ctid naming network 0 (Mainnet).', xrplObservation(xrplTx({ ctid: ctid(XRPL_LEDGER, XRPL_TX_INDEX, 0) })), COMMITMENT, 'FAIL', ['RNAX_WRONG_NETWORK']],
    ['wrong-network-observation', 'An observation labelled for Sepolia given as XRPL.', xrplObservation(xrplTx(), { network: 'evm:11155111' }), COMMITMENT, 'FAIL', ['RNAO_WRONG_NETWORK']],
    ['contradictory-ledger-ctid', 'A ctid naming another ledger.', xrplObservation(xrplTx({ ctid: ctid(XRPL_LEDGER + 1, XRPL_TX_INDEX, 1) })), COMMITMENT, 'FAIL', ['RNAX_CONTRADICTORY_REFERENCE']],
    ['contradictory-transaction-index', 'A ctid naming another position in the ledger.', xrplObservation(xrplTx({}, {}, { TransactionIndex: XRPL_TX_INDEX + 1 })), COMMITMENT, 'FAIL', ['RNAX_CONTRADICTORY_REFERENCE']],
    ['contradictory-ledger-index', 'tx_json.ledger_index differs from ledger_index.', xrplObservation(xrplTx({}, { ledger_index: XRPL_LEDGER - 1 })), COMMITMENT, 'FAIL', ['RNAX_CONTRADICTORY_REFERENCE']],
    ['contradictory-hash', 'tx_json.hash differs from hash.', xrplObservation(xrplTx({}, { hash: label('xrpl-tx-2').toUpperCase() })), COMMITMENT, 'FAIL', ['RNAX_CONTRADICTORY_REFERENCE']],
    ['ctid-without-transaction-index', 'A ctid with no meta.TransactionIndex to check it against.', xrplObservation(xrplTx({}, {}, { TransactionIndex: undefined })), COMMITMENT, 'FAIL', ['RNAX_MISSING_FIELD']],
    ['transaction-index-string', 'meta.TransactionIndex as a string.', xrplObservation(xrplTx({}, {}, { TransactionIndex: '3' })), COMMITMENT, 'FAIL', ['RNAX_FIELD_TYPE']],
    ['tx-json-ctid-only', 'A ctid inside tx_json only, consistent: as in the API v2 example.', xrplObservation(xrplTx({ ctid: undefined }, { ctid: ctid(XRPL_LEDGER, XRPL_TX_INDEX, 1) })), COMMITMENT, 'PASS', []],
    ['tx-json-ctid-both-consistent', 'The same ctid at the top level and inside tx_json.', xrplObservation(xrplTx({}, { ctid: ctid(XRPL_LEDGER, XRPL_TX_INDEX, 1) })), COMMITMENT, 'PASS', []],
    ['tx-json-ctid-mainnet', 'A tx_json.ctid naming network 0 (Mainnet).', xrplObservation(xrplTx({}, { ctid: ctid(XRPL_LEDGER, XRPL_TX_INDEX, 0) })), COMMITMENT, 'FAIL', ['RNAX_WRONG_NETWORK']],
    ['tx-json-ctid-mainnet-only', 'Only a tx_json.ctid, naming network 0.', xrplObservation(xrplTx({ ctid: undefined }, { ctid: ctid(XRPL_LEDGER, XRPL_TX_INDEX, 0) })), COMMITMENT, 'FAIL', ['RNAX_WRONG_NETWORK']],
    ['tx-json-ctid-contradicts', 'A tx_json.ctid for another ledger than the top-level ctid.', xrplObservation(xrplTx({}, { ctid: ctid(XRPL_LEDGER + 1, XRPL_TX_INDEX, 1) })), COMMITMENT, 'FAIL', ['RNAX_CONTRADICTORY_REFERENCE']],
    ['tx-json-ctid-invalid', 'A malformed tx_json.ctid.', xrplObservation(xrplTx({}, { ctid: 'zz' })), COMMITMENT, 'FAIL', ['RNAX_INVALID_CTID']],
    ['memo-empty', 'An empty Memo object.', xrplObservation(xrplTx({}, { Memos: [memo({}), anchorMemo()] })), COMMITMENT, 'FAIL', ['RNAX_MALFORMED_MEMO']],
    ['accountset-changes-settings', 'An AccountSet that also sets a flag: not a no-op anchor.', xrplObservation(xrplTx({}, { SetFlag: 8 })), COMMITMENT, 'UNSUPPORTED', ['RNAX_UNSUPPORTED_TRANSACTION_TYPE']],
    ['accountset-flags-require-dest-tag', 'Flags with tfRequireDestTag: the transaction changes a setting.', xrplObservation(xrplTx({}, { Flags: 65536 })), COMMITMENT, 'UNSUPPORTED', ['RNAX_UNSUPPORTED_TRANSACTION_TYPE']],
    ['accountset-flags-disallow-xrp', 'Flags with tfDisallowXRP.', xrplObservation(xrplTx({}, { Flags: 1048576 })), COMMITMENT, 'UNSUPPORTED', ['RNAX_UNSUPPORTED_TRANSACTION_TYPE']],
    ['accountset-flags-fully-canonical', 'Flags with only tfFullyCanonicalSig: no setting changes.', xrplObservation(xrplTx({}, { Flags: 2147483648 })), COMMITMENT, 'PASS', []],
    ['accountset-flags-string', 'Flags as a string.', xrplObservation(xrplTx({}, { Flags: '0' })), COMMITMENT, 'FAIL', ['RNAX_FIELD_TYPE']],
    ['ctids-differ-and-no-transaction-index', 'Two different CTIDs and no TransactionIndex: the CTID comparison comes first.', xrplObservation(xrplTx({}, { ctid: ctid(XRPL_LEDGER + 1, XRPL_TX_INDEX, 1) }, { TransactionIndex: undefined })), COMMITMENT, 'FAIL', ['RNAX_CONTRADICTORY_REFERENCE']],
    ['unvalidated-with-unsupported-payload', 'An unsupported payload in an unvalidated transaction: the failure wins.', xrplObservation(xrplTx({ validated: false }, { Memos: [anchorMemo(withByte(PAYLOAD, 8, '02'))] })), COMMITMENT, 'FAIL', ['RNAP_UNSUPPORTED_VERSION', 'RNAX_NOT_VALIDATED']],
    ['invalid-ctid', 'A ctid not starting with C.', xrplObservation(xrplTx({ ctid: `D${ctid(XRPL_LEDGER, XRPL_TX_INDEX, 1).slice(1)}` })), COMMITMENT, 'FAIL', ['RNAX_INVALID_CTID']],
    ['ledger-index-zero', 'Ledger index 0.', xrplObservation(xrplTx({ ledger_index: 0, ctid: undefined })), COMMITMENT, 'FAIL', ['RNAX_INVALID_LEDGER_INDEX']],
    ['validated-as-string', 'validated: "true" (a string): a spoofed status is a type error.', xrplObservation(xrplTx({ validated: 'true' })), COMMITMENT, 'FAIL', ['RNAX_FIELD_TYPE']],
    ['payment-transaction', 'A Payment carrying the memo: not the anchoring transaction type.', xrplObservation(xrplTx({}, { TransactionType: 'Payment' })), COMMITMENT, 'UNSUPPORTED', ['RNAX_UNSUPPORTED_TRANSACTION_TYPE']],
    ['invalid-account', 'An account that is not an XRPL address.', xrplObservation(xrplTx({}, { Account: '0xabc' })), COMMITMENT, 'FAIL', ['RNAX_INVALID_ACCOUNT']],
    ['api-v1-shape', 'An API v1 result (no tx_json): not supported.', xrplObservation(without(xrplTx(), 'tx_json')), COMMITMENT, 'FAIL', ['RNAX_MISSING_FIELD']],
    ['observation-extra-member', 'An observation with an extra member.', xrplObservation(xrplTx(), { note: 'trust me' }), COMMITMENT, 'FAIL', ['RNAO_UNKNOWN_FIELD']],
    ['observation-unsupported-version', 'An observation of a later version.', xrplObservation(xrplTx(), { format: 'rnnet.anchor-observation.v2' }), COMMITMENT, 'UNSUPPORTED', ['RNAO_UNSUPPORTED_VERSION']],
    ['observation-float', 'A non-integer number in the supplied data.', xrplObservation(xrplTx({ ledger_index: 4242424.5 })), COMMITMENT, 'FAIL', ['RNCJ_NUMBER_NOT_INTEGER']],
    ['observation-too-large', 'An observation over 65,536 bytes.', xrplObservation(xrplTx({ padding: 'x'.repeat(66_000) })), COMMITMENT, 'FAIL', ['RNAO_TOO_LARGE']],
  ].map(([id, description, input, commitment, outcome, codes]) => build('xrpl', verifyXrplObservation, { id, description, input, commitment, outcome, codes }));
}

// --- Sepolia ---------------------------------------------------------------------------------
const ADDRESS = `0x${label('evm-account').slice(0, 40)}`;
function evmPair(txChanges = {}, receiptChanges = {}) {
  const transaction = {
    hash: `0x${label('evm-tx-1')}`,
    chainId: '0xaa36a7',
    type: '0x2',
    nonce: '0x7',
    from: ADDRESS,
    to: ADDRESS,
    value: '0x0',
    gas: '0x5a3c',
    input: `0x${PAYLOAD}`,
    blockHash: `0x${label('evm-block-7162922')}`,
    blockNumber: '0x6d4c2a',
    transactionIndex: '0x5',
    ...txChanges,
  };
  const receipt = {
    transactionHash: transaction.hash,
    blockHash: transaction.blockHash,
    blockNumber: transaction.blockNumber,
    transactionIndex: transaction.transactionIndex,
    from: transaction.from,
    to: transaction.to,
    status: '0x1',
    contractAddress: null,
    gasUsed: '0x5a3c',
    logs: [],
    ...receiptChanges,
  };
  return { transaction, receipt };
}
const evmObservation = ({ transaction, receipt }, changes = {}) => json({ format: 'rnnet.anchor-observation.v1', network: 'evm:11155111', transaction, receipt, ...changes });
const pending = () => {
  const pair = evmPair({ blockHash: null, blockNumber: null, transactionIndex: null });
  return { transaction: pair.transaction, receipt: null };
};

function evmCases() {
  const base = evmPair();
  return [
    ['valid', 'An included, successful type-2 transaction whose input is the anchor payload.', evmObservation(base), COMMITMENT, 'PASS', []],
    ['valid-legacy-type', 'A type-0 transaction with a chainId.', evmObservation(evmPair({ type: '0x0' })), COMMITMENT, 'PASS', []],
    ['empty-input', 'Input 0x.', evmObservation(evmPair({ input: '0x' })), COMMITMENT, 'FAIL', ['RNAE_MISSING_ANCHOR']],
    ['malformed-payload', 'Input that is not an anchor payload.', evmObservation(evmPair({ input: '0xa9059cbb' })), COMMITMENT, 'FAIL', ['RNAP_NOT_ANCHOR_PAYLOAD']],
    ['payload-with-prefix', 'A 4-byte selector before the payload.', evmObservation(evmPair({ input: `0xa9059cbb${PAYLOAD}` })), COMMITMENT, 'FAIL', ['RNAP_NOT_ANCHOR_PAYLOAD']],
    ['duplicate-payload-in-input', 'The payload twice in one input: ambiguous, rejected by length.', evmObservation(evmPair({ input: `0x${PAYLOAD}${PAYLOAD}` })), COMMITMENT, 'FAIL', ['RNAP_INVALID_LENGTH']],
    ['input-uppercase-hex', 'Input in uppercase hex.', evmObservation(evmPair({ input: `0x${PAYLOAD.toUpperCase()}` })), COMMITMENT, 'FAIL', ['RNAE_INVALID_INPUT']],
    ['input-odd-length', 'Input with an odd number of hex digits.', evmObservation(evmPair({ input: `0x${PAYLOAD}0` })), COMMITMENT, 'FAIL', ['RNAE_INVALID_INPUT']],
    ['reverted', 'Receipt status 0x0; the payload is correct.', evmObservation(evmPair({}, { status: '0x0' })), COMMITMENT, 'FAIL', ['RNAE_TRANSACTION_REVERTED']],
    ['status-spoofed', 'Receipt status "0x01": not a canonical quantity.', evmObservation(evmPair({}, { status: '0x01' })), COMMITMENT, 'FAIL', ['RNAE_INVALID_STATUS']],
    ['pending', 'No block, no receipt; the payload is correct.', evmObservation(pending()), COMMITMENT, 'FAIL', ['RNAE_PENDING']],
    ['receipt-without-block', 'A receipt for a transaction whose block fields are null.', evmObservation({ transaction: pending().transaction, receipt: base.receipt }), COMMITMENT, 'FAIL', ['RNAE_CONFLICTING_BLOCK_REFERENCE']],
    ['incorrect-chain-id-mainnet', 'chainId 0x1 (Ethereum Mainnet).', evmObservation(evmPair({ chainId: '0x1' })), COMMITMENT, 'FAIL', ['RNAE_WRONG_NETWORK']],
    ['incorrect-chain-id-holesky', 'chainId 0x4268 (Holesky).', evmObservation(evmPair({ chainId: '0x4268' })), COMMITMENT, 'FAIL', ['RNAE_WRONG_NETWORK']],
    ['chain-id-decimal', 'chainId as a decimal string.', evmObservation(evmPair({ chainId: '11155111' })), COMMITMENT, 'FAIL', ['RNAE_FIELD_TYPE']],
    ['chain-id-leading-zero', 'chainId 0x0aa36a7: not a canonical quantity.', evmObservation(evmPair({ chainId: '0x0aa36a7' })), COMMITMENT, 'FAIL', ['RNAE_FIELD_TYPE']],
    ['missing-chain-id', 'A transaction without chainId.', evmObservation({ ...base, transaction: without(base.transaction, 'chainId') }), COMMITMENT, 'FAIL', ['RNAE_MISSING_FIELD']],
    ['wrong-network-observation', 'An observation labelled XRPL given as Sepolia.', evmObservation(base, { network: 'xrpl:testnet' }), COMMITMENT, 'FAIL', ['RNAO_WRONG_NETWORK']],
    ['incorrect-transaction-hash', 'A transaction hash of 31 bytes.', evmObservation(evmPair({ hash: `0x${label('evm-tx-1').slice(2)}` })), COMMITMENT, 'FAIL', ['RNAE_INVALID_HASH']],
    ['transaction-hash-uppercase', 'A transaction hash in uppercase hex.', evmObservation(evmPair({ hash: `0x${label('evm-tx-1').toUpperCase()}` })), COMMITMENT, 'FAIL', ['RNAE_INVALID_HASH']],
    ['receipt-for-other-transaction', 'A receipt whose transactionHash is another transaction.', evmObservation(evmPair({}, { transactionHash: `0x${label('evm-tx-2')}` })), COMMITMENT, 'FAIL', ['RNAE_RECEIPT_MISMATCH']],
    ['receipt-other-sender', 'A receipt naming another sender.', evmObservation(evmPair({}, { from: `0x${label('evm-other').slice(0, 40)}` })), COMMITMENT, 'FAIL', ['RNAE_RECEIPT_MISMATCH']],
    ['conflicting-block-hash', 'Receipt and transaction name different blocks.', evmObservation(evmPair({}, { blockHash: `0x${label('evm-block-other')}` })), COMMITMENT, 'FAIL', ['RNAE_CONFLICTING_BLOCK_REFERENCE']],
    ['conflicting-block-number', 'Receipt and transaction name different block numbers.', evmObservation(evmPair({}, { blockNumber: '0x6d4c2b' })), COMMITMENT, 'FAIL', ['RNAE_CONFLICTING_BLOCK_REFERENCE']],
    ['conflicting-transaction-index', 'Receipt and transaction name different positions.', evmObservation(evmPair({}, { transactionIndex: '0x6' })), COMMITMENT, 'FAIL', ['RNAE_CONFLICTING_BLOCK_REFERENCE']],
    ['partial-block-reference', 'A blockHash with no blockNumber.', evmObservation(evmPair({ blockNumber: null })), COMMITMENT, 'FAIL', ['RNAE_INVALID_BLOCK_REFERENCE']],
    ['incorrect-payload-digest', 'A well-formed anchor for another commitment.', evmObservation(base), OTHER, 'FAIL', ['RNAP_COMMITMENT_MISMATCH']],
    ['tampered-input-one-bit', 'One bit of the digest flipped.', evmObservation(evmPair({ input: `0x${PAYLOAD.slice(0, -1)}${(Number.parseInt(PAYLOAD.at(-1), 16) ^ 1).toString(16)}` })), COMMITMENT, 'FAIL', ['RNAP_COMMITMENT_MISMATCH']],
    ['contract-creation', 'to: null (contract creation).', evmObservation(evmPair({ to: null }, { to: null })), COMMITMENT, 'FAIL', ['RNAE_CONTRACT_CREATION']],
    ['receipt-contract-address', 'A receipt reporting a created contract.', evmObservation(evmPair({}, { contractAddress: ADDRESS })), COMMITMENT, 'FAIL', ['RNAE_CONTRACT_CREATION']],
    ['blob-transaction', 'A type-3 (blob) transaction: an unsupported transport.', evmObservation(evmPair({ type: '0x3' })), COMMITMENT, 'UNSUPPORTED', ['RNAE_UNSUPPORTED_TRANSACTION_TYPE']],
    ['checksummed-address', 'A mixed-case (checksummed) address, which JSON-RPC does not return.', evmObservation(evmPair({ from: ADDRESS.toUpperCase().replace('0X', '0x') })), COMMITMENT, 'FAIL', ['RNAE_INVALID_ADDRESS']],
    ['receipt-status-number', 'A receipt status given as the number 1.', evmObservation(evmPair({}, { status: 1 })), COMMITMENT, 'FAIL', ['RNAE_FIELD_TYPE']],
  ].map(([id, description, input, commitment, outcome, codes]) => build('evm', verifyEvmObservation, { id, description, input, commitment, outcome, codes }));
}

function build(kind, verify, { id, description, input, commitment, outcome, codes }) {
  const record = verify(new TextEncoder().encode(input), commitment);
  const found = record.findings.map((f) => f.code);
  if (record.outcome !== outcome || json(found) !== json(codes)) throw new Error(`${kind} ${id}: expected ${outcome} ${codes}, got ${record.outcome} ${found}`);
  return { id, description, input, expectedCommitment: commitment, expectedOutcome: outcome, expectedFindings: codes, expectedRecord: text(record) };
}

// --- dual ------------------------------------------------------------------------------------
function dualCases() {
  const xrplOk = xrplObservation(xrplTx());
  const evmOk = evmObservation(evmPair());
  const xrplOther = xrplObservation(xrplTx({}, { Memos: [anchorMemo(hex(encodeAnchorPayload(OTHER)))] }));
  return [
    ['same-commitment-both', 'The same commitment, consistently, in the data supplied for both networks: PASS, chain inclusion unverified.', { xrpl: xrplOk, evm: evmOk }, COMMITMENT, 'PASS', ['PAYLOAD_MATCH', 'RECORDS_CONSISTENT', 'CHAIN_INCLUSION_UNVERIFIED'], []],
    ['different-commitments', 'XRPL anchors another commitment.', { xrpl: xrplOther, evm: evmOk }, COMMITMENT, 'FAIL', ['CHAIN_INCLUSION_UNVERIFIED'], ['RNAD_RECORD_NOT_PASSED', 'RNAD_PAYLOAD_DIFFERS']],
    ['wrong-network-pairing', 'The two observations swapped between slots.', { xrpl: evmOk, evm: xrplOk }, COMMITMENT, 'FAIL', ['CHAIN_INCLUSION_UNVERIFIED'], ['RNAD_RECORD_NOT_PASSED', 'RNAD_RECORD_NOT_PASSED']],
    ['same-network-twice', 'Two XRPL observations.', { xrpl: xrplOk, evm: xrplOk }, COMMITMENT, 'FAIL', ['CHAIN_INCLUSION_UNVERIFIED'], ['RNAD_RECORD_NOT_PASSED']],
    ['missing-evm', 'No Sepolia observation.', { xrpl: xrplOk }, COMMITMENT, 'FAIL', ['CHAIN_INCLUSION_UNVERIFIED'], ['RNAD_MISSING_RECORD']],
    ['missing-xrpl', 'No XRPL observation.', { evm: evmOk }, COMMITMENT, 'FAIL', ['CHAIN_INCLUSION_UNVERIFIED'], ['RNAD_MISSING_RECORD']],
    ['one-unsuccessful', 'Sepolia reverted; the payloads still match.', { xrpl: xrplOk, evm: evmObservation(evmPair({}, { status: '0x0' })) }, COMMITMENT, 'FAIL', ['PAYLOAD_MATCH', 'CHAIN_INCLUSION_UNVERIFIED'], ['RNAD_RECORD_NOT_PASSED']],
    ['one-unvalidated', 'XRPL not validated; the payloads still match.', { xrpl: xrplObservation(xrplTx({ validated: false })), evm: evmOk }, COMMITMENT, 'FAIL', ['PAYLOAD_MATCH', 'CHAIN_INCLUSION_UNVERIFIED'], ['RNAD_RECORD_NOT_PASSED']],
    ['tampered-transaction-input', 'Sepolia input tampered.', { xrpl: xrplOk, evm: evmObservation(evmPair({ input: `0x${PAYLOAD.slice(0, -2)}00` })) }, COMMITMENT, 'FAIL', ['CHAIN_INCLUSION_UNVERIFIED'], ['RNAD_RECORD_NOT_PASSED', 'RNAD_PAYLOAD_DIFFERS']],
    ['unsupported-anchor-version', 'Both anchors use payload version 2.', { xrpl: xrplObservation(xrplTx({}, { Memos: [anchorMemo(withByte(PAYLOAD, 8, '02'))] })), evm: evmObservation(evmPair({ input: `0x${withByte(PAYLOAD, 8, '02')}` })) }, COMMITMENT, 'UNSUPPORTED', ['CHAIN_INCLUSION_UNVERIFIED'], ['RNAD_RECORD_NOT_PASSED', 'RNAD_RECORD_NOT_PASSED']],
    ['both-for-other-commitment', 'Both networks consistently anchor a commitment other than the one expected.', { xrpl: xrplOther, evm: evmObservation(evmPair({ input: `0x${hex(encodeAnchorPayload(OTHER))}` })) }, COMMITMENT, 'FAIL', ['CHAIN_INCLUSION_UNVERIFIED'], ['RNAD_RECORD_NOT_PASSED', 'RNAD_RECORD_NOT_PASSED']],
    ['missing-evm-xrpl-unsupported', 'A missing record and an unsupported one: FAIL, not UNSUPPORTED.', { xrpl: xrplObservation(xrplTx({}, { Memos: [anchorMemo(withByte(PAYLOAD, 8, '02'))] })) }, COMMITMENT, 'FAIL', ['CHAIN_INCLUSION_UNVERIFIED'], ['RNAD_MISSING_RECORD', 'RNAD_RECORD_NOT_PASSED']],
    ['none', 'No observation at all.', {}, COMMITMENT, 'FAIL', ['CHAIN_INCLUSION_UNVERIFIED'], ['RNAD_MISSING_RECORD', 'RNAD_MISSING_RECORD']],
  ].map(([id, description, inputs, commitment, outcome, conclusions, codes]) => {
    const encoded = Object.fromEntries(Object.entries(inputs).map(([k, v]) => [k, new TextEncoder().encode(v)]));
    const report = verifyDualAnchor(encoded, commitment);
    const found = report.findings.map((f) => f.code);
    if (report.outcome !== outcome || json(report.conclusions) !== json(conclusions) || json(found) !== json(codes)) {
      throw new Error(`dual ${id}: got ${report.outcome} ${report.conclusions} ${found}`);
    }
    return { id, description, ...inputs, expectedCommitment: commitment, expectedOutcome: outcome, expectedConclusions: conclusions, expectedFindings: codes, expectedReport: text(report) };
  });
}

const file = (profile, kind, vectors) => ({
  format: 'rnnet.conformance-vectors.v1',
  profile,
  kind,
  note: 'Synthetic. Every transaction record, hash, ledger, block and account here is derived from a label and does not exist on any network.',
  vectors,
});

export function buildAnchorVectors() {
  return {
    payload: file('rnnet.anchor-payload.v1', 'anchor-payload', payloadCases()),
    xrpl: file('rnnet.anchor-record.v1', 'anchor-xrpl', xrplCases()),
    evm: file('rnnet.anchor-record.v1', 'anchor-evm', evmCases()),
    dual: file('rnnet.anchor-record.v1', 'anchor-dual', dualCases()),
  };
}
export const serialize = (value) => `${JSON.stringify(value, null, 2)}\n`;
export { OUT };

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const files = buildAnchorVectors();
  let stale = false;
  for (const [name, value] of Object.entries(files)) {
    if (process.argv.includes('--write')) writeFileSync(OUT(name), serialize(value));
    else if (readFileSync(OUT(name), 'utf8') !== serialize(value)) stale = true;
  }
  if (stale) {
    console.error('vectors/anchor/ is out of date; run with --write');
    process.exitCode = 1;
  }
}
