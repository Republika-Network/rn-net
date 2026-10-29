// XRPL Testnet anchor adapter (spec/rnnet.anchor-record.v1.md §3). Offline: it checks a supplied
// rippled `tx` result (API v2) and never contacts a server. A supplied result is unauthenticated;
// the record says so.
import { Buffer } from 'node:buffer';
import {
  bytesOfHex,
  checkCommitment,
  fail,
  finish,
  hexOf,
  kind,
  Network,
  newRecord,
  parseObservation,
  phase,
  snapshotBytes,
} from './common.mjs';
import { decodeAnchorPayload, PAYLOAD_FORMAT } from './payload.mjs';

/** MemoType of an anchor memo: the uppercase hex of "rnnet.anchor-payload.v1". */
export const ANCHOR_MEMO_TYPE = Buffer.from(PAYLOAD_FORMAT, 'ascii').toString('hex').toUpperCase();
const HASH = /^[0-9A-F]{64}$/;
const CTID = /^C[0-9A-F]{15}$/;
const ACCOUNT = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const MEMO_HEX = /^(?:[0-9A-F]{2}){0,1024}$/;
const MEMO_FIELDS = ['MemoType', 'MemoData', 'MemoFormat'];
const MAX_MEMOS = 32;
const XRPL_TESTNET_ID = 1n;

/** Phase A (§3.2): structure, network and consistency; throws on the first failure. */
function checkStructure(tx) {
  if (kind(tx) !== 'object') fail('RNAX_FIELD_TYPE', 'tx');
  const required = { hash: 'string', ledger_index: 'number', ledger_hash: 'string', validated: 'boolean', meta: 'object', tx_json: 'object' };
  for (const [field, type] of Object.entries(required)) {
    if (!Object.hasOwn(tx, field)) fail('RNAX_MISSING_FIELD', `tx.${field}`);
    if (kind(tx[field]) !== type) fail('RNAX_FIELD_TYPE', `tx.${field}`);
  }
  if (!HASH.test(tx.hash)) fail('RNAX_INVALID_HASH', 'tx.hash');
  if (!HASH.test(tx.ledger_hash)) fail('RNAX_INVALID_LEDGER_HASH', 'tx.ledger_hash');
  if (!Number.isInteger(tx.ledger_index) || tx.ledger_index < 1 || tx.ledger_index > 0xffffffff) fail('RNAX_INVALID_LEDGER_INDEX', 'tx.ledger_index');
  const { tx_json: body, meta } = tx;
  if (Object.hasOwn(body, 'NetworkID')) fail('RNAX_WRONG_NETWORK', 'tx.tx_json.NetworkID');
  let ctid;
  if (Object.hasOwn(tx, 'ctid')) {
    if (typeof tx.ctid !== 'string' || !CTID.test(tx.ctid)) fail('RNAX_INVALID_CTID', 'tx.ctid');
    ctid = BigInt(`0x${tx.ctid}`);
    if ((ctid & 0xffffn) !== XRPL_TESTNET_ID) fail('RNAX_WRONG_NETWORK', 'tx.ctid');
  }
  if (Object.hasOwn(body, 'hash') && body.hash !== tx.hash) fail('RNAX_CONTRADICTORY_REFERENCE', 'tx.tx_json.hash');
  if (Object.hasOwn(body, 'ledger_index') && body.ledger_index !== tx.ledger_index) fail('RNAX_CONTRADICTORY_REFERENCE', 'tx.tx_json.ledger_index');
  if (ctid !== undefined) {
    if (Number((ctid >> 32n) & 0x0fffffffn) !== tx.ledger_index) fail('RNAX_CONTRADICTORY_REFERENCE', 'tx.ctid');
    if (Object.hasOwn(meta, 'TransactionIndex')) {
      if (!Number.isInteger(meta.TransactionIndex)) fail('RNAX_FIELD_TYPE', 'tx.meta.TransactionIndex');
      if (Number((ctid >> 16n) & 0xffffn) !== meta.TransactionIndex) fail('RNAX_CONTRADICTORY_REFERENCE', 'tx.ctid');
    }
  }
  if (body.TransactionType !== 'AccountSet') fail('RNAX_UNSUPPORTED_TRANSACTION_TYPE', 'tx.tx_json.TransactionType');
  if (typeof body.Account !== 'string' || !ACCOUNT.test(body.Account)) fail('RNAX_INVALID_ACCOUNT', 'tx.tx_json.Account');
  if (Object.hasOwn(body, 'Memos')) {
    if (kind(body.Memos) !== 'array' || body.Memos.length > MAX_MEMOS) fail('RNAX_MALFORMED_MEMO', 'tx.tx_json.Memos');
    body.Memos.forEach((wrapper, i) => {
      const subject = `tx.tx_json.Memos[${i}]`;
      if (kind(wrapper) !== 'object' || Object.keys(wrapper).length !== 1 || kind(wrapper.Memo) !== 'object') fail('RNAX_MALFORMED_MEMO', subject);
      for (const [field, value] of Object.entries(wrapper.Memo)) {
        if (!MEMO_FIELDS.includes(field) || typeof value !== 'string' || !MEMO_HEX.test(value)) fail('RNAX_MALFORMED_MEMO', subject);
      }
    });
  }
}

/** Phase B: exactly one anchor memo, carrying exactly the expected payload. */
function checkAnchor(tx, expected, record) {
  const memos = tx.tx_json.Memos ?? [];
  const anchors = memos.flatMap((wrapper, i) => (wrapper.Memo.MemoType === ANCHOR_MEMO_TYPE ? [i] : []));
  if (anchors.length === 0) fail('RNAX_MISSING_ANCHOR', 'tx.tx_json.Memos');
  if (anchors.length > 1) fail('RNAX_DUPLICATE_ANCHOR', `tx.tx_json.Memos[${anchors[1]}]`);
  const index = anchors[0];
  const memo = memos[index].Memo;
  if (Object.hasOwn(memo, 'MemoFormat') || !Object.hasOwn(memo, 'MemoData')) fail('RNAX_MALFORMED_MEMO', `tx.tx_json.Memos[${index}]`);
  const bytes = bytesOfHex(memo.MemoData);
  const commitment = decodeAnchorPayload(bytes, `tx.tx_json.Memos[${index}].MemoData`);
  record.payload = { hex: hexOf(bytes), commitment, matchesExpected: commitment === expected };
  if (commitment !== expected) fail('RNAP_COMMITMENT_MISMATCH', `tx.tx_json.Memos[${index}].MemoData`);
}

/** Phase C: the claimed status. */
function checkStatus(tx) {
  if (tx.validated !== true) fail('RNAX_NOT_VALIDATED', 'tx.validated');
  if (tx.meta.TransactionResult !== 'tesSUCCESS') fail('RNAX_TRANSACTION_NOT_SUCCESSFUL', 'tx.meta.TransactionResult');
}

export const XRPL_BASIS = Object.freeze({
  finality: 'The supplied data states the transaction is in a validated ledger; not authenticated.',
});

/**
 * Checks a supplied XRPL Testnet observation against an expected commitment.
 * @param {Uint8Array} observationBytes rnnet.anchor-observation.v1 JSON bytes
 * @param {string} expectedCommitment sha256:<64 lowercase hex>
 * @returns {Readonly<object>} an rnnet.anchor-record.v1 record
 */
export function verifyXrplObservation(observationBytes, expectedCommitment) {
  const expected = checkCommitment(expectedCommitment);
  const bytes = snapshotBytes(observationBytes, 'observationBytes');
  const record = newRecord(Network.XRPL_TESTNET, expected, bytes);
  let tx;
  const structured = phase(record.findings, () => {
    tx = parseObservation(bytes, Network.XRPL_TESTNET).tx;
    checkStructure(tx);
  });
  if (structured) {
    record.transaction = { hash: tx.hash, ledgerIndex: tx.ledger_index, ledgerHash: tx.ledger_hash, account: tx.tx_json.Account };
    phase(record.findings, () => checkAnchor(tx, expected, record));
    phase(record.findings, () => checkStatus(tx));
  }
  return finish(record, XRPL_BASIS.finality, 'CLAIMED');
}
