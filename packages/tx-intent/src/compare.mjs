// Field-by-field comparison of decoded signed bytes with the approved intent's transaction.
//
// The first difference, in a fixed order, decides the code, so the JavaScript and the Python
// verifiers report the same reason (spec/rnnet.unsigned-tx-intent.v1.md §5).
import { Buffer } from 'node:buffer';
import { canonicalBytes } from '../../canonical/src/index.mjs';
import { TxErrorCode } from './errors.mjs';

const same = (a, b) => a !== undefined && b !== undefined && Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));

// [field, code when it differs], in the order they are compared.
export const XRPL_COMPARE_ORDER = Object.freeze([
  ['TransactionType', TxErrorCode.FIELD_MISMATCH],
  ['Flags', TxErrorCode.FIELD_MISMATCH],
  ['Sequence', TxErrorCode.NONCE_MISMATCH],
  ['LastLedgerSequence', TxErrorCode.FIELD_MISMATCH],
  ['Fee', TxErrorCode.FEE_MISMATCH],
  ['Memos', TxErrorCode.PAYLOAD_MISMATCH],
  ['Account', TxErrorCode.SENDER_MISMATCH],
  ['SigningPubKey', TxErrorCode.SENDER_MISMATCH],
]);
export const SEPOLIA_COMPARE_ORDER = Object.freeze([
  ['type', TxErrorCode.WRONG_TX_TYPE],
  ['chainId', TxErrorCode.WRONG_CHAIN],
  ['nonce', TxErrorCode.NONCE_MISMATCH],
  ['maxPriorityFeePerGas', TxErrorCode.FEE_MISMATCH],
  ['maxFeePerGas', TxErrorCode.FEE_MISMATCH],
  ['gas', TxErrorCode.FEE_MISMATCH],
  ['to', TxErrorCode.FIELD_MISMATCH],
  ['value', TxErrorCode.FIELD_MISMATCH],
  ['input', TxErrorCode.PAYLOAD_MISMATCH],
  ['accessList', TxErrorCode.FIELD_MISMATCH],
]);

function compare(order, expected, actual) {
  for (const [name, code] of order) {
    const has = Object.hasOwn(expected, name);
    if (has !== Object.hasOwn(actual, name) || (has && !same(expected[name], actual[name]))) return { code, field: name };
  }
  return null;
}

/** First difference between an XRPL intent transaction and a decoded blob (TxnSignature aside). */
export function compareXrpl(expected, decoded) {
  const { TxnSignature, ...actual } = decoded;
  for (const name of Object.keys(actual)) if (!XRPL_COMPARE_ORDER.some(([n]) => n === name)) return { code: TxErrorCode.FIELD_MISMATCH, field: name };
  return compare(XRPL_COMPARE_ORDER, expected, actual);
}

/** First difference between a Sepolia intent transaction (`from` aside) and a decoded one. */
export function compareSepolia(expected, decoded) {
  const { from, ...wanted } = expected;
  return compare(SEPOLIA_COMPARE_ORDER, wanted, decoded);
}
