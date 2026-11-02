// EIP-1559 (type 0x02) transaction encoding and decoding (EIP-1559, EIP-2718), offline.
//
//   unsigned: 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to,
//                          value, data, accessList])
//   signed:   0x02 || rlp([... the nine above ..., yParity, r, s])
//
// The signing hash is Keccak-256 of the unsigned bytes and the transaction hash is Keccak-256 of
// the signed bytes. Keccak is not a Node built-in, so hashing and signatures live in signer/;
// this file only turns transactions into bytes and back.
import { Buffer } from 'node:buffer';
import { TxError, TxErrorCode } from './errors.mjs';
import { decodeUint, encodeUint, rlpDecode, rlpEncode } from './rlp.mjs';

export const EIP1559_TYPE = 0x02;
/** The secp256k1 group order; signatures need r and s in [1, n-1], and s <= n/2 (EIP-2). */
export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const ADDRESS = /^0x[0-9a-f]{40}$/;
const DATA = /^0x(?:[0-9a-f]{2})*$/;
const QUANTITY = /^0x(0|[1-9a-f][0-9a-f]*)$/;
const quantity = (n) => `0x${n.toString(16)}`;
const hex = (bytes) => `0x${Buffer.from(bytes).toString('hex')}`;
const invalid = (detail) => new TxError(TxErrorCode.INTENT_INVALID, detail);

const UINT_FIELDS = ['chainId', 'nonce', 'maxPriorityFeePerGas', 'maxFeePerGas', 'gas', 'value'];

function fields(tx) {
  if (tx === null || typeof tx !== 'object') throw invalid('transaction must be an object');
  if (tx.type !== '0x2') throw invalid('type must be 0x2');
  for (const name of UINT_FIELDS) if (typeof tx[name] !== 'string' || !QUANTITY.test(tx[name])) throw invalid(`${name} must be a quantity`);
  if (typeof tx.to !== 'string' || !ADDRESS.test(tx.to)) throw invalid('to must be a lowercase address');
  if (typeof tx.input !== 'string' || !DATA.test(tx.input)) throw invalid('input must be hex data');
  if (!Array.isArray(tx.accessList) || tx.accessList.length !== 0) throw invalid('only an empty access list is supported');
  const u = (name) => encodeUint(BigInt(tx[name]));
  return [u('chainId'), u('nonce'), u('maxPriorityFeePerGas'), u('maxFeePerGas'), u('gas'), Buffer.from(tx.to.slice(2), 'hex'), u('value'), Buffer.from(tx.input.slice(2), 'hex'), []];
}

/** The unsigned type-2 bytes whose Keccak-256 is signed. `from` is not part of them. */
export function encodeEip1559Unsigned(tx) {
  return Buffer.concat([Buffer.of(EIP1559_TYPE), rlpEncode(fields(tx))]);
}

/** The signed type-2 bytes, from the transaction and { yParity, r, s } (BigInts). */
export function encodeEip1559Signed(tx, { yParity, r, s }) {
  return Buffer.concat([Buffer.of(EIP1559_TYPE), rlpEncode([...fields(tx), encodeUint(yParity), encodeUint(r), encodeUint(s)])]);
}

/**
 * Decodes signed type-2 bytes. Returns { transaction, signature: { yParity, r, s }, unsigned }
 * where `transaction` has the intent's field names (without `from`, which only the signature
 * gives) and `unsigned` is the re-encoded signing preimage. Signature values are returned as read;
 * their checks (range, low s, parity) belong to the verifier, after the fields are compared.
 */
export function decodeEip1559Signed(bytes) {
  const data = Uint8Array.from(bytes);
  if (data.length === 0) throw new TxError(TxErrorCode.DECODE, 'empty');
  if (data[0] !== EIP1559_TYPE) throw new TxError(TxErrorCode.WRONG_TX_TYPE, `transaction type byte 0x${data[0].toString(16).padStart(2, '0')} is not 0x02`);
  const items = rlpDecode(data.subarray(1));
  if (!Array.isArray(items) || items.length !== 12) throw new TxError(TxErrorCode.DECODE, 'a signed type-2 transaction has exactly 12 items');
  const [chainId, nonce, tip, maxFee, gas, to, value, input, accessList, yParity, r, s] = items;
  for (const item of [chainId, nonce, tip, maxFee, gas, to, value, input, yParity, r, s]) {
    if (Array.isArray(item)) throw new TxError(TxErrorCode.DECODE, 'expected a byte string');
  }
  if (!Array.isArray(accessList)) throw new TxError(TxErrorCode.DECODE, 'accessList must be a list');
  if (to.length !== 20) throw new TxError(TxErrorCode.FIELD_MISMATCH, to.length === 0 ? 'contract creation is not allowed' : 'to must be 20 bytes');
  const decodedAccessList = accessList.map((entry) => {
    if (!Array.isArray(entry) || entry.length !== 2 || Array.isArray(entry[0]) || entry[0].length !== 20 || !Array.isArray(entry[1])) throw new TxError(TxErrorCode.DECODE, 'malformed access list');
    return { address: hex(entry[0]), storageKeys: entry[1].map((key) => {
      if (Array.isArray(key) || key.length !== 32) throw new TxError(TxErrorCode.DECODE, 'malformed storage key');
      return hex(key);
    }) };
  });
  const transaction = {
    type: '0x2',
    chainId: quantity(decodeUint(chainId, 'chainId')),
    nonce: quantity(decodeUint(nonce, 'nonce')),
    maxPriorityFeePerGas: quantity(decodeUint(tip, 'maxPriorityFeePerGas')),
    maxFeePerGas: quantity(decodeUint(maxFee, 'maxFeePerGas')),
    gas: quantity(decodeUint(gas, 'gas')),
    to: hex(to),
    value: quantity(decodeUint(value, 'value')),
    input: hex(input),
    accessList: decodedAccessList,
  };
  const signature = { yParity: decodeUint(yParity, 'yParity'), r: decodeUint(r, 'r'), s: decodeUint(s, 's') };
  const unsigned = Buffer.concat([Buffer.of(EIP1559_TYPE), rlpEncode(items.slice(0, 9))]);
  return { transaction, signature, unsigned };
}
