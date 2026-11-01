// XRPL binary serialization, restricted to the Genesis AccountSet (ADR-RN-016 §1).
//
// Encodes and decodes only the fields ADR-RN-016 allows, in canonical order (by type code, then
// field code), and refuses anything else. Field and type codes are the XRPL protocol's; they are
// checked against the official ripple-binary-codec fixtures in vectors/signing/. Pure: it signs
// nothing and verifies no signature (signer/ does that).
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { TxError, TxErrorCode } from './errors.mjs';

/** Prefix of the bytes a single signature covers ("STX\0"). */
export const SIGNING_PREFIX = Buffer.from('53545800', 'hex');
/** Prefix of the bytes a transaction ID hashes ("TXN\0"). */
export const TX_ID_PREFIX = Buffer.from('54584e00', 'hex');
const TRANSACTION_TYPES = Object.freeze({ AccountSet: 3 });

// [type code, field code, kind] for every field the codec knows.
export const XRPL_FIELD_CODES = Object.freeze({
  TransactionType: [1, 2, 'UInt16'],
  NetworkID: [2, 1, 'UInt32'], // known only so that it can be refused with RNTX_WRONG_CHAIN
  Flags: [2, 2, 'UInt32'],
  Sequence: [2, 4, 'UInt32'],
  LastLedgerSequence: [2, 27, 'UInt32'],
  Fee: [6, 8, 'Amount'],
  SigningPubKey: [7, 3, 'Blob'],
  TxnSignature: [7, 4, 'Blob'],
  MemoType: [7, 12, 'Blob'],
  MemoData: [7, 13, 'Blob'],
  MemoFormat: [7, 14, 'Blob'], // known only so that it can be refused
  Account: [8, 1, 'AccountID'],
  ObjectEndMarker: [14, 1, 'STObject'],
  Memo: [14, 10, 'STObject'],
  ArrayEndMarker: [15, 1, 'STArray'],
  Memos: [15, 9, 'STArray'],
});
const TOP_LEVEL = ['TransactionType', 'Flags', 'Sequence', 'LastLedgerSequence', 'Fee', 'SigningPubKey', 'TxnSignature', 'Account', 'Memos'];
const MEMO_FIELDS = ['MemoType', 'MemoData'];
const byCode = new Map(Object.entries(XRPL_FIELD_CODES).map(([name, [type, nth]]) => [`${type}/${nth}`, name]));
const order = (name) => XRPL_FIELD_CODES[name][0] * 256 + XRPL_FIELD_CODES[name][1];

const MAX_DROPS = 100_000_000_000_000_000n; // 10^17: all XRP in drops
const HEX = /^(?:[0-9A-F]{2})*$/;
const DROPS = /^(0|[1-9][0-9]{0,17})$/;
const fail = (code, detail) => {
  throw new TxError(code, detail);
};

// --- primitives -------------------------------------------------------------------------------

/** The field header for a type and field code. */
export function fieldHeader(type, nth) {
  if (type < 16 && nth < 16) return Buffer.of((type << 4) | nth);
  if (type < 16) return Buffer.of(type << 4, nth);
  if (nth < 16) return Buffer.of(nth, type);
  return Buffer.of(0, type, nth);
}

/** The variable-length prefix for a blob of `length` bytes. */
export function encodeVL(length) {
  if (!Number.isInteger(length) || length < 0) fail(TxErrorCode.DECODE, 'bad length');
  if (length <= 192) return Buffer.of(length);
  if (length <= 12_480) {
    const n = length - 193;
    return Buffer.of(193 + (n >> 8), n & 0xff);
  }
  if (length <= 918_744) {
    const n = length - 12_481;
    return Buffer.of(241 + (n >> 16), (n >> 8) & 0xff, n & 0xff);
  }
  return fail(TxErrorCode.DECODE, 'blob too long');
}

/** An XRP amount in drops (a decimal string) as its 8 bytes. */
export function encodeNativeAmount(drops) {
  if (typeof drops !== 'string' || !DROPS.test(drops) || BigInt(drops) > MAX_DROPS) fail(TxErrorCode.INTENT_INVALID, 'amount must be drops from 0 to 10^17');
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(drops) | 0x4000_0000_0000_0000n);
  return out;
}

const ALPHABET = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();

/** A 20-byte account ID as a classic address (base58check, XRPL alphabet, version 0). */
export function encodeAddress(accountId) {
  if (accountId.length !== 20) fail(TxErrorCode.DECODE, 'account ID must be 20 bytes');
  const payload = Buffer.concat([Buffer.of(0), accountId]);
  const bytes = Buffer.concat([payload, sha256(sha256(payload)).subarray(0, 4)]);
  let n = BigInt(`0x${bytes.toString('hex')}`);
  let text = '';
  while (n > 0n) {
    text = ALPHABET[Number(n % 58n)] + text;
    n /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    text = ALPHABET[0] + text;
  }
  return text;
}

/** A classic address as its 20-byte account ID; throws RNTX_INTENT_INVALID if it is not one. */
export function decodeAddress(address) {
  if (typeof address !== 'string' || address.length < 25 || address.length > 35) fail(TxErrorCode.INTENT_INVALID, 'not a classic address');
  let n = 0n;
  for (const char of address) {
    const digit = ALPHABET.indexOf(char);
    if (digit < 0) fail(TxErrorCode.INTENT_INVALID, 'not a classic address');
    n = n * 58n + BigInt(digit);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let leading = 0;
  while (address[leading] === ALPHABET[0]) leading++;
  const bytes = Buffer.concat([Buffer.alloc(leading), Buffer.from(n === 0n ? '' : hex, 'hex')]);
  const valid = bytes.length === 25 && bytes[0] === 0 && sha256(sha256(bytes.subarray(0, 21))).subarray(0, 4).equals(bytes.subarray(21));
  if (!valid || encodeAddress(bytes.subarray(1, 21)) !== address) fail(TxErrorCode.INTENT_INVALID, 'not a classic address');
  return bytes.subarray(1, 21);
}

/** The classic address of an `SigningPubKey`: base58check(RIPEMD-160(SHA-256(key))). */
export function addressFromPublicKey(signingPubKey) {
  return encodeAddress(createHash('ripemd160').update(sha256(signingPubKey)).digest());
}

// --- encoding ----------------------------------------------------------------------------------

const blob = (name, hex) => {
  if (typeof hex !== 'string' || !HEX.test(hex)) fail(TxErrorCode.INTENT_INVALID, `${name} must be upper-case hex`);
  const bytes = Buffer.from(hex, 'hex');
  return Buffer.concat([fieldHeader(...XRPL_FIELD_CODES[name]), encodeVL(bytes.length), bytes]);
};
const uint = (name, value, width) => {
  const max = width === 2 ? 0xffff : 0xffff_ffff;
  if (!Number.isInteger(value) || value < 0 || value > max) fail(TxErrorCode.INTENT_INVALID, `${name} out of range`);
  const out = Buffer.alloc(width);
  if (width === 2) out.writeUInt16BE(value);
  else out.writeUInt32BE(value);
  return Buffer.concat([fieldHeader(...XRPL_FIELD_CODES[name]), out]);
};

function encodeField(name, value) {
  switch (name) {
    case 'TransactionType': {
      if (!Object.hasOwn(TRANSACTION_TYPES, value)) fail(TxErrorCode.INTENT_INVALID, 'TransactionType must be AccountSet');
      return uint(name, TRANSACTION_TYPES[value], 2);
    }
    case 'Flags':
    case 'Sequence':
    case 'LastLedgerSequence':
      return uint(name, value, 4);
    case 'Fee':
      return Buffer.concat([fieldHeader(...XRPL_FIELD_CODES.Fee), encodeNativeAmount(value)]);
    case 'SigningPubKey':
    case 'TxnSignature':
      return blob(name, value);
    case 'Account':
      return Buffer.concat([fieldHeader(...XRPL_FIELD_CODES.Account), encodeVL(20), decodeAddress(value)]);
    case 'Memos': {
      if (!Array.isArray(value)) fail(TxErrorCode.INTENT_INVALID, 'Memos must be an array');
      const parts = [fieldHeader(...XRPL_FIELD_CODES.Memos)];
      for (const entry of value) {
        const memo = entry?.Memo;
        if (memo === null || typeof memo !== 'object' || Object.keys(entry).length !== 1) fail(TxErrorCode.INTENT_INVALID, 'a memo must be {"Memo": {...}}');
        const names = Object.keys(memo).sort((a, b) => order(a) - order(b));
        if (!names.every((n) => MEMO_FIELDS.includes(n))) fail(TxErrorCode.INTENT_INVALID, 'a memo may have only MemoType and MemoData');
        parts.push(fieldHeader(...XRPL_FIELD_CODES.Memo), ...names.map((n) => blob(n, memo[n])), fieldHeader(...XRPL_FIELD_CODES.ObjectEndMarker));
      }
      parts.push(fieldHeader(...XRPL_FIELD_CODES.ArrayEndMarker));
      return Buffer.concat(parts);
    }
    default:
      return fail(TxErrorCode.INTENT_INVALID, `field ${name} is not allowed`);
  }
}

/** Serializes an AccountSet (with or without TxnSignature) in canonical field order. */
export function encodeXrplTx(tx) {
  if (tx === null || typeof tx !== 'object' || Array.isArray(tx)) fail(TxErrorCode.INTENT_INVALID, 'transaction must be an object');
  const names = Object.keys(tx);
  for (const name of names) if (!TOP_LEVEL.includes(name)) fail(TxErrorCode.INTENT_INVALID, `field ${name} is not allowed`);
  names.sort((a, b) => order(a) - order(b));
  return Buffer.concat(names.map((name) => encodeField(name, tx[name])));
}

/** The bytes one Ed25519 signature covers: "STX\0" + the transaction without TxnSignature. */
export function xrplSigningPreimage(tx) {
  const { TxnSignature, ...unsigned } = tx;
  return Buffer.concat([SIGNING_PREFIX, encodeXrplTx(unsigned)]);
}

/** The transaction ID: SHA-512Half("TXN\0" + signed blob), upper-case hex. */
export const xrplTxHash = (blobBytes) => createHash('sha512').update(TX_ID_PREFIX).update(blobBytes).digest().subarray(0, 32).toString('hex').toUpperCase();

// --- decoding ----------------------------------------------------------------------------------

class Reader {
  constructor(bytes) {
    this.bytes = Buffer.from(bytes);
    this.at = 0;
  }
  get done() {
    return this.at >= this.bytes.length;
  }
  take(n) {
    if (this.at + n > this.bytes.length) fail(TxErrorCode.DECODE, 'truncated');
    const out = this.bytes.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }
  header() {
    const first = this.take(1)[0];
    let type = first >> 4;
    let nth = first & 0x0f;
    if (type === 0) type = this.take(1)[0];
    if (nth === 0) nth = this.take(1)[0];
    const name = byCode.get(`${type}/${nth}`);
    if (name === 'NetworkID') fail(TxErrorCode.WRONG_CHAIN, 'NetworkID must be omitted on XRPL Testnet');
    if (name === undefined) fail(TxErrorCode.UNKNOWN_FIELD, `field ${type}/${nth}`);
    return name;
  }
  vl() {
    const b1 = this.take(1)[0];
    if (b1 <= 192) return b1;
    if (b1 <= 240) return 193 + (b1 - 193) * 256 + this.take(1)[0];
    if (b1 <= 254) {
      const [b2, b3] = this.take(2);
      return 12_481 + (b1 - 241) * 65_536 + b2 * 256 + b3;
    }
    return fail(TxErrorCode.DECODE, 'bad length prefix');
  }
}

const hexUpper = (bytes) => Buffer.from(bytes).toString('hex').toUpperCase();

/**
 * Decodes a signed or unsigned Genesis AccountSet blob into its JSON fields. Refuses unknown or
 * repeated fields, non-canonical order, NetworkID, MemoFormat, non-native amounts and any byte
 * after the Memos array.
 */
export function decodeXrplTx(bytes) {
  const r = new Reader(bytes);
  const tx = {};
  let last = -1;
  while (!r.done) {
    const name = r.header();
    if (!TOP_LEVEL.includes(name)) fail(TxErrorCode.UNKNOWN_FIELD, `field ${name} is not allowed here`);
    if (order(name) <= last) fail(TxErrorCode.NONCANONICAL_ENCODING, `field ${name} out of canonical order`);
    last = order(name);
    switch (XRPL_FIELD_CODES[name][2]) {
      case 'UInt16': {
        const code = r.take(2).readUInt16BE();
        tx[name] = code === TRANSACTION_TYPES.AccountSet ? 'AccountSet' : code;
        break;
      }
      case 'UInt32':
        tx[name] = r.take(4).readUInt32BE();
        break;
      case 'Amount': {
        const raw = r.take(8).readBigUInt64BE();
        if (raw & 0x8000_0000_0000_0000n) fail(TxErrorCode.DECODE, `${name} must be an XRP amount`);
        if (!(raw & 0x4000_0000_0000_0000n)) fail(TxErrorCode.DECODE, `${name} must not be negative`);
        const drops = raw & 0x3fff_ffff_ffff_ffffn;
        if (drops > MAX_DROPS) fail(TxErrorCode.DECODE, `${name} out of range`);
        tx[name] = drops.toString();
        break;
      }
      case 'Blob':
        tx[name] = hexUpper(r.take(r.vl()));
        break;
      case 'AccountID': {
        if (r.vl() !== 20) fail(TxErrorCode.DECODE, 'Account must be 20 bytes');
        tx[name] = encodeAddress(r.take(20));
        break;
      }
      case 'STArray': {
        tx[name] = decodeMemos(r);
        if (!r.done) fail(TxErrorCode.TRAILING_BYTES, 'bytes after Memos');
        break;
      }
      default:
        fail(TxErrorCode.UNKNOWN_FIELD, `field ${name} is not allowed here`);
    }
  }
  return tx;
}

function decodeMemos(r) {
  const memos = [];
  for (;;) {
    const name = r.header();
    if (name === 'ArrayEndMarker') return memos;
    if (name !== 'Memo') fail(TxErrorCode.UNKNOWN_FIELD, `${name} inside Memos`);
    const memo = {};
    let last = -1;
    for (;;) {
      const inner = r.header();
      if (inner === 'ObjectEndMarker') break;
      if (!MEMO_FIELDS.includes(inner)) fail(TxErrorCode.UNKNOWN_FIELD, `${inner} inside a memo`);
      if (order(inner) <= last) fail(TxErrorCode.NONCANONICAL_ENCODING, `${inner} out of canonical order`);
      last = order(inner);
      memo[inner] = hexUpper(r.take(r.vl()));
    }
    memos.push({ Memo: memo });
  }
}
