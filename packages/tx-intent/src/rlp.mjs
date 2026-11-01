// Recursive Length Prefix encoding (Ethereum Yellow Paper, Appendix B), strict.
//
// The decoder accepts only the one canonical encoding of each value: a single byte below 0x80
// must stand alone, lengths use the short form whenever they can and never start with a zero
// byte. Anything else is RNTX_NONCANONICAL_ENCODING; running out of bytes is RNTX_DECODE.
import { Buffer } from 'node:buffer';
import { TxError, TxErrorCode } from './errors.mjs';

const lengthBytes = (n) => {
  let hex = n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return Buffer.from(hex, 'hex');
};

const header = (length, short, long) => (length <= 55 ? Buffer.of(short + length) : Buffer.concat([Buffer.of(long + lengthBytes(length).length), lengthBytes(length)]));

/** Encodes a byte string (Uint8Array) or a list of items. */
export function rlpEncode(item) {
  if (Array.isArray(item)) {
    const body = Buffer.concat(item.map(rlpEncode));
    return Buffer.concat([header(body.length, 0xc0, 0xf7), body]);
  }
  const bytes = Buffer.from(item);
  if (bytes.length === 1 && bytes[0] < 0x80) return bytes;
  return Buffer.concat([header(bytes.length, 0x80, 0xb7), bytes]);
}

/** A non-negative integer as its minimal big-endian bytes (zero is the empty string). */
export function encodeUint(value) {
  const n = BigInt(value);
  if (n < 0n) throw new TxError(TxErrorCode.INTENT_INVALID, 'negative integer');
  return n === 0n ? Buffer.alloc(0) : lengthBytes(n);
}

/**
 * Decodes an integer: at most 32 bytes, and no leading zero byte (zero is the empty string).
 * Throws RNTX_NONCANONICAL_ENCODING otherwise.
 */
export function decodeUint(bytes, name) {
  if (!(bytes instanceof Uint8Array)) throw new TxError(TxErrorCode.DECODE, `${name} must be a byte string`);
  if (bytes.length > 32) throw new TxError(TxErrorCode.NONCANONICAL_ENCODING, `${name} longer than 32 bytes`);
  if (bytes.length > 0 && bytes[0] === 0) throw new TxError(TxErrorCode.NONCANONICAL_ENCODING, `${name} has a leading zero byte`);
  return bytes.length === 0 ? 0n : BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
}

function readLength(bytes, at, count) {
  if (at + count > bytes.length) throw new TxError(TxErrorCode.DECODE, 'truncated length');
  if (bytes[at] === 0) throw new TxError(TxErrorCode.NONCANONICAL_ENCODING, 'length with a leading zero byte');
  let n = 0;
  for (let i = 0; i < count; i++) n = n * 256 + bytes[at + i];
  if (n <= 55) throw new TxError(TxErrorCode.NONCANONICAL_ENCODING, 'long form for a short length');
  return n;
}

function decodeAt(bytes, at) {
  if (at >= bytes.length) throw new TxError(TxErrorCode.DECODE, 'truncated');
  const b = bytes[at];
  let start;
  let length;
  let list = false;
  if (b < 0x80) return { item: bytes.subarray(at, at + 1), next: at + 1 };
  if (b <= 0xb7) {
    start = at + 1;
    length = b - 0x80;
    if (length === 1 && start < bytes.length && bytes[start] < 0x80) throw new TxError(TxErrorCode.NONCANONICAL_ENCODING, 'single byte below 0x80 with a prefix');
  } else if (b <= 0xbf) {
    const count = b - 0xb7;
    length = readLength(bytes, at + 1, count);
    start = at + 1 + count;
  } else if (b <= 0xf7) {
    list = true;
    start = at + 1;
    length = b - 0xc0;
  } else {
    list = true;
    const count = b - 0xf7;
    length = readLength(bytes, at + 1, count);
    start = at + 1 + count;
  }
  const end = start + length;
  if (end > bytes.length) throw new TxError(TxErrorCode.DECODE, 'truncated');
  if (!list) return { item: bytes.subarray(start, end), next: end };
  const items = [];
  let cursor = start;
  while (cursor < end) {
    const { item, next } = decodeAt(bytes, cursor);
    if (next > end) throw new TxError(TxErrorCode.DECODE, 'list item overruns its list');
    items.push(item);
    cursor = next;
  }
  return { item: items, next: end };
}

/** Decodes exactly one item that fills `bytes`; extra bytes are RNTX_TRAILING_BYTES. */
export function rlpDecode(bytes) {
  const data = Uint8Array.from(bytes);
  const { item, next } = decodeAt(data, 0);
  if (next !== data.length) throw new TxError(TxErrorCode.TRAILING_BYTES, 'bytes after the RLP item');
  return item;
}
