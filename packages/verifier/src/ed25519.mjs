// Strict Ed25519 verification (spec/rnnet.synthetic-evidence.v1.md §5.3).
//
// Libraries agree on ordinary signatures but differ on edge cases: non-canonical encodings,
// small-order keys, S not reduced modulo L, cofactored versus cofactorless checks. This file
// settles those cases itself, from RFC 8032, before the cofactorless equation is checked by
// Node's built-in Ed25519 (OpenSSL). Only public data is handled; there is no signing here.
import { Buffer } from 'node:buffer';
import { createPublicKey, verify } from 'node:crypto';

export const SignatureResult = Object.freeze({
  VALID: 'VALID',
  INVALID: 'INVALID',
  KEY_REJECTED: 'KEY_REJECTED',
});

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const mod = (a) => ((a % P) + P) % P;
function power(base, exponent) {
  let result = 1n;
  let b = mod(base);
  for (let e = exponent; e > 0n; e >>= 1n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
  }
  return result;
}
const inverse = (a) => power(a, P - 2n);
const D = mod(-121665n * inverse(121666n));
const SQRT_M1 = power(2n, (P - 1n) / 4n);

const littleEndian = (bytes) => {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
};

/** RFC 8032 §5.1.3: the point an encoding names, or null if the encoding is not canonical or not on the curve. */
function decodePoint(bytes) {
  const sign = bytes[31] >> 7;
  const y = littleEndian(Uint8Array.from(bytes, (b, i) => (i === 31 ? b & 0x7f : b)));
  if (y >= P) return null;
  const x2 = mod((y * y - 1n) * inverse(D * y * y + 1n));
  if (x2 === 0n) {
    if (sign === 1) return null;
    return { x: 0n, y };
  }
  let x = power(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1);
  if (mod(x * x - x2) !== 0n) return null;
  if (Number(x & 1n) !== sign) x = P - x;
  return { x, y };
}

// Extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z (RFC 8032 §5.1.4).
function add(p, q) {
  const a = mod((p.Y - p.X) * (q.Y - q.X));
  const b = mod((p.Y + p.X) * (q.Y + q.X));
  const c = mod(p.T * 2n * D * q.T);
  const d = mod(p.Z * 2n * q.Z);
  const e = b - a;
  const f = d - c;
  const g = d + c;
  const h = b + a;
  return { X: mod(e * f), Y: mod(g * h), Z: mod(f * g), T: mod(e * h) };
}

/** Whether multiplying the point by the cofactor 8 gives the neutral element. */
function hasSmallOrder({ x, y }) {
  let q = { X: x, Y: y, Z: 1n, T: mod(x * y) };
  for (let i = 0; i < 3; i++) q = add(q, q);
  return q.X === 0n && q.Y === q.Z;
}

/** Whether a 32-byte public key is accepted: canonical, on the curve, not of small order. */
export function isAcceptedPublicKey(publicKey) {
  const point = decodePoint(publicKey);
  return point !== null && !hasSmallOrder(point);
}

/**
 * Verifies one signature over message under publicKey (both raw bytes).
 * @param {Uint8Array} publicKey 32 bytes
 * @param {Uint8Array} signature 64 bytes
 * @param {Uint8Array} message
 * @returns {string} one of SignatureResult
 */
export function verifyEd25519(publicKey, signature, message) {
  if (!isAcceptedPublicKey(publicKey)) return SignatureResult.KEY_REJECTED;
  if (decodePoint(signature.subarray(0, 32)) === null) return SignatureResult.INVALID;
  if (littleEndian(signature.subarray(32, 64)) >= L) return SignatureResult.INVALID;
  const key = createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(publicKey).toString('base64url') },
    format: 'jwk',
  });
  return verify(null, message, key, signature) ? SignatureResult.VALID : SignatureResult.INVALID;
}
