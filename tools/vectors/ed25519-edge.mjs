// Edwards25519 arithmetic for building adversarial Ed25519 test inputs (RFC 8032 §5.1).
// Vector tooling only: it constructs public keys and signatures from scalars derived from public
// labels, so the edge cases of rnnet.synthetic-evidence.v1 §5.3 (mixed-order keys, torsion and
// non-canonical R, cofactored-only signatures) are pinned by vectors. Nothing here is a credential.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

export const P = 2n ** 255n - 19n;
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;
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

/** The x coordinate with the given parity for y, or null if y is not on the curve. */
export function xFor(y, sign) {
  const x2 = mod((y * y - 1n) * inverse(D * y * y + 1n));
  if (x2 === 0n) return sign ? null : 0n;
  let x = power(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1);
  if (mod(x * x - x2) !== 0n) return null;
  return Number(x & 1n) === sign ? x : P - x;
}
const point = (x, y) => ({ X: x, Y: y, Z: 1n, T: mod(x * y) });
export const IDENTITY = point(0n, 1n);
export function add(p, q) {
  const a = mod((p.Y - p.X) * (q.Y - q.X));
  const b = mod((p.Y + p.X) * (q.Y + q.X));
  const c = mod(p.T * 2n * D * q.T);
  const d = mod(p.Z * 2n * q.Z);
  const [e, f, g, h] = [b - a, d - c, d + c, b + a];
  return { X: mod(e * f), Y: mod(g * h), Z: mod(f * g), T: mod(e * h) };
}
export function multiply(scalar, p) {
  let q = IDENTITY;
  for (let s = scalar, r = p; s > 0n; s >>= 1n, r = add(r, r)) if (s & 1n) q = add(q, r);
  return q;
}
export const equal = (p, q) => mod(p.X * q.Z - q.X * p.Z) === 0n && mod(p.Y * q.Z - q.Y * p.Z) === 0n;
export const littleEndian = (n, length = 32) => Buffer.from(Array.from({ length }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn)));
export function encode(p) {
  const zi = inverse(p.Z);
  const [x, y] = [mod(p.X * zi), mod(p.Y * zi)];
  const bytes = littleEndian(y);
  if (x & 1n) bytes[31] |= 0x80;
  return bytes;
}
const GY = mod(4n * inverse(5n));
export const BASE = point(xFor(GY, 0), GY);
/** A point of order 8: L times a curve point, kept if four times it is not the identity. */
export const TORSION8 = (() => {
  for (let y = 2n; ; y++) {
    const x = xFor(y, 0);
    if (x === null) continue;
    const t = multiply(L, point(x, y));
    if (!equal(multiply(4n, t), IDENTITY)) return t;
  }
})();
export const pointAt = (x, y) => point(x, y);

/** A scalar derived from a public label. */
export const scalar = (label) => {
  const digest = createHash('sha256').update(`rnnet:synthetic-edge-case:v1:${label}`).digest();
  let n = 0n;
  for (let i = digest.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(digest[i]);
  return n % L;
};
/** k = SHA-512(R || A || M) mod L. */
export function challenge(R, A, message) {
  const digest = createHash('sha512').update(Buffer.concat([R, A, Buffer.from(message)])).digest();
  let n = 0n;
  for (let i = digest.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(digest[i]);
  return n % L;
}
