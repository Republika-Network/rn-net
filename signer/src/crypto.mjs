// The cryptographic primitives of the signer (ADR-RN-017).
//
//   Sepolia: recoverable secp256k1 ECDSA from @noble/curves@2.4.0, pinned exactly; Keccak-256
//            (@noble/hashes@2.4.0) comes through txverify/.
//   XRPL:    Ed25519 from the Node.js built-ins (RFC 8032), no third-party code.
//
// The verification primitives (Keccak-256, Ed25519 verification, secp256k1 recovery, the EVM
// address) live in txverify/ (RN-NET-03B2-B3, ADR-RN-019 §3) and are re-exported here unchanged,
// so the broadcaster never needs to import signer/.
//
// Approved for offline, test-only use in RN-NET-03B2-B1 with single-purpose testnet keys that
// hold no value. Not for custody: JavaScript gives no constant-time or memory-erasure guarantee.
import { Buffer } from 'node:buffer';
import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { SECP256K1_N, TxError, TxErrorCode } from '../../packages/tx-intent/src/index.mjs';
import { ed25519Verify, evmAddress, keccak256, secp256k1RecoverAddress } from '../../txverify/src/index.mjs';

export { ed25519Verify, evmAddress, keccak256, secp256k1RecoverAddress };

const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');

const secretBytes = (secretKey) => {
  if (!(secretKey instanceof Uint8Array) || secretKey.length !== 32) throw new TxError(TxErrorCode.KEY_INVALID, 'a secret key is 32 bytes');
  return Buffer.from(secretKey);
};

// --- Ed25519 (XRPL) -------------------------------------------------------------------------

const ed25519Private = (seed) => createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, secretBytes(seed)]), format: 'der', type: 'pkcs8' });

/** The 32-byte Ed25519 public key of a 32-byte seed. */
export const ed25519PublicKey = (seed) => Buffer.from(createPublicKey(ed25519Private(seed)).export({ format: 'der', type: 'spki' })).subarray(-32);

/** An Ed25519 signature (64 bytes) over the whole message; Ed25519 has no prehash. */
export const ed25519Sign = (seed, message) => nodeSign(null, Buffer.from(message), ed25519Private(seed));

// --- secp256k1 (Sepolia) ----------------------------------------------------------------------

/** Checks a secp256k1 secret: 32 bytes, from 1 to n-1. */
export function secp256k1Secret(secretKey) {
  const bytes = secretBytes(secretKey);
  const k = BigInt(`0x${bytes.toString('hex')}`);
  if (k === 0n || k >= SECP256K1_N) throw new TxError(TxErrorCode.KEY_INVALID, 'secp256k1 secret out of range');
  return bytes;
}

export const secp256k1PublicKey = (secretKey) => Buffer.from(secp256k1.getPublicKey(secp256k1Secret(secretKey), false));

/**
 * Signs a 32-byte digest (already Keccak-256 hashed; no further hashing). Returns
 * { yParity, r, s } as BigInts. The library returns low-s signatures; a recovery byte of 2 or 3
 * (r overflowed the group order) is refused.
 */
export function secp256k1SignDigest(secretKey, digest) {
  if (digest.length !== 32) throw new TxError(TxErrorCode.SIGNATURE_INVALID, 'digest must be 32 bytes');
  const bytes = secp256k1.sign(Uint8Array.from(digest), secp256k1Secret(secretKey), { prehash: false, format: 'recovered' });
  const recovery = bytes[0];
  if (recovery > 1) throw new TxError(TxErrorCode.SIGNATURE_INVALID, 'recovery byte above 1');
  const r = BigInt(`0x${Buffer.from(bytes.subarray(1, 33)).toString('hex')}`);
  const s = BigInt(`0x${Buffer.from(bytes.subarray(33, 65)).toString('hex')}`);
  return { yParity: BigInt(recovery), r, s };
}
