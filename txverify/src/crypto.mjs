// The verification primitives of RN-NET (RN-NET-03B2-B3, ADR-RN-019 §3). Moved unchanged in
// behaviour from the verification half of signer/src/crypto.mjs (ADR-RN-017).
//
//   Sepolia: Keccak-256 and secp256k1 public-key recovery from @noble/hashes@2.4.0 and
//            @noble/curves@2.4.0, pinned exactly. Only keccak_256,
//            secp256k1.Signature.fromBytes(..., 'recovered') and recoverPublicKey are used.
//   XRPL:    Ed25519 verification from the Node.js built-ins (createPublicKey and verify).
//
// Verification only: nothing here signs, derives a public key from a secret, generates a key or
// reads a key file. The guard (tools/guards/dependency-boundaries.mjs) enforces it.
import { Buffer } from 'node:buffer';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';

export const keccak256 = (bytes) => Buffer.from(keccak_256(Uint8Array.from(bytes)));

const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');

/** Whether a 64-byte Ed25519 signature verifies; malformed inputs are false. */
export function ed25519Verify(publicKey, message, signature) {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519, Buffer.from(publicKey)]), format: 'der', type: 'spki' });
    return nodeVerify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return false;
  }
}

/** The Ethereum address of an uncompressed public key (65 bytes, 0x04 prefix). */
export const evmAddress = (uncompressed) => `0x${keccak256(Buffer.from(uncompressed).subarray(1)).subarray(12).toString('hex')}`;

const toBytes32 = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');

/**
 * The address that signed `digest` with { yParity, r, s }, or null if no public key recovers.
 * The caller checks ranges, parity and low s first.
 */
export function secp256k1RecoverAddress(digest, { yParity, r, s }) {
  try {
    const signature = secp256k1.Signature.fromBytes(Buffer.concat([Buffer.of(Number(yParity)), toBytes32(r), toBytes32(s)]), 'recovered');
    return evmAddress(signature.recoverPublicKey(Uint8Array.from(digest)).toBytes(false));
  } catch {
    return null;
  }
}
