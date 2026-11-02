// Testnet key generation (RN-NET-03B2-C4; ADR-RN-017 Amendment C1, K1). Generation only: no file,
// terminal, environment or network access. The command line in tools/keytool/cli.mjs does all I/O.
//
// The only file in signer/ that may use randomness (the guard pins this exception):
//   Ed25519 (XRPL):     the operating system, through Node's generateKeyPairSync('ed25519'); the
//                       32-byte seed is read back from the PKCS #8 encoding.
//   secp256k1 (Sepolia): randomBytes(32), redrawn until 1 <= k < n. Never reduced modulo n.
//   Key-file salt and IV: randomBytes(16) and randomBytes(12).
//
// Tests replace the source with a synthetic one (`source`); nothing else changes. A key made from
// a synthetic source is a test key: anyone who knows the source can recompute it.
//
// Approved for single-purpose testnet keys that hold no value. JavaScript gives no constant-time
// or memory-erasure guarantee: callers should overwrite the returned secret when done, which
// limits, but does not remove, copies the runtime may keep.
import { Buffer } from 'node:buffer';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { IntentNetwork, PURPOSES, SECP256K1_N, TxError, TxErrorCode } from '../../packages/tx-intent/src/index.mjs';
import { ed25519Sign, ed25519Verify, keccak256, secp256k1RecoverAddress, secp256k1SignDigest } from './crypto.mjs';
import { bindKey } from './keys.mjs';

const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
/** Draws allowed before giving up. A correct source fails one draw with probability below 2^-127. */
export const MAX_SECP256K1_DRAWS = 8;
const SELF_TEST_MESSAGE = Buffer.from('rnnet:keygen-self-test:v1\0', 'utf8');

const bytesOf = (value, length, what) => {
  if (!(value instanceof Uint8Array) || value.length !== length) throw new TxError(TxErrorCode.KEY_INVALID, `${what} must be ${length} bytes`);
  return Uint8Array.from(value);
};

/** The operating-system source. */
export const OS_SOURCE = Object.freeze({
  ed25519Seed() {
    const { privateKey } = generateKeyPairSync('ed25519');
    const der = privateKey.export({ format: 'der', type: 'pkcs8' });
    try {
      if (der.length !== 48 || !der.subarray(0, 16).equals(PKCS8_ED25519)) throw new TxError(TxErrorCode.KEY_INVALID, 'unexpected Ed25519 PKCS #8 encoding');
      return Uint8Array.from(der.subarray(16));
    } finally {
      der.fill(0);
    }
  },
  bytes(length) {
    return randomBytes(length);
  },
});

/**
 * Draws a secp256k1 secret by rejection sampling: each draw is 32 bytes read as a big-endian
 * integer k, accepted only if 1 <= k < n. Returns { secretKey, draws }.
 */
export function drawSecp256k1Secret(source = OS_SOURCE) {
  for (let draw = 1; draw <= MAX_SECP256K1_DRAWS; draw += 1) {
    const drawn = source.bytes(32);
    const candidate = bytesOf(drawn, 32, 'a secp256k1 draw');
    // The operating-system buffer belongs to this file: overwrite it once copied.
    if (source === OS_SOURCE) drawn.fill(0);
    const k = BigInt(`0x${Buffer.from(candidate).toString('hex')}`);
    if (k >= 1n && k < SECP256K1_N) return { secretKey: candidate, draws: draw };
    candidate.fill(0);
  }
  throw new TxError(TxErrorCode.KEY_INVALID, `no secp256k1 secret in ${MAX_SECP256K1_DRAWS} draws: the random source is broken`);
}

// Signs a fixed message with the new key and verifies it against the derived public key and
// address, so a key whose derivation is wrong is refused before it is ever stored.
function selfTest(bound) {
  if (bound.network === IntentNetwork.XRPL_TESTNET) {
    const signature = ed25519Sign(bound.secretKey, SELF_TEST_MESSAGE);
    if (!ed25519Verify(Buffer.from(bound.publicKey.slice(2), 'hex'), SELF_TEST_MESSAGE, signature)) throw new TxError(TxErrorCode.KEY_INVALID, 'Ed25519 self-test failed');
    return;
  }
  const digest = keccak256(SELF_TEST_MESSAGE);
  if (secp256k1RecoverAddress(digest, secp256k1SignDigest(bound.secretKey, digest)) !== bound.address) throw new TxError(TxErrorCode.KEY_INVALID, 'secp256k1 self-test failed');
}

/**
 * Generates a fresh key bound to one network and purpose. Returns the frozen bound key
 * { network, purpose, secretKey, publicKey, address } (see keys.mjs) after a signing self-test.
 */
export function generateKey({ network, purpose, source = OS_SOURCE } = {}) {
  if (!Object.values(IntentNetwork).includes(network)) throw new TxError(TxErrorCode.KEY_INVALID, 'unknown network');
  if (!PURPOSES.includes(purpose)) throw new TxError(TxErrorCode.KEY_INVALID, 'unknown purpose');
  let secretKey;
  if (network === IntentNetwork.XRPL_TESTNET) {
    const seed = source.ed25519Seed();
    secretKey = bytesOf(seed, 32, 'an Ed25519 seed');
    if (source === OS_SOURCE) seed.fill(0);
  } else {
    secretKey = drawSecp256k1Secret(source).secretKey;
  }
  try {
    const bound = bindKey({ network, purpose, secretKey });
    selfTest(bound);
    return bound;
  } finally {
    secretKey.fill(0);
  }
}

/** Fresh salt (16 bytes) and IV (12 bytes) for rnnet.testnet-key-file.v1. */
export function keyFileRandomness(source = OS_SOURCE) {
  return { salt: bytesOf(source.bytes(16), 16, 'a salt'), iv: bytesOf(source.bytes(12), 12, 'an IV') };
}
