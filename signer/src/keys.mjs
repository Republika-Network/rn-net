// Binds a caller-supplied secret to one network and purpose (ADR-RN-017).
//
// B1 has no key generation and no key loader: the signer receives key bytes from its caller.
// In this repository the only callers are the B1 tests and fixture generator, which pass
// label-derived test keys (signer/test/fixture-keys.mjs).
import { Buffer } from 'node:buffer';
import { addressFromPublicKey, IntentNetwork, PURPOSES, TxError, TxErrorCode } from '../../packages/tx-intent/src/index.mjs';
import { ed25519PublicKey, evmAddress, secp256k1PublicKey } from './crypto.mjs';

/**
 * Checks { network, purpose, secretKey } and returns a frozen key with its public key and
 * address. XRPL public keys are written as XRPL does ("ED" + upper-case hex).
 */
export function bindKey(input) {
  if (input === null || typeof input !== 'object') throw new TxError(TxErrorCode.KEY_INVALID, 'a key is { network, purpose, secretKey }');
  // Read each member once, so a getter cannot show the checks one value and the result another.
  const key = { network: input.network, purpose: input.purpose, secretKey: input.secretKey };
  if (!Object.values(IntentNetwork).includes(key.network)) throw new TxError(TxErrorCode.KEY_INVALID, 'unknown network');
  if (!PURPOSES.includes(key.purpose)) throw new TxError(TxErrorCode.KEY_INVALID, 'unknown purpose');
  if (!(key.secretKey instanceof Uint8Array) || key.secretKey.length !== 32) throw new TxError(TxErrorCode.KEY_INVALID, 'a secret key is 32 bytes');
  const secretKey = Uint8Array.from(key.secretKey);
  if (key.network === IntentNetwork.XRPL_TESTNET) {
    const publicKey = `ED${ed25519PublicKey(secretKey).toString('hex').toUpperCase()}`;
    return Object.freeze({ network: key.network, purpose: key.purpose, secretKey, publicKey, address: addressFromPublicKey(Buffer.from(publicKey, 'hex')) });
  }
  const uncompressed = secp256k1PublicKey(secretKey);
  return Object.freeze({ network: key.network, purpose: key.purpose, secretKey, publicKey: uncompressed.toString('hex'), address: evmAddress(uncompressed) });
}
