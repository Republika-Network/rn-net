// Test keys derived from public labels, for RN-NET-03B2-B1 tests and fixtures only.
//
// seed = SHA-256("rnnet:synthetic-test-key:v1:<label>"), as in RN-NET-02. For Ed25519 (XRPL) the
// seed is the key; for secp256k1 (Sepolia) it is read as a big-endian integer modulo the group
// order and must not be zero. Anyone can recompute these keys from their labels, so they can
// never stand for an identity and must never hold funds.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { IntentNetwork, SECP256K1_N } from '../../packages/tx-intent/src/index.mjs';

export const FIXTURE_PURPOSE = 'genesis-proof-01';

export function fixtureKey(network, label) {
  const seed = createHash('sha256').update(`rnnet:synthetic-test-key:v1:${label}`).digest();
  if (network === IntentNetwork.XRPL_TESTNET) return { network, purpose: FIXTURE_PURPOSE, secretKey: Uint8Array.from(seed) };
  const k = BigInt(`0x${seed.toString('hex')}`) % SECP256K1_N;
  if (k === 0n) throw new Error('label gives a zero key');
  return { network, purpose: FIXTURE_PURPOSE, secretKey: Uint8Array.from(Buffer.from(k.toString(16).padStart(64, '0'), 'hex')) };
}
