// The only write requests RN-NET can express (ADR-RN-019 §4; spec/rnnet.broadcast.v1.md §4).
//
// One builder per network, and it takes only the signed bytes: there is no parameter through
// which a caller could pass a field, a fee, a secret or a key. The write allowlist is kept apart
// from chain-readonly's READ_ONLY_METHODS, and a test pins that the two are disjoint.
import { canonicalBytes } from '../../canonical/src/index.mjs';

export const SubmitNetwork = Object.freeze({ XRPL_TESTNET: 'xrpl:testnet', SEPOLIA: 'evm:11155111' });

/** The only write method per network. Exact names; there is no pattern matching. */
export const WRITE_METHODS = Object.freeze({
  [SubmitNetwork.XRPL_TESTNET]: Object.freeze(['submit']),
  [SubmitNetwork.SEPOLIA]: Object.freeze(['eth_sendRawTransaction']),
});

/** Limits of the one write request (ADR-RN-019 §6; design §4). */
export const SUBMIT_LIMITS = Object.freeze({
  timeoutMs: 10_000,
  maxResponseBytes: 262_144,
  /** One attempt, no retry, no fallback provider. */
  maxAttempts: 1,
  /** Write requests per run. */
  maxWrites: 1,
  /** Largest signed transaction accepted, in bytes; the Genesis transactions are under 300. */
  maxBlobBytes: 4096,
});

const XRPL_BLOB = /^(?:[0-9A-F]{2})+$/;
const EVM_BLOB = /^0x(?:[0-9a-f]{2})+$/;

/** Whether `signedTransaction` is written as its network writes signed bytes, within the size limit. */
export function isSignedTransactionText(network, signedTransaction) {
  if (typeof signedTransaction !== 'string') return false;
  if (network === SubmitNetwork.XRPL_TESTNET) return XRPL_BLOB.test(signedTransaction) && signedTransaction.length / 2 <= SUBMIT_LIMITS.maxBlobBytes;
  if (network === SubmitNetwork.SEPOLIA) return EVM_BLOB.test(signedTransaction) && (signedTransaction.length - 2) / 2 <= SUBMIT_LIMITS.maxBlobBytes;
  return false;
}

/**
 * The exact request bytes of the one write (canonical JSON):
 *   xrpl:testnet  {"method":"submit","params":[{"fail_hard":true,"tx_blob":<upper-case hex>}]}
 *   evm:11155111  {"id":1,"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":[<0x hex>]}
 * Throws TypeError for any other network or a malformed blob.
 */
export function submitRequestBytes(network, signedTransaction) {
  if (!Object.hasOwn(WRITE_METHODS, network)) throw new TypeError(`no write method for ${network}`);
  if (!isSignedTransactionText(network, signedTransaction)) throw new TypeError('signed transaction is not well-formed hex for its network');
  const body =
    network === SubmitNetwork.XRPL_TESTNET
      ? { method: 'submit', params: [{ tx_blob: signedTransaction, fail_hard: true }] }
      : { jsonrpc: '2.0', id: 1, method: 'eth_sendRawTransaction', params: [signedTransaction] };
  return canonicalBytes(body);
}
