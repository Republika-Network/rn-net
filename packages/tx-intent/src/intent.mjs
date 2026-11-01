// rnnet.unsigned-tx-intent.v1 (spec/rnnet.unsigned-tx-intent.v1.md): the exact unsigned
// transaction the founder approves by digest, before anything is signed.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../../canonical/src/index.mjs';
import { ensure, TxErrorCode } from './errors.mjs';
import { checkSepoliaAnchorTx, checkXrplAnchorTx, isPlainData, SEPOLIA, XRPL } from './genesis.mjs';
import { addressFromPublicKey } from './xrpl.mjs';

export const INTENT_FORMAT = 'rnnet.unsigned-tx-intent.v1';
export const INTENT_DIGEST_DOMAIN = 'rnnet:unsigned-tx-intent:v1\0';
/** The networks an intent may name. There is no Mainnet value. */
export const IntentNetwork = Object.freeze({ XRPL_TESTNET: XRPL.network, SEPOLIA: SEPOLIA.network });
/** The only purpose B1 knows. */
export const PURPOSES = Object.freeze(['genesis-proof-01']);

const INTENT_FIELDS = ['commitment', 'format', 'network', 'preparation', 'purpose', 'transaction'];
const COMMITMENT = /^sha256:[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

const deepFreeze = (value) => {
  if (value !== null && typeof value === 'object') {
    for (const key of Object.keys(value)) deepFreeze(value[key]);
    Object.freeze(value);
  }
  return value;
};

/**
 * Checks an intent and returns an immutable copy of it: plain data parsed back from its own
 * canonical JSON, deeply frozen. What is signed is derived from this copy only, so a caller that
 * later changes its own object cannot change what was checked (ADR-RN-016 §3).
 * Throws RNTX_INTENT_INVALID with the list of problems.
 */
export function makeIntent(intent) {
  ensure(isPlainData(intent) && intent !== null && typeof intent === 'object' && !Array.isArray(intent), TxErrorCode.INTENT_INVALID, 'intent must be a plain JSON object');
  const keys = Object.keys(intent).sort();
  ensure(keys.join(',') === INTENT_FIELDS.join(','), TxErrorCode.INTENT_INVALID, `intent fields must be exactly ${INTENT_FIELDS.join(', ')}`);
  ensure(intent.format === INTENT_FORMAT, TxErrorCode.INTENT_INVALID, `format must be ${INTENT_FORMAT}`);
  ensure(Object.values(IntentNetwork).includes(intent.network), TxErrorCode.INTENT_INVALID, 'network must be xrpl:testnet or evm:11155111');
  ensure(PURPOSES.includes(intent.purpose), TxErrorCode.INTENT_INVALID, 'unknown purpose');
  ensure(typeof intent.commitment === 'string' && COMMITMENT.test(intent.commitment), TxErrorCode.INTENT_INVALID, 'commitment must be sha256:<64 lowercase hex>');
  ensure(intent.preparation !== null && typeof intent.preparation === 'object' && !Array.isArray(intent.preparation), TxErrorCode.INTENT_INVALID, 'preparation must be an object');
  const tx = intent.transaction;
  const problems = intent.network === IntentNetwork.XRPL_TESTNET ? checkXrplAnchorTx(tx, intent.commitment) : checkSepoliaAnchorTx(tx, intent.commitment);
  if (intent.network === IntentNetwork.XRPL_TESTNET && problems.length === 0) {
    // SigningPubKey is bound at gate D, before approval, so the approved digest covers it, and the
    // Account must be the one that key controls.
    if (!Object.hasOwn(tx, 'SigningPubKey')) problems.push('SigningPubKey is required in an intent');
    else if (addressFromPublicKey(Buffer.from(tx.SigningPubKey, 'hex')) !== tx.Account) problems.push('Account is not the address of SigningPubKey');
  }
  ensure(problems.length === 0, TxErrorCode.INTENT_INVALID, problems.join('; '));
  return deepFreeze(JSON.parse(Buffer.from(canonicalBytes(intent)).toString('utf8')));
}

/** "sha256:<hex>" of the domain-separated canonical JSON of a checked intent. */
export function intentDigest(intent) {
  const checked = makeIntent(intent);
  const hash = createHash('sha256').update(INTENT_DIGEST_DOMAIN).update(canonicalBytes(checked)).digest('hex');
  return `sha256:${hash}`;
}

/**
 * Checks an intent and that `approvedDigest` is exactly its digest; returns the immutable intent.
 * Throws RNTX_INTENT_INVALID or RNTX_INTENT_DIGEST_MISMATCH.
 */
export function approvedIntent(intent, approvedDigest) {
  const checked = makeIntent(intent);
  ensure(typeof approvedDigest === 'string' && DIGEST.test(approvedDigest), TxErrorCode.INTENT_DIGEST_MISMATCH, 'approved digest must be sha256:<64 lowercase hex>');
  ensure(intentDigest(checked) === approvedDigest, TxErrorCode.INTENT_DIGEST_MISMATCH, 'the intent does not match the approved digest');
  return checked;
}

/** The sender an intent names: the XRPL Account or the Sepolia `from`. */
export const intentSender = (intent) => (intent.network === IntentNetwork.XRPL_TESTNET ? intent.transaction.Account : intent.transaction.from);
/** The sequence number an intent uses: the XRPL Sequence, or the Sepolia nonce as a BigInt. */
export const intentSequence = (intent) => (intent.network === IntentNetwork.XRPL_TESTNET ? BigInt(intent.transaction.Sequence) : BigInt(intent.transaction.nonce));
