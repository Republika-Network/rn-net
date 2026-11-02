// Verification of signed transaction bytes against the approved intent (ADR-RN-017;
// spec/rnnet.unsigned-tx-intent.v1.md §5). Never signs and needs no key. The independent Python
// reference (tools/reference/rnnet_tx_reference.py) produces the same record.
//
// Moved unchanged in behaviour from signer/src/verify.mjs in RN-NET-03B2-B3 (ADR-RN-019 §3), so
// that the signer's self-check and the broadcaster share it and the broadcaster never imports
// signer/. verifyXrplSignature and verifySepoliaSignature expose the signature step alone.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
  approvedIntent,
  compareSepolia,
  compareXrpl,
  decodeEip1559Signed,
  decodeXrplTx,
  IntentNetwork,
  SECP256K1_N,
  TxError,
  TxErrorCode,
  xrplSigningPreimage,
  xrplTxHash,
} from '../../packages/tx-intent/src/index.mjs';
import { CanonicalError } from '../../packages/canonical/src/index.mjs';
import { ed25519Verify, keccak256, secp256k1RecoverAddress } from './crypto.mjs';

export const VERIFICATION_FORMAT = 'rnnet.signed-tx-verification.v1';
const XRPL_BLOB = /^(?:[0-9A-F]{2})+$/;
const EVM_BLOB = /^0x(?:[0-9a-f]{2})+$/;

/** The bytes of a signed transaction as written for its network, or null if it is not well formed. */
export function signedBytes(network, signedTransaction) {
  if (typeof signedTransaction !== 'string') return null;
  if (network === IntentNetwork.XRPL_TESTNET) return XRPL_BLOB.test(signedTransaction) ? Buffer.from(signedTransaction, 'hex') : null;
  return EVM_BLOB.test(signedTransaction) ? Buffer.from(signedTransaction.slice(2), 'hex') : null;
}

/** The network's transaction hash of signed bytes. */
export const transactionHash = (network, bytes) => (network === IntentNetwork.XRPL_TESTNET ? xrplTxHash(bytes) : `0x${keccak256(bytes).toString('hex')}`);

/**
 * Checks the Ed25519 signature of a decoded XRPL transaction (spec §5 step 5): over `STX\0` and
 * the serialization without TxnSignature, with the key in SigningPubKey. Throws a TxError.
 * The caller has already checked that Account is the address of SigningPubKey.
 */
export function verifyXrplSignature(decoded) {
  if (typeof decoded.TxnSignature !== 'string') throw new TxError(TxErrorCode.SIGNATURE_INVALID, 'TxnSignature missing');
  const publicKey = Buffer.from(decoded.SigningPubKey, 'hex').subarray(1);
  if (!ed25519Verify(publicKey, xrplSigningPreimage(decoded), Buffer.from(decoded.TxnSignature, 'hex'))) throw new TxError(TxErrorCode.SIGNATURE_INVALID, 'Ed25519 signature does not verify');
}

/**
 * Checks the signature of decoded EIP-1559 bytes in the spec §5 order (y-parity, ranges, low s,
 * recovery) and returns { sender, transactionHash }: the recovered address and the Keccak-256
 * hash of the signed envelope. Throws a TxError. Comparing the sender with `from` is the caller's.
 */
export function verifySepoliaSignature(bytes) {
  const { signature, unsigned } = decodeEip1559Signed(bytes);
  const { yParity, r, s } = signature;
  if (yParity > 1n) throw new TxError(TxErrorCode.BAD_Y_PARITY, 'yParity must be 0 or 1');
  if (r === 0n || r >= SECP256K1_N || s === 0n || s >= SECP256K1_N) throw new TxError(TxErrorCode.SIGNATURE_INVALID, 'r or s out of range');
  if (s > SECP256K1_N / 2n) throw new TxError(TxErrorCode.HIGH_S, 's above n/2 (EIP-2)');
  const sender = secp256k1RecoverAddress(keccak256(unsigned), signature);
  if (sender === null) throw new TxError(TxErrorCode.SIGNATURE_INVALID, 'no public key recovers');
  return { sender, transactionHash: `0x${keccak256(bytes).toString('hex')}` };
}

function check(intent, bytes) {
  if (intent.network === IntentNetwork.XRPL_TESTNET) {
    const decoded = decodeXrplTx(bytes);
    const diff = compareXrpl(intent.transaction, decoded);
    if (diff) throw new TxError(diff.code, `field ${diff.field}`);
    verifyXrplSignature(decoded);
    return;
  }
  const { transaction } = decodeEip1559Signed(bytes);
  const diff = compareSepolia(intent.transaction, transaction);
  if (diff) throw new TxError(diff.code, `field ${diff.field}`);
  const { sender } = verifySepoliaSignature(bytes);
  if (sender !== intent.transaction.from) throw new TxError(TxErrorCode.SENDER_MISMATCH, 'recovered sender differs from the intent');
}

/**
 * Verifies `signedTransaction` (XRPL: upper-case hex blob; Sepolia: 0x-prefixed lower-case hex)
 * against `intent` and `approvedDigest`. Returns an rnnet.signed-tx-verification.v1 record:
 * outcome PASS with code null, or FAIL with the first failure's code.
 */
export function verifySignedTransaction({ intent, approvedDigest, signedTransaction }) {
  const record = { format: VERIFICATION_FORMAT, network: null, intentDigest: null, blobSha256: null, transactionHash: null, outcome: 'FAIL', code: null };
  let checked;
  try {
    checked = approvedIntent(intent, approvedDigest);
  } catch (error) {
    // A value outside rnnet.canonical-json.v1 (a lone surrogate, an unsafe integer, -0) is an
    // invalid intent too, reported as a record rather than thrown.
    if (error instanceof CanonicalError) return { ...record, code: TxErrorCode.INTENT_INVALID };
    if (!(error instanceof TxError)) throw error;
    return { ...record, code: error.code };
  }
  record.network = checked.network;
  record.intentDigest = approvedDigest;
  const bytes = signedBytes(checked.network, signedTransaction);
  if (bytes === null) return { ...record, code: TxErrorCode.DECODE };
  record.blobSha256 = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  record.transactionHash = transactionHash(checked.network, bytes);
  try {
    check(checked, bytes);
  } catch (error) {
    if (!(error instanceof TxError)) throw error;
    return { ...record, code: error.code };
  }
  return { ...record, outcome: 'PASS' };
}
