// The future broadcaster's input check (RN-NET-03B2-B1: interface only; spec/
// rnnet.unsigned-tx-intent.v1.md §6). There is no transport, no RPC method and no key here: the
// write path is RN-NET-03B2-B3, behind its own ADR (ADR-RN-019) and founder gate E.
//
// A verification record is a file anyone could write, so it is not trusted alone. The hand-off
// recomputes the blob hash, re-checks the intent against the approved digest, decodes the blob
// with packages/tx-intent and compares every field with the intent. Only the signature check is
// left to the two verifiers (packages/ has no Keccak-256).
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { approvedIntent, compareSepolia, compareXrpl, decodeEip1559Signed, decodeXrplTx, IntentNetwork, TxError, TxErrorCode } from '../../tx-intent/src/index.mjs';

export const HANDOFF_FORMAT = 'rnnet.signed-tx-verification.v1';
const RECORD_FIELDS = ['blobSha256', 'code', 'format', 'intentDigest', 'network', 'outcome', 'transactionHash'];

function bytesOf(network, signedTransaction) {
  if (typeof signedTransaction !== 'string') return null;
  if (network === IntentNetwork.XRPL_TESTNET) return /^(?:[0-9A-F]{2})+$/.test(signedTransaction) ? Buffer.from(signedTransaction, 'hex') : null;
  return /^0x(?:[0-9a-f]{2})+$/.test(signedTransaction) ? Buffer.from(signedTransaction.slice(2), 'hex') : null;
}

/**
 * Checks what a broadcaster would receive: the approved intent and digest, the signed
 * transaction, and the verification records of BOTH verifiers (JavaScript and Python), which must
 * be identical. Returns { network, signedTransaction, blobSha256, transactionHash } frozen, or
 * throws a TxError (RNTX_HANDOFF_*, RNTX_INTENT_*, or a decode or field code).
 */
export function checkHandoff({ intent, approvedDigest, signedTransaction, verifications }) {
  const checked = approvedIntent(intent, approvedDigest);
  if (!Array.isArray(verifications) || verifications.length !== 2) throw new TxError(TxErrorCode.HANDOFF_INVALID, 'two verification records are required (JavaScript and Python)');
  for (const record of verifications) {
    if (record === null || typeof record !== 'object' || Object.keys(record).sort().join(',') !== RECORD_FIELDS.join(',') || record.format !== HANDOFF_FORMAT) {
      throw new TxError(TxErrorCode.HANDOFF_INVALID, 'malformed verification record');
    }
  }
  const [first, second] = verifications;
  if (RECORD_FIELDS.some((field) => first[field] !== second[field])) throw new TxError(TxErrorCode.HANDOFF_INVALID, 'the two verification records differ');
  if (first.outcome !== 'PASS' || first.code !== null) throw new TxError(TxErrorCode.HANDOFF_NOT_PASS, `verification outcome ${first.outcome}`);
  if (first.network !== checked.network || first.intentDigest !== approvedDigest) throw new TxError(TxErrorCode.HANDOFF_INVALID, 'the record is for another intent');
  const bytes = bytesOf(checked.network, signedTransaction);
  if (bytes === null) throw new TxError(TxErrorCode.DECODE, 'signed transaction is not well-formed hex');
  const blobSha256 = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  if (blobSha256 !== first.blobSha256) throw new TxError(TxErrorCode.HANDOFF_BLOB_MISMATCH, 'the blob is not the verified one');
  const diff = checked.network === IntentNetwork.XRPL_TESTNET ? compareXrpl(checked.transaction, decodeXrplTx(bytes)) : compareSepolia(checked.transaction, decodeEip1559Signed(bytes).transaction);
  if (diff) throw new TxError(diff.code, `field ${diff.field}`);
  return Object.freeze({ network: checked.network, signedTransaction, blobSha256, transactionHash: first.transactionHash });
}
