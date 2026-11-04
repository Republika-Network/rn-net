// rnnet.tx-preparation-v2-candidate.v1: the Stage A envelope of a fork-aware Sepolia preparation
// (ADR-RN-018 Amendment C2, Q4 as amended in WP3-R1, Proposed; spec/rnnet.tx-preparation.v2.md §5).
//
// A candidate is NOT an rnnet.unsigned-tx-intent.v1. makeIntent, approvedIntent, the signer, the
// keytool, txverify, the hand-off, the broadcaster and status all refuse it: its `format` is not
// the intent format. A v2 preparation placed in an intent is refused by the S1 allowlist. Its digest
// uses its own domain, so it is never an intent digest and confers no authority to sign or
// broadcast. Stage B (a v2 preparation inside an approved intent) needs a separately reviewed
// acceptance-policy change. It is not implemented.
//
// These functions check the envelope only: exact members, the Sepolia transaction shape, and the
// v2 record's top level. The record's semantics (pin agreement, gas recomputation, estimates) are
// checked by verifySepoliaCandidateV2 in packages/tx-prepare.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../../canonical/src/index.mjs';
import { ensure, TxErrorCode } from './errors.mjs';
import { checkSepoliaAnchorTx, isPlainData, SEPOLIA } from './genesis.mjs';

export const CANDIDATE_FORMAT = 'rnnet.tx-preparation-v2-candidate.v1';
export const CANDIDATE_DIGEST_DOMAIN = 'rnnet:tx-preparation-v2-candidate:v1\0';
const CANDIDATE_FIELDS = ['commitment', 'format', 'network', 'preparation', 'purpose', 'transaction'];
const PREPARATION_V2_FIELDS = ['format', 'gas', 'observedAt', 'providers', 'rules', 'source'];
const COMMITMENT = /^sha256:[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

const deepFreeze = (value) => {
  if (value !== null && typeof value === 'object') {
    for (const key of Object.keys(value)) deepFreeze(value[key]);
    Object.freeze(value);
  }
  return value;
};
const invalid = (condition, detail) => ensure(condition, TxErrorCode.INTENT_INVALID, `candidate: ${detail}`);

/** Checks a Stage A candidate envelope and returns an immutable canonical copy. Throws RNTX_INTENT_INVALID. */
export function makePreparationCandidate(candidate) {
  invalid(isPlainData(candidate) && candidate !== null && typeof candidate === 'object' && !Array.isArray(candidate), 'must be a plain JSON object');
  invalid(Object.keys(candidate).sort().join(',') === CANDIDATE_FIELDS.join(','), `fields must be exactly ${CANDIDATE_FIELDS.join(', ')}`);
  invalid(candidate.format === CANDIDATE_FORMAT, `format must be ${CANDIDATE_FORMAT}`);
  invalid(candidate.network === SEPOLIA.network, 'network must be evm:11155111 (v2 is Sepolia only)');
  invalid(candidate.purpose === 'genesis-proof-01', 'purpose must be genesis-proof-01');
  invalid(typeof candidate.commitment === 'string' && COMMITMENT.test(candidate.commitment), 'commitment must be sha256:<64 lowercase hex>');
  const p = candidate.preparation;
  invalid(p !== null && typeof p === 'object' && !Array.isArray(p) && Object.keys(p).sort().join(',') === PREPARATION_V2_FIELDS.join(','), `preparation must have exactly ${PREPARATION_V2_FIELDS.join(', ')}`);
  invalid(p.format === 'rnnet.tx-preparation.v2', 'preparation format must be rnnet.tx-preparation.v2');
  const problems = checkSepoliaAnchorTx(candidate.transaction, candidate.commitment);
  if (problems.length === 0 && BigInt(candidate.transaction.nonce) >= 2n ** 64n) problems.push('nonce must be below 2^64 (EIP-2681)');
  invalid(problems.length === 0, problems.join('; '));
  return deepFreeze(JSON.parse(Buffer.from(canonicalBytes(candidate)).toString('utf8')));
}

/** "sha256:<hex>" over the candidate domain and the canonical JSON of a checked candidate. Never an intent digest. */
export function candidateDigest(candidate) {
  const checked = makePreparationCandidate(candidate);
  return `sha256:${createHash('sha256').update(CANDIDATE_DIGEST_DOMAIN).update(canonicalBytes(checked)).digest('hex')}`;
}

/** Checks a candidate and that `digest` is its candidate digest; returns the immutable candidate. */
export function verifiedPreparationCandidate(candidate, digest) {
  const checked = makePreparationCandidate(candidate);
  ensure(typeof digest === 'string' && DIGEST.test(digest), TxErrorCode.INTENT_DIGEST_MISMATCH, 'candidate digest must be sha256:<64 lowercase hex>');
  ensure(candidateDigest(checked) === digest, TxErrorCode.INTENT_DIGEST_MISMATCH, 'the candidate does not match its digest');
  return checked;
}
