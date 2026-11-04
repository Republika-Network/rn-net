// Fork-aware gas rules for the Genesis Proof 01 Sepolia transaction (ADR-RN-018 Amendment C2,
// G1–G7; founder decisions Q1 and Q2). RN-NET-03B2-WP2: offline only.
//
// It is NOT wired into preparation, signing, broadcasting, C6 or gate F. WP3 integrates it. The
// production `intrinsicGas` and `checkSepoliaAnchorTx` in genesis.mjs are unchanged.
//
// Pure and deterministic:
//   - no network, file system, environment, clock or randomness;
//   - every time is an explicit input;
//   - inputs are never mutated, and results are frozen;
//   - every refusal is a TxError with an RNTX_GAS_* code.
//
// The rule set is chosen ONLY from the reviewed activation table below and an explicit
// timestamp. It is never chosen from a provider field (`blockAccessListHash`, `slotNumber`, an
// estimate, a label).
//
// The review horizon bounds how long one recorded review of the sources is trusted. It is NOT
// detection of unannounced forks: this engine cannot know network state.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../../canonical/src/index.mjs';
import { COMMITMENT_FORMAT_V1, MAGIC, PAYLOAD_LENGTH, PAYLOAD_VERSION } from '../../anchor/src/index.mjs';
import { TxError, TxErrorCode as E } from './errors.mjs';
import { isPlainData, payloadHex, SEPOLIA } from './genesis.mjs';

/** The fixed, signed gas limit (ADR-RN-016; C2 G7). Never derived from an estimate or a need. */
export const GAS_RULES_LIMIT = Number(SEPOLIA.gasLimit);
/** C2 G5 R3, founder decision Q2. The window is inclusive at both ends. */
export const BOUNDARY_BEFORE_SECONDS = 3600;
export const BOUNDARY_AFTER_SECONDS = 86400;
/** C2 G5 R2, founder decision Q1: horizon ≤ reviewedAt + 30 days. */
export const MAX_REVIEW_AGE_SECONDS = 2_592_000;
/** Timestamps are integers in [0, 2^40); this keeps every sum below 2^53. */
export const MAX_TIMESTAMP = 2 ** 40 - 1;

/**
 * The reviewed rule sets (C2 G3), with their constants from the G2 sources. The bases apply only
 * to a zero-value self-transfer, the one shape this engine accepts. Under `amsterdam`, EIP-2780
 * charges no recipient or value surcharge for it.
 */
export const GAS_RULE_SETS = Object.freeze({
  // EIP-2028 calldata; EIP-7623 floor: 10 per token (zero byte = 1 token, non-zero byte = 4).
  prague: Object.freeze({ id: 'prague', selfTransferBase: 21000, standardPerZeroByte: 4, standardPerNonzeroByte: 16, floorPerToken: 10, floorTokensPerZeroByte: 1, floorTokensPerNonzeroByte: 4 }),
  // EIP-2780 base 12,000; calldata metering unchanged; EIP-7976 floor: 16 per token, 4 tokens per
  // byte whether zero or not; the floor base is the EIP-2780 base.
  amsterdam: Object.freeze({ id: 'amsterdam', selfTransferBase: 12000, standardPerZeroByte: 4, standardPerNonzeroByte: 16, floorPerToken: 16, floorTokensPerZeroByte: 4, floorTokensPerNonzeroByte: 4 }),
});

/**
 * Sepolia activations by execution-layer timestamp (C2 G1, from the pinned `eth-clients/sepolia`
 * genesis.json). Osaka and the two blob-parameter forks leave this transaction's gas unchanged.
 */
export const SEPOLIA_ACTIVATIONS = Object.freeze([
  Object.freeze({ fork: 'prague', timestamp: 1741159776, ruleSetId: 'prague' }),
  Object.freeze({ fork: 'osaka', timestamp: 1760427360, ruleSetId: 'prague' }),
  Object.freeze({ fork: 'bpo1', timestamp: 1761017184, ruleSetId: 'prague' }),
  Object.freeze({ fork: 'bpo2', timestamp: 1761607008, ruleSetId: 'prague' }),
  Object.freeze({ fork: 'amsterdam', timestamp: 1791294816, ruleSetId: 'amsterdam' }),
]);

/** The pinned primary sources (C2 G2). A review record must list exactly these. */
export const REVIEWED_GAS_RULE_SOURCES = Object.freeze([
  ['eth-clients/sepolia:metadata/genesis.json', '7b1b9d9549787b6bbf538f943304c4cf84f7e39e', 'd558a75ef48e6fdb224b063c84c309de8a55995e263db63515b79ad4432a37df'],
  ['ethereum/execution-specs:src/ethereum/forks/amsterdam/vm/gas.py', '16898000911c1e3caa57be08509536c10ae92d3e', '67973191c49234387186ad17316c556adab73723f782e95104dd3a949132367c'],
  ['ethereum/execution-specs:src/ethereum/forks/amsterdam/transactions.py', '16898000911c1e3caa57be08509536c10ae92d3e', '846e1b579e133ab2e282ca19e85903b2b7a969d47b0b8511cf70c938e38d7188'],
  ['ethereum/go-ethereum:params/protocol_params.go', '3d858f858a458effb2a563788aedf1fe65e1f0d3', '94657cdf80d2f0b136ff6d89003326f496d3b1ba1abcb1a855b7b98c941e9e28'],
  ['ethereum/go-ethereum:core/state_transition.go', '3d858f858a458effb2a563788aedf1fe65e1f0d3', '72e7a68d1f180069920dd5db624fe8fbc7f4cb96f4491d3478239a91ae3d170d'],
  ['ethereum/go-ethereum:eth/gasestimator/gasestimator.go', '3d858f858a458effb2a563788aedf1fe65e1f0d3', '5b2949f6c16abf05cf5ad5a1ecd985c0adc693530c11b9b6e0221aefa70fcf68'],
  ['ethereum/go-ethereum:internal/ethapi/api.go', '3d858f858a458effb2a563788aedf1fe65e1f0d3', 'df5d20455fe37005d4b953a448a019f5ba0ec7aaee258060c7ed28d142743990'],
].map(([source, revision, sha256]) => Object.freeze({ source, revision, sha256: `sha256:${sha256}` })));

/**
 * The recorded review of the G2 sources (C2 G5 R2), as a reviewed constant. It is null: no
 * review is recorded yet, so every use refuses (RNTX_GAS_RULES_UNREVIEWED).
 *
 * Recording one is a reviewed change (WP3 or later), with `reviewedAt`, the reviewer and the
 * horizon. It must never be built from a clock or from caller input. A test pins it null.
 */
export const SEPOLIA_GAS_RULES_REVIEW = null;

const fail = (code, detail) => {
  throw new TxError(code, detail);
};
const isTime = (t) => Number.isSafeInteger(t) && t >= 0 && t <= MAX_TIMESTAMP;
const requireTime = (t, name) => {
  if (!isTime(t)) fail(E.GAS_INPUT_INVALID, `${name} must be an integer timestamp in [0, 2^40)`);
  return t;
};
const exactKeys = (value, keys) => {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((k) => Object.hasOwn(value, k));
};
const plainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && isPlainData(v);

/** Refuses an inconsistent activation table (RNTX_GAS_RULES_UNSUPPORTED). Checked at load for the reviewed one. */
export function validateActivationTable(table) {
  const bad = (detail) => fail(E.GAS_RULES_UNSUPPORTED, `inconsistent fork configuration: ${detail}`);
  if (!Array.isArray(table) || table.length === 0 || !isPlainData(table)) bad('not a non-empty list');
  const forks = new Set();
  table.forEach((entry, i) => {
    if (!plainObject(entry) || !exactKeys(entry, ['fork', 'timestamp', 'ruleSetId'])) bad(`entry ${i} has the wrong fields`);
    if (typeof entry.fork !== 'string' || !/^[a-z0-9]+$/.test(entry.fork) || forks.has(entry.fork)) bad(`entry ${i} fork name`);
    forks.add(entry.fork);
    if (!isTime(entry.timestamp) || (i > 0 && entry.timestamp <= table[i - 1].timestamp)) bad(`entry ${i} timestamp is not strictly increasing`);
    if (!Object.hasOwn(GAS_RULE_SETS, entry.ruleSetId)) bad(`entry ${i} names an unreviewed rule set`);
  });
  if (table[0].ruleSetId !== 'prague') bad('the first rule set must be prague');
}
validateActivationTable(SEPOLIA_ACTIVATIONS);

/**
 * The rule set in force at `timestamp`: the last reviewed activation at or before it. Refuses a
 * malformed timestamp (RNTX_GAS_INPUT_INVALID), and a pre-Prague one (RNTX_GAS_RULES_UNSUPPORTED).
 * There is no fallback: an unknown fork can never default to `amsterdam`; the horizon check
 * refuses times beyond the reviewed period.
 */
export function selectSepoliaGasRules(timestamp) {
  requireTime(timestamp, 'timestamp');
  let found = null;
  for (const activation of SEPOLIA_ACTIVATIONS) if (activation.timestamp <= timestamp) found = activation;
  if (found === null) fail(E.GAS_RULES_UNSUPPORTED, 'before the first reviewed rule set (pre-Prague)');
  return Object.freeze({ ruleSetId: found.ruleSetId, fork: found.fork, activationTimestamp: found.timestamp });
}

/** Refuses unless `ruleSetId` is reviewed and is the rule set in force at `timestamp`. */
export function checkRuleSetForTimestamp(ruleSetId, timestamp) {
  if (typeof ruleSetId !== 'string' || !Object.hasOwn(GAS_RULE_SETS, ruleSetId)) fail(E.GAS_RULES_UNSUPPORTED, 'unknown rule set');
  if (selectSepoliaGasRules(timestamp).ruleSetId !== ruleSetId) fail(E.GAS_RULES_UNSUPPORTED, 'the rule set does not match the reviewed rule set at that timestamp');
}

/**
 * Arithmetic only: the standard cost, floor and need of a zero-value self-transfer with these
 * calldata byte counts under `ruleSetId`. It does NOT validate a Genesis transaction, and its
 * result is no evidence that the transaction is safe to send. Refuses results above 2^53 − 1
 * (RNTX_GAS_OVERFLOW).
 */
export function calldataGas(ruleSetId, zeroBytes, nonzeroBytes) {
  if (typeof ruleSetId !== 'string' || !Object.hasOwn(GAS_RULE_SETS, ruleSetId)) fail(E.GAS_RULES_UNSUPPORTED, 'unknown rule set');
  for (const [name, v] of [['zeroBytes', zeroBytes], ['nonzeroBytes', nonzeroBytes]]) {
    if (!Number.isSafeInteger(v) || v < 0) fail(E.GAS_INPUT_INVALID, `${name} must be a non-negative safe integer`);
  }
  const r = GAS_RULE_SETS[ruleSetId];
  const z = BigInt(zeroBytes);
  const n = BigInt(nonzeroBytes);
  const standard = BigInt(r.selfTransferBase) + BigInt(r.standardPerZeroByte) * z + BigInt(r.standardPerNonzeroByte) * n;
  const floor = BigInt(r.selfTransferBase) + BigInt(r.floorPerToken) * (BigInt(r.floorTokensPerZeroByte) * z + BigInt(r.floorTokensPerNonzeroByte) * n);
  const max = BigInt(Number.MAX_SAFE_INTEGER);
  if (standard > max || floor > max) fail(E.GAS_OVERFLOW, 'gas exceeds 2^53 - 1');
  const need = standard > floor ? standard : floor;
  return Object.freeze({ ruleSetId, zeroBytes, nonzeroBytes, standard: Number(standard), floor: Number(floor), need: Number(need) });
}

const HEX_DATA = /^0x(?:[0-9a-f]{2})*$/;

/** Arithmetic over `0x` lowercase hex calldata; see calldataGas. */
export function calldataGasForInput(ruleSetId, inputHex) {
  if (typeof inputHex !== 'string' || !HEX_DATA.test(inputHex)) fail(E.GAS_INPUT_INVALID, 'input must be 0x-prefixed lowercase hex bytes');
  const bytes = Buffer.from(inputHex.slice(2), 'hex');
  const zero = bytes.filter((b) => b === 0).length;
  return calldataGas(ruleSetId, zero, bytes.length - zero);
}

/** Refuses `need` above the fixed limit (RNTX_GAS_LIMIT_EXCEEDED). Never clamps. */
export function checkGasWithinLimit(need) {
  if (!Number.isSafeInteger(need) || need < 0) fail(E.GAS_INPUT_INVALID, 'need must be a non-negative safe integer');
  if (need > GAS_RULES_LIMIT) fail(E.GAS_LIMIT_EXCEEDED, `need ${need} exceeds the fixed ${GAS_RULES_LIMIT} gas limit`);
  return GAS_RULES_LIMIT - need;
}

const REVIEW_KEYS = ['reviewedAt', 'reviewer', 'horizon', 'sources', 'knownUnreviewedActivations'];
const LAST_REVIEWED_ACTIVATION = SEPOLIA_ACTIVATIONS[SEPOLIA_ACTIVATIONS.length - 1].timestamp;

/**
 * C2 G5 R2 (founder decision Q1). The review record holds:
 *   - reviewedAt: when the G2 sources were explicitly re-checked;
 *   - reviewer: a non-empty name;
 *   - sources: exactly REVIEWED_GAS_RULE_SOURCES;
 *   - horizon;
 *   - knownUnreviewedActivations: strictly increasing timestamps, each after the last reviewed
 *     activation, of activations known at review time but not covered by a reviewed rule set.
 *
 * It refuses (RNTX_GAS_RULES_UNREVIEWED) when:
 *   - the record is missing or malformed, or a source does not match;
 *   - horizon ≤ reviewedAt, or horizon > reviewedAt + 30 days;
 *   - horizon > any known unreviewed activation;
 *   - pinTimestamp or now is at or after the horizon (inclusive).
 *
 * The horizon never extends with time, and it does not detect unannounced forks. Returns the
 * review digest (SHA-256 of the record's canonical JSON) and the horizon.
 */
export function validateReviewedRulesHorizon(review, { pinTimestamp, now }) {
  const bad = (detail) => fail(E.GAS_RULES_UNREVIEWED, detail);
  requireTime(pinTimestamp, 'pinTimestamp');
  requireTime(now, 'now');
  if (review === null || review === undefined) bad('no recorded review of the gas-rule sources');
  if (!plainObject(review) || !exactKeys(review, REVIEW_KEYS)) bad('the review record has the wrong fields');
  const { reviewedAt, reviewer, horizon, sources, knownUnreviewedActivations: unreviewed } = review;
  if (!isTime(reviewedAt) || reviewedAt === 0) bad('reviewedAt must be a positive timestamp');
  if (typeof reviewer !== 'string' || reviewer.trim().length === 0 || reviewer.length > 200) bad('reviewer must be a non-empty name');
  if (!Array.isArray(sources) || sources.length !== REVIEWED_GAS_RULE_SOURCES.length) bad('the review must list exactly the pinned sources');
  REVIEWED_GAS_RULE_SOURCES.forEach((pinned, i) => {
    const s = sources[i];
    if (!plainObject(s) || !exactKeys(s, ['source', 'revision', 'sha256']) || s.source !== pinned.source || s.revision !== pinned.revision || s.sha256 !== pinned.sha256) {
      bad(`source ${i} does not match the pinned source, revision and digest`);
    }
  });
  if (!Array.isArray(unreviewed)) bad('knownUnreviewedActivations must be a list');
  unreviewed.forEach((a, i) => {
    if (!isTime(a) || a <= LAST_REVIEWED_ACTIVATION || (i > 0 && a <= unreviewed[i - 1])) bad('knownUnreviewedActivations is inconsistent with the reviewed table');
  });
  if (!isTime(horizon) || horizon <= reviewedAt) bad('horizon must be a timestamp after reviewedAt');
  if (horizon > reviewedAt + MAX_REVIEW_AGE_SECONDS) bad('horizon is more than 30 days after the review');
  if (unreviewed.length > 0 && horizon > unreviewed[0]) bad('horizon is after a known unreviewed activation');
  if (pinTimestamp >= horizon || now >= horizon) bad('at or past the review horizon');
  const reviewDigest = `sha256:${createHash('sha256').update(canonicalBytes(review)).digest('hex')}`;
  return Object.freeze({ reviewDigest, horizon });
}

/**
 * C2 G5 R3 (founder decision Q2). Refuses (RNTX_GAS_FORK_BOUNDARY) when any known activation A
 * (the reviewed table plus `extraKnownActivations`) satisfies
 *     pinTimestamp − 3600 ≤ A ≤ now + 86400      (inclusive),
 * or when rules(pinTimestamp) ≠ rules(now).
 */
export function checkForkBoundary(pinTimestamp, now, extraKnownActivations = []) {
  requireTime(pinTimestamp, 'pinTimestamp');
  requireTime(now, 'now');
  if (!Array.isArray(extraKnownActivations) || !extraKnownActivations.every(isTime)) fail(E.GAS_INPUT_INVALID, 'known activations must be timestamps');
  const lower = pinTimestamp - BOUNDARY_BEFORE_SECONDS;
  const upper = now + BOUNDARY_AFTER_SECONDS;
  for (const a of [...SEPOLIA_ACTIVATIONS.map((x) => x.timestamp), ...extraKnownActivations]) {
    if (lower <= a && a <= upper) fail(E.GAS_FORK_BOUNDARY, `a known activation at ${a} is within [pin − ${BOUNDARY_BEFORE_SECONDS}, now + ${BOUNDARY_AFTER_SECONDS}]`);
  }
  if (selectSepoliaGasRules(pinTimestamp).ruleSetId !== selectSepoliaGasRules(now).ruleSetId) fail(E.GAS_FORK_BOUNDARY, 'the pin and now are under different rule sets');
}

const SEPOLIA_FIELDS = ['type', 'chainId', 'nonce', 'from', 'to', 'value', 'input', 'gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'accessList'];
const BLOB_FIELDS = ['maxFeePerBlobGas', 'blobVersionedHashes', 'blobs', 'sidecar'];
const ADDRESS = /^0x[0-9a-f]{40}$/;
const COMMITMENT = /^sha256:[0-9a-f]{64}$/;
const DELEGATION_PREFIX = '0xef0100';

/**
 * C2 G4: the exact Genesis Proof 01 transaction shape, and the code-state evidence that makes
 * execution, state and refund gas zero. Refuses (RNTX_GAS_PRECONDITION) anything else. It reads
 * nothing: `codeEvidence` maps each required provider id to the `eth_getCode` result it returned
 * at the agreed pin (obtained by the caller; WP3 binds it to the pinned reads). At least two
 * distinct providers are required (C1's two-provider rule).
 */
export function validateGenesisGasPreconditions(transaction, { commitment, providerIds, codeEvidence }) {
  const bad = (detail) => fail(E.GAS_PRECONDITION, detail);
  if (typeof commitment !== 'string' || !COMMITMENT.test(commitment)) fail(E.GAS_INPUT_INVALID, 'commitment must be sha256:<64 lowercase hex>');
  if (!plainObject(transaction)) bad('transaction must be a plain JSON object');
  const tx = transaction;
  if (Object.hasOwn(tx, 'authorizationList')) bad('an EIP-7702 authorization list is present');
  for (const f of BLOB_FIELDS) if (Object.hasOwn(tx, f)) bad(`blob field ${f} is present`);
  for (const key of Object.keys(tx)) if (!SEPOLIA_FIELDS.includes(key)) bad(`unexpected field ${key}`);
  for (const key of SEPOLIA_FIELDS) if (!Object.hasOwn(tx, key)) bad(`missing field ${key}`);
  if (tx.type !== '0x2') bad('type must be 0x2 (EIP-1559)');
  if (tx.chainId !== '0xaa36a7') bad('chainId must be 0xaa36a7 (Sepolia)');
  if (typeof tx.from !== 'string' || !ADDRESS.test(tx.from)) bad('from must be a lowercase address');
  if (tx.to === null) bad('to must be set: no contract creation');
  if (tx.to !== tx.from) bad('to must equal from (self-send)');
  if (tx.value !== '0x0') bad('value must be 0x0');
  if (!Array.isArray(tx.accessList) || tx.accessList.length !== 0) bad('accessList must be empty');
  if (tx.gas !== `0x${GAS_RULES_LIMIT.toString(16)}`) bad(`gas must be the fixed ${GAS_RULES_LIMIT}`);
  if (typeof tx.input !== 'string' || !HEX_DATA.test(tx.input)) bad('input must be 0x-prefixed lowercase hex bytes');
  const input = Buffer.from(tx.input.slice(2), 'hex');
  if (input.length !== PAYLOAD_LENGTH) bad(`input must be exactly ${PAYLOAD_LENGTH} bytes`);
  if (!MAGIC.every((b, i) => input[i] === b)) bad('input does not start with the anchor payload magic');
  if (input[MAGIC.length] !== PAYLOAD_VERSION) bad('input has an unsupported payload version');
  if (input[MAGIC.length + 1] !== COMMITMENT_FORMAT_V1) bad('input has an unsupported commitment format');
  if (tx.input !== `0x${payloadHex(commitment)}`) bad('input does not encode the Genesis commitment');

  if (!Array.isArray(providerIds) || !providerIds.every((p) => typeof p === 'string' && p.length > 0) || new Set(providerIds).size !== providerIds.length) {
    bad('providerIds must be distinct non-empty strings');
  }
  if (providerIds.length < 2) bad('at least two providers are required');
  if (!plainObject(codeEvidence)) bad('code evidence is missing');
  for (const id of providerIds) if (!Object.hasOwn(codeEvidence, id)) bad(`missing code evidence for ${id}`);
  for (const id of Object.keys(codeEvidence)) if (!providerIds.includes(id)) bad(`code evidence from an unexpected provider ${id}`);
  for (const id of providerIds) if (typeof codeEvidence[id] !== 'string' || !HEX_DATA.test(codeEvidence[id])) bad(`malformed code evidence from ${id}`);
  if (new Set(providerIds.map((id) => codeEvidence[id])).size !== 1) bad('providers disagree on the sender code');
  const code = codeEvidence[providerIds[0]];
  if (code.startsWith(DELEGATION_PREFIX)) bad('the sender has an EIP-7702 delegation');
  if (code !== '0x') bad('the sender has code');
}

const EVALUATE_KEYS = ['transaction', 'commitment', 'providerIds', 'codeEvidence', 'pinTimestamp', 'now', 'review'];

/**
 * The composed evaluator (C2 G1–G7), in order:
 *   1. the review and its horizon (R2);
 *   2. the rule sets at the pin and at `now`;
 *   3. the fork boundary (R3; R2's known unreviewed activations included);
 *   4. the transaction and code preconditions (G4);
 *   5. the calldata gas;
 *   6. the fixed limit (R6).
 *
 * The input must have exactly these keys: transaction, commitment, providerIds, codeEvidence,
 * pinTimestamp, now, review. Nothing else is read, so a provider estimate or header field cannot
 * affect the result.
 *
 * The result is local to this engine, not an accepted protocol format (the rnnet.tx-preparation.v2
 * schema is reviewed in WP3): rule set, fork at the pin, review digest, byte counts, standard,
 * floor, need, the fixed limit, and the margin. Execution, state and refund gas are zero only
 * because step 4 established the preconditions.
 */
export function evaluateGenesisGas(input) {
  if (!plainObject(input) || !exactKeys(input, EVALUATE_KEYS)) fail(E.GAS_INPUT_INVALID, `input must have exactly the fields ${EVALUATE_KEYS.join(', ')}`);
  const { transaction, commitment, providerIds, codeEvidence, pinTimestamp, now, review } = input;
  const { reviewDigest } = validateReviewedRulesHorizon(review, { pinTimestamp, now });
  const atPin = selectSepoliaGasRules(pinTimestamp);
  checkForkBoundary(pinTimestamp, now, review.knownUnreviewedActivations);
  validateGenesisGasPreconditions(transaction, { commitment, providerIds, codeEvidence });
  const gas = calldataGasForInput(atPin.ruleSetId, transaction.input);
  const margin = checkGasWithinLimit(gas.need);
  return Object.freeze({
    ruleSetId: atPin.ruleSetId,
    fork: atPin.fork,
    reviewDigest,
    zeroBytes: gas.zeroBytes,
    nonzeroBytes: gas.nonzeroBytes,
    standard: gas.standard,
    floor: gas.floor,
    need: gas.need,
    gasLimit: GAS_RULES_LIMIT,
    margin,
  });
}
