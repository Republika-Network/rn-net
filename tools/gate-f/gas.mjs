// Gate-F gas: integrity of the recorded gas member, the inclusion rule set and the accounting
// (spec rnnet.gate-f-sepolia-verification.v1 §4; ADR-RN-018 C2 G10; ADR-RN-020 V6–V8).
// RN-NET-03B2-WP4-B2. OFFLINE and PURE.
//
// It reuses the reviewed WP2 engine (packages/tx-intent gas-rules.mjs) and never copies its
// activation table, rule-set constants, sources or limits:
//   - evaluateGenesisGas: the integrity recomputation of the recorded member at its own pin and
//     observedAt, under the recorded review, the way the WP3 verifier re-runs it;
//   - validateReviewedRulesHorizon: the validity of each review in the history, and which review
//     covers the inclusion time;
//   - selectSepoliaGasRules: the rule set at the inclusion time, from the reviewed table only;
//   - calldataGasForInput: the need under the inclusion rule set, for a crossed fork.
//
// No clock, environment, network, key or file. Every time is an input:
//   - the preparation's pin and observedAt;
//   - t_i, which only core.mjs derives from the linked inclusion block (§3.5).
//
// AUTHORITY. Every function takes the review history as an argument, like the WP2 engine takes a
// review. The history is NOT caller authority:
//   - the operational evaluator in core.mjs passes only verifierReviewHistory(), built from the
//     reviewed constant SEPOLIA_GAS_RULES_REVIEW (null today, so the history is empty);
//   - the test stand-in passes a TEST ONLY synthetic history, through the restricted test seam.
// The dependency guard (GATE_F_RESTRICTED) lets only core.mjs and the gas test import this file.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../../packages/canonical/src/index.mjs';
import { Network, PREPARATION_REQUESTS } from '../../packages/chain-readonly/src/index.mjs';
import { calldataGasForInput, evaluateGenesisGas, GAS_RULE_SETS, GAS_RULES_LIMIT, isPlainData, selectSepoliaGasRules, SEPOLIA_GAS_RULES_REVIEW, sepoliaMaxFee, validateReviewedRulesHorizon } from '../../packages/tx-intent/src/index.mjs';

/** The v2 preparation record (spec rnnet.tx-preparation.v2 §3). Only this format carries a gas member. */
export const PREPARATION_V2 = Object.freeze({ format: 'rnnet.tx-preparation.v2', source: 'rpc-read', rules: 'ADR-RN-018-C2' });
const RECORD_KEYS = ['format', 'source', 'rules', 'observedAt', 'gas', 'providers'];
const GAS_KEYS = ['ruleSetId', 'fork', 'reviewDigest', 'review', 'standard', 'floor', 'need', 'gasLimit'];
const PROVIDER_KEYS = ['id', 'operator', 'block', 'code', 'estimateGas', 'exchanges'];
const BLOCK_KEYS = ['number', 'hash', 'timestamp', 'baseFeePerGas'];
const EXCHANGE_KEYS = ['method', 'requestSha256', 'responseSha256'];
/** spec rnnet.tx-preparation.v2 §3 (the C1 provider rule, as the WP3 verifier applies it). */
const MIN_PROVIDERS = 2;
const MAX_PROVIDERS = 4;
const EVM_HASH = /^0x[0-9a-f]{64}$/;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
/** A history entry used through the test stand-in must say so (the WP3 fixture convention). */
export const TEST_REVIEWER_PREFIX = 'TEST ONLY';

const keysAre = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
const canonicalHex = (v) => Buffer.from(canonicalBytes(v)).toString('hex');
const isGas = (v) => Number.isSafeInteger(v) && v >= 0;
/** WP2's review digest: SHA-256 of the review's canonical JSON (gas-rules.mjs validateReviewedRulesHorizon). */
export const reviewDigestOf = (review) => `sha256:${createHash('sha256').update(Buffer.from(canonicalBytes(review))).digest('hex')}`;

/**
 * The verifier's reviewed history (spec §2, I8): SEPOLIA_GAS_RULES_REVIEW and its recorded
 * successors. Only the constant exists, and it is null, so the history is empty (D2). It is never
 * read from an input, a file, the environment or a clock.
 */
export function verifierReviewHistory() {
  return Object.freeze(SEPOLIA_GAS_RULES_REVIEW === null ? [] : [SEPOLIA_GAS_RULES_REVIEW]);
}

/**
 * Refuses a malformed review history (TypeError). Each entry must be a valid WP2 review record,
 * checked at its own reviewedAt (there is no clock): exact fields, the pinned sources, a horizon
 * after reviewedAt and at most 30 days later, no horizon past a known unreviewed activation.
 * Entries are distinct. With `testOnly`, every reviewer must start with TEST ONLY.
 */
export function checkReviewHistory(history, { testOnly }) {
  if (!Array.isArray(history)) throw new TypeError('the review history must be a list');
  const seen = new Set();
  for (const review of history) {
    try {
      validateReviewedRulesHorizon(review, { pinTimestamp: review?.reviewedAt, now: review?.reviewedAt });
    } catch (error) {
      throw new TypeError(`a review in the history is invalid (${error.code ?? error.message})`);
    }
    if (testOnly && !review.reviewer.startsWith(TEST_REVIEWER_PREFIX)) throw new TypeError(`a test history review must have a reviewer starting with ${TEST_REVIEWER_PREFIX}`);
    const key = canonicalHex(review);
    if (seen.has(key)) throw new TypeError('the review history lists a review twice');
    seen.add(key);
  }
  return history;
}

/** §3.1 step 3 (Stage B policy, format part): the preparation is a v2 record. No fallback, no other version. */
export function isPreparationV2(preparation) {
  return isPlainData(preparation) && keysAre(preparation, RECORD_KEYS) && preparation.format === PREPARATION_V2.format && preparation.source === PREPARATION_V2.source && preparation.rules === PREPARATION_V2.rules;
}

// A WP2 engine refusal, as the recorded member it shows to be wrong (spec §4.1, item order).
const ENGINE_SUBJECT = Object.freeze({
  RNTX_GAS_RULES_UNREVIEWED: 'gas.review', // the review does not cover the pin or observedAt (item 7)
  RNTX_GAS_FORK_BOUNDARY: 'gas.fork', // a known activation inside the boundary window (C2 G5 R3)
  RNTX_GAS_RULES_UNSUPPORTED: 'gas.ruleSetId', // no reviewed rule set at the pin
  RNTX_GAS_PRECONDITION: 'transaction', // the G4 shape or the recorded code evidence
  RNTX_GAS_INPUT_INVALID: 'observedAt', // pin after observedAt, or a malformed time
  RNTX_GAS_LIMIT_EXCEEDED: 'gas.need',
  RNTX_GAS_OVERFLOW: 'gas.need',
});

/**
 * §4.1: the integrity of the recorded gas member. `history` must already be non-empty and checked.
 * Returns { valid: true, recorded } or { valid: false, subject } (GAS_RECORD_INVALID: the first
 * failing check, named by the member it shows to be wrong). A matching receipt never repairs it,
 * and a valid intent digest is no evidence that the values are correct.
 *
 * Order (first failure wins):
 *   1. the gas member's exact fields and types;                                  subject gas
 *   2. observedAt, and the provider entries' exact shape (as the WP3 verifier);   observedAt / providers
 *   3. one pinned block on every entry;                                           providers
 *   4. ruleSetId is a reviewed rule set;                                          gas.ruleSetId
 *   5. the recorded review is in the verifier's history (exact canonical bytes);  gas.review
 *   6. reviewDigest is the digest of the recorded review;                         gas.reviewDigest
 *   7. gasLimit = 30,000 = the transaction's gas;                                 gas.gasLimit
 *   8. maxFeePerGas is the one the pinned base fee implies;                       transaction.maxFeePerGas
 *   9. the WP2 engine at the pin and observedAt under that review: coverage
 *      (reviewedAt ≤ observedAt < horizon, pin ≤ observedAt), the boundary window,
 *      the G4 preconditions with the recorded code evidence, the calldata gas;  ENGINE_SUBJECT
 *  10. ruleSetId, fork, reviewDigest, standard, floor, need, gasLimit each equal
 *      the recomputation, checked separately;                                   gas.<member>
 *  11. every recorded estimate within [need, 30,000].                           providers
 */
export function verifyRecordedGas({ transaction, commitment, preparation, history }) {
  const invalid = (subject) => Object.freeze({ valid: false, subject });
  const g = preparation.gas;
  if (!keysAre(g, GAS_KEYS) || !['standard', 'floor', 'need', 'gasLimit'].every((k) => isGas(g[k])) || typeof g.ruleSetId !== 'string' || typeof g.fork !== 'string'
    || typeof g.reviewDigest !== 'string' || !DIGEST.test(g.reviewDigest) || g.review === null || typeof g.review !== 'object' || Array.isArray(g.review)) return invalid('gas');
  if (!Number.isSafeInteger(preparation.observedAt) || preparation.observedAt <= 0) return invalid('observedAt');
  const entries = preparation.providers;
  if (!Array.isArray(entries) || entries.length < MIN_PROVIDERS || entries.length > MAX_PROVIDERS) return invalid('providers');
  const plan = PREPARATION_REQUESTS[Network.SEPOLIA];
  const ids = new Set();
  const operators = new Set();
  for (const e of entries) {
    if (!keysAre(e, PROVIDER_KEYS) || typeof e.id !== 'string' || e.id === '' || ids.has(e.id) || typeof e.operator !== 'string' || operators.has(e.operator)) return invalid('providers');
    ids.add(e.id);
    operators.add(e.operator);
    if (!keysAre(e.block, BLOCK_KEYS) || typeof e.block.hash !== 'string' || !EVM_HASH.test(e.block.hash) || !['number', 'timestamp', 'baseFeePerGas'].every((k) => typeof e.block[k] === 'string' && QUANTITY.test(e.block[k]))) return invalid('providers');
    if (typeof e.code !== 'string' || typeof e.estimateGas !== 'string' || !QUANTITY.test(e.estimateGas)) return invalid('providers');
    if (!Array.isArray(e.exchanges) || e.exchanges.length !== plan.length) return invalid('providers');
    if (!e.exchanges.every((x, i) => keysAre(x, EXCHANGE_KEYS) && x.method === plan[i] && typeof x.requestSha256 === 'string' && DIGEST.test(x.requestSha256) && typeof x.responseSha256 === 'string' && DIGEST.test(x.responseSha256))) return invalid('providers');
  }
  const pin = entries[0].block;
  if (!entries.every((e) => canonicalHex(e.block) === canonicalHex(pin))) return invalid('providers');
  const pinTime = BigInt(pin.timestamp);
  if (pinTime > BigInt(Number.MAX_SAFE_INTEGER)) return invalid('providers');

  if (!Object.hasOwn(GAS_RULE_SETS, g.ruleSetId)) return invalid('gas.ruleSetId');
  const recordedReview = canonicalHex(g.review);
  if (!history.some((r) => canonicalHex(r) === recordedReview)) return invalid('gas.review');
  if (g.reviewDigest !== reviewDigestOf(g.review)) return invalid('gas.reviewDigest');
  if (g.gasLimit !== GAS_RULES_LIMIT || transaction.gas !== `0x${GAS_RULES_LIMIT.toString(16)}`) return invalid('gas.gasLimit');
  if (transaction.maxFeePerGas !== sepoliaMaxFee(pin.baseFeePerGas)) return invalid('transaction.maxFeePerGas');

  let recomputed;
  try {
    recomputed = evaluateGenesisGas({
      transaction: { ...transaction, accessList: [...transaction.accessList] },
      commitment,
      providerIds: entries.map((e) => e.id),
      codeEvidence: Object.fromEntries(entries.map((e) => [e.id, e.code])),
      pinTimestamp: Number(pinTime),
      now: preparation.observedAt,
      review: g.review,
    });
  } catch (error) {
    if (error?.name !== 'TxError' || !Object.hasOwn(ENGINE_SUBJECT, error.code)) throw error;
    return invalid(ENGINE_SUBJECT[error.code]);
  }
  for (const k of ['ruleSetId', 'fork', 'reviewDigest', 'standard', 'floor', 'need', 'gasLimit']) if (g[k] !== recomputed[k]) return invalid(`gas.${k}`);
  for (const e of entries) {
    const estimate = BigInt(e.estimateGas);
    if (estimate > BigInt(GAS_RULES_LIMIT) || estimate < BigInt(recomputed.need)) return invalid('providers');
  }
  return Object.freeze({
    valid: true,
    recorded: Object.freeze({ ruleSetId: g.ruleSetId, fork: g.fork, reviewDigest: g.reviewDigest, standard: g.standard, floor: g.floor, need: g.need, gasLimit: g.gasLimit }),
  });
}

/**
 * §4.2: R_i, the rule set at the inclusion time, or null when it is unknown.
 *   - Coverage: a review in the history whose horizon is after t_i. Each review is valid at its own
 *     reviewedAt (checkReviewHistory), so its horizon is at most 30 days after reviewedAt and not
 *     past a known unreviewed activation; t_i < horizon then also puts t_i before every such
 *     activation. A review made after t_i may cover it: coverage is a statement about the table at
 *     t_i, and there is no clock.
 *   - The rule set: selectSepoliaGasRules(t_i) from the reviewed table, inclusive at an activation
 *     (A gives the new rule set, A − 1 the old one).
 * Never the recorded ruleSetId, a provider label, a header field, the nearest set or a default.
 */
export function inclusionRuleSet(timestamp, history) {
  const covered = history.some((review) => {
    try {
      validateReviewedRulesHorizon(review, { pinTimestamp: timestamp, now: review.reviewedAt });
      return true;
    } catch (error) {
      if (error?.name !== 'TxError') throw error;
      return false;
    }
  });
  if (!covered) return null;
  try {
    const r = selectSepoliaGasRules(timestamp);
    return Object.freeze({ ruleSetId: r.ruleSetId, fork: r.fork });
  } catch (error) {
    if (error?.name !== 'TxError') throw error;
    return null;
  }
}

/**
 * §4.1–§4.3 for one verification whose inclusion is established with a linked t_i and whose
 * gasUsed passed §3.6. `history` must be non-empty and checked (an empty history is
 * RNGF_RULES_AUTHORITY_ABSENT, decided by the caller before this runs).
 * Returns { gas, findings }: the gate-F gas member (spec §6.1) and the gas findings, in order.
 */
export function evaluateRecordedGas({ transaction, commitment, preparation, history, inclusionTimestamp, gasUsed }) {
  const base = { codeStateAtInclusion: 'NOT_ESTABLISHED', codeStateBasis: 'G4.3' };
  const integrity = verifyRecordedGas({ transaction, commitment, preparation, history });
  if (!integrity.valid) {
    return Object.freeze({
      gas: { record: 'GAS_RECORD_INVALID', recorded: null, rules: 'NOT_EVALUATED', atInclusion: null, expected: null, gasUsed, accounting: 'NOT_EVALUATED', ...base },
      findings: [{ code: 'GAS_RECORD_INVALID', group: 'gasRecord', subject: integrity.subject }],
    });
  }
  const { recorded } = integrity;
  const findings = [];
  const ri = inclusionRuleSet(inclusionTimestamp, history);
  if (ri === null) {
    findings.push({ code: 'GAS_RULES_UNRESOLVED', group: 'gasRules', subject: 'inclusion.timestamp' });
    return Object.freeze({ gas: { record: 'VALID', recorded, rules: 'GAS_RULES_UNRESOLVED', atInclusion: null, expected: null, gasUsed, accounting: 'UNRESOLVED', ...base }, findings });
  }
  let rules;
  let atInclusion = null;
  let expected;
  if (ri.ruleSetId === recorded.ruleSetId) {
    rules = 'SAME';
    expected = recorded.need;
  } else {
    rules = 'GAS_RULES_CROSSED';
    const at = calldataGasForInput(ri.ruleSetId, transaction.input);
    atInclusion = { ruleSetId: ri.ruleSetId, standard: at.standard, floor: at.floor, need: at.need };
    expected = at.need;
    findings.push({ code: 'GAS_RULES_CROSSED', group: 'gasRules', subject: null });
  }
  const accounting = gasUsed === expected ? 'GAS_ACCOUNTED' : 'GAS_ACCOUNTING_MISMATCH';
  if (accounting === 'GAS_ACCOUNTING_MISMATCH') findings.push({ code: 'GAS_ACCOUNTING_MISMATCH', group: 'gasAccounting', subject: 'receipt.gasUsed' });
  return Object.freeze({ gas: { record: 'VALID', recorded, rules, atInclusion, expected, gasUsed, accounting, ...base }, findings });
}
