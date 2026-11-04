// Fork-aware Sepolia preparation and the rnnet.tx-preparation.v2 record (RN-NET-03B2-WP3;
// ADR-RN-018 Amendment C2, Proposed; spec/rnnet.tx-preparation.v2.md). OFFLINE ONLY.
//
// It is a separate, explicitly versioned path:
//   - the C1 `prepareSepoliaIntent` (v1), XRPL preparation, the B2 and C3 fixtures and
//     tools/prepare/ (disabled) are unchanged and still produce v1;
//   - this path produces only v2, and its verifier accepts only v2.
//
// Request plan: the C1 three passes, byte for byte (8 requests per provider, one attempt, pinned
// reads at {blockHash, requireCanonical: true}, eth_estimateGas included). WP3 adds no request,
// no retry and no fallback.
//
// Gas-rule authority. The operational exports take the review ONLY from the reviewed constant
// SEPOLIA_GAS_RULES_REVIEW (packages/tx-intent), which is null, so they refuse every run. The
// `…WithAuthority` functions are the test seam:
//   - they take an explicit review, used for synthetic TEST records only;
//   - index.mjs does not export them;
//   - tools/preparation-v2.test.mjs pins every file that imports this one;
//   - the guard forbids joining tx-prepare to any transport (PREPARE_TRANSPORT_JOINERS is empty).
import { Network, PREPARATION_REQUESTS, readSepoliaHead, readSepoliaPin, readSepoliaPinned } from '../../chain-readonly/src/index.mjs';
import {
  approvedIntent,
  evaluateGenesisGas,
  GAS_RULES_LIMIT,
  INTENT_FORMAT,
  isPlainData,
  SEPOLIA,
  SEPOLIA_GAS_RULES_REVIEW,
  sepoliaAnchorTemplate,
  sepoliaMaxFee,
  validateReviewedRulesHorizon,
} from '../../tx-intent/src/index.mjs';
import { PrepError, PrepErrorCode as C } from './errors.mjs';
import { checkCommon, intentFrom, maxOf, minOf, PREPARATION_RULES, providerReader } from './prepare.mjs';

export const PREPARATION_FORMAT_V2 = 'rnnet.tx-preparation.v2';
export const PREPARATION_RULES_V2_ID = 'ADR-RN-018-C2';

const EVM_ADDRESS = /^0x[0-9a-f]{40}$/;
const EVM_HASH = /^0x[0-9a-f]{64}$/;
const QUANTITY = /^0x(0|[1-9a-f][0-9a-f]*)$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const INPUT_KEYS = ['commitment', 'from', 'now', 'providers', 'transport'];
const RECORD_KEYS = ['format', 'source', 'rules', 'observedAt', 'gas', 'providers'];
const GAS_KEYS = ['ruleSetId', 'fork', 'reviewDigest', 'review', 'standard', 'floor', 'need', 'gasLimit'];
const PROVIDER_KEYS = ['id', 'operator', 'block', 'code', 'estimateGas', 'exchanges'];
const BLOCK_KEYS = ['number', 'hash', 'timestamp', 'baseFeePerGas'];
const EXCHANGE_KEYS = ['method', 'requestSha256', 'responseSha256'];
/** Strict structural equality of plain JSON data (same keys, same values, same array order). */
const sameText = (a, b) => {
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return a === b;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => Object.hasOwn(b, k) && sameText(a[k], b[k]));
};
const exactKeys = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));

/**
 * A refusal of the WP2 gas engine as a preparation refusal, with the existing codes (C2 G5):
 *   - the limit → RNTP_GAS_TOO_HIGH;
 *   - review, horizon, rule set, boundary, time order, preconditions, overflow →
 *     RNTP_INCONSISTENT.
 * `gasRules` keeps the exact RNTX_GAS_* code.
 */
function gasRefusal(error, providerId = null) {
  if (error?.name !== 'TxError' || typeof error.code !== 'string' || !error.code.startsWith('RNTX_GAS_')) throw error;
  const refusal = new PrepError(error.code === 'RNTX_GAS_LIMIT_EXCEEDED' ? C.GAS_TOO_HIGH : C.INCONSISTENT, providerId, error.detail);
  refusal.gasRules = error.code;
  return refusal;
}
const gasStep = (fn) => {
  try {
    return fn();
  } catch (error) {
    throw gasRefusal(error);
  }
};
const toTimestamp = (quantity) => {
  const v = BigInt(quantity);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new PrepError(C.MALFORMED, null, 'block timestamp out of range');
  return Number(v);
};

/** Operational v2 preparation: the reviewed authority only (null today, so every run is refused before any request). */
export function prepareSepoliaIntentV2(input) {
  return prepareSepoliaIntentV2WithAuthority(input, SEPOLIA_GAS_RULES_REVIEW);
}

/**
 * The v2 flow. The order of refusals is deterministic:
 *   1. input: exact keys {commitment, from, now, providers, transport}; C1 provider checks;
 *   2. the review authority at `now` (missing, malformed, future-dated, expired), before any
 *      request;
 *   3. head pass;
 *   4. pin pass (one agreed hash and contents);
 *   5. pinned pass: per provider, the pending nonce and code === "0x";
 *   6. nonce agreement across providers;
 *   7. the fee from the pin, and the completed transaction (gas fixed at 30,000);
 *   8. the WP2 engine on that transaction, the pin timestamp, `now`, the authority and each
 *      provider's pinned code;
 *   9. per provider: estimate > 30,000 → RNTP_GAS_TOO_HIGH; estimate < need → RNTP_INCONSISTENT;
 *  10. balance ≥ 30,000 × maxFeePerGas;
 *  11. the v2 record and the intent, built once.
 *
 * Change from v1: v1 checks the estimate inside step 5 against the Prague bound. v2 checks it in
 * step 9 against the fork-aware need. Everything else keeps the v1 order.
 */
export async function prepareSepoliaIntentV2WithAuthority(input, authority) {
  if (input === null || typeof input !== 'object' || !exactKeys(input, INPUT_KEYS)) throw new PrepError(C.INPUT_INVALID, null, `input must have exactly ${INPUT_KEYS.join(', ')}`);
  // Each field is read exactly once; providers must be plain data and are frozen copies from here
  // on, so a getter, a proxy or a transport that edits the caller's objects cannot show the checks
  // one value and the record another.
  const commitment = input.commitment;
  const from = input.from;
  const now = input.now;
  const transport = input.transport;
  const given = input.providers;
  if (!isPlainData(given)) throw new PrepError(C.INPUT_INVALID, null, 'providers must be plain JSON data');
  checkCommon({ commitment, providers: given, transport, now }, Network.SEPOLIA);
  const providers = given.map((g) => Object.freeze({ id: g.id, network: g.network, url: g.url, operator: g.operator }));
  if (typeof from !== 'string' || !EVM_ADDRESS.test(from)) throw new PrepError(C.INPUT_INVALID, null, 'from must be a lowercase address');
  gasStep(() => validateReviewedRulesHorizon(authority, { pinTimestamp: now, now }));

  const rules = PREPARATION_RULES.sepolia;
  const template = sepoliaAnchorTemplate(commitment, { from });
  const call = { from, input: template.input };
  const readers = providers.map((provider) => providerReader(provider, transport, Network.SEPOLIA));
  const fresh = (block, maxAge, id, what) => {
    const timestamp = BigInt(block.timestamp);
    if (BigInt(now) - timestamp > BigInt(maxAge)) throw new PrepError(C.STALE, id, `${what} too old`);
    if (timestamp - BigInt(now) >= BigInt(rules.maxClockAheadSeconds)) throw new PrepError(C.STALE, id, `${what} is in the future`);
    if (BigInt(block.baseFeePerGas) > rules.maxBaseFeeWei) throw new PrepError(C.FEE_TOO_HIGH, id, `${what}: base fee above 19 gwei`);
  };

  // 3. Head pass.
  const heads = [];
  for (const reader of readers) {
    const { block } = await reader.read((context) => readSepoliaHead(context));
    fresh(block, rules.maxBlockAgeSeconds, reader.provider.id, 'latest block');
    heads.push(block);
  }
  const heights = heads.map((b) => BigInt(b.number));
  if (maxOf(heights) - minOf(heights) > BigInt(rules.maxBlockSkew)) throw new PrepError(C.INCONSISTENT, null, 'providers are too far apart');
  if (heads.some((a) => heads.some((b) => a.number === b.number && a.hash !== b.hash))) throw new PrepError(C.INCONSISTENT, null, 'one block number with two hashes');

  // 4. The pin.
  const pinNumber = minOf(heights) - BigInt(rules.pinDepth);
  if (pinNumber < 0n) throw new PrepError(C.INCONSISTENT, null, 'the chain is shorter than the pin depth');
  const pinQuantity = `0x${pinNumber.toString(16)}`;
  const pins = [];
  for (const [i, reader] of readers.entries()) {
    const id = reader.provider.id;
    const pin = await reader.read((context) => readSepoliaPin(context, pinQuantity));
    if (pin.number !== pinQuantity) throw new PrepError(C.INCONSISTENT, id, 'the pinned block is not the block asked for');
    if (pin.hash === heads[i].hash || BigInt(pin.timestamp) > BigInt(heads[i].timestamp)) throw new PrepError(C.INCONSISTENT, id, 'the pinned block does not precede the latest block');
    fresh(pin, rules.maxPinAgeSeconds, id, 'pinned block');
    pins.push(pin);
  }
  const pin = pins[0];
  if (pins.some((b) => b.hash !== pin.hash)) throw new PrepError(C.INCONSISTENT, null, 'providers disagree on the pinned block hash');
  if (pins.some((b) => b.timestamp !== pin.timestamp || b.baseFeePerGas !== pin.baseFeePerGas)) throw new PrepError(C.INCONSISTENT, null, 'one pinned block hash with two contents');

  // 5. Pinned pass: account state at the agreed hash only.
  const readings = [];
  for (const reader of readers) {
    const id = reader.provider.id;
    const o = await reader.read((context) => readSepoliaPinned(context, { ...call, blockHash: pin.hash }), { pinned: true });
    if (o.noncePending !== o.nonceLatest) throw new PrepError(C.NONCE_PENDING, id, 'the pending nonce is not the pinned nonce');
    if (o.code !== '0x') throw new PrepError(C.ACCOUNT_UNSUITABLE, id, 'the sender has code or an EIP-7702 delegation');
    readings.push({ reader, o });
  }
  // 6. Nonce agreement.
  if (new Set(readings.map((r) => r.o.nonceLatest)).size !== 1) throw new PrepError(C.INCONSISTENT, null, 'providers disagree on the nonce');
  // 7. The completed transaction (gas fixed at 30,000; never from the need or an estimate).
  const maxFeePerGas = sepoliaMaxFee(pin.baseFeePerGas);
  const transaction = sepoliaAnchorTemplate(commitment, { nonce: readings[0].o.nonceLatest, from, maxFeePerGas });

  // 8. The fork-aware need (WP2), on the code each provider returned at the agreed pin H.
  const providerIds = readings.map((r) => r.reader.provider.id);
  const gas = gasStep(() => evaluateGenesisGas({
    transaction,
    commitment,
    providerIds,
    codeEvidence: Object.fromEntries(readings.map((r) => [r.reader.provider.id, r.o.code])),
    pinTimestamp: toTimestamp(pin.timestamp),
    now,
    review: authority,
  }));
  // 9. The live estimate as a numerical cross-check only: need ≤ estimate ≤ 30,000.
  for (const { reader, o } of readings) {
    const estimate = BigInt(o.estimateGas);
    if (estimate > BigInt(GAS_RULES_LIMIT)) throw new PrepError(C.GAS_TOO_HIGH, reader.provider.id, 'estimate above the gas limit');
    if (estimate < BigInt(gas.need)) throw new PrepError(C.INCONSISTENT, reader.provider.id, `estimate below the ${gas.ruleSetId} need ${gas.need}`);
  }
  // 10. Balance.
  const worstCase = SEPOLIA.gasLimit * BigInt(maxFeePerGas);
  for (const { reader, o } of readings) {
    if (BigInt(o.balance) < worstCase) throw new PrepError(C.INSUFFICIENT_BALANCE, reader.provider.id, 'balance below gas limit times maxFeePerGas');
  }
  // 11. One record, one intent.
  const preparation = {
    format: PREPARATION_FORMAT_V2,
    source: 'rpc-read',
    rules: PREPARATION_RULES_V2_ID,
    observedAt: now,
    gas: { ruleSetId: gas.ruleSetId, fork: gas.fork, reviewDigest: gas.reviewDigest, review: authority, standard: gas.standard, floor: gas.floor, need: gas.need, gasLimit: gas.gasLimit },
    providers: readings.map(({ reader, o }) => ({
      id: reader.provider.id,
      operator: reader.provider.operator,
      block: { ...pin },
      code: o.code,
      estimateGas: o.estimateGas,
      exchanges: reader.exchanges,
    })),
  };
  return intentFrom({ network: Network.SEPOLIA, commitment, transaction, preparation });
}

/** Operational v2 verifier: the reviewed authority only (null today, so every record is refused). */
export function verifySepoliaPreparationV2(intent, approvedDigest) {
  return verifySepoliaPreparationV2WithAuthority(intent, approvedDigest, SEPOLIA_GAS_RULES_REVIEW);
}

/**
 * Checks an approved Sepolia intent whose preparation is a v2 record, without any network, in
 * this order:
 *   1. the intent and its digest (approvedIntent): any change to the record, its gas member or
 *      its review breaks the digest;
 *   2. the record's exact structure: RNTP_INTENT_INVALID for an unsupported `format` (v1
 *      included), an unknown, missing or ill-typed member;
 *   3. pin agreement: every provider entry names the same block;
 *   4. the fee is the one the pin implies; gas is 30,000;
 *   5. the WP2 engine is re-run on the intent's transaction, the pin timestamp, `observedAt`, the
 *      given authority and the recorded codes. `ruleSetId`, `fork`, `reviewDigest`, `review`,
 *      `standard`, `floor`, `need` and `gasLimit` must each equal the recomputation
 *      (RNTP_INCONSISTENT);
 *   6. every estimate within [need, 30,000].
 * Returns the frozen intent. Gate D and later gates do not call this yet (WP4).
 */
export function verifySepoliaPreparationV2WithAuthority(intent, approvedDigest, authority) {
  let checked;
  try {
    checked = approvedIntent(intent, approvedDigest);
  } catch (error) {
    // TxError: an invalid intent or digest; CanonicalError: not canonical data (a fractional or unsafe number).
    if (error?.name === 'TxError' || error?.name === 'CanonicalError') throw new PrepError(C.INTENT_INVALID, null, error.detail ?? error.code);
    throw error;
  }
  const invalid = (detail) => {
    throw new PrepError(C.INTENT_INVALID, null, detail);
  };
  const inconsistent = (detail, providerId = null) => {
    throw new PrepError(C.INCONSISTENT, providerId, detail);
  };
  if (checked.format !== INTENT_FORMAT || checked.network !== Network.SEPOLIA) invalid('not a Sepolia rnnet.unsigned-tx-intent.v1');
  const p = checked.preparation;
  if (!isPlainData(p) || !exactKeys(p, RECORD_KEYS)) invalid(`preparation must have exactly ${RECORD_KEYS.join(', ')}`);
  if (p.format !== PREPARATION_FORMAT_V2) invalid(`unsupported preparation format ${JSON.stringify(p.format)}: only ${PREPARATION_FORMAT_V2}`);
  if (p.source !== 'rpc-read' || p.rules !== PREPARATION_RULES_V2_ID) invalid('source must be rpc-read and rules ADR-RN-018-C2');
  if (!Number.isSafeInteger(p.observedAt) || p.observedAt <= 0) invalid('observedAt must be a positive integer');
  if (!exactKeys(p.gas, GAS_KEYS)) invalid(`gas must have exactly ${GAS_KEYS.join(', ')}`);
  for (const k of ['standard', 'floor', 'need', 'gasLimit']) if (!Number.isSafeInteger(p.gas[k]) || p.gas[k] < 0) invalid(`gas.${k} must be a non-negative integer`);
  for (const k of ['ruleSetId', 'fork']) if (typeof p.gas[k] !== 'string') invalid(`gas.${k} must be a string`);
  if (typeof p.gas.reviewDigest !== 'string' || !DIGEST.test(p.gas.reviewDigest)) invalid('gas.reviewDigest must be sha256:<hex>');
  const { minProviders, maxProviders } = PREPARATION_RULES;
  if (!Array.isArray(p.providers) || p.providers.length < minProviders || p.providers.length > maxProviders) invalid(`${minProviders} to ${maxProviders} providers`);
  const plan = PREPARATION_REQUESTS[Network.SEPOLIA];
  const ids = new Set();
  const operators = new Set();
  for (const e of p.providers) {
    if (!exactKeys(e, PROVIDER_KEYS)) invalid(`a provider entry must have exactly ${PROVIDER_KEYS.join(', ')}`);
    if (typeof e.id !== 'string' || e.id === '' || ids.has(e.id) || typeof e.operator !== 'string' || operators.has(e.operator)) invalid('provider ids and operators must be distinct strings');
    ids.add(e.id);
    operators.add(e.operator);
    if (!exactKeys(e.block, BLOCK_KEYS) || !EVM_HASH.test(e.block.hash) || !['number', 'timestamp', 'baseFeePerGas'].every((k) => typeof e.block[k] === 'string' && QUANTITY.test(e.block[k]))) invalid(`${e.id}: malformed block`);
    if (typeof e.code !== 'string' || typeof e.estimateGas !== 'string' || !QUANTITY.test(e.estimateGas)) invalid(`${e.id}: malformed code or estimate`);
    if (!Array.isArray(e.exchanges) || e.exchanges.length !== plan.length) invalid(`${e.id}: exactly ${plan.length} exchanges`);
    e.exchanges.forEach((x, i) => {
      if (!exactKeys(x, EXCHANGE_KEYS) || x.method !== plan[i] || !DIGEST.test(x.requestSha256) || !DIGEST.test(x.responseSha256)) invalid(`${e.id}: exchange ${i} must be ${plan[i]} with request and response digests`);
    });
  }
  const pin = p.providers[0].block;
  if (!p.providers.every((e) => sameText(e.block, pin))) inconsistent('providers name different pinned blocks');
  const tx = checked.transaction;
  if (tx.gas !== `0x${GAS_RULES_LIMIT.toString(16)}` || p.gas.gasLimit !== GAS_RULES_LIMIT) inconsistent('gas must be the fixed 30,000');
  if (tx.maxFeePerGas !== sepoliaMaxFee(pin.baseFeePerGas)) inconsistent('maxFeePerGas is not the one the pinned base fee implies');
  let recomputed;
  try {
    recomputed = evaluateGenesisGas({
      transaction: { ...tx, accessList: [...tx.accessList] },
      commitment: checked.commitment,
      providerIds: p.providers.map((e) => e.id),
      codeEvidence: Object.fromEntries(p.providers.map((e) => [e.id, e.code])),
      pinTimestamp: toTimestamp(pin.timestamp),
      now: p.observedAt,
      review: authority,
    });
  } catch (error) {
    throw gasRefusal(error);
  }
  if (!sameText(p.gas.review, authority)) inconsistent('gas.review is not the reviewed rules authority');
  for (const k of ['ruleSetId', 'fork', 'reviewDigest', 'standard', 'floor', 'need', 'gasLimit']) {
    if (p.gas[k] !== recomputed[k]) inconsistent(`gas.${k} ${JSON.stringify(p.gas[k])} is not the recomputed ${JSON.stringify(recomputed[k])}`);
  }
  for (const e of p.providers) {
    const est = BigInt(e.estimateGas);
    if (est > BigInt(GAS_RULES_LIMIT)) throw new PrepError(C.GAS_TOO_HIGH, e.id, 'recorded estimate above the gas limit');
    if (est < BigInt(recomputed.need)) inconsistent('recorded estimate below the need', e.id);
  }
  return checked;
}
