// Builds fixtures/gas-rules-wp2/vectors.json: deterministic vectors for the fork-aware gas
// rules (ADR-RN-018 Amendment C2; RN-NET-03B2-WP2). Each case has an input and the outcome of
// packages/tx-intent/src/gas-rules.mjs: `{ "ok": <result> }` or `{ "error": <RNTX code> }`.
//
//   node tools/gas-rules/build-gas-rules-vectors.mjs           # check the committed file is current
//   node tools/gas-rules/build-gas-rules-vectors.mjs --write   # write it (refuses to overwrite)
//
// tools/reference/rnnet_gas_rules_reference.py recomputes every outcome independently. Its golden
// values come from its own formulas, not from this file.
//
// Everything is synthetic or public:
//   - the review records are TEST records, never a recorded review;
//   - the address is the public B1 test address;
//   - the commitment is the public Genesis commitment.
// No network, no key, no clock: the "property" cases use a fixed-seed generator.
import { Buffer } from 'node:buffer';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  calldataGas,
  calldataGasForInput,
  checkForkBoundary,
  checkGasWithinLimit,
  checkRuleSetForTimestamp,
  evaluateGenesisGas,
  REVIEWED_GAS_RULE_SOURCES,
  selectSepoliaGasRules,
  sepoliaAnchorTemplate,
  SEPOLIA_ACTIVATIONS,
  validateActivationTable,
  validateGenesisGasPreconditions,
  validateReviewedRulesHorizon,
} from '../../packages/tx-intent/src/index.mjs';

export const DIR = fileURLToPath(new URL('../../fixtures/gas-rules-wp2/', import.meta.url));
export const FILE = 'vectors.json';
export const FORMAT = 'rnnet.gas-rules-vectors.v1';

export const GENESIS_COMMITMENT = 'sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7';
const OTHER_COMMITMENT = 'sha256:7082efeb67d3252191c9a1b7d59c757ed82382b943460cc512c16859ba5e59ff';
const T = '0x57db031993583fe0cbbf42dbfcf6489e0fb70b86'; // public B1 test address (label rn-net-03b2b1-sepolia-1)
const OTHER = '0x1111111111111111111111111111111111111111';
const AMSTERDAM = 1791294816;
const PRAGUE = 1741159776;
const PROVIDERS = ['sepolia-publicnode', 'sepolia-1rpc'];

// Synthetic times, well away from every activation.
const A_NOW = 1794000000; // Amsterdam rules
const A_PIN = A_NOW - 24;
const P_NOW = 1750000000; // Prague rules
const P_PIN = P_NOW - 24;

/** A TEST review record (never a recorded review). */
export const testReview = (reviewedAt, extra = {}) => ({
  reviewedAt,
  reviewer: 'TEST VECTOR ONLY: not a recorded review',
  horizon: reviewedAt + 2592000,
  sources: REVIEWED_GAS_RULE_SOURCES.map((s) => ({ ...s })),
  knownUnreviewedActivations: [],
  ...extra,
});
const A_REVIEW = testReview(A_NOW - 86400);
const P_REVIEW = testReview(P_NOW - 86400);

const genesisTx = (overrides = {}) => ({
  ...sepoliaAnchorTemplate(GENESIS_COMMITMENT, { nonce: '0x0', from: T, maxFeePerGas: '0x77359401' }),
  ...overrides,
});
const code = (a, b = a) => ({ [PROVIDERS[0]]: a, [PROVIDERS[1]]: b });
const evalInput = (o = {}) => ({
  transaction: genesisTx(),
  commitment: GENESIS_COMMITMENT,
  providerIds: [...PROVIDERS],
  codeEvidence: code('0x'),
  pinTimestamp: A_PIN,
  now: A_NOW,
  review: A_REVIEW,
  ...o,
});

// Deterministic generator (mulberry32), fixed seed.
function generator(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const run = (fn) => {
  try {
    const v = fn();
    return { ok: v === undefined ? null : JSON.parse(JSON.stringify(v)) };
  } catch (e) {
    if (typeof e?.code !== 'string' || !e.code.startsWith('RNTX_GAS_')) throw e;
    return { error: e.code };
  }
};

const KINDS = {
  calldata: (i) => calldataGas(i.ruleSetId, i.zeroBytes, i.nonzeroBytes),
  calldataInput: (i) => calldataGasForInput(i.ruleSetId, i.input),
  select: (i) => selectSepoliaGasRules(i.timestamp),
  ruleForTimestamp: (i) => checkRuleSetForTimestamp(i.ruleSetId, i.timestamp),
  table: (i) => validateActivationTable(i.table),
  limit: (i) => checkGasWithinLimit(i.need),
  horizon: (i) => validateReviewedRulesHorizon(i.review, { pinTimestamp: i.pinTimestamp, now: i.now }),
  boundary: (i) => checkForkBoundary(i.pinTimestamp, i.now, i.extra),
  preconditions: (i) => validateGenesisGasPreconditions(i.transaction, { commitment: i.commitment, providerIds: i.providerIds, codeEvidence: i.codeEvidence }),
  evaluate: (i) => evaluateGenesisGas(i.input),
};
export const runCase = (c) => run(() => KINDS[c.kind](c.input));

function cases() {
  const out = [];
  const add = (name, kind, input) => out.push({ name, kind, input });
  const genesisInput = `0x${genesisTx().input.slice(2)}`;

  // Golden arithmetic.
  for (const r of ['prague', 'amsterdam']) {
    add(`golden ${r}: the Genesis payload`, 'calldataInput', { ruleSetId: r, input: genesisInput });
    add(`golden ${r}: 42 zero bytes`, 'calldata', { ruleSetId: r, zeroBytes: 42, nonzeroBytes: 0 });
    add(`golden ${r}: 10 zero, 32 non-zero`, 'calldata', { ruleSetId: r, zeroBytes: 10, nonzeroBytes: 32 });
    add(`golden ${r}: empty calldata`, 'calldata', { ruleSetId: r, zeroBytes: 0, nonzeroBytes: 0 });
    add(`overflow ${r}`, 'calldata', { ruleSetId: r, zeroBytes: 0, nonzeroBytes: Number.MAX_SAFE_INTEGER });
    add(`overflow ${r}: near the bound`, 'calldata', { ruleSetId: r, zeroBytes: 2 ** 47, nonzeroBytes: 2 ** 47 });
  }
  add('calldata: unknown rule set', 'calldata', { ruleSetId: 'osaka', zeroBytes: 0, nonzeroBytes: 42 });
  add('calldata: fractional count', 'calldata', { ruleSetId: 'prague', zeroBytes: 1.5, nonzeroBytes: 0 });
  add('calldata: negative count', 'calldata', { ruleSetId: 'prague', zeroBytes: -1, nonzeroBytes: 0 });
  add('calldataInput: uppercase hex', 'calldataInput', { ruleSetId: 'prague', input: genesisInput.toUpperCase().replace('0X', '0x') });
  add('calldataInput: odd length', 'calldataInput', { ruleSetId: 'prague', input: '0x123' });
  add('calldataInput: mixed bytes', 'calldataInput', { ruleSetId: 'amsterdam', input: '0x00ff00ff0000' });

  // Selection at every activation: −1, 0, +1.
  for (const a of SEPOLIA_ACTIVATIONS) {
    for (const d of [-1, 0, 1]) add(`select ${a.fork} ${d >= 0 ? '+' : ''}${d}`, 'select', { timestamp: a.timestamp + d });
  }
  add('select: missing timestamp', 'select', { timestamp: null });
  add('select: string timestamp', 'select', { timestamp: String(AMSTERDAM) });
  add('select: fractional', 'select', { timestamp: AMSTERDAM + 0.5 });
  add('select: negative', 'select', { timestamp: -1 });
  add('select: 2^40', 'select', { timestamp: 2 ** 40 });
  add('select: 0 (pre-Prague)', 'select', { timestamp: 0 });
  add('ruleForTimestamp: amsterdam at amsterdam', 'ruleForTimestamp', { ruleSetId: 'amsterdam', timestamp: AMSTERDAM });
  add('ruleForTimestamp: prague at amsterdam', 'ruleForTimestamp', { ruleSetId: 'prague', timestamp: AMSTERDAM });
  add('ruleForTimestamp: amsterdam one second before', 'ruleForTimestamp', { ruleSetId: 'amsterdam', timestamp: AMSTERDAM - 1 });
  add('ruleForTimestamp: unknown id', 'ruleForTimestamp', { ruleSetId: 'glamsterdam', timestamp: AMSTERDAM });

  // Table consistency.
  const table = SEPOLIA_ACTIVATIONS.map((a) => ({ ...a }));
  add('table: the reviewed table', 'table', { table });
  add('table: out of order', 'table', { table: [table[0], table[2], table[1], ...table.slice(3)] });
  add('table: unreviewed rule set', 'table', { table: [...table, { fork: 'bogota', timestamp: AMSTERDAM + 100, ruleSetId: 'bogota' }] });
  add('table: duplicate fork', 'table', { table: [...table, { ...table[4], timestamp: AMSTERDAM + 100 }] });
  add('table: starts at amsterdam', 'table', { table: [table[4]] });
  add('table: empty', 'table', { table: [] });

  // Limit.
  for (const need of [14688, 22680, 30000, 30001, -1]) add(`limit ${need}`, 'limit', { need });

  // Review horizon (Q1).
  const h = A_REVIEW.horizon;
  add('horizon: valid', 'horizon', { review: A_REVIEW, pinTimestamp: A_PIN, now: A_NOW });
  add('horizon: now = horizon − 1', 'horizon', { review: A_REVIEW, pinTimestamp: h - 30, now: h - 1 });
  add('horizon: now = horizon', 'horizon', { review: A_REVIEW, pinTimestamp: h - 30, now: h });
  add('horizon: pin = horizon', 'horizon', { review: A_REVIEW, pinTimestamp: h, now: h - 1 });
  add('horizon: missing record', 'horizon', { review: null, pinTimestamp: A_PIN, now: A_NOW });
  add('horizon: 30 days + 1 s', 'horizon', { review: { ...A_REVIEW, horizon: A_REVIEW.reviewedAt + 2592001 }, pinTimestamp: A_PIN, now: A_NOW });
  add('horizon: horizon = reviewedAt', 'horizon', { review: { ...A_REVIEW, horizon: A_REVIEW.reviewedAt }, pinTimestamp: A_PIN, now: A_NOW });
  add('horizon: missing source digest', 'horizon', { review: { ...A_REVIEW, sources: A_REVIEW.sources.slice(1) }, pinTimestamp: A_PIN, now: A_NOW });
  add('horizon: wrong source digest', 'horizon', { review: { ...A_REVIEW, sources: A_REVIEW.sources.map((s, i) => (i === 3 ? { ...s, sha256: `sha256:${'0'.repeat(64)}` } : s)) }, pinTimestamp: A_PIN, now: A_NOW });
  add('horizon: wrong source revision', 'horizon', { review: { ...A_REVIEW, sources: A_REVIEW.sources.map((s, i) => (i === 0 ? { ...s, revision: 'main' } : s)) }, pinTimestamp: A_PIN, now: A_NOW });
  add('horizon: empty reviewer', 'horizon', { review: { ...A_REVIEW, reviewer: '  ' }, pinTimestamp: A_PIN, now: A_NOW });
  add('horizon: extra field', 'horizon', { review: { ...A_REVIEW, renewed: true }, pinTimestamp: A_PIN, now: A_NOW });
  add('horizon: known unreviewed activation before the horizon', 'horizon', { review: { ...A_REVIEW, knownUnreviewedActivations: [h - 1000] }, pinTimestamp: A_PIN, now: A_NOW });
  add('horizon: known unreviewed activation at the horizon', 'horizon', { review: testReview(A_NOW - 86400, { knownUnreviewedActivations: [h] }), pinTimestamp: A_PIN, now: A_NOW });
  add('horizon: "unreviewed" activation already reviewed', 'horizon', { review: { ...A_REVIEW, knownUnreviewedActivations: [AMSTERDAM] }, pinTimestamp: A_PIN, now: A_NOW });
  add('horizon: string now', 'horizon', { review: A_REVIEW, pinTimestamp: A_PIN, now: String(A_NOW) });
  // Review R2: reviewedAt ≤ now.
  add('R2 horizon: reviewedAt = now', 'horizon', { review: testReview(A_NOW), pinTimestamp: A_PIN, now: A_NOW });
  add('R2 horizon: reviewedAt = now + 1', 'horizon', { review: testReview(A_NOW + 1), pinTimestamp: A_PIN, now: A_NOW });
  add('R2 horizon: reviewedAt < now', 'horizon', { review: testReview(A_NOW - 1), pinTimestamp: A_PIN, now: A_NOW });
  add('R2 horizon: future review cannot extend the window', 'horizon', { review: testReview(A_NOW + 10 * 86400), pinTimestamp: A_PIN, now: A_NOW });

  // Fork boundary (Q2): pin and now fixed under Amsterdam rules; one extra known activation.
  const pin = A_PIN;
  const now = A_NOW;
  for (const [label, a] of [
    ['A = pin − 3601', pin - 3601],
    ['A = pin − 3600', pin - 3600],
    ['A between pin and now', pin + 10],
    ['A = now + 86400', now + 86400],
    ['A = now + 86401', now + 86401],
  ]) add(`boundary: ${label}`, 'boundary', { pinTimestamp: pin, now, extra: [a] });
  add('boundary: no activation in the window', 'boundary', { pinTimestamp: pin, now, extra: [] });
  add('boundary: reviewed Amsterdam activation inside (pin just after)', 'boundary', { pinTimestamp: AMSTERDAM + 100, now: AMSTERDAM + 124, extra: [] });
  add('boundary: pin before Amsterdam, now after', 'boundary', { pinTimestamp: AMSTERDAM - 7200, now: AMSTERDAM + 7200, extra: [] });
  add('boundary: Amsterdam within 24 h after now', 'boundary', { pinTimestamp: AMSTERDAM - 50000, now: AMSTERDAM - 40000, extra: [] });
  add('boundary: Amsterdam 24 h + 1 s after now', 'boundary', { pinTimestamp: AMSTERDAM - 86500, now: AMSTERDAM - 86401, extra: [] });
  add('boundary: pre-Prague pin', 'boundary', { pinTimestamp: PRAGUE - 200000, now: PRAGUE - 100000, extra: [] });

  // Preconditions (G4).
  const pre = (name, txOverrides, o = {}) => add(`preconditions: ${name}`, 'preconditions', { transaction: genesisTx(txOverrides), commitment: GENESIS_COMMITMENT, providerIds: [...PROVIDERS], codeEvidence: code('0x'), ...o });
  pre('valid', {});
  pre('wrong chain id', { chainId: '0x1' });
  pre('wrong type', { type: '0x0' });
  pre('wrong recipient', { to: OTHER });
  pre('null recipient', { to: null });
  pre('non-zero value', { value: '0x1' });
  pre('non-empty access list', { accessList: [{ address: T, storageKeys: [] }] });
  pre('authorization list present', { authorizationList: [] });
  pre('blob field present', { maxFeePerBlobGas: '0x1' });
  pre('blob hashes present', { blobVersionedHashes: [] });
  pre('estimate field present', { estimateGas: '0x5208' });
  pre('missing field', { accessList: undefined }, {});
  pre('input 41 bytes', { input: genesisInput.slice(0, -2) });
  pre('input 43 bytes', { input: `${genesisInput}00` });
  pre('wrong payload prefix', { input: `0x${'00'}${genesisInput.slice(4)}` });
  pre('wrong payload version', { input: `${genesisInput.slice(0, 18)}02${genesisInput.slice(20)}` });
  pre('wrong commitment format', { input: `${genesisInput.slice(0, 20)}02${genesisInput.slice(22)}` });
  pre('incorrect commitment', {}, { commitment: OTHER_COMMITMENT });
  pre('gas limit changed', { gas: '0x7531' });
  pre('missing code evidence', {}, { codeEvidence: { [PROVIDERS[0]]: '0x' } });
  pre('no code evidence', {}, { codeEvidence: null });
  pre('code not 0x', {}, { codeEvidence: code('0x6000') });
  pre('EIP-7702 delegation', {}, { codeEvidence: code(`0xef0100${'ab'.repeat(20)}`) });
  pre('providers disagree on code', {}, { codeEvidence: code('0x', '0x6000') });
  pre('malformed code', {}, { codeEvidence: code('0x', 'not hex') });
  pre('missing required provider', {}, { providerIds: [PROVIDERS[0]], codeEvidence: { [PROVIDERS[0]]: '0x' } });
  pre('unexpected provider', {}, { codeEvidence: { ...code('0x'), other: '0x' } });
  pre('duplicate providers', {}, { providerIds: [PROVIDERS[0], PROVIDERS[0]] });
  pre('malformed commitment', {}, { commitment: 'sha256:xyz' });

  // Composed evaluator.
  add('evaluate: Amsterdam, Genesis', 'evaluate', { input: evalInput() });
  add('evaluate: Prague, Genesis', 'evaluate', { input: evalInput({ pinTimestamp: P_PIN, now: P_NOW, review: P_REVIEW }) });
  add('evaluate: Osaka fork pin', 'evaluate', { input: evalInput({ pinTimestamp: 1760600000, now: 1760600024, review: testReview(1760600000 - 86400) }) });
  add('evaluate: BPO2-era pin', 'evaluate', { input: evalInput({ pinTimestamp: 1765000000, now: 1765000024, review: testReview(1765000000 - 86400) }) });
  add('evaluate: no review (the shipped constant is null)', 'evaluate', { input: evalInput({ review: null }) });
  add('evaluate: expired review', 'evaluate', { input: evalInput({ now: A_REVIEW.horizon }) });
  add('evaluate: at a boundary', 'evaluate', { input: evalInput({ pinTimestamp: AMSTERDAM + 100, now: AMSTERDAM + 124, review: testReview(AMSTERDAM) }) });
  add('evaluate: known unreviewed activation tomorrow', 'evaluate', { input: evalInput({ review: { ...A_REVIEW, horizon: A_NOW + 3600, knownUnreviewedActivations: [A_NOW + 3600] } }) });
  add('evaluate: delegation', 'evaluate', { input: evalInput({ codeEvidence: code(`0xef0100${'ab'.repeat(20)}`) }) });
  add('evaluate: extra input field (estimate)', 'evaluate', { input: { ...evalInput(), estimateGas: '0x5208' } });
  add('evaluate: extra input field (header)', 'evaluate', { input: { ...evalInput(), blockAccessListHash: `0x${'00'.repeat(32)}` } });
  // Review R1: pinTimestamp ≤ now (before any gas computation).
  add('R1 evaluate: pin = now', 'evaluate', { input: evalInput({ pinTimestamp: A_NOW }) });
  add('R1 evaluate: pin = now + 1', 'evaluate', { input: evalInput({ pinTimestamp: A_NOW + 1 }) });
  add('R1 evaluate: pin < now', 'evaluate', { input: evalInput({ pinTimestamp: A_NOW - 1 }) });
  add('R1 evaluate: malformed pin', 'evaluate', { input: evalInput({ pinTimestamp: String(A_PIN) }) });
  add('R1 evaluate: malformed now', 'evaluate', { input: evalInput({ now: A_NOW + 0.5 }) });
  add('R1 evaluate: missing pin', 'evaluate', { input: evalInput({ pinTimestamp: null }) });
  add('R1 evaluate: pin after now, also past the horizon (R1 first)', 'evaluate', { input: evalInput({ pinTimestamp: A_REVIEW.horizon + 5, now: A_REVIEW.horizon + 4 }) });
  // Review R2 through the evaluator.
  add('R2 evaluate: reviewedAt = now', 'evaluate', { input: evalInput({ review: testReview(A_NOW) }) });
  add('R2 evaluate: reviewedAt = now + 1', 'evaluate', { input: evalInput({ review: testReview(A_NOW + 1) }) });
  add('R2 evaluate: reviewedAt < now', 'evaluate', { input: evalInput({ review: testReview(A_NOW - 1) }) });
  add('evaluate: pre-Prague', 'evaluate', { input: evalInput({ pinTimestamp: PRAGUE - 100000, now: PRAGUE - 99976, review: testReview(PRAGUE - 200000) }) });

  // Properties: random digests (some with zero bytes) through both rule sets, and random counts.
  const rnd = generator(0x52_4e_57_32); // "RNW2"
  for (let k = 0; k < 24; k += 1) {
    const digest = Buffer.alloc(32);
    for (let i = 0; i < 32; i += 1) digest[i] = rnd() < 0.3 ? 0 : Math.floor(rnd() * 256);
    const commitment = `sha256:${digest.toString('hex')}`;
    const tx = { ...sepoliaAnchorTemplate(commitment, { nonce: '0x0', from: T, maxFeePerGas: '0x77359401' }) };
    const amsterdam = k % 2 === 0;
    add(`property ${k}: random digest, ${amsterdam ? 'amsterdam' : 'prague'}`, 'evaluate', {
      input: evalInput({ transaction: tx, commitment, ...(amsterdam ? {} : { pinTimestamp: P_PIN, now: P_NOW, review: P_REVIEW }) }),
    });
  }
  for (let k = 0; k < 16; k += 1) {
    const z = Math.floor(rnd() * 5000);
    const n = Math.floor(rnd() * 5000);
    add(`property counts ${k}`, 'calldata', { ruleSetId: k % 2 ? 'prague' : 'amsterdam', zeroBytes: z, nonzeroBytes: n });
  }
  return out;
}

export function build() {
  const list = cases().map((c) => {
    const input = JSON.parse(JSON.stringify(c.input)); // drop undefined fields, as the file will
    return { name: c.name, kind: c.kind, input, expect: runCase({ kind: c.kind, input }) };
  });
  const doc = {
    format: FORMAT,
    note: 'Synthetic offline vectors for ADR-RN-018 Amendment C2 (WP2). The review records are test records, not a recorded review.',
    cases: list,
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const built = build();
  if (process.argv.includes('--write')) {
    writeFileSync(DIR + FILE, built, { flag: 'wx' });
    console.log(`wrote ${DIR}${FILE}`);
  } else {
    const current = existsSync(DIR + FILE) && readFileSync(DIR + FILE, 'utf8') === built;
    console.log(current ? 'gas-rules vectors: current' : 'gas-rules vectors: NOT current');
    process.exit(current ? 0 : 1);
  }
}
