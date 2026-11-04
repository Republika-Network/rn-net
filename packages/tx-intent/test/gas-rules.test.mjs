// Fork-aware gas rules (ADR-RN-018 Amendment C2; RN-NET-03B2-WP2). Offline unit tests.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { test } from 'node:test';
import {
  BOUNDARY_AFTER_SECONDS,
  BOUNDARY_BEFORE_SECONDS,
  calldataGas,
  calldataGasForInput,
  checkForkBoundary,
  checkGasWithinLimit,
  checkRuleSetForTimestamp,
  evaluateGenesisGas,
  GAS_RULE_SETS,
  GAS_RULES_LIMIT,
  intrinsicGas,
  MAX_REVIEW_AGE_SECONDS,
  payloadHex,
  REVIEWED_GAS_RULE_SOURCES,
  selectSepoliaGasRules,
  SEPOLIA,
  SEPOLIA_ACTIVATIONS,
  SEPOLIA_GAS_RULES_REVIEW,
  sepoliaAnchorTemplate,
  TxErrorCode as E,
  validateActivationTable,
  validateGenesisGasPreconditions,
  validateReviewedRulesHorizon,
} from '../src/index.mjs';

const GENESIS = 'sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7';
const T = '0x57db031993583fe0cbbf42dbfcf6489e0fb70b86';
const AMSTERDAM = 1791294816;
const NOW = 1794000000;
const PIN = NOW - 24;
const PROVIDERS = ['sepolia-publicnode', 'sepolia-1rpc'];
const review = (reviewedAt = NOW - 86400, extra = {}) => ({
  reviewedAt,
  reviewer: 'unit test (not a recorded review)',
  horizon: reviewedAt + MAX_REVIEW_AGE_SECONDS,
  sources: REVIEWED_GAS_RULE_SOURCES.map((s) => ({ ...s })),
  knownUnreviewedActivations: [],
  ...extra,
});
const tx = (o = {}) => ({ ...sepoliaAnchorTemplate(GENESIS, { nonce: '0x0', from: T, maxFeePerGas: '0x77359401' }), ...o });
const code = (a, b = a) => ({ [PROVIDERS[0]]: a, [PROVIDERS[1]]: b });
const input = (o = {}) => ({ transaction: tx(), commitment: GENESIS, providerIds: [...PROVIDERS], codeEvidence: code('0x'), pinTimestamp: PIN, now: NOW, review: review(), ...o });
const refuses = (fn, code) => assert.throws(fn, (e) => e.code === code, code);

test('golden: the Genesis payload under Prague/Osaka is 22,680 and under Amsterdam 14,688, computed from its bytes', () => {
  const data = `0x${payloadHex(GENESIS)}`;
  assert.equal(Buffer.from(data.slice(2), 'hex').length, 42);
  assert.deepEqual({ ...calldataGasForInput('prague', data) }, { ruleSetId: 'prague', zeroBytes: 0, nonzeroBytes: 42, standard: 21672, floor: 22680, need: 22680 });
  assert.deepEqual({ ...calldataGasForInput('amsterdam', data) }, { ruleSetId: 'amsterdam', zeroBytes: 0, nonzeroBytes: 42, standard: 12672, floor: 14688, need: 14688 });
  // Other payloads, from the formulas (not the Genesis transaction: arithmetic only).
  assert.equal(calldataGas('prague', 42, 0).need, 21000 + 10 * 42); // floor 21,420 > standard 21,168
  assert.equal(calldataGas('amsterdam', 42, 0).need, 12000 + 16 * 4 * 42); // 14,688 for any 42 bytes
  assert.equal(calldataGas('prague', 10, 32).need, 21000 + 10 * (10 + 4 * 32)); // 22,380
  assert.equal(calldataGas('amsterdam', 10, 32).standard, 12000 + 4 * 10 + 16 * 32); // 12,552
});

test('the production gas helper and gas limit are unchanged and not replaced', () => {
  assert.equal(intrinsicGas(Buffer.from(payloadHex(GENESIS), 'hex')).gasUsed, 22680);
  assert.equal(GAS_RULES_LIMIT, 30000);
  assert.equal(SEPOLIA.gasLimit, 30000n);
});

test('the shipped review record is null: no review is recorded, so evaluation refuses', () => {
  assert.equal(SEPOLIA_GAS_RULES_REVIEW, null);
  refuses(() => evaluateGenesisGas(input({ review: SEPOLIA_GAS_RULES_REVIEW })), E.GAS_RULES_UNREVIEWED);
});

test('fork selection: −1, 0, +1 s around every reviewed activation; pre-Prague and malformed refused', () => {
  const expected = { prague: 'prague', osaka: 'prague', bpo1: 'prague', bpo2: 'prague', amsterdam: 'amsterdam' };
  SEPOLIA_ACTIVATIONS.forEach((a, i) => {
    assert.equal(selectSepoliaGasRules(a.timestamp).fork, a.fork);
    assert.equal(selectSepoliaGasRules(a.timestamp + 1).ruleSetId, expected[a.fork]);
    if (i > 0) assert.equal(selectSepoliaGasRules(a.timestamp - 1).fork, SEPOLIA_ACTIVATIONS[i - 1].fork);
  });
  assert.equal(selectSepoliaGasRules(AMSTERDAM - 1).ruleSetId, 'prague');
  assert.equal(selectSepoliaGasRules(AMSTERDAM).ruleSetId, 'amsterdam');
  refuses(() => selectSepoliaGasRules(1741159775), E.GAS_RULES_UNSUPPORTED);
  for (const bad of [undefined, null, '1791294816', 1791294816.5, -1, 2 ** 40, Number.NaN, true]) refuses(() => selectSepoliaGasRules(bad), E.GAS_INPUT_INVALID);
  refuses(() => checkRuleSetForTimestamp('glamsterdam', AMSTERDAM), E.GAS_RULES_UNSUPPORTED);
  refuses(() => checkRuleSetForTimestamp('prague', AMSTERDAM), E.GAS_RULES_UNSUPPORTED);
  assert.equal(checkRuleSetForTimestamp('amsterdam', AMSTERDAM), undefined);
});

test('the activation table is consistent, and inconsistent tables are refused', () => {
  validateActivationTable(SEPOLIA_ACTIVATIONS);
  const t = SEPOLIA_ACTIVATIONS.map((a) => ({ ...a }));
  for (const bad of [[], [t[1], t[0]], [...t, { fork: 'x', timestamp: AMSTERDAM + 1, ruleSetId: 'osaka' }], [t[4]], [...t, { ...t[4], timestamp: AMSTERDAM + 1 }], 'table']) {
    refuses(() => validateActivationTable(bad), E.GAS_RULES_UNSUPPORTED);
  }
  assert.ok(Object.isFrozen(SEPOLIA_ACTIVATIONS) && Object.isFrozen(GAS_RULE_SETS.amsterdam));
});

test('review horizon (Q1): inclusive refusal at the horizon; 30-day bound; sources and record required', () => {
  const r = review();
  assert.match(validateReviewedRulesHorizon(r, { pinTimestamp: PIN, now: NOW }).reviewDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(validateReviewedRulesHorizon(r, { pinTimestamp: r.horizon - 30, now: r.horizon - 1 }).horizon, r.horizon);
  refuses(() => validateReviewedRulesHorizon(r, { pinTimestamp: r.horizon - 30, now: r.horizon }), E.GAS_RULES_UNREVIEWED);
  refuses(() => validateReviewedRulesHorizon(r, { pinTimestamp: r.horizon, now: r.horizon - 1 }), E.GAS_RULES_UNREVIEWED);
  for (const bad of [
    null,
    undefined,
    { ...r, horizon: r.reviewedAt + MAX_REVIEW_AGE_SECONDS + 1 },
    { ...r, horizon: r.reviewedAt },
    { ...r, sources: r.sources.slice(1) },
    { ...r, sources: r.sources.map((s, i) => (i === 6 ? { ...s, sha256: `sha256:${'f'.repeat(64)}` } : s)) },
    { ...r, reviewer: '' },
    { ...r, reviewedAt: 0 },
    { ...r, renewedAt: NOW },
    { ...r, knownUnreviewedActivations: [r.horizon - 1] }, // horizon must be shortened to it
    { ...r, knownUnreviewedActivations: [AMSTERDAM] }, // already reviewed: contradictory
  ]) refuses(() => validateReviewedRulesHorizon(bad, { pinTimestamp: PIN, now: NOW }), E.GAS_RULES_UNREVIEWED);
  // A shortened horizon at the known activation is accepted.
  validateReviewedRulesHorizon({ ...r, knownUnreviewedActivations: [r.horizon] }, { pinTimestamp: PIN, now: NOW });
  refuses(() => validateReviewedRulesHorizon(r, { pinTimestamp: PIN, now: 'now' }), E.GAS_INPUT_INVALID);
});

test('the horizon is not renewed by time passing, and is not fork detection: far-future times refuse instead of defaulting', () => {
  // selectSepoliaGasRules alone knows no later fork; the composed evaluator refuses past the horizon.
  assert.equal(selectSepoliaGasRules(2 ** 40 - 1).ruleSetId, 'amsterdam');
  const r = review();
  refuses(() => evaluateGenesisGas(input({ review: r, now: r.horizon + 86400 * 365, pinTimestamp: r.horizon + 86400 * 365 - 24 })), E.GAS_RULES_UNREVIEWED);
});

test('fork boundary (Q2): each edge separately', () => {
  assert.equal(BOUNDARY_BEFORE_SECONDS, 3600);
  assert.equal(BOUNDARY_AFTER_SECONDS, 86400);
  assert.equal(checkForkBoundary(PIN, NOW, [PIN - 3601]), undefined);
  refuses(() => checkForkBoundary(PIN, NOW, [PIN - 3600]), E.GAS_FORK_BOUNDARY);
  refuses(() => checkForkBoundary(PIN, NOW, [PIN + 1]), E.GAS_FORK_BOUNDARY);
  refuses(() => checkForkBoundary(PIN, NOW, [NOW + 86400]), E.GAS_FORK_BOUNDARY);
  assert.equal(checkForkBoundary(PIN, NOW, [NOW + 86401]), undefined);
  assert.equal(checkForkBoundary(PIN, NOW, []), undefined);
  // The reviewed Amsterdam activation itself, and rules(pin) ≠ rules(now).
  refuses(() => checkForkBoundary(AMSTERDAM + 100, AMSTERDAM + 124), E.GAS_FORK_BOUNDARY);
  refuses(() => checkForkBoundary(AMSTERDAM - 100000, AMSTERDAM + 100000), E.GAS_FORK_BOUNDARY);
  refuses(() => checkForkBoundary(PIN, NOW, ['soon']), E.GAS_INPUT_INVALID);
});

test('composed: a boundary-allowed activation is still refused by the horizon, and vice versa', () => {
  // A known unreviewed activation at now + 86401 is outside the R3 window, so R3 allows it.
  // R2 must still hold: the horizon is shortened to A (accepted); a horizon past A is refused.
  const a = NOW + 86401;
  const shortened = review(NOW - 86400, { horizon: a, knownUnreviewedActivations: [a] });
  assert.equal(evaluateGenesisGas(input({ review: shortened })).need, 14688);
  refuses(() => evaluateGenesisGas(input({ review: { ...shortened, horizon: a + 1 } })), E.GAS_RULES_UNREVIEWED); // R2: horizon past A
  const near = review(NOW - 86400, { horizon: NOW + 86400, knownUnreviewedActivations: [NOW + 86400] });
  refuses(() => evaluateGenesisGas(input({ review: near })), E.GAS_FORK_BOUNDARY); // R2 passes, R3 refuses
});

test('transaction and code preconditions (G4): the valid shape passes, every deviation refuses', () => {
  const ctx = { commitment: GENESIS, providerIds: [...PROVIDERS], codeEvidence: code('0x') };
  assert.equal(validateGenesisGasPreconditions(tx(), ctx), undefined);
  const g = tx().input;
  const shapes = [
    { chainId: '0x1' }, { type: '0x0' }, { type: '0x4' }, { to: '0x1111111111111111111111111111111111111111' }, { to: null }, { value: '0x1' },
    { accessList: [{ address: T, storageKeys: [] }] }, { authorizationList: [] }, { maxFeePerBlobGas: '0x1' }, { blobVersionedHashes: [] },
    { input: g.slice(0, -2) }, { input: `${g}00` }, { input: `0x00${g.slice(4)}` }, { input: `${g.slice(0, 18)}02${g.slice(20)}` },
    { input: `${g.slice(0, 20)}02${g.slice(22)}` }, { gas: '0x7531' }, { gas: '0x5dc0' }, { estimateGas: '0x5208' }, { from: T.toUpperCase().replace('0X', '0x') },
  ];
  for (const o of shapes) refuses(() => validateGenesisGasPreconditions(tx(o), ctx), E.GAS_PRECONDITION);
  const missing = tx();
  delete missing.accessList;
  refuses(() => validateGenesisGasPreconditions(missing, ctx), E.GAS_PRECONDITION);
  refuses(() => validateGenesisGasPreconditions(tx(), { ...ctx, commitment: 'sha256:7082efeb67d3252191c9a1b7d59c757ed82382b943460cc512c16859ba5e59ff' }), E.GAS_PRECONDITION);
  refuses(() => validateGenesisGasPreconditions(tx(), { ...ctx, commitment: 'nope' }), E.GAS_INPUT_INVALID);
  for (const codeEvidence of [undefined, null, { [PROVIDERS[0]]: '0x' }, code('0x6000'), code(`0xef0100${'ab'.repeat(20)}`), code('0x', '0x6000'), code('0x', 'zz'), { ...code('0x'), extra: '0x' }]) {
    refuses(() => validateGenesisGasPreconditions(tx(), { ...ctx, codeEvidence }), E.GAS_PRECONDITION);
  }
  for (const providerIds of [[PROVIDERS[0]], [PROVIDERS[0], PROVIDERS[0]], [], ['', 'x'], 'sepolia-publicnode']) {
    refuses(() => validateGenesisGasPreconditions(tx(), { ...ctx, providerIds }), E.GAS_PRECONDITION);
  }
});

test('a synthetic payload is never accepted as the Genesis transaction, though its arithmetic is defined', () => {
  const synthetic = `0x${'00'.repeat(42)}`;
  assert.equal(calldataGasForInput('amsterdam', synthetic).need, 14688);
  refuses(() => evaluateGenesisGas(input({ transaction: tx({ input: synthetic }) })), E.GAS_PRECONDITION);
});

test('composed evaluator: Amsterdam and Prague results; the result is frozen and only reviewed inputs count', () => {
  const a = evaluateGenesisGas(input());
  assert.deepEqual(
    { ...a, reviewDigest: undefined },
    { ruleSetId: 'amsterdam', fork: 'amsterdam', reviewDigest: undefined, zeroBytes: 0, nonzeroBytes: 42, standard: 12672, floor: 14688, need: 14688, gasLimit: 30000, margin: 15312 },
  );
  assert.ok(Object.isFrozen(a));
  const p = evaluateGenesisGas(input({ pinTimestamp: 1750000000 - 24, now: 1750000000, review: review(1750000000 - 86400) }));
  assert.equal(p.ruleSetId, 'prague');
  assert.equal(p.need, 22680);
  assert.equal(p.margin, 7320);
  // A provider estimate or header field cannot reach the computation: extra input is refused.
  refuses(() => evaluateGenesisGas({ ...input(), estimateGas: '0x5208' }), E.GAS_INPUT_INVALID);
  refuses(() => evaluateGenesisGas({ ...input(), blockAccessListHash: `0x${'00'.repeat(32)}` }), E.GAS_INPUT_INVALID);
  refuses(() => evaluateGenesisGas({ ...input(), ruleSetId: 'prague' }), E.GAS_INPUT_INVALID);
  refuses(() => evaluateGenesisGas(null), E.GAS_INPUT_INVALID);
});

test('limit: never clamped; above 30,000 refuses', () => {
  assert.equal(checkGasWithinLimit(30000), 0);
  assert.equal(checkGasWithinLimit(14688), 15312);
  refuses(() => checkGasWithinLimit(30001), E.GAS_LIMIT_EXCEEDED);
  refuses(() => checkGasWithinLimit(-1), E.GAS_INPUT_INVALID);
  refuses(() => checkGasWithinLimit(1.5), E.GAS_INPUT_INVALID);
});

test('arithmetic: overflow and malformed counts refuse', () => {
  refuses(() => calldataGas('prague', 0, Number.MAX_SAFE_INTEGER), E.GAS_OVERFLOW);
  refuses(() => calldataGas('amsterdam', Number.MAX_SAFE_INTEGER, 0), E.GAS_OVERFLOW);
  for (const bad of [-1, 1.5, '42', null, true]) refuses(() => calldataGas('prague', bad, 0), E.GAS_INPUT_INVALID);
  refuses(() => calldataGas('osaka', 0, 42), E.GAS_RULES_UNSUPPORTED);
  refuses(() => calldataGasForInput('prague', '0xABCD'), E.GAS_INPUT_INVALID);
});

test('properties (fixed seed): integer costs, need ≥ both terms, determinism, no input mutation', () => {
  let s = 0x2545f491;
  const rnd = () => {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return (s >>> 0) / 2 ** 32;
  };
  for (let k = 0; k < 300; k += 1) {
    const z = Math.floor(rnd() * 100000);
    const n = Math.floor(rnd() * 100000);
    for (const r of ['prague', 'amsterdam']) {
      const g = calldataGas(r, z, n);
      for (const v of [g.standard, g.floor, g.need]) assert.ok(Number.isSafeInteger(v) && v >= 0);
      assert.ok(g.need >= g.standard && g.need >= g.floor && (g.need === g.standard || g.need === g.floor));
      assert.deepEqual(calldataGas(r, z, n), g);
    }
  }
  for (let k = 0; k < 40; k += 1) {
    const digest = Buffer.alloc(32);
    for (let i = 0; i < 32; i += 1) digest[i] = rnd() < 0.25 ? 0 : Math.floor(rnd() * 256);
    const commitment = `sha256:${digest.toString('hex')}`;
    const arg = input({ commitment, transaction: { ...sepoliaAnchorTemplate(commitment, { nonce: '0x0', from: T, maxFeePerGas: '0x1' }) } });
    const before = JSON.stringify(arg);
    const r = evaluateGenesisGas(arg);
    assert.equal(JSON.stringify(arg), before);
    assert.equal(r.need, 14688); // the Amsterdam floor depends only on the length
    assert.ok(r.need <= 30000 && r.margin === 30000 - r.need);
    assert.deepEqual(evaluateGenesisGas(arg), r);
  }
});
