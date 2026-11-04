// RN-NET-03B2-WP4-B2: gate-F gas — recorded-member integrity, the inclusion rule set and the
// accounting (spec rnnet.gate-f-sepolia-verification.v1 §3.6, §4; ADR-RN-018 C2 G10). Synthetic and
// offline: the subject is the B1 TEST ONLY stand-in, the v2 preparation and every review are TEST
// ONLY, and every capture comes from the simulated chain read by the existing reader.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { calldataGasForInput, GAS_RULES_LIMIT, SEPOLIA_ACTIVATIONS, SEPOLIA_GAS_RULES_REVIEW } from '../packages/tx-intent/src/index.mjs';
import { A, B2_CASES, baseInputs, build, DAY, gasOf, H, INTENT, PATH_B2, PREP_AMSTERDAM, PREP_PRAGUE, REVIEW, REVIEW_OLD, runCase, synthReview, v2Preparation, VALUES } from './gate-f/build-gate-f-fixtures.mjs';
import { checkReviewHistory, evaluateRecordedGas, inclusionRuleSet, isPreparationV2, verifierReviewHistory, verifyRecordedGas } from './gate-f/gas.mjs';
import { verifyGateFHypotheticalStageBGas } from './gate-f/test-seam.mjs';
import { checkGateFChain, checkGateFRecord, gateFRecordDigest, verifyGateF } from './gate-f/verify.mjs';

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const doc = JSON.parse(readFileSync(PATH_B2, 'utf8'));
const byId = Object.fromEntries(doc.cases.map((c) => [c.id, c.expected]));
const caseOf = (id) => B2_CASES.find((c) => c.id === id);
const clone = (v) => JSON.parse(JSON.stringify(v));
const refusedAs = (code) => (e) => e.name === 'GateFError' && e.code === code;
const rec = (id) => byId[id].record;
const T_AMSTERDAM = A + 3 * DAY;
const tx = INTENT.transaction;

test('B2 fixtures: current, every vector replays to its recorded record and digest, twice, byte for byte', async () => {
  assert.equal(readFileSync(PATH_B2, 'utf8'), await build(B2_CASES));
  assert.match(doc.status, /^SYNTHETIC/);
  assert.equal(doc.cases.length, B2_CASES.length);
  for (const c of B2_CASES) {
    const first = await runCase(c);
    assert.deepEqual(clone(first.record), byId[c.id].record, c.id);
    assert.equal(first.digest, byId[c.id].digest, c.id);
    assert.equal((await runCase(c)).digest, first.digest, `${c.id}: deterministic`);
  }
});

test('the regression anchors: the WP2 engine gives the reviewed Genesis values for this payload; gas.mjs hard-codes none', () => {
  // The stand-in calldata (42 non-zero bytes) is the Genesis payload shape of spec §7.
  assert.deepEqual({ ...calldataGasForInput('prague', tx.input) }, { ruleSetId: 'prague', zeroBytes: 0, nonzeroBytes: 42, ...VALUES.prague });
  assert.deepEqual({ ...calldataGasForInput('amsterdam', tx.input) }, { ruleSetId: 'amsterdam', zeroBytes: 0, nonzeroBytes: 42, ...VALUES.amsterdam });
  assert.deepEqual([VALUES.prague, VALUES.amsterdam], [{ standard: 21672, floor: 22680, need: 22680 }, { standard: 12672, floor: 14688, need: 14688 }]);
  assert.equal(GAS_RULES_LIMIT, 30000);
  assert.equal(SEPOLIA_ACTIVATIONS.find((a) => a.fork === 'amsterdam').timestamp, A);
  // Gate F reuses the engine: no activation time, rule-set constant, source digest or gas value of its own.
  const gas = read('tools/gate-f/gas.mjs').replace(/\/\/.*$/gm, '');
  for (const literal of ['1791294816', '1741159776', '21000', '12000', '22680', '14688', '21672', '12672', '2592000', 'd558a75e', 'selfTransferBase', 'floorPerToken']) assert.ok(!gas.includes(literal), literal);
});

test('P1–P4, P10: same rules and crossed forks are accounted; both the recorded and the inclusion values are kept', () => {
  const p1 = rec('b2-p1-amsterdam-same');
  assert.deepEqual(p1.gas.recorded, { ruleSetId: 'amsterdam', fork: 'amsterdam', reviewDigest: PREP_AMSTERDAM().gas.reviewDigest, ...VALUES.amsterdam, gasLimit: 30000 });
  assert.deepEqual([p1.gas.atInclusion, p1.disposition], [null, 'ELIGIBLE_FOR_FOUNDER_REVIEW']);
  const p3 = rec('b2-p3-prague-crossed-to-amsterdam');
  // D4: original prague 22,680 is kept; amsterdam 14,688 at inclusion is the expected value.
  assert.deepEqual(p3.gas.recorded, { ruleSetId: 'prague', fork: 'bpo2', reviewDigest: PREP_PRAGUE().gas.reviewDigest, ...VALUES.prague, gasLimit: 30000 });
  assert.deepEqual(p3.gas.atInclusion, { ruleSetId: 'amsterdam', ...VALUES.amsterdam });
  assert.deepEqual([p3.gas.rules, p3.gas.expected, p3.gas.gasUsed, p3.gas.accounting], ['GAS_RULES_CROSSED', 14688, 14688, 'GAS_ACCOUNTED']);
  // D4 second example: gasUsed equal to the ORIGINAL need is a mismatch under the inclusion rules.
  const n36 = rec('b2-n36-crossed-gas-used-is-the-recorded-need');
  assert.deepEqual([n36.gas.rules, n36.gas.expected, n36.gas.gasUsed, n36.gas.accounting, n36.disposition], ['GAS_RULES_CROSSED', 14688, 22680, 'GAS_ACCOUNTING_MISMATCH', 'UNRESOLVED']);
  assert.equal(n36.gas.recorded.need, 22680);
  // P10: bpo1 recorded, bpo2 at inclusion: the same rule set, so SAME (fork labels never select rules).
  assert.deepEqual([rec('b2-p10-same-rule-set-other-fork-label').gas.recorded.fork, rec('b2-p10-same-rule-set-other-fork-label').gas.rules], ['bpo1', 'SAME']);
  // A successor review covers t_i after the original review's horizon.
  assert.equal(rec('b2-crossed-under-a-successor-review').gas.rules, 'GAS_RULES_CROSSED');
  for (const { record } of Object.values(byId)) assert.deepEqual([record.gas.codeStateAtInclusion, record.gas.codeStateBasis, record.finality.chainInclusionProof], ['NOT_ESTABLISHED', 'G4.3', 'UNRESOLVED']);
});

test('P11 / A3: no authority is NOT_EVALUATED, never a corrupt record', () => {
  const r = rec('b2-p11-authority-absent');
  assert.deepEqual(gasOf(r), ['NOT_EVALUATED', 'NOT_EVALUATED', 'NOT_EVALUATED', null, null]);
  assert.deepEqual([r.findings.map((f) => f.code), r.disposition], [['RNGF_RULES_AUTHORITY_ABSENT'], 'UNRESOLVED']);
  // The operational history is the reviewed constant only, and it is empty today.
  assert.equal(SEPOLIA_GAS_RULES_REVIEW, null);
  assert.deepEqual(verifierReviewHistory(), []);
  assert.ok(Object.isFrozen(verifierReviewHistory()));
});

test('G1 / N1–N15: an invalid recorded member is GAS_RECORD_INVALID and FAIL; inclusion and finality stay as observed', () => {
  const ids = B2_CASES.filter((c) => c.recordedSubject !== undefined).map((c) => c.id);
  assert.ok(ids.length >= 20);
  for (const id of ids) {
    const r = rec(id);
    assert.equal(r.disposition, 'FAIL', id);
    assert.deepEqual([r.gas.record, r.gas.recorded, r.gas.rules, r.gas.atInclusion, r.gas.expected, r.gas.accounting], ['GAS_RECORD_INVALID', null, 'NOT_EVALUATED', null, null, 'NOT_EVALUATED'], id);
    assert.deepEqual(r.findings, [{ code: 'GAS_RECORD_INVALID', group: 'gasRecord', subject: caseOf(id).recordedSubject }], id);
    assert.equal(r.inclusion.status, 'ESTABLISHED', id);
    assert.equal(r.finality.disposition, 'PROVIDER_REPORTED_FINALIZED', id);
    assert.notEqual(r.gas.gasUsed, null, id);
  }
  // A receipt matching the (altered) recorded need does not repair it.
  assert.equal(rec('b2-integrity-before-accounting').gas.gasUsed, 14688);
  // Not a v2 record (v1 relabel, v9, wrong source, extra member, a candidate envelope): not eligible.
  for (const id of ['b2-n13-preparation-relabelled-v1', 'b2-n14-unknown-preparation-format', 'b2-preparation-source-not-rpc-read', 'b2-preparation-extra-member', 'b2-candidate-envelope-as-preparation']) {
    assert.deepEqual(rec(id).findings, [{ code: 'RNGF_SUBJECT_NOT_ELIGIBLE', group: 'subject', subject: 'preparation' }], id);
  }
});

test('G2 / C2: inclusion rules come from t_i and the reviewed table only, inclusive at A, exclusive at H', () => {
  const history = [REVIEW];
  assert.deepEqual({ ...inclusionRuleSet(A - 1, history) }, { ruleSetId: 'prague', fork: 'bpo2' });
  assert.deepEqual({ ...inclusionRuleSet(A, history) }, { ruleSetId: 'amsterdam', fork: 'amsterdam' });
  assert.deepEqual({ ...inclusionRuleSet(A + 1, history) }, { ruleSetId: 'amsterdam', fork: 'amsterdam' });
  assert.deepEqual({ ...inclusionRuleSet(H - 1, history) }, { ruleSetId: 'amsterdam', fork: 'amsterdam' });
  assert.equal(inclusionRuleSet(H, history), null);
  assert.equal(inclusionRuleSet(H + 1, history), null);
  assert.equal(inclusionRuleSet(SEPOLIA_ACTIVATIONS[0].timestamp - 1, history), null); // before the table
  assert.equal(inclusionRuleSet(T_AMSTERDAM, [REVIEW_OLD]), null); // an expired review never extends
  assert.equal(inclusionRuleSet(T_AMSTERDAM, []), null);
  // The same vectors end to end (spec §7.3, B1–B6).
  assert.deepEqual(['b2-boundary-a-minus-1', 'b2-boundary-a', 'b2-boundary-a-plus-1', 'b2-boundary-h-minus-1', 'b2-boundary-h', 'b2-boundary-h-plus-1'].map((id) => rec(id).gas.rules),
    ['SAME', 'GAS_RULES_CROSSED', 'GAS_RULES_CROSSED', 'SAME', 'GAS_RULES_UNRESOLVED', 'GAS_RULES_UNRESOLVED']);
  // N23: a fork label, slot or access-list hash in the captured block changes nothing.
  assert.deepEqual(gasOf(rec('b2-n23-provider-fork-label-ignored')), gasOf(rec('b2-p3-prague-crossed-to-amsterdam')));
});

test('G5 / C4: unknown inclusion rules give no expected value, no nearest set, no default', () => {
  for (const id of ['b2-boundary-h', 'b2-boundary-h-plus-1', 'b2-n18-inclusion-before-the-table', 'b2-n19-unreviewed-activation-before-inclusion']) {
    const r = rec(id);
    assert.deepEqual([r.gas.record, r.gas.rules, r.gas.accounting, r.gas.expected, r.gas.atInclusion, r.disposition], ['VALID', 'GAS_RULES_UNRESOLVED', 'UNRESOLVED', null, null, 'UNRESOLVED'], id);
    assert.notEqual(r.gas.gasUsed, null, id);
    assert.notEqual(r.gas.recorded, null, id);
  }
  assert.equal(rec('b2-covered-before-the-unreviewed-activation').gas.rules, 'SAME');
});

test('B3–B5: gasUsed only from linked captured receipts; malformed is evidence FAIL, contradictory is FAIL, never averaged', () => {
  for (const id of ['b2-n25-gas-used-missing', 'b2-n26-gas-used-malformed', 'b2-n27-gas-used-not-canonical', 'b2-gas-used-overflow']) {
    assert.deepEqual([rec(id).disposition, rec(id).findings], ['FAIL', [{ code: 'RNGF_EVIDENCE_INVALID', group: 'evidence', subject: 'sepolia-publicnode' }]], id);
    assert.equal(rec(id).gas.rules, 'NOT_EVALUATED', id);
  }
  for (const id of ['b2-n28-gas-used-differs-between-providers', 'b2-n28b-1rpc-gas-used-matches-the-recorded-need']) {
    assert.deepEqual([rec(id).disposition, rec(id).findings], ['FAIL', [{ code: 'RNGF_EVIDENCE_CONTRADICTORY', group: 'evidence', subject: 'receipt.gasUsed' }]], id);
  }
  assert.deepEqual(rec('b2-n29-receipt-for-another-transaction').findings.map((f) => f.code), ['RNAE_RECEIPT_MISMATCH']);
  assert.deepEqual(rec('b2-n30-receipt-block-hash-differs').findings.map((f) => f.code), ['RNAE_CONFLICTING_BLOCK_REFERENCE']);
  assert.deepEqual(rec('b2-n31-receipt-reverted').findings.map((f) => f.code), ['RNAE_TRANSACTION_REVERTED']);
  // The provider estimate in the preparation is never the expected value.
  assert.equal(PREP_AMSTERDAM().providers[0].estimateGas, '0x39ff');
  assert.equal(rec('b2-p1-amsterdam-same').gas.expected, 14688);
});

test('G6 / S10 / S11 / S19: gas and finality are independent', () => {
  // Accounted gas does not make finality: SINGLE stays SINGLE, UNRESOLVED.
  const single = rec('b2-single-provider-accounted');
  assert.deepEqual([single.finality.disposition, single.gas.accounting, single.disposition], ['PROVIDER_REPORTED_FINALIZED_SINGLE', 'GAS_ACCOUNTED', 'UNRESOLVED']);
  // A mismatch does not revoke inclusion or finality.
  const p1 = rec('b2-p1-amsterdam-same');
  for (const id of ['b2-n34-same-need-minus-1', 'b2-n35-same-need-plus-1', 'b2-n37-crossed-need-minus-1', 'b2-n38-crossed-need-plus-1']) {
    assert.deepEqual([rec(id).inclusion.status, rec(id).finality, rec(id).disposition, rec(id).gas.accounting], ['ESTABLISHED', p1.finality, 'UNRESOLVED', 'GAS_ACCOUNTING_MISMATCH'], id);
  }
  // Finality alone does not establish gas: without a linked t_i, gas is NOT_EVALUATED (spec N20, clarified).
  const n20 = rec('b2-n20-finality-not-established-gas-not-evaluated');
  assert.deepEqual([n20.finality.disposition, n20.inclusion.timestamp, ...gasOf(n20), n20.disposition], ['NOT_ESTABLISHED', null, 'NOT_EVALUATED', 'NOT_EVALUATED', 'NOT_EVALUATED', null, null, 'UNRESOLVED']);
  assert.deepEqual(gasOf(rec('b2-n33-inclusion-not-established')), ['NOT_EVALUATED', 'NOT_EVALUATED', 'NOT_EVALUATED', null, null]);
  // An execution symptom keeps the accounting and gives UNRESOLVED.
  assert.deepEqual([rec('b2-n32-execution-observed-accounted').gas.accounting, rec('b2-n32-execution-observed-accounted').disposition], ['GAS_ACCOUNTED', 'UNRESOLVED']);
});

test('G7 / S13 / S17 / N41–N44: the operational verifier has no authority to inject and is never eligible', async () => {
  const p1 = caseOf('b2-p1-amsterdam-same');
  const seamInputs = { ...(await baseInputs(p1.chain)), reviewHistory: [REVIEW] };
  assert.equal((await verifyGateFHypotheticalStageBGas(seamInputs, PREP_AMSTERDAM())).record.disposition, 'ELIGIBLE_FOR_FOUNDER_REVIEW');
  // N42: a forged (TEST) history is refused by the operational verifier, not used.
  await assert.rejects(verifyGateF(seamInputs), refusedAs('RNGF_EVIDENCE_INVALID'));
  await assert.rejects(verifyGateF({ ...seamInputs, reviewHistory: [{ ...REVIEW, reviewer: 'Founder' }] }), refusedAs('RNGF_EVIDENCE_INVALID'));
  // N41 / N44: the same eligible vector through the operational verifier is FAIL at §3.1; a
  // preparation, a review or a table passed as extra arguments is ignored.
  const opInputs = { ...seamInputs, reviewHistory: [] };
  const op = await verifyGateF(opInputs);
  assert.deepEqual([op.record.disposition, op.record.findings.map((f) => f.code)], ['FAIL', ['RNGF_SUBJECT_NOT_ELIGIBLE']]);
  for (const extra of [PREP_AMSTERDAM(), [REVIEW], { activations: [{ fork: 'amsterdam', timestamp: 0, ruleSetId: 'amsterdam' }] }, 'TEST']) {
    assert.equal((await verifyGateF(opInputs, extra)).digest, op.digest);
  }
  // N43: an activation table, a review or a preparation as an input member is refused.
  for (const member of ['activations', 'review', 'preparation', 'authority']) await assert.rejects(verifyGateF({ ...opInputs, [member]: [] }), refusedAs('RNGF_EVIDENCE_INVALID'), member);
  assert.equal(byId['b2-n41-operational-refuses-the-p1-subject'].record.disposition, 'FAIL');
});

test('G8: the test stand-in accepts only TEST ONLY, valid, distinct reviews (WP2 rules, at each review time)', async () => {
  const inputs = await baseInputs(caseOf('b2-p1-amsterdam-same').chain);
  const run = (history) => verifyGateFHypotheticalStageBGas({ ...inputs, reviewHistory: history }, PREP_AMSTERDAM());
  const bad = [
    [{ ...REVIEW, reviewer: 'Operational reviewer' }], // not marked TEST ONLY
    [{ ...REVIEW, horizon: undefined }].map((r) => Object.fromEntries(Object.entries(r).filter(([k]) => k !== 'horizon'))), // missing horizon
    [synthReview('eq', A, A)], // horizon = reviewedAt
    [synthReview('old', A, A + 30 * DAY + 1)], // beyond 30 days
    [synthReview('ua', A + DAY, A + 10 * DAY, [A + 5 * DAY])], // horizon past a known unreviewed activation
    [{ ...REVIEW, sources: REVIEW.sources.slice(1) }], // not the pinned sources
    [{ ...REVIEW, reviewedAt: 1.5 }], // malformed time
    [REVIEW, REVIEW], // twice
  ];
  for (const history of bad) await assert.rejects(run(history), refusedAs('RNGF_EVIDENCE_INVALID'), JSON.stringify(history).slice(0, 120));
  assert.throws(() => checkReviewHistory([{ ...REVIEW, reviewer: 'x' }], { testOnly: true }), TypeError);
  checkReviewHistory([REVIEW, REVIEW_OLD], { testOnly: true });
  // An unsafe integer cannot even enter: the input is not canonical JSON data.
  await assert.rejects(verifyGateFHypotheticalStageBGas(inputs, { ...PREP_AMSTERDAM(), observedAt: 2 ** 53 }), refusedAs('RNGF_EVIDENCE_INVALID'));
});

test('the pure gas functions: integrity first, independent inclusion selection, no expected value without rules', () => {
  const history = [REVIEW];
  const base = { transaction: tx, commitment: INTENT.commitment, history };
  assert.equal(isPreparationV2(PREP_AMSTERDAM()), true);
  assert.equal(isPreparationV2({ ...PREP_AMSTERDAM(), format: 'rnnet.tx-preparation.v1' }), false);
  assert.equal(verifyRecordedGas({ ...base, preparation: PREP_PRAGUE() }).valid, true);
  // Integrity precedes accounting: a receipt equal to the altered need is still GAS_RECORD_INVALID.
  const altered = PREP_PRAGUE();
  altered.gas.need = 14688;
  const r = evaluateRecordedGas({ ...base, preparation: altered, inclusionTimestamp: A - 1, gasUsed: 14688 });
  assert.deepEqual([r.gas.record, r.gas.rules, r.findings[0].subject], ['GAS_RECORD_INVALID', 'NOT_EVALUATED', 'gas.need']);
  // The recorded ruleSetId never selects the inclusion rules.
  const crossed = evaluateRecordedGas({ ...base, preparation: PREP_PRAGUE(), inclusionTimestamp: A, gasUsed: 14688 });
  assert.deepEqual([crossed.gas.rules, crossed.gas.atInclusion.ruleSetId, crossed.gas.expected], ['GAS_RULES_CROSSED', 'amsterdam', 14688]);
  const unknown = evaluateRecordedGas({ ...base, preparation: PREP_PRAGUE(), inclusionTimestamp: H, gasUsed: 22680 });
  assert.deepEqual([unknown.gas.rules, unknown.gas.expected, unknown.gas.accounting], ['GAS_RULES_UNRESOLVED', null, 'UNRESOLVED']);
  // The inputs are not changed.
  const p = PREP_AMSTERDAM();
  const before = JSON.stringify(p);
  verifyRecordedGas({ ...base, preparation: p });
  assert.equal(JSON.stringify(p), before);
});

test('S20 / §6.3: an UNRESOLVED record stays as it was; a later review is a NEW_RULES_REVIEW successor', async () => {
  const c = caseOf('b2-boundary-h');
  const pred = rec('b2-boundary-h');
  const before = JSON.stringify(pred);
  const later = synthReview('R2', H - DAY, H + 20 * DAY);
  const inputs = { ...(await baseInputs(c.chain)), reviewHistory: [REVIEW, later], supersedes: { record: pred, reason: 'NEW_RULES_REVIEW' } };
  const { record } = await verifyGateFHypotheticalStageBGas(inputs, PREP_AMSTERDAM());
  assert.deepEqual([record.gas.rules, record.gas.accounting, record.disposition], ['SAME', 'GAS_ACCOUNTED', 'ELIGIBLE_FOR_FOUNDER_REVIEW']);
  assert.deepEqual(record.supersedes, { recordDigest: gateFRecordDigest(pred), reason: 'NEW_RULES_REVIEW' });
  assert.equal(checkGateFChain([record, pred]).length, 2);
  assert.equal(JSON.stringify(pred), before);
});

test('the schema refuses B2 state inconsistencies', () => {
  const variants = [
    ['b2-p1-amsterdam-same', (r) => { r.gas.accounting = 'GAS_ACCOUNTING_MISMATCH'; }],
    ['b2-p1-amsterdam-same', (r) => { r.gas.gasUsed = 14687; }],
    ['b2-p1-amsterdam-same', (r) => { r.gas.expected = 22680; }],
    ['b2-p1-amsterdam-same', (r) => { r.gas.recorded = null; }],
    ['b2-p1-amsterdam-same', (r) => { r.gas.rules = 'NOT_EVALUATED'; r.gas.expected = null; r.gas.accounting = 'NOT_EVALUATED'; }],
    ['b2-p1-amsterdam-same', (r) => { r.findings.push({ code: 'RNGF_EXECUTION_OBSERVED', group: 'binding', subject: 'sepolia-1rpc' }); }],
    ['b2-p1-amsterdam-same', (r) => { r.inclusion.timestamp = null; }],
    ['b2-p3-prague-crossed-to-amsterdam', (r) => { r.gas.atInclusion = null; }],
    ['b2-boundary-h', (r) => { r.gas.accounting = 'GAS_ACCOUNTED'; }],
    ['b2-boundary-h', (r) => { r.gas.expected = 14688; }],
    ['b2-n1-need-changed', (r) => { r.disposition = 'UNRESOLVED'; }],
    ['b2-n1-need-changed', (r) => { r.gas.recorded = clone(rec('b2-p1-amsterdam-same').gas.recorded); }],
    ['b2-n20-finality-not-established-gas-not-evaluated', (r) => { Object.assign(r.gas, rec('b2-p1-amsterdam-same').gas); }],
    ['b2-single-provider-accounted', (r) => { r.disposition = 'ELIGIBLE_FOR_FOUNDER_REVIEW'; }],
    ['b2-p11-authority-absent', (r) => { r.gas.gasUsed = 14688; }],
  ];
  for (const [id, edit] of variants) {
    const r = clone(rec(id));
    checkGateFRecord(clone(r));
    edit(r);
    assert.throws(() => checkGateFRecord(r), refusedAs('RNGF_EVIDENCE_INVALID'), `${id}: ${edit}`);
  }
});

test('only the core and this test reach gas.mjs; the B2 stand-in is reachable only through the test seam', () => {
  const guard = read('tools/guards/dependency-boundaries.mjs');
  assert.match(guard, /gas: \{ file: 'tools\/gate-f\/gas\.mjs', text: \/gate-f\\\/gas\\b\/, importers: \['tools\/gate-f\/core\.mjs', 'tools\/gate-f-gas\.test\.mjs'\] \}/);
  assert.doesNotMatch(read('tools/gate-f/verify.mjs'), /gas\.mjs|TestStandIn|StageB/);
  const core = read('tools/gate-f/core.mjs');
  assert.match(core, /^import \{ checkReviewHistory, evaluateRecordedGas, isPreparationV2, verifierReviewHistory \} from '\.\/gas\.mjs';$/m);
  // The operational evaluator takes its history from the reviewed constant only.
  const operational = core.slice(core.indexOf('export function evaluateGateFOperational'), core.indexOf('export function evaluateGateFTestStandIn('));
  assert.match(operational, /const history = verifierReviewHistory\(\);/);
  assert.match(operational, /mayBeEligible: false/);
  assert.doesNotMatch(operational, /history: v\.reviewHistory|checkReviewHistory/);
});
