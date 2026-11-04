// Builds fixtures/preparation-v2/cases.json: offline cases for the fork-aware Sepolia preparation
// and the rnnet.tx-preparation.v2 record (RN-NET-03B2-WP3; ADR-RN-018 Amendment C2, Proposed).
//
//   node tools/preparation-v2/build-v2-fixtures.mjs           # check the committed file is current
//   node tools/preparation-v2/build-v2-fixtures.mjs --write   # write it (refuses to overwrite)
//
// Two lists, both SYNTHETIC:
//   - `preparations`: a simulated provider pair (the B2 fake providers, unresolvable
//     fixture.invalid hosts), the exact exchanges, and the result stated BY HAND below (PASS, or
//     a code, provider, RNTX_GAS_* code and request count);
//   - `records`: approved v2 intents, valid or tampered, and the verifier's expected outcome,
//     stated by hand.
//
// The rules review in each case is a TEST record ("TEST ONLY"). It is passed to the internal
// …WithAuthority seam and is never the reviewed authority, which stays null.
// tools/reference/rnnet_prep_v2_reference.py reproduces every case independently.
import { Buffer } from 'node:buffer';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalBytes } from '../../packages/canonical/src/index.mjs';
import { intentDigest, REVIEWED_GAS_RULE_SOURCES } from '../../packages/tx-intent/src/index.mjs';
import { prepareSepoliaIntentV2WithAuthority, verifySepoliaPreparationV2WithAuthority } from '../../packages/tx-prepare/src/prepare-v2.mjs';
import { COMMITMENT, fakeTransport, NOW, reply, SEPOLIA_FROM, sepoliaProviders, sepoliaServer } from '../../packages/tx-prepare/test/fake-providers.mjs';

export const PATH = fileURLToPath(new URL('../../fixtures/preparation-v2/cases.json', import.meta.url));
export const FIXTURES_FORMAT = 'rnnet.preparation-v2-fixtures.v1';

const S = 'evm:11155111';
const SA = 'fixture-sepolia-a';
const SB = 'fixture-sepolia-b';
const AMSTERDAM = 1791294816;
const q = (n) => `0x${BigInt(n).toString(16)}`;
const NUMBER_B = 9_437_185;

/** A TEST rules review (never the reviewed authority). */
export const testReview = (reviewedAt, extra = {}) => ({
  reviewedAt,
  reviewer: 'TEST ONLY: synthetic WP3 fixture, not a recorded review',
  horizon: reviewedAt + 2_592_000,
  sources: REVIEWED_GAS_RULE_SOURCES.map((s) => ({ ...s })),
  knownUnreviewedActivations: [],
  ...extra,
});

// Times. Amsterdam: the fake providers' NOW (2026-11-01). Prague and Osaka: earlier "now", with
// every block shifted by the same amount so that freshness holds.
const ERA = {
  amsterdam: { now: NOW, shift: 0 },
  prague: { now: 1_750_000_000, shift: NOW - 1_750_000_000 },
  osaka: { now: 1_760_600_000, shift: NOW - 1_760_600_000 },
};
const reviewFor = (era) => testReview(ERA[era].now - 86400);

// A pair of servers: options for a, options for b (b one block ahead, as in B2).
const pair = (a = {}, b = a, era = 'amsterdam') => ({ [SA]: { shift: ERA[era].shift, ...a }, [SB]: { number: NUMBER_B, shift: ERA[era].shift, ...b } });
const est = (a, b = a) => pair({ estimate: q(a) }, { estimate: q(b) });
const evmError = () => reply(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'synthetic failure' } }));
const result = (value) => () => reply(JSON.stringify({ jsonrpc: '2.0', id: 1, result: value }));

// expect: 'PASS', or [code, providerId, gasRules, requests]. requests: 16 (all) or 0 (refused before any request).
export const PREPARATIONS = [
  // Accepted.
  { id: 'amsterdam-pass-estimate-14847', servers: est(14847), expect: 'PASS' },
  { id: 'amsterdam-pass-estimate-equals-need', servers: est(14688), expect: 'PASS' },
  { id: 'amsterdam-pass-estimate-30000', servers: est(30000), expect: 'PASS' },
  { id: 'amsterdam-pass-estimates-differ', servers: est(14847, 14700), expect: 'PASS' },
  { id: 'prague-pass', era: 'prague', servers: pair({ estimate: q(22680) }, { estimate: q(23016) }, 'prague'), expect: 'PASS' },
  { id: 'osaka-pass', era: 'osaka', servers: pair({ estimate: q(22680) }, { estimate: q(22680) }, 'osaka'), expect: 'PASS' },
  // Estimate cross-check.
  { id: 'amsterdam-estimate-need-minus-1', servers: est(14847, 14687), expect: ['RNTP_INCONSISTENT', SB, null, 16] },
  { id: 'amsterdam-estimate-30001', servers: est(30001, 14847), expect: ['RNTP_GAS_TOO_HIGH', SA, null, 16] },
  { id: 'prague-estimate-22679', era: 'prague', servers: pair({ estimate: q(22679) }, { estimate: q(22680) }, 'prague'), expect: ['RNTP_INCONSISTENT', SA, null, 16] },
  { id: 'amsterdam-estimate-malformed', servers: pair({ raw: { eth_estimateGas: result('0x0039ff') } }, { estimate: q(14847) }), expect: ['RNTP_MALFORMED', SA, null, 11] },
  { id: 'amsterdam-estimate-missing', servers: pair({ estimate: q(14847) }, { raw: { eth_estimateGas: result(null) } }), expect: ['RNTP_MALFORMED', SB, null, 16] },
  { id: 'amsterdam-estimate-rpc-error', servers: pair({ raw: { eth_estimateGas: evmError } }, { estimate: q(14847) }), expect: ['RNTP_PROVIDER_ERROR', SA, null, 11], blocked: 'GAS_ESTIMATION_UNAVAILABLE' },
  // The rules review: refused before any request.
  { id: 'review-missing', review: null, servers: est(14847), expect: ['RNTP_INCONSISTENT', null, 'RNTX_GAS_RULES_UNREVIEWED', 0] },
  { id: 'review-expired', review: testReview(NOW - 2_592_000), servers: est(14847), expect: ['RNTP_INCONSISTENT', null, 'RNTX_GAS_RULES_UNREVIEWED', 0] },
  { id: 'review-future-dated', review: testReview(NOW + 1), servers: est(14847), expect: ['RNTP_INCONSISTENT', null, 'RNTX_GAS_RULES_UNREVIEWED', 0] },
  { id: 'review-beyond-30-days', review: testReview(NOW - 86400, { horizon: NOW - 86400 + 2_592_001 }), servers: est(14847), expect: ['RNTP_INCONSISTENT', null, 'RNTX_GAS_RULES_UNREVIEWED', 0] },
  { id: 'review-source-digest-differs', review: { ...testReview(NOW - 86400), sources: REVIEWED_GAS_RULE_SOURCES.map((s, i) => (i === 1 ? { ...s, sha256: `sha256:${'1'.repeat(64)}` } : { ...s })) }, servers: est(14847), expect: ['RNTP_INCONSISTENT', null, 'RNTX_GAS_RULES_UNREVIEWED', 0] },
  { id: 'review-source-revision-differs', review: { ...testReview(NOW - 86400), sources: REVIEWED_GAS_RULE_SOURCES.map((s, i) => (i === 4 ? { ...s, revision: 'master' } : { ...s })) }, servers: est(14847), expect: ['RNTP_INCONSISTENT', null, 'RNTX_GAS_RULES_UNREVIEWED', 0] },
  { id: 'review-unreviewed-fork-before-horizon', review: testReview(NOW - 86400, { knownUnreviewedActivations: [NOW + 7 * 86400] }), servers: est(14847), expect: ['RNTP_INCONSISTENT', null, 'RNTX_GAS_RULES_UNREVIEWED', 0] },
  // Rules decided after the reads.
  { id: 'known-activation-in-window', review: testReview(NOW - 86400, { horizon: NOW + 3600, knownUnreviewedActivations: [NOW + 3600] }), servers: est(14847), expect: ['RNTP_INCONSISTENT', null, 'RNTX_GAS_FORK_BOUNDARY', 16] },
  { id: 'pin-and-now-different-rule-sets', era: 'cross', now: AMSTERDAM + 10, review: testReview(AMSTERDAM + 10 - 86400), servers: pair({ shift: NOW - (AMSTERDAM + 10), estimate: q(22680) }, { shift: NOW - (AMSTERDAM + 10), estimate: q(22680) }), expect: ['RNTP_INCONSISTENT', null, 'RNTX_GAS_FORK_BOUNDARY', 16] },
  { id: 'future-pinned-timestamp', servers: pair({ estimate: q(14847), timestamp: NOW + 10, pin: (b) => { b.timestamp = q(NOW + 5); } }, { estimate: q(14847), timestamp: NOW + 10, pin: (b) => { b.timestamp = q(NOW + 5); } }), expect: ['RNTP_INCONSISTENT', null, 'RNTX_GAS_INPUT_INVALID', 16] },
  { id: 'pre-prague', era: 'pre-prague', now: 1_741_000_000, review: testReview(1_741_000_000 - 86400), servers: pair({ shift: NOW - 1_741_000_000, estimate: q(22680) }, { shift: NOW - 1_741_000_000, estimate: q(22680) }), expect: ['RNTP_INCONSISTENT', null, 'RNTX_GAS_RULES_UNSUPPORTED', 16] },
  // Code state (the C1 per-provider check, before the engine).
  { id: 'sender-has-code', servers: pair({ estimate: q(14847), code: '0x6000' }, { estimate: q(14847) }), expect: ['RNTP_ACCOUNT_UNSUITABLE', SA, null, 11] },
  { id: 'sender-delegated-7702', servers: pair({ estimate: q(14847) }, { estimate: q(14847), code: `0xef0100${'ab'.repeat(20)}` }), expect: ['RNTP_ACCOUNT_UNSUITABLE', SB, null, 16] },
  // C1 refusals keep their codes on the v2 path.
  { id: 'c1-pin-hash-disagreement', servers: pair({ estimate: q(14847) }, { estimate: q(14847), pin: (b) => { b.hash = `0x${'ee'.repeat(32)}`; } }), expect: ['RNTP_INCONSISTENT', null, null, 6] },
  { id: 'c1-nonce-pending', servers: pair({ estimate: q(14847), pending: '0x1' }, { estimate: q(14847) }), expect: ['RNTP_NONCE_PENDING', SA, null, 11] },
  { id: 'c1-insufficient-balance', servers: pair({ estimate: q(14847), balance: '0x1' }, { estimate: q(14847) }), expect: ['RNTP_INSUFFICIENT_BALANCE', SA, null, 16] },
  { id: 'c1-wrong-chain', servers: pair({ estimate: q(14847), chainId: '0x1' }, { estimate: q(14847) }), expect: ['RNTP_WRONG_NETWORK', SA, null, 1] },
  { id: 'c1-stale-head', servers: pair({ estimate: q(14847), shift: 120 }, { estimate: q(14847), shift: 120 }), expect: ['RNTP_STALE', SA, null, 2] },
  // Inputs: refused before any request.
  { id: 'input-review-injection', input: { rulesReview: testReview(NOW - 86400) }, servers: est(14847), expect: ['RNTP_INPUT_INVALID', null, null, 0] },
  { id: 'input-one-provider', input: { providers: 1 }, servers: est(14847), expect: ['RNTP_INPUT_INVALID', null, null, 0] },
  { id: 'input-same-operator', input: { providers: 'same-operator' }, servers: est(14847), expect: ['RNTP_INPUT_INVALID', null, null, 0] },
  { id: 'input-xrpl-provider', input: { providers: 'xrpl' }, servers: est(14847), expect: ['RNTP_INPUT_INVALID', null, null, 0] },
  { id: 'input-uppercase-from', input: { from: SEPOLIA_FROM.toUpperCase().replace('0X', '0x') }, servers: est(14847), expect: ['RNTP_INPUT_INVALID', null, null, 0] },
  { id: 'input-zero-now', input: { now: 0 }, servers: est(14847), expect: ['RNTP_INPUT_INVALID', null, null, 0] },
];

const publicProvider = ({ id, network, operator, url }) => ({ id, network, operator, url });

function inputFor(c) {
  const now = c.now ?? ERA[c.era ?? 'amsterdam']?.now ?? NOW;
  let providers = sepoliaProviders();
  const o = c.input ?? {};
  if (o.providers === 1) providers = providers.slice(0, 1);
  if (o.providers === 'same-operator') providers = [providers[0], { ...providers[1], operator: providers[0].operator }];
  if (o.providers === 'xrpl') providers = [providers[0], { ...providers[1], network: 'xrpl:testnet' }];
  const input = { commitment: COMMITMENT, from: o.from ?? SEPOLIA_FROM, now: o.now ?? now, providers };
  if (o.rulesReview) input.rulesReview = o.rulesReview;
  return input;
}

const reviewOf = (c) => (Object.hasOwn(c, 'review') ? c.review : reviewFor(c.era && ERA[c.era] ? c.era : 'amsterdam'));

async function runPreparation(c) {
  // Estimate replies use the key order id, jsonrpc, result (valid JSON-RPC): the fixtures' response
  // bytes, and so their digests, never coincide with any recorded provider response.
  const withEstimate = (opts) => (opts.estimate === undefined || opts.raw?.eth_estimateGas ? opts : { ...opts, raw: { ...opts.raw, eth_estimateGas: () => reply(JSON.stringify({ id: 1, jsonrpc: '2.0', result: opts.estimate })) } });
  const transport = fakeTransport(Object.fromEntries(Object.entries(c.servers).map(([id, opts]) => [id, sepoliaServer(withEstimate(opts))])));
  const input = inputFor(c);
  const review = reviewOf(c);
  let r;
  try {
    const { intent, digest } = await prepareSepoliaIntentV2WithAuthority({ ...input, transport }, review);
    r = { outcome: 'PASS', code: null, providerId: null, gasRules: null, blocked: null, digest, intent };
  } catch (error) {
    if (error?.name !== 'PrepError') throw error;
    r = { outcome: 'FAIL', code: error.code, providerId: error.providerId, gasRules: error.gasRules ?? null, blocked: error.blocked, digest: null, intent: null };
  }
  const exp = c.expect;
  const ok = exp === 'PASS'
    ? r.outcome === 'PASS' && transport.exchanges.length === 16
    : r.code === exp[0] && r.providerId === exp[1] && r.gasRules === exp[2] && transport.exchanges.length === exp[3] && r.blocked === (c.blocked ?? null);
  if (!ok) throw new Error(`${c.id}: expected ${JSON.stringify(exp)}, got ${r.code ?? 'PASS'} ${r.providerId} ${r.gasRules} after ${transport.exchanges.length} requests`);
  const { providers, ...rest } = input;
  return {
    id: c.id,
    network: S,
    input: { ...rest, providers: providers.map(publicProvider) },
    testRulesReview: review,
    exchanges: transport.exchanges,
    expected: r,
  };
}

// --- records: the verifier ------------------------------------------------------------------------

const clone = (v) => JSON.parse(JSON.stringify(v));
const RECORD_MUTATIONS = [
  // [id, mutate(intent), redigest?, expected [code, gasRules]]
  ['format-v1', (i) => { i.preparation.format = 'rnnet.tx-preparation.v1'; }, true, ['RNTP_INTENT_INVALID', null]],
  ['format-v3', (i) => { i.preparation.format = 'rnnet.tx-preparation.v3'; }, true, ['RNTP_INTENT_INVALID', null]],
  ['rules-c1', (i) => { i.preparation.rules = 'ADR-RN-018'; }, true, ['RNTP_INTENT_INVALID', null]],
  ['fork', (i) => { i.preparation.gas.fork = 'osaka'; }, true, ['RNTP_INCONSISTENT', null]],
  ['rule-set', (i) => { i.preparation.gas.ruleSetId = 'prague'; }, true, ['RNTP_INCONSISTENT', null]],
  ['review-digest', (i) => { i.preparation.gas.reviewDigest = `sha256:${'2'.repeat(64)}`; }, true, ['RNTP_INCONSISTENT', null]],
  ['review-reviewer', (i) => { i.preparation.gas.review.reviewer = 'someone else'; }, true, ['RNTP_INCONSISTENT', null]],
  ['review-source-digest', (i) => { i.preparation.gas.review.sources[2].sha256 = `sha256:${'3'.repeat(64)}`; }, true, ['RNTP_INCONSISTENT', null]],
  ['review-horizon-extended', (i) => { i.preparation.gas.review.horizon += 86400; }, true, ['RNTP_INCONSISTENT', null]],
  ['standard', (i) => { i.preparation.gas.standard += 1; }, true, ['RNTP_INCONSISTENT', null]],
  ['floor', (i) => { i.preparation.gas.floor -= 1; }, true, ['RNTP_INCONSISTENT', null]],
  ['need', (i) => { i.preparation.gas.need = 22680; }, true, ['RNTP_INCONSISTENT', null]],
  ['gas-limit', (i) => { i.preparation.gas.gasLimit = 29999; }, true, ['RNTP_INCONSISTENT', null]],
  ['gas-member-string', (i) => { i.preparation.gas.need = '14688'; }, true, ['RNTP_INTENT_INVALID', null]],
  ['gas-member-unknown', (i) => { i.preparation.gas.margin = 15312; }, true, ['RNTP_INTENT_INVALID', null]],
  ['gas-member-missing', (i) => { delete i.preparation.gas.floor; }, true, ['RNTP_INTENT_INVALID', null]],
  ['record-member-unknown', (i) => { i.preparation.estimate = '0x39ff'; }, true, ['RNTP_INTENT_INVALID', null]],
  ['record-member-missing', (i) => { delete i.preparation.gas; }, true, ['RNTP_INTENT_INVALID', null]],
  ['provider-member-unknown', (i) => { i.preparation.providers[0].note = 'x'; }, true, ['RNTP_INTENT_INVALID', null]],
  ['provider-duplicate-id', (i) => { i.preparation.providers[1].id = i.preparation.providers[0].id; }, true, ['RNTP_INTENT_INVALID', null]],
  ['provider-removed', (i) => { i.preparation.providers.pop(); }, true, ['RNTP_INTENT_INVALID', null]],
  ['provider-exchange-method', (i) => { i.preparation.providers[0].exchanges[7].method = 'eth_call'; }, true, ['RNTP_INTENT_INVALID', null]],
  ['pin-timestamp-one-provider', (i) => { i.preparation.providers[1].block.timestamp = q(BigInt(i.preparation.providers[1].block.timestamp) - 1n); }, true, ['RNTP_INCONSISTENT', null]],
  ['pin-timestamp-after-observation', (i) => { for (const p of i.preparation.providers) p.block.timestamp = q(i.preparation.observedAt + 1); }, true, ['RNTP_INCONSISTENT', 'RNTX_GAS_INPUT_INVALID']],
  ['pin-base-fee-vs-max-fee', (i) => { for (const p of i.preparation.providers) p.block.baseFeePerGas = '0x1'; }, true, ['RNTP_INCONSISTENT', null]],
  ['code-not-empty', (i) => { for (const p of i.preparation.providers) p.code = '0x6000'; }, true, ['RNTP_INCONSISTENT', 'RNTX_GAS_PRECONDITION']],
  ['code-disagree', (i) => { i.preparation.providers[1].code = '0x6000'; }, true, ['RNTP_INCONSISTENT', 'RNTX_GAS_PRECONDITION']],
  ['estimate-below-need', (i) => { i.preparation.providers[0].estimateGas = q(14687); }, true, ['RNTP_INCONSISTENT', null]],
  ['estimate-above-limit', (i) => { i.preparation.providers[1].estimateGas = q(30001); }, true, ['RNTP_GAS_TOO_HIGH', null]],
  ['observed-after-horizon', (i) => { i.preparation.observedAt = i.preparation.gas.review.horizon; }, true, ['RNTP_INCONSISTENT', 'RNTX_GAS_RULES_UNREVIEWED']],
  ['transaction-gas', (i) => { i.transaction.gas = '0x7531'; }, true, ['RNTP_INTENT_INVALID', null]],
  ['transaction-max-fee', (i) => { i.transaction.maxFeePerGas = '0x77359400'; }, true, ['RNTP_INCONSISTENT', null]],
  // Without a new digest, every change is a digest mismatch.
  ['need-not-redigested', (i) => { i.preparation.gas.need += 1; }, false, ['RNTP_INTENT_INVALID', null]],
  ['review-not-redigested', (i) => { i.preparation.gas.review.reviewedAt -= 1; }, false, ['RNTP_INTENT_INVALID', null]],
  ['provider-not-redigested', (i) => { i.preparation.providers[0].id = 'fixture-sepolia-z'; }, false, ['RNTP_INTENT_INVALID', null]],
  ['pin-not-redigested', (i) => { i.preparation.providers[0].block.hash = `0x${'aa'.repeat(32)}`; }, false, ['RNTP_INTENT_INVALID', null]],
];

function runRecord(id, intent, digest, authority, expect) {
  let got;
  try {
    verifySepoliaPreparationV2WithAuthority(intent, digest, authority);
    got = 'PASS';
  } catch (error) {
    if (error?.name !== 'PrepError') throw error;
    got = [error.code, error.gasRules ?? null];
  }
  if (JSON.stringify(got) !== JSON.stringify(expect)) throw new Error(`record ${id}: expected ${JSON.stringify(expect)}, got ${JSON.stringify(got)}`);
  return { id, intent, approvedDigest: digest, testRulesReview: authority, expected: got };
}

function buildRecords(preparations, b2Cases) {
  const out = [];
  for (const base of preparations.filter((p) => p.expected.outcome === 'PASS' && ['amsterdam-pass-estimate-14847', 'prague-pass', 'osaka-pass'].includes(p.id))) {
    out.push(runRecord(`valid-${base.id}`, base.expected.intent, base.expected.digest, base.testRulesReview, 'PASS'));
  }
  const base = preparations.find((p) => p.id === 'amsterdam-pass-estimate-14847');
  out.push(runRecord('no-authority', base.expected.intent, base.expected.digest, null, ['RNTP_INCONSISTENT', 'RNTX_GAS_RULES_UNREVIEWED']));
  out.push(runRecord('other-authority', base.expected.intent, base.expected.digest, testReview(NOW - 3600), ['RNTP_INCONSISTENT', null]));
  out.push(runRecord('wrong-approved-digest', base.expected.intent, `sha256:${'4'.repeat(64)}`, base.testRulesReview, ['RNTP_INTENT_INVALID', null]));
  for (const [id, mutate, redigest, expect] of RECORD_MUTATIONS) {
    const intent = clone(base.expected.intent);
    mutate(intent);
    let digest = base.expected.digest;
    if (redigest) {
      try {
        digest = intentDigest(intent);
      } catch {
        digest = base.expected.digest; // the intent itself is invalid: the verifier refuses it before any digest comparison matters
      }
    }
    out.push(runRecord(`tamper-${id}`, intent, digest, base.testRulesReview, expect));
  }
  // A v1 record (the C1 B2 fixture) is never accepted as v2.
  const v1 = b2Cases.find((c) => c.id === 'sepolia-pass');
  out.push(runRecord('v1-record-refused', v1.expected.intent, v1.expected.digest, base.testRulesReview, ['RNTP_INTENT_INVALID', null]));
  return out;
}

export async function build() {
  const preparations = [];
  for (const c of PREPARATIONS) preparations.push(await runPreparation(c));
  const b2 = JSON.parse(readFileSync(new URL('../../fixtures/preparation-b2/cases.json', import.meta.url), 'utf8'));
  const records = buildRecords(preparations, b2.cases);
  const document = {
    format: FIXTURES_FORMAT,
    status: 'SYNTHETIC: simulated providers, made-up blocks and balances, and TEST rules reviews; never read from or sent to a network; not an authority',
    preparations,
    records,
  };
  return `${Buffer.from(canonicalBytes(document)).toString('utf8')}\n`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = await build();
  if (process.argv.includes('--write')) {
    if (existsSync(PATH)) throw new Error(`${PATH} exists; remove it first to rebuild`);
    writeFileSync(PATH, text, { flag: 'wx' });
    console.log(`wrote ${PATH}`);
  } else {
    const current = existsSync(PATH) && readFileSync(PATH, 'utf8') === text;
    console.log(current ? 'preparation-v2 fixtures: current' : 'preparation-v2 fixtures: NOT current');
    process.exit(current ? 0 : 1);
  }
}
