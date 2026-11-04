// RN-NET-03B2-WP3: fork-aware Sepolia preparation and rnnet.tx-preparation.v2 (offline, synthetic).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { approvedIntent, candidateDigest, intentDigest, makeIntent, REVIEWED_GAS_RULE_SOURCES, SEPOLIA_GAS_RULES_REVIEW } from '../../tx-intent/src/index.mjs';
import * as api from '../src/index.mjs';
import { PREPARATION_FORMAT_V2, prepareSepoliaCandidateV2WithAuthority, verifySepoliaCandidateV2WithAuthority } from '../src/prepare-v2.mjs';
import { COMMITMENT, fakeTransport, NOW, SEPOLIA_FROM, sepoliaProviders, sepoliaServer } from './fake-providers.mjs';

const [A, B] = sepoliaProviders();
const q = (n) => `0x${BigInt(n).toString(16)}`;
const review = (reviewedAt = NOW - 86400, extra = {}) => ({
  reviewedAt,
  reviewer: 'TEST ONLY: unit test',
  horizon: reviewedAt + 2_592_000,
  sources: REVIEWED_GAS_RULE_SOURCES.map((s) => ({ ...s })),
  knownUnreviewedActivations: [],
  ...extra,
});
const servers = (a = {}, b = a, shift = 0) => ({ [A.id]: sepoliaServer({ shift, estimate: q(14847), ...a }), [B.id]: sepoliaServer({ number: 9_437_185, shift, estimate: q(14847), ...b }) });
const run = (opts = {}) => {
  const transport = fakeTransport(opts.servers ?? servers());
  const input = { commitment: COMMITMENT, from: SEPOLIA_FROM, now: opts.now ?? NOW, providers: opts.providers ?? [A, B], transport, ...(opts.extra ?? {}) };
  return { transport, promise: prepareSepoliaCandidateV2WithAuthority(input, Object.hasOwn(opts, 'review') ? opts.review : review()) };
};
const refused = (code, providerId = null, gasRules = undefined) => (e) => {
  assert.equal(e.name, 'PrepError');
  assert.equal(e.code, code);
  assert.equal(e.providerId, providerId);
  if (gasRules !== undefined) assert.equal(e.gasRules ?? null, gasRules);
  return true;
};
const neverCalled = async () => {
  throw new Error('no request may be sent');
};

test('the operational v2 exports take the reviewed authority only, which is null: refused before any request', async () => {
  assert.equal(SEPOLIA_GAS_RULES_REVIEW, null);
  assert.ok(!('prepareSepoliaCandidateV2WithAuthority' in api) && !('verifySepoliaCandidateV2WithAuthority' in api));
  await assert.rejects(api.prepareSepoliaCandidateV2({ commitment: COMMITMENT, from: SEPOLIA_FROM, now: NOW, providers: [A, B], transport: neverCalled }), refused('RNTP_INCONSISTENT', null, 'RNTX_GAS_RULES_UNREVIEWED'));
  const { promise } = run();
  const { candidate: intent, digest } = await promise;
  assert.throws(() => api.verifySepoliaCandidateV2(intent, digest), refused('RNTP_INCONSISTENT', null, 'RNTX_GAS_RULES_UNREVIEWED'));
});

test('Amsterdam: need 14,688; estimate 14,847 accepted; gas stays 30,000; one v2 record covered by the digest', async () => {
  const { transport, promise } = run();
  const { candidate: intent, digest } = await promise;
  assert.equal(transport.exchanges.length, 16);
  const p = intent.preparation;
  assert.equal(p.format, PREPARATION_FORMAT_V2);
  assert.equal(p.rules, 'ADR-RN-018-C2');
  assert.deepEqual({ ...p.gas, review: undefined, reviewDigest: undefined }, { ruleSetId: 'amsterdam', fork: 'amsterdam', review: undefined, reviewDigest: undefined, standard: 12672, floor: 14688, need: 14688, gasLimit: 30000 });
  assert.deepEqual(p.gas.review, review());
  assert.equal(intent.transaction.gas, '0x7530');
  assert.deepEqual(p.providers.map((e) => [e.id, e.code, e.estimateGas]), [[A.id, '0x', '0x39ff'], [B.id, '0x', '0x39ff']]);
  // A Stage A candidate: its own format and digest domain; never an intent (S1, C2 Q4).
  assert.equal(intent.format, 'rnnet.tx-preparation-v2-candidate.v1');
  assert.equal(candidateDigest(intent), digest);
  assert.deepEqual(verifySepoliaCandidateV2WithAuthority(intent, digest, review()), intent);
  assert.throws(() => makeIntent(intent), (e) => e.code === 'RNTX_INTENT_INVALID');
  assert.throws(() => approvedIntent(intent, digest), (e) => e.code === 'RNTX_INTENT_INVALID');
  const asIntent = { ...intent, format: 'rnnet.unsigned-tx-intent.v1' };
  assert.throws(() => intentDigest(asIntent), (e) => e.code === 'RNTX_INTENT_INVALID'); // the S1 allowlist refuses v2
});

test('Prague and Osaka eras: need 22,680 under rule set prague; the fork is recorded', async () => {
  for (const [now, fork] of [[1_750_000_000, 'prague'], [1_760_600_000, 'osaka']]) {
    const { promise } = run({ now, review: review(now - 86400), servers: servers({ estimate: q(22680) }, { estimate: q(22680) }, NOW - now) });
    const { candidate: intent } = await promise;
    assert.deepEqual([intent.preparation.gas.ruleSetId, intent.preparation.gas.fork, intent.preparation.gas.need], ['prague', fork, 22680]);
  }
});

test('estimate cross-check: need ≤ estimate ≤ 30,000, attributed to the provider; no equality required', async () => {
  for (const ok of [14688, 14700, 30000]) await run({ servers: servers({ estimate: q(ok) }) }).promise;
  await assert.rejects(run({ servers: servers({}, { estimate: q(14687) }) }).promise, refused('RNTP_INCONSISTENT', B.id));
  await assert.rejects(run({ servers: servers({ estimate: q(30001) }) }).promise, refused('RNTP_GAS_TOO_HIGH', A.id));
  // A Prague-era estimate below 22,680 is refused; an Amsterdam one is not held to it.
  await assert.rejects(run({ now: 1_750_000_000, review: review(1_750_000_000 - 86400), servers: servers({ estimate: q(22679) }, { estimate: q(22680) }, NOW - 1_750_000_000) }).promise, refused('RNTP_INCONSISTENT', A.id));
});

test('authority refusals happen before the first request', async () => {
  const cases = [
    null,
    review(NOW - 2_592_000), // expired: now = horizon
    review(NOW + 1), // future-dated
    review(NOW - 86400, { horizon: NOW - 86400 + 2_592_001 }), // beyond 30 days
    { ...review(), sources: review().sources.map((s, i) => (i === 0 ? { ...s, sha256: `sha256:${'9'.repeat(64)}` } : s)) },
    { ...review(), sources: review().sources.map((s, i) => (i === 3 ? { ...s, revision: 'main' } : s)) },
    review(NOW - 86400, { knownUnreviewedActivations: [NOW + 86400 * 7] }), // unreviewed fork before the horizon
    { ...review(), horizon: NOW + 99_999_999 }, // a horizon the caller "extends"
  ];
  for (const r of cases) {
    const t = run({ review: r });
    await assert.rejects(t.promise, refused('RNTP_INCONSISTENT', null, 'RNTX_GAS_RULES_UNREVIEWED'));
    assert.equal(t.transport.exchanges.length, 0);
  }
});

test('rules decided after the reads: boundary window, rule sets that differ, future pin, pre-Prague', async () => {
  await assert.rejects(run({ review: review(NOW - 86400, { horizon: NOW + 3600, knownUnreviewedActivations: [NOW + 3600] }) }).promise, refused('RNTP_INCONSISTENT', null, 'RNTX_GAS_FORK_BOUNDARY'));
  const cross = 1791294816 + 10;
  await assert.rejects(run({ now: cross, review: review(cross - 86400), servers: servers({ estimate: q(22680) }, { estimate: q(22680) }, NOW - cross) }).promise, refused('RNTP_INCONSISTENT', null, 'RNTX_GAS_FORK_BOUNDARY'));
  const ahead = { timestamp: NOW + 10, pin: (b) => { b.timestamp = q(NOW + 5); } };
  await assert.rejects(run({ servers: servers(ahead, ahead) }).promise, refused('RNTP_INCONSISTENT', null, 'RNTX_GAS_INPUT_INVALID'));
  const old = 1_741_000_000;
  await assert.rejects(run({ now: old, review: review(old - 86400), servers: servers({ estimate: q(22680) }, { estimate: q(22680) }, NOW - old) }).promise, refused('RNTP_INCONSISTENT', null, 'RNTX_GAS_RULES_UNSUPPORTED'));
});

test('code state: non-empty code or an EIP-7702 delegation refuses on that provider', async () => {
  await assert.rejects(run({ servers: servers({ code: '0x6000' }, {}) }).promise, refused('RNTP_ACCOUNT_UNSUITABLE', A.id));
  await assert.rejects(run({ servers: servers({}, { code: `0xef0100${'ab'.repeat(20)}` }) }).promise, refused('RNTP_ACCOUNT_UNSUITABLE', B.id));
});

test('authority injection and input tampering are refused before any request', async () => {
  for (const extra of [{ rulesReview: review() }, { review: review() }, { activations: [] }, { ruleSetId: 'prague' }, { estimateGas: '0x39ff' }]) {
    const t = run({ extra });
    await assert.rejects(t.promise, refused('RNTP_INPUT_INVALID'));
    assert.equal(t.transport.exchanges.length, 0);
  }
  for (const providers of [[A], [A, A], [A, { ...B, operator: A.operator }], [A, { ...B, network: 'xrpl:testnet' }], [A, new Proxy({ ...B }, {})]]) {
    const t = run({ providers });
    await assert.rejects(t.promise, refused('RNTP_INPUT_INVALID'));
    assert.equal(t.transport.exchanges.length, 0);
  }
});

test('each input field is read once; a transport that edits the caller objects cannot change the record', async () => {
  let reads = 0;
  const providers = [{ ...A }, { ...B }];
  const base = fakeTransport(servers());
  const transport = async (request) => {
    providers[0].id = 'fixture-sepolia-evil';
    providers[1].operator = 'Evil';
    return base(request);
  };
  const input = { commitment: COMMITMENT, from: SEPOLIA_FROM, providers, transport };
  Object.defineProperty(input, 'now', { enumerable: true, get: () => { reads += 1; return NOW; } });
  const { candidate: intent } = await prepareSepoliaCandidateV2WithAuthority(input, review());
  assert.equal(reads, 1);
  assert.deepEqual(intent.preparation.providers.map((e) => [e.id, e.operator]), [[A.id, A.operator], [B.id, B.operator]]);
});

test('the request plan is C1 exactly: 8 per provider, every account read and the estimate at {blockHash, requireCanonical}', async () => {
  const { transport, promise } = run();
  const { candidate: intent } = await promise;
  const hash = intent.preparation.providers[0].block.hash;
  for (const id of [A.id, B.id]) {
    const bodies = transport.exchanges.filter((e) => e.providerId === id).map((e) => JSON.parse(e.request));
    assert.deepEqual(bodies.map((b) => b.method), ['eth_chainId', 'eth_getBlockByNumber', 'eth_getBlockByNumber', 'eth_getTransactionCount', 'eth_getTransactionCount', 'eth_getBalance', 'eth_getCode', 'eth_estimateGas']);
    for (const i of [3, 5, 6, 7]) assert.deepEqual(bodies[i].params.at(-1), { blockHash: hash, requireCanonical: true });
    assert.equal(bodies[4].params[1], 'pending');
    assert.ok(!bodies.some((b) => b.params.includes('latest') && b.method !== 'eth_getBlockByNumber'));
  }
});

test('verifier: strict version dispatch and recomputation of every gas field', async () => {
  const { candidate: intent, digest } = await run().promise;
  const r = review();
  const tamper = (edit) => {
    const i = JSON.parse(JSON.stringify(intent));
    edit(i);
    return [i, candidateDigest(i)];
  };
  for (const edit of [(i) => { i.preparation.format = 'rnnet.tx-preparation.v1'; }, (i) => { i.preparation.gas.extra = 1; }, (i) => { i.preparation.gas.need = 14688.5; }]) {
    const [i, d] = (() => { try { return tamper(edit); } catch { const i2 = JSON.parse(JSON.stringify(intent)); edit(i2); return [i2, digest]; } })();
    assert.throws(() => verifySepoliaCandidateV2WithAuthority(i, d, r), refused('RNTP_INTENT_INVALID'));
  }
  for (const k of ['standard', 'floor', 'need']) {
    const [i, d] = tamper((x) => { x.preparation.gas[k] += 1; });
    assert.throws(() => verifySepoliaCandidateV2WithAuthority(i, d, r), refused('RNTP_INCONSISTENT'));
  }
  // A digest that is not the approved one.
  const changed = JSON.parse(JSON.stringify(intent));
  changed.preparation.gas.need += 1;
  assert.throws(() => verifySepoliaCandidateV2WithAuthority(changed, digest, r), refused('RNTP_INTENT_INVALID'));
});
