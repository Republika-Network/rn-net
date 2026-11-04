// RN-NET-03B2-B2: read-only transaction preparation against simulated providers. No network is
// used; every transport is injected. The fixture corpus (fixtures/preparation-b2) is replayed by
// tools/preparation.test.mjs and reproduced by tools/reference/rnnet_prep_reference.py.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { PREPARATION_REQUESTS, READ_ONLY_METHODS, ReplayMismatch } from '../../chain-readonly/src/index.mjs';
import { approvedIntent, makeIntent, SEPOLIA, XRPL } from '../../tx-intent/src/index.mjs';
import * as api from '../src/index.mjs';
import { BlockedReason, PREPARATION_FORMAT, PREPARATION_RULES, PrepErrorCode, prepareSepoliaIntent, prepareXrplIntent } from '../src/index.mjs';
import {
  COMMITMENT,
  evmBlockHash,
  evmBlockTimestamp,
  fakeTransport,
  NOW,
  reply,
  SEPOLIA_FROM,
  sepoliaProviders,
  sepoliaServer,
  transportError,
  XRPL_ACCOUNT,
  XRPL_SIGNING_PUB_KEY,
  xrplProviders,
  xrplServer,
} from './fake-providers.mjs';

const [XA, XB] = xrplProviders();
const [SA, SB] = sepoliaProviders();
const xrplInput = (servers, extra = {}) => {
  const transport = fakeTransport(servers);
  return { transport, input: { commitment: COMMITMENT, account: XRPL_ACCOUNT, signingPubKey: XRPL_SIGNING_PUB_KEY, providers: [XA, XB], transport, now: NOW, ...extra } };
};
const sepInput = (servers, extra = {}) => {
  const transport = fakeTransport(servers);
  return { transport, input: { commitment: COMMITMENT, from: SEPOLIA_FROM, providers: [SA, SB], transport, now: NOW, ...extra } };
};
const xrplPair = (a = {}, b = {}) => ({ [XA.id]: xrplServer(a), [XB.id]: xrplServer({ seq: 5_000_001, ...b }) });
const sepPair = (a = {}, b = {}) => ({ [SA.id]: sepoliaServer(a), [SB.id]: sepoliaServer({ number: 9_437_185, timestamp: NOW - 1, ...b }) });
const refused = (code, providerId = null) => (error) => {
  assert.equal(error.name, 'PrepError');
  assert.equal(error.code, code);
  assert.equal(error.providerId, providerId);
  return true;
};
const methodsOf = (exchanges, id) => exchanges.filter((e) => e.providerId === id).map((e) => JSON.parse(e.request).method);

test('the public API prepares intents only: no key, signing or write function', () => {
  assert.deepEqual(Object.keys(api).sort(), ['BlockedReason', 'PREPARATION_FORMAT', 'PREPARATION_FORMAT_V2', 'PREPARATION_RULES', 'PREPARATION_RULES_V2_ID', 'PrepError', 'PrepErrorCode', 'prepareSepoliaCandidateV2', 'prepareSepoliaIntent', 'prepareXrplIntent', 'verifySepoliaCandidateV2']);
  assert.ok(Object.isFrozen(PREPARATION_RULES) && Object.isFrozen(PREPARATION_RULES.xrpl) && Object.isFrozen(PREPARATION_RULES.sepolia));
  assert.equal(PREPARATION_RULES.maxAttempts, 1);
});

test('XRPL: binds Account, Sequence, LastLedgerSequence and SigningPubKey from two providers', async () => {
  const { transport, input } = xrplInput(xrplPair());
  const { intent, digest } = await prepareXrplIntent(input);
  assert.ok(Object.isFrozen(intent) && Object.isFrozen(intent.transaction));
  assert.deepEqual(makeIntent(intent), intent);
  assert.deepEqual(approvedIntent(intent, digest), intent);
  const tx = intent.transaction;
  assert.equal(tx.Account, XRPL_ACCOUNT);
  assert.equal(tx.SigningPubKey, XRPL_SIGNING_PUB_KEY);
  assert.equal(tx.Sequence, 4_999_001);
  assert.equal(tx.Fee, XRPL.feeDrops);
  // The expiry counts from the lower of the two validated ledgers, + 80 (ADR-RN-016 Amendment C1).
  assert.equal(XRPL.lastLedgerOffset, 80);
  assert.equal(tx.LastLedgerSequence, 5_000_080);
  assert.equal(Object.hasOwn(tx, 'NetworkID'), false);
  const p = intent.preparation;
  assert.equal(p.format, PREPARATION_FORMAT);
  assert.equal(p.observedAt, NOW);
  assert.deepEqual(p.providers.map((e) => e.id), [XA.id, XB.id]);
  assert.deepEqual(p.providers[1].validatedLedger.index, 5_000_001);
  for (const entry of p.providers) {
    assert.deepEqual(entry.exchanges.map((e) => e.method), PREPARATION_REQUESTS['xrpl:testnet']);
    for (const e of entry.exchanges) assert.match(e.responseSha256, /^sha256:[0-9a-f]{64}$/);
  }
  // Exactly the stated request list, per provider, providers one after the other.
  assert.deepEqual(transport.exchanges.map((e) => e.providerId), [XA.id, XA.id, XB.id, XB.id]);
  assert.deepEqual(JSON.parse(transport.exchanges[1].request).params[0], { account: XRPL_ACCOUNT, api_version: 2, ledger_index: 'validated', signer_lists: true });
});

const PIN = { blockHash: evmBlockHash(9_437_182), requireCanonical: true };

test('Sepolia: two passes, then account reads pinned to the agreed block hash (ADR-RN-018 Amendment C1)', async () => {
  const twoGwei = '0x77359400';
  const { transport, input } = sepInput(sepPair({ pinBaseFee: twoGwei }, { pinBaseFee: twoGwei }));
  const { intent } = await prepareSepoliaIntent(input);
  const tx = intent.transaction;
  assert.equal(tx.from, SEPOLIA_FROM);
  assert.equal(tx.to, SEPOLIA_FROM);
  assert.equal(tx.nonce, '0x0');
  // 2 x the PINNED block's base fee (2 gwei) + 1 gwei tip (P6).
  assert.equal(tx.maxFeePerGas, `0x${(5_000_000_000).toString(16)}`);
  assert.equal(tx.gas, `0x${SEPOLIA.gasLimit.toString(16)}`);
  // Order: the head pass on both providers, the pin on both, then the pinned reads.
  assert.deepEqual(transport.exchanges.map((e) => `${e.providerId.slice(-1)}:${JSON.parse(e.request).method}`), [
    'a:eth_chainId', 'a:eth_getBlockByNumber', 'b:eth_chainId', 'b:eth_getBlockByNumber',
    'a:eth_getBlockByNumber', 'b:eth_getBlockByNumber',
    'a:eth_getTransactionCount', 'a:eth_getTransactionCount', 'a:eth_getBalance', 'a:eth_getCode', 'a:eth_estimateGas',
    'b:eth_getTransactionCount', 'b:eth_getTransactionCount', 'b:eth_getBalance', 'b:eth_getCode', 'b:eth_estimateGas',
  ]);
  for (const provider of [SA, SB]) {
    assert.deepEqual(methodsOf(transport.exchanges, provider.id), PREPARATION_REQUESTS['evm:11155111']);
    const params = transport.exchanges.filter((e) => e.providerId === provider.id).map((e) => JSON.parse(e.request).params);
    assert.deepEqual(params[1], ['latest', false]);
    // P = the lower head (9,437,184) - 2, by number.
    assert.deepEqual(params[2], ['0x8ffffe', false]);
    assert.deepEqual(params[3], [SEPOLIA_FROM, PIN]);
    assert.deepEqual(params[4], [SEPOLIA_FROM, 'pending']);
    assert.deepEqual(params[5], [SEPOLIA_FROM, PIN]);
    assert.deepEqual(params[6], [SEPOLIA_FROM, PIN]);
    assert.deepEqual(params[7], [{ data: tx.input, from: SEPOLIA_FROM, to: SEPOLIA_FROM, value: '0x0' }, PIN]);
  }
  // The record's block is the pin P, the same on both providers.
  for (const entry of intent.preparation.providers) {
    assert.deepEqual(entry.block, { number: '0x8ffffe', hash: PIN.blockHash, timestamp: `0x${evmBlockTimestamp(9_437_182).toString(16)}`, baseFeePerGas: twoGwei });
    assert.equal(entry.exchanges.length, 8);
  }
  assert.equal(PREPARATION_REQUESTS['evm:11155111'].length, 8);
});

test('Sepolia: no account read before the pin is agreed, and a disagreement refuses', async () => {
  const { transport, input } = sepInput(sepPair({}, { pin: (b) => { b.hash = `0x${'cd'.repeat(32)}`; } }));
  await assert.rejects(prepareSepoliaIntent(input), refused(PrepErrorCode.INCONSISTENT, null));
  assert.equal(transport.exchanges.length, 6);
  assert.ok(transport.exchanges.every((e) => ['eth_chainId', 'eth_getBlockByNumber'].includes(JSON.parse(e.request).method)));
});

test('Sepolia: a refused pinned read blocks preparation, with no fallback by number, tag or provider', async () => {
  for (const [opts, reason, method] of [
    [{ eip1898: false }, BlockedReason.BLOCK_HASH_READ_REFUSED, 'eth_getTransactionCount'],
    [{ estimateGasBlockHash: false }, BlockedReason.GAS_ESTIMATION_UNAVAILABLE, 'eth_estimateGas'],
  ]) {
    const { transport, input } = sepInput(sepPair(opts));
    await assert.rejects(prepareSepoliaIntent(input), (error) => {
      refused(PrepErrorCode.PROVIDER_ERROR, SA.id)(error);
      assert.equal(error.blocked, reason);
      assert.equal(error.method, method);
      return true;
    });
    // The refused request was the last one: nothing re-sent to a, nothing sent to b's pinned pass.
    const last = JSON.parse(transport.exchanges.at(-1).request);
    assert.equal(transport.exchanges.at(-1).providerId, SA.id);
    assert.equal(last.method, method);
    assert.equal(transport.exchanges.filter((e) => e.providerId === SB.id).length, 3);
    for (const e of transport.exchanges) {
      const { method: m, params } = JSON.parse(e.request);
      if (['eth_getBalance', 'eth_getCode', 'eth_estimateGas'].includes(m)) assert.deepEqual(params[1], PIN);
      if (m === 'eth_getTransactionCount') assert.ok(params[1] === 'pending' || JSON.stringify(params[1]) === JSON.stringify(PIN));
    }
  }
  // A transport failure on a pinned read is unavailability, not a block.
  const timeout = sepInput(sepPair({ raw: { eth_estimateGas: transportError('RNLO_TIMEOUT') } }));
  await assert.rejects(prepareSepoliaIntent(timeout.input), (error) => refused(PrepErrorCode.PROVIDER_UNAVAILABLE, SA.id)(error) && error.blocked === null);
});

test('Sepolia: the pin must be the block asked for, precede the head, and be at most 90 s old', async () => {
  const s = async (a, b, code, who) => assert.rejects(prepareSepoliaIntent(sepInput(sepPair(a, b)).input), refused(code, who));
  await s({ pin: (b) => { b.number = '0x8fffff'; } }, {}, PrepErrorCode.INCONSISTENT, SA.id);
  await s({ pin: (b) => { b.timestamp = `0x${(NOW - 5).toString(16)}`; } }, {}, PrepErrorCode.INCONSISTENT, SA.id);
  const stale = (b) => { b.timestamp = `0x${(NOW - 91).toString(16)}`; };
  await s({ pin: stale }, { pin: stale }, PrepErrorCode.STALE, SA.id);
  const old = (b) => { b.timestamp = `0x${(NOW - 90).toString(16)}`; };
  await prepareSepoliaIntent(sepInput(sepPair({ pin: old }, { pin: old })).input);
});

test('the fee never rises above the cap, and a base fee above 19 gwei stops the run', async () => {
  const fifteen = '0x37e11d600';
  const capped = await prepareSepoliaIntent(sepInput(sepPair({ pinBaseFee: fifteen }, { pinBaseFee: fifteen })).input);
  assert.equal(capped.intent.transaction.maxFeePerGas, `0x${SEPOLIA.maxFeePerGasCapWei.toString(16)}`);
  const over = `0x${(19_000_000_001).toString(16)}`;
  await assert.rejects(prepareSepoliaIntent(sepInput(sepPair({ baseFee: over })).input), refused(PrepErrorCode.FEE_TOO_HIGH, SA.id));
  await assert.rejects(prepareSepoliaIntent(sepInput(sepPair({ pinBaseFee: over }, { pinBaseFee: over })).input), refused(PrepErrorCode.FEE_TOO_HIGH, SA.id));
});

test('every request is an allowlisted read-only method, sent once (no retry)', async () => {
  for (const [network, run, servers] of [
    ['xrpl:testnet', (i) => prepareXrplIntent(i), xrplPair()],
    ['evm:11155111', (i) => prepareSepoliaIntent(i), sepPair()],
  ]) {
    const { transport, input } = network === 'xrpl:testnet' ? xrplInput(servers) : sepInput(servers);
    await run(input);
    for (const e of transport.exchanges) assert.ok(READ_ONLY_METHODS[network].includes(JSON.parse(e.request).method));
  }
  // A 503 would be retried by the verification path; here it is not.
  const { transport, input } = xrplInput(xrplPair({ raw: { server_info: () => reply('busy', 503) } }));
  await assert.rejects(prepareXrplIntent(input), refused(PrepErrorCode.PROVIDER_UNAVAILABLE, XA.id));
  assert.equal(transport.exchanges.length, 1);
});

test('fail closed: the first refusing provider stops the run, and later providers are not read', async () => {
  const { transport, input } = sepInput(sepPair({ chainId: '0x1' }));
  await assert.rejects(prepareSepoliaIntent(input), refused(PrepErrorCode.WRONG_NETWORK, SA.id));
  assert.deepEqual(transport.exchanges.map((e) => e.providerId), [SA.id]);
  const timeout = xrplInput(xrplPair({}, { raw: { account_info: transportError('RNLO_TIMEOUT') } }));
  await assert.rejects(prepareXrplIntent(timeout.input), refused(PrepErrorCode.PROVIDER_UNAVAILABLE, XB.id));
});

test('stale, inconsistent and malformed data are refused with their codes', async () => {
  const x = async (a, b, code, who) => assert.rejects(prepareXrplIntent(xrplInput(xrplPair(a, b)).input), refused(code, who));
  const s = async (a, b, code, who) => assert.rejects(prepareSepoliaIntent(sepInput(sepPair(a, b)).input), refused(code, who));
  await x({ info: (i) => { i.validated_ledger.age = 31; } }, {}, PrepErrorCode.STALE, XA.id);
  await x({}, { seq: 5_000_005 }, PrepErrorCode.INCONSISTENT, null);
  await x({}, { account: (r) => { r.account_data.Sequence = 7; } }, PrepErrorCode.INCONSISTENT, null);
  await x({ account: (r) => { r.account_data.Balance = '-1'; } }, {}, PrepErrorCode.MALFORMED, XA.id);
  await x({ info: (i) => { i.validated_ledger.base_fee_xrp = '0.00001'; } }, {}, PrepErrorCode.MALFORMED, XA.id);
  await x({ info: (i) => { i.server_state = 'connected'; } }, {}, PrepErrorCode.NOT_SYNCED, XA.id);
  await s({ timestamp: NOW - 61 }, {}, PrepErrorCode.STALE, SA.id);
  await s({}, { number: 9_437_189, timestamp: NOW - 1 }, PrepErrorCode.INCONSISTENT, null);
  await s({ pending: '0x3' }, {}, PrepErrorCode.NONCE_PENDING, SA.id);
  await s({ code: '0x6001' }, {}, PrepErrorCode.ACCOUNT_UNSUITABLE, SA.id);
  await s({ estimate: '0x7531' }, {}, PrepErrorCode.GAS_TOO_HIGH, SA.id);
  await s({ block: (b) => { b.timestamp = 1_793_491_194; } }, {}, PrepErrorCode.MALFORMED, SA.id);
});

test('input refusals send nothing', async () => {
  const cases = [
    { providers: [XA] },
    { providers: [XA, XA] },
    { providers: [XA, { ...XB, operator: XA.operator }] },
    { providers: [XA, { ...XB, network: 'evm:11155111' }] },
    { providers: [XA, XB, { ...XA, id: 'c', url: 'https://c.fixture.invalid/' }, { ...XA, id: 'd', url: 'https://d.fixture.invalid/' }, { ...XA, id: 'e', url: 'https://e.fixture.invalid/' }] },
    { account: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh' },
    { signingPubKey: XRPL_SIGNING_PUB_KEY.toLowerCase() },
    { commitment: COMMITMENT.toUpperCase() },
    { now: 0 },
    { now: Number.MAX_SAFE_INTEGER + 1 },
    { transport: 'https://example.org/' },
  ];
  for (const extra of cases) {
    const { transport, input } = xrplInput(xrplPair(), extra);
    await assert.rejects(prepareXrplIntent(input), refused(PrepErrorCode.INPUT_INVALID), JSON.stringify(Object.keys(extra)));
    assert.equal(transport.exchanges.length, 0);
  }
});

test('the digest covers the observations: another time or another provider answer is another intent', async () => {
  const a = await prepareXrplIntent(xrplInput(xrplPair()).input);
  const b = await prepareXrplIntent(xrplInput(xrplPair()).input);
  assert.equal(a.digest, b.digest);
  const later = await prepareXrplIntent(xrplInput(xrplPair(), { now: NOW + 1 }).input);
  assert.notEqual(later.digest, a.digest);
  const otherAnswer = await prepareXrplIntent(xrplInput(xrplPair({ info: (i) => { i.build_version = '2.6.2'; } })).input);
  assert.deepEqual(otherAnswer.intent.transaction, a.intent.transaction);
  assert.notEqual(otherAnswer.digest, a.digest);
});

test('a capture that does not fit, or a bug, is never turned into a refusal', async () => {
  const mismatch = xrplInput({ [XA.id]: () => { throw new ReplayMismatch('synthetic'); }, [XB.id]: xrplServer() });
  await assert.rejects(prepareXrplIntent(mismatch.input), (e) => e instanceof ReplayMismatch);
  const broken = sepInput(sepPair());
  broken.input.transport = async () => ({ status: 200, body: 'not bytes' });
  await assert.rejects(prepareSepoliaIntent(broken.input), refused(PrepErrorCode.PROVIDER_UNAVAILABLE, SA.id));
});

test('a provider value that cannot be sent back in a request is refused, not sent', async () => {
  // The block number is reused in later requests; a malformed one stops the run before them.
  const { transport, input } = sepInput(sepPair({ block: (b) => { b.number = '0x0900000'; } }));
  await assert.rejects(prepareSepoliaIntent(input), refused(PrepErrorCode.MALFORMED, SA.id));
  assert.equal(transport.exchanges.length, 2);
  assert.ok(!Buffer.from(transport.exchanges.map((e) => e.request).join('')).includes('0x0900000'));
});
