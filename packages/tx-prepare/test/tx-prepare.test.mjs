// RN-NET-03B2-B2: read-only transaction preparation against simulated providers. No network is
// used; every transport is injected. The fixture corpus (fixtures/preparation-b2) is replayed by
// tools/preparation.test.mjs and reproduced by tools/reference/rnnet_prep_reference.py.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { PREPARATION_REQUESTS, READ_ONLY_METHODS, ReplayMismatch } from '../../chain-readonly/src/index.mjs';
import { approvedIntent, makeIntent, SEPOLIA, XRPL } from '../../tx-intent/src/index.mjs';
import * as api from '../src/index.mjs';
import { PREPARATION_FORMAT, PREPARATION_RULES, PrepErrorCode, prepareSepoliaIntent, prepareXrplIntent } from '../src/index.mjs';
import {
  COMMITMENT,
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
  assert.deepEqual(Object.keys(api).sort(), ['PREPARATION_FORMAT', 'PREPARATION_RULES', 'PrepError', 'PrepErrorCode', 'prepareSepoliaIntent', 'prepareXrplIntent']);
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
  // The expiry counts from the lower of the two validated ledgers.
  assert.equal(tx.LastLedgerSequence, 5_000_000 + XRPL.lastLedgerOffset);
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

test('Sepolia: binds nonce, from/to and maxFeePerGas; reads are pinned to the latest block', async () => {
  const { transport, input } = sepInput(sepPair({}, { baseFee: '0x77359400' })); // b: 2 gwei
  const { intent } = await prepareSepoliaIntent(input);
  const tx = intent.transaction;
  assert.equal(tx.from, SEPOLIA_FROM);
  assert.equal(tx.to, SEPOLIA_FROM);
  assert.equal(tx.nonce, '0x0');
  // 2 x the highest base fee (2 gwei) + 1 gwei tip.
  assert.equal(tx.maxFeePerGas, `0x${(5_000_000_000).toString(16)}`);
  assert.equal(tx.gas, `0x${SEPOLIA.gasLimit.toString(16)}`);
  assert.deepEqual(methodsOf(transport.exchanges, SA.id), PREPARATION_REQUESTS['evm:11155111']);
  const params = transport.exchanges.filter((e) => e.providerId === SA.id).map((e) => JSON.parse(e.request).params);
  assert.deepEqual(params[1], ['latest', false]);
  assert.deepEqual(params[2], [SEPOLIA_FROM, '0x900000']);
  assert.deepEqual(params[3], [SEPOLIA_FROM, 'pending']);
  assert.deepEqual(params[6], [{ data: tx.input, from: SEPOLIA_FROM, to: SEPOLIA_FROM, value: '0x0' }, '0x900000']);
  assert.equal(intent.preparation.providers[0].block.number, '0x900000');
});

test('the fee never rises above the cap, and a base fee above 19 gwei stops the run', async () => {
  const capped = await prepareSepoliaIntent(sepInput(sepPair({ baseFee: '0x37e11d600', balance: '0x2386f26fc10000' })).input); // 15 gwei
  assert.equal(capped.intent.transaction.maxFeePerGas, `0x${SEPOLIA.maxFeePerGasCapWei.toString(16)}`);
  await assert.rejects(prepareSepoliaIntent(sepInput(sepPair({ baseFee: `0x${(19_000_000_001).toString(16)}` })).input), refused(PrepErrorCode.FEE_TOO_HIGH, SA.id));
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
  await s({}, { number: 9_437_189 }, PrepErrorCode.INCONSISTENT, null);
  await s({ pending: '0x3' }, {}, PrepErrorCode.NONCE_PENDING, SA.id);
  await s({ code: '0x6001' }, {}, PrepErrorCode.ACCOUNT_UNSUITABLE, SA.id);
  await s({ estimate: '0x7531' }, {}, PrepErrorCode.GAS_TOO_HIGH, SA.id);
  await s({ block: (b) => { b.timestamp = 1_793_491_194; } }, {}, PrepErrorCode.MALFORMED, SA.id);
});

test('input refusals send nothing', async () => {
  const cases = [
    { providers: [XA] },
    { providers: [XA, XA] },
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
