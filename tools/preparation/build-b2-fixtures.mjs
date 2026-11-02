// Builds fixtures/preparation-b2/cases.json: offline preparation cases for RN-NET-03B2-B2
// (ADR-RN-018), each with the exact exchanges a simulated provider pair answered and the result
// preparation must give: an intent and its digest, or one refusal code.
//
//   node tools/preparation/build-b2-fixtures.mjs           # check the committed file is current
//   node tools/preparation/build-b2-fixtures.mjs --write   # write it (refuses to overwrite)
//
// Everything is synthetic and offline: the providers are simulated (fixture.invalid hosts that
// cannot resolve), the ledger, block, balance and nonce values are made up, and the senders are
// the public fixtures/signing-b1 test-key addresses, never funded. Expected codes are stated by
// hand below; packages/tx-prepare and tools/reference/rnnet_prep_reference.py must both reproduce
// every case from the recorded exchanges alone.
import { Buffer } from 'node:buffer';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalBytes } from '../../packages/canonical/src/index.mjs';
import { prepareSepoliaIntent, prepareXrplIntent } from '../../packages/tx-prepare/src/index.mjs';
import {
  COMMITMENT,
  fakeTransport,
  NOW,
  raw,
  reply,
  SEPOLIA_FROM,
  sepoliaProviders,
  sepoliaServer,
  transportError,
  XRPL_ACCOUNT,
  XRPL_SIGNING_PUB_KEY,
  xrplLedgerHash,
  xrplProviders,
  xrplServer,
} from '../../packages/tx-prepare/test/fake-providers.mjs';

export const PATH = fileURLToPath(new URL('../../fixtures/preparation-b2/cases.json', import.meta.url));
export const FIXTURES_FORMAT = 'rnnet.preparation-b2-fixtures.v1';

const X = 'xrpl:testnet';
const S = 'evm:11155111';
const XA = 'fixture-xrpl-a';
const XB = 'fixture-xrpl-b';
const SA = 'fixture-sepolia-a';
const SB = 'fixture-sepolia-b';
const B = 5_000_001; // provider b's validated ledger in the default XRPL pair
const GWEI = 1_000_000_000n;
const q = (n) => `0x${BigInt(n).toString(16)}`;

// --- the cases ------------------------------------------------------------------------------------
// Each XRPL case: servers for a and b (xrplServer options); each Sepolia case likewise.
// `expect` is [code, providerId] for a refusal, or 'PASS'.

const xrplDefault = { [XA]: {}, [XB]: { seq: B } };
const xrplB = (opts) => ({ [XA]: {}, [XB]: { seq: B, ...opts } });
const xrplA = (opts) => ({ [XA]: opts, [XB]: { seq: B } });
const sepDefault = { [SA]: {}, [SB]: { number: 9_437_185, timestamp: NOW - 1 } };
const sepB = (opts) => ({ [SA]: {}, [SB]: { number: 9_437_185, timestamp: NOW - 1, ...opts } });
const sepA = (opts) => ({ [SA]: opts, [SB]: { number: 9_437_185, timestamp: NOW - 1 } });
const xrplError = (error) => () => reply(JSON.stringify({ result: { status: 'error', error, request: {} } }));
const evmError = () => reply(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'synthetic failure' } }));

export const CASES = [
  // XRPL: accepted
  { id: 'xrpl-pass', network: X, servers: xrplDefault, expect: 'PASS' },
  { id: 'xrpl-pass-load-factor-1.2', network: X, servers: xrplB({ info: (i) => { i.load_factor = raw('1.2'); } }), expect: 'PASS' },
  { id: 'xrpl-pass-balance-exactly-reserve-plus-fee', network: X, servers: xrplA({ account: (r) => { r.account_data.Balance = '1000012'; } }), expect: 'PASS' },
  { id: 'xrpl-pass-skew-4', network: X, servers: { [XA]: {}, [XB]: { seq: 5_000_004 } }, expect: 'PASS' },
  { id: 'xrpl-pass-account-ledger-lead-2', network: X, servers: xrplA({ accountLead: 2 }), expect: 'PASS' },
  // XRPL: network
  { id: 'xrpl-wrong-network-mainnet', network: X, servers: xrplB({ info: (i) => { i.network_id = 0; } }), expect: ['RNTP_WRONG_NETWORK', XB] },
  { id: 'xrpl-network-id-missing', network: X, servers: xrplA({ info: (i) => { delete i.network_id; } }), expect: ['RNTP_WRONG_NETWORK', XA] },
  { id: 'xrpl-network-id-string', network: X, servers: xrplA({ info: (i) => { i.network_id = '1'; } }), expect: ['RNTP_MALFORMED', XA] },
  // XRPL: freshness and consistency
  { id: 'xrpl-not-synced', network: X, servers: xrplB({ info: (i) => { i.server_state = 'syncing'; } }), expect: ['RNTP_NOT_SYNCED', XB] },
  { id: 'xrpl-stale-ledger', network: X, servers: xrplA({ info: (i) => { i.validated_ledger.age = 31; } }), expect: ['RNTP_STALE', XA] },
  { id: 'xrpl-account-not-validated', network: X, servers: xrplA({ account: (r) => { r.validated = false; } }), expect: ['RNTP_INCONSISTENT', XA] },
  { id: 'xrpl-account-ledger-behind', network: X, servers: xrplA({ accountLead: -1 }), expect: ['RNTP_INCONSISTENT', XA] },
  { id: 'xrpl-account-ledger-lead-3', network: X, servers: xrplA({ accountLead: 3 }), expect: ['RNTP_INCONSISTENT', XA] },
  { id: 'xrpl-same-ledger-other-hash', network: X, servers: xrplA({ account: (r) => { r.ledger_hash = xrplLedgerHash(1); } }), expect: ['RNTP_INCONSISTENT', XA] },
  { id: 'xrpl-other-account', network: X, servers: xrplB({ account: (r) => { r.account_data.Account = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'; } }), expect: ['RNTP_INCONSISTENT', XB] },
  { id: 'xrpl-skew-5', network: X, servers: { [XA]: {}, [XB]: { seq: 5_000_005 } }, expect: ['RNTP_INCONSISTENT', null] },
  { id: 'xrpl-same-index-two-hashes', network: X, servers: { [XA]: {}, [XB]: { seq: 5_000_000, info: (i) => { i.validated_ledger.hash = xrplLedgerHash(9); }, account: (r) => { r.ledger_hash = xrplLedgerHash(9); } } }, expect: ['RNTP_INCONSISTENT', null] },
  { id: 'xrpl-ledger-near-uint32-limit', network: X, servers: { [XA]: { seq: 4_294_967_290 }, [XB]: { seq: 4_294_967_291 } }, expect: ['RNTP_INTENT_INVALID', null] },
  { id: 'xrpl-sequence-disagreement', network: X, servers: xrplB({ account: (r) => { r.account_data.Sequence = 4_999_002; } }), expect: ['RNTP_INCONSISTENT', null] },
  // XRPL: account suitability
  { id: 'xrpl-regular-key', network: X, servers: xrplA({ account: (r) => { r.account_data.RegularKey = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'; } }), expect: ['RNTP_ACCOUNT_UNSUITABLE', XA] },
  { id: 'xrpl-master-disabled', network: X, servers: xrplA({ account: (r) => { r.account_data.Flags = 0x0010_0000; } }), expect: ['RNTP_ACCOUNT_UNSUITABLE', XA] },
  { id: 'xrpl-signer-list', network: X, servers: xrplB({ account: (r) => { r.signer_lists = [{ SignerQuorum: 1, SignerEntries: [] }]; } }), expect: ['RNTP_ACCOUNT_UNSUITABLE', XB] },
  { id: 'xrpl-account-not-found', network: X, servers: xrplA({ raw: { account_info: xrplError('actNotFound') } }), expect: ['RNTP_ACCOUNT_NOT_FOUND', XA] },
  // XRPL: fee and balance
  { id: 'xrpl-load-factor-1.5', network: X, servers: xrplB({ info: (i) => { i.load_factor = raw('1.5'); } }), expect: ['RNTP_FEE_TOO_HIGH', XB] },
  { id: 'xrpl-base-fee-13-drops', network: X, servers: xrplA({ info: (i) => { i.validated_ledger.base_fee_xrp = raw('0.000013'); } }), expect: ['RNTP_FEE_TOO_HIGH', XA] },
  { id: 'xrpl-balance-one-drop-short', network: X, servers: xrplA({ account: (r) => { r.account_data.Balance = '1000011'; } }), expect: ['RNTP_INSUFFICIENT_BALANCE', XA] },
  { id: 'xrpl-owner-reserve-short', network: X, servers: xrplB({ account: (r) => { r.account_data.OwnerCount = 3; r.account_data.Balance = '1600011'; } }), expect: ['RNTP_INSUFFICIENT_BALANCE', XB] },
  // XRPL: malformed data
  { id: 'xrpl-owner-count-minus-zero', network: X, servers: xrplA({ raw: { account_info: (p) => { const r = xrplServer()('account_info', p); return reply(Buffer.from(r.body).toString('utf8').replace('"OwnerCount":0', '"OwnerCount":-0')); } } }), expect: ['RNTP_MALFORMED', XA] },
  { id: 'xrpl-pass-5000-digit-integer-in-unused-field', network: X, servers: xrplA({ info: (i) => { i.peers = raw('9'.repeat(5000)); } }), expect: 'PASS' },
  { id: 'xrpl-txn-not-found-answer', network: X, servers: xrplB({ raw: { account_info: xrplError('txnNotFound') } }), expect: ['RNTP_PROVIDER_ERROR', XB] },
  { id: 'xrpl-balance-number', network: X, servers: xrplA({ account: (r) => { r.account_data.Balance = 25_000_000; } }), expect: ['RNTP_MALFORMED', XA] },
  { id: 'xrpl-base-fee-fraction-of-drop', network: X, servers: xrplA({ info: (i) => { i.validated_ledger.base_fee_xrp = raw('0.0000105'); } }), expect: ['RNTP_MALFORMED', XA] },
  { id: 'xrpl-load-factor-below-1', network: X, servers: xrplA({ info: (i) => { i.load_factor = raw('0.5'); } }), expect: ['RNTP_MALFORMED', XA] },
  { id: 'xrpl-sequence-string', network: X, servers: xrplA({ account: (r) => { r.account_data.Sequence = '4999001'; } }), expect: ['RNTP_MALFORMED', XA] },
  { id: 'xrpl-signer-lists-missing', network: X, servers: xrplA({ account: (r) => { delete r.signer_lists; } }), expect: ['RNTP_MALFORMED', XA] },
  { id: 'xrpl-ledger-hash-lowercase', network: X, servers: xrplA({ info: (i) => { i.validated_ledger.hash = i.validated_ledger.hash.toLowerCase(); } }), expect: ['RNTP_MALFORMED', XA] },
  { id: 'xrpl-age-fraction', network: X, servers: xrplA({ info: (i) => { i.validated_ledger.age = raw('2.5'); } }), expect: ['RNTP_MALFORMED', XA] },
  { id: 'xrpl-duplicate-key', network: X, servers: xrplA({ raw: { server_info: () => reply('{"result":{"info":{"network_id":1},"info":{"network_id":1},"status":"success"}}') } }), expect: ['RNTP_MALFORMED', XA] },
  { id: 'xrpl-invalid-json', network: X, servers: xrplA({ raw: { server_info: () => reply('{"result":') } }), expect: ['RNTP_MALFORMED', XA] },
  { id: 'xrpl-status-missing', network: X, servers: xrplB({ raw: { account_info: () => reply('{"result":{"validated":true}}') } }), expect: ['RNTP_MALFORMED', XB] },
  // XRPL: provider failures (one attempt, no retry)
  { id: 'xrpl-rpc-error', network: X, servers: xrplA({ raw: { server_info: xrplError('noNetwork') } }), expect: ['RNTP_PROVIDER_ERROR', XA] },
  { id: 'xrpl-timeout', network: X, servers: xrplB({ raw: { server_info: transportError('RNLO_TIMEOUT') } }), expect: ['RNTP_PROVIDER_UNAVAILABLE', XB] },
  { id: 'xrpl-http-503-no-retry', network: X, servers: xrplA({ raw: { account_info: () => reply('busy', 503) } }), expect: ['RNTP_PROVIDER_UNAVAILABLE', XA] },

  // Sepolia: accepted
  { id: 'sepolia-pass', network: S, servers: sepDefault, expect: 'PASS' },
  { id: 'sepolia-pass-fee-capped', network: S, servers: sepB({ baseFee: q(15n * GWEI), balance: q(600_000n * GWEI) }), expect: 'PASS' },
  { id: 'sepolia-pass-base-fee-19-gwei', network: S, servers: { [SA]: { baseFee: q(19n * GWEI), balance: q(600_000n * GWEI) }, [SB]: { number: 9_437_185, timestamp: NOW - 1, balance: q(600_000n * GWEI) } }, expect: 'PASS' },
  { id: 'sepolia-pass-block-60s-old', network: S, servers: sepA({ timestamp: NOW - 60 }), expect: 'PASS' },
  { id: 'sepolia-pass-skew-4', network: S, servers: sepB({ number: 9_437_188 }), expect: 'PASS' },
  // Sepolia: network
  { id: 'sepolia-wrong-chain-mainnet', network: S, servers: sepB({ chainId: '0x1' }), expect: ['RNTP_WRONG_NETWORK', SB] },
  { id: 'sepolia-chain-id-uppercase', network: S, servers: sepA({ chainId: '0xAA36A7' }), expect: ['RNTP_MALFORMED', SA] },
  // Sepolia: freshness and consistency
  { id: 'sepolia-stale-block', network: S, servers: sepA({ timestamp: NOW - 61 }), expect: ['RNTP_STALE', SA] },
  { id: 'sepolia-block-in-future', network: S, servers: sepB({ timestamp: NOW + 15 }), expect: ['RNTP_STALE', SB] },
  { id: 'sepolia-skew-5', network: S, servers: sepB({ number: 9_437_189 }), expect: ['RNTP_INCONSISTENT', null] },
  { id: 'sepolia-same-number-two-hashes', network: S, servers: sepB({ number: 9_437_184, block: (b) => { b.hash = `0x${'ab'.repeat(32)}`; } }), expect: ['RNTP_INCONSISTENT', null] },
  { id: 'sepolia-nonce-disagreement', network: S, servers: sepB({ nonce: '0x1' }), expect: ['RNTP_INCONSISTENT', null] },
  { id: 'sepolia-estimate-below-intrinsic', network: S, servers: sepA({ estimate: q(21_000) }), expect: ['RNTP_INCONSISTENT', SA] },
  // Sepolia: nonce, code, fee, gas, balance
  { id: 'sepolia-nonce-pending', network: S, servers: sepA({ pending: '0x1' }), expect: ['RNTP_NONCE_PENDING', SA] },
  { id: 'sepolia-eip7702-delegation', network: S, servers: sepB({ code: `0xef0100${'11'.repeat(20)}` }), expect: ['RNTP_ACCOUNT_UNSUITABLE', SB] },
  { id: 'sepolia-base-fee-above-19-gwei', network: S, servers: sepA({ baseFee: q(19n * GWEI + 1n) }), expect: ['RNTP_FEE_TOO_HIGH', SA] },
  { id: 'sepolia-estimate-above-limit', network: S, servers: sepB({ estimate: q(30_001) }), expect: ['RNTP_GAS_TOO_HIGH', SB] },
  { id: 'sepolia-balance-short', network: S, servers: sepA({ balance: q(30_000n * 3_400_000_000n - 1n) }), expect: ['RNTP_INSUFFICIENT_BALANCE', SA] },
  { id: 'sepolia-balance-short-for-other-providers-fee', network: S, servers: { [SA]: { balance: q(30_000n * 3_400_000_000n) }, [SB]: { number: 9_437_185, timestamp: NOW - 1, baseFee: q(2n * GWEI) } }, expect: ['RNTP_INSUFFICIENT_BALANCE', SA] },
  // Sepolia: malformed data
  { id: 'sepolia-base-fee-missing', network: S, servers: sepA({ block: (b) => { delete b.baseFeePerGas; } }), expect: ['RNTP_MALFORMED', SA] },
  { id: 'sepolia-quantity-leading-zero', network: S, servers: sepA({ balance: '0x02386f26fc10000' }), expect: ['RNTP_MALFORMED', SA] },
  { id: 'sepolia-block-hash-uppercase', network: S, servers: sepB({ block: (b) => { b.hash = b.hash.toUpperCase().replace('0X', '0x'); } }), expect: ['RNTP_MALFORMED', SB] },
  { id: 'sepolia-code-odd-length', network: S, servers: sepA({ code: '0x0' }), expect: ['RNTP_MALFORMED', SA] },
  { id: 'sepolia-nonce-2-pow-64', network: S, servers: sepA({ nonce: q(2n ** 64n), pending: q(2n ** 64n) }), expect: ['RNTP_MALFORMED', SA] },
  { id: 'sepolia-balance-number', network: S, servers: sepA({ balance: raw('1e18') }), expect: ['RNTP_MALFORMED', SA] },
  { id: 'sepolia-envelope-id-2', network: S, servers: sepA({ raw: { eth_chainId: () => reply('{"jsonrpc":"2.0","id":2,"result":"0xaa36a7"}') } }), expect: ['RNTP_MALFORMED', SA] },
  // Sepolia: provider failures (one attempt, no retry)
  { id: 'sepolia-rpc-error', network: S, servers: sepB({ raw: { eth_estimateGas: evmError } }), expect: ['RNTP_PROVIDER_ERROR', SB] },
  { id: 'sepolia-http-429-no-retry', network: S, servers: sepA({ raw: { eth_getBalance: () => reply('slow down', 429) } }), expect: ['RNTP_PROVIDER_UNAVAILABLE', SA] },
  { id: 'sepolia-connection-failure', network: S, servers: sepB({ raw: { eth_getCode: transportError('RNLO_CONNECTION') } }), expect: ['RNTP_PROVIDER_UNAVAILABLE', SB] },
];

// Input refusals: nothing is sent.
export const INPUT_CASES = [
  { id: 'input-one-provider', network: X, input: { providers: 1 }, expect: ['RNTP_INPUT_INVALID', null] },
  { id: 'input-same-operator', network: X, input: { providers: 'same-operator' }, expect: ['RNTP_INPUT_INVALID', null] },
  { id: 'input-provider-twice', network: S, input: { providers: 'twice' }, expect: ['RNTP_INPUT_INVALID', null] },
  { id: 'input-account-not-of-key', network: X, input: { account: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh' }, expect: ['RNTP_INPUT_INVALID', null] },
  { id: 'input-from-uppercase', network: S, input: { from: SEPOLIA_FROM.toUpperCase().replace('0X', '0x') }, expect: ['RNTP_INPUT_INVALID', null] },
  { id: 'input-now-string', network: S, input: { now: '1793491200' }, expect: ['RNTP_INPUT_INVALID', null] },
];

// --- building ---------------------------------------------------------------------------------------

const publicProvider = ({ id, network, operator, url }) => ({ id, network, operator, url });

function inputFor(network, overrides = {}) {
  let providers = network === X ? xrplProviders() : sepoliaProviders();
  if (overrides.providers === 1) providers = providers.slice(0, 1);
  if (overrides.providers === 'twice') providers = [providers[0], providers[0]];
  if (overrides.providers === 'same-operator') providers = [providers[0], { ...providers[1], operator: providers[0].operator }];
  const base = network === X
    ? { commitment: COMMITMENT, account: overrides.account ?? XRPL_ACCOUNT, signingPubKey: XRPL_SIGNING_PUB_KEY }
    : { commitment: COMMITMENT, from: overrides.from ?? SEPOLIA_FROM };
  return { ...base, now: overrides.now ?? NOW, providers };
}

async function run(network, input, transport) {
  const prepare = network === X ? prepareXrplIntent : prepareSepoliaIntent;
  try {
    const { intent, digest } = await prepare({ ...input, transport });
    return { outcome: 'PASS', code: null, providerId: null, digest, intent };
  } catch (error) {
    if (error?.name !== 'PrepError') throw error;
    return { outcome: 'FAIL', code: error.code, providerId: error.providerId, digest: null, intent: null };
  }
}

const sameExpectation = (result, expect) => (expect === 'PASS' ? result.outcome === 'PASS' : result.code === expect[0] && result.providerId === expect[1]);

export async function buildCases() {
  const cases = [];
  for (const c of CASES) {
    const servers = Object.fromEntries(Object.entries(c.servers).map(([id, opts]) => [id, (c.network === X ? xrplServer : sepoliaServer)(opts)]));
    const transport = fakeTransport(servers);
    const input = inputFor(c.network);
    const result = await run(c.network, input, transport);
    if (!sameExpectation(result, c.expect)) throw new Error(`${c.id}: expected ${c.expect}, got ${result.code ?? 'PASS'} (${result.providerId})`);
    cases.push(entry(c, input, transport.exchanges, result));
  }
  for (const c of INPUT_CASES) {
    const transport = fakeTransport({});
    const input = inputFor(c.network, c.input);
    const result = await run(c.network, input, transport);
    if (!sameExpectation(result, c.expect)) throw new Error(`${c.id}: expected ${c.expect}, got ${result.code ?? 'PASS'}`);
    if (transport.exchanges.length !== 0) throw new Error(`${c.id}: an input refusal sent a request`);
    cases.push(entry(c, input, [], result));
  }
  return cases;
}

function entry(c, input, exchanges, result) {
  const { providers, ...rest } = input;
  return {
    id: c.id,
    network: c.network,
    input: { ...rest, providers: providers.map(publicProvider) },
    exchanges,
    expected: { outcome: result.outcome, code: result.code, providerId: result.providerId, digest: result.digest, intent: result.intent },
  };
}

export async function build() {
  const cases = await buildCases();
  const document = {
    format: FIXTURES_FORMAT,
    status: 'SYNTHETIC: simulated providers and made-up ledger, block, balance and nonce values; never read from or sent to a network',
    cases,
  };
  return `${Buffer.from(canonicalBytes(document)).toString('utf8')}\n`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = await build();
  if (process.argv.includes('--write')) {
    if (existsSync(PATH)) throw new Error(`${PATH} exists; remove it first to rebuild`);
    writeFileSync(PATH, text, { flag: 'wx' });
    console.log(`wrote ${PATH}`);
  } else if (!existsSync(PATH) || readFileSync(PATH, 'utf8') !== text) {
    console.error('fixtures/preparation-b2/cases.json is not current: rebuild with --write');
    process.exit(1);
  } else {
    console.log('fixtures/preparation-b2/cases.json is current');
  }
}
