// RN-NET-03B1: live read-only verification against simulated servers. No network is used.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { encodeAnchorPayload } from '../../anchor/src/index.mjs';
import {
  checkCapture, encodeLiveReport, loadEndpointConfig, parseRpcJson, RawNumber, READ_ONLY_METHODS,
  recordingTransport, replayTransport, ReplayMismatch, requestBytes, verifyLiveAnchor,
} from '../src/index.mjs';
import { COMMITMENT, fakeEvm, fakeXrpl, PAYLOAD, provider } from './fake-chains.mjs';

const XRPL = 'xrpl:testnet';
const EVM = 'evm:11155111';
const run = (network, fake, providers = [provider('p1', network)], commitment = COMMITMENT) =>
  verifyLiveAnchor({ network, transactionHash: fake.hash, expectedCommitment: commitment, providers, transport: fake.transport });
const codes = (report) => report.findings.map((f) => f.code);
const json = (status, value) => ({ status, body: new Uint8Array(Buffer.from(typeof value === 'string' ? value : JSON.stringify(value))) });

// --- XRPL ----------------------------------------------------------------------------------------

test('XRPL: a validated transaction with the anchor passes, as provider-reported only', async () => {
  const report = await run(XRPL, fakeXrpl());
  assert.equal(report.outcome, 'PASS');
  assert.equal(report.agreement, 'INSUFFICIENT_SOURCES');
  assert.deepEqual(report.statuses, ['OBSERVED_FROM_RPC', 'PROVIDER_REPORTED_VALIDATED']);
  assert.equal(report.providers[0].record.outcome, 'PASS');
  const classes = Object.fromEntries(report.statements.map((s) => [s.subject, s.classification]));
  assert.deepEqual(classes, { providerObservation: 'CLAIMED', finality: 'CLAIMED', chainInclusionProof: 'UNRESOLVED' });
  assert.ok(!JSON.stringify(report).includes('CHAIN_PROVEN'));
});

test('XRPL: network identity comes from server_info, never from the provider name', async () => {
  const wrong = await run(XRPL, fakeXrpl({ networkId: 0 }), [provider('xrpl-testnet-looks-right', XRPL)]);
  assert.equal(wrong.outcome, 'FAIL');
  assert.deepEqual(codes(wrong), ['RNLO_WRONG_NETWORK']);
  const unknown = await run(XRPL, fakeXrpl({ fail: { server_info: () => json(200, { result: { status: 'success', info: {} } }) } }));
  assert.deepEqual(codes(unknown), ['RNLO_NETWORK_UNKNOWN']);
});

test('XRPL: unvalidated, unsuccessful, missing anchor and wrong commitment all fail', async () => {
  const unvalidated = await run(XRPL, fakeXrpl({ tx: { validated: false } }));
  assert.equal(unvalidated.outcome, 'FAIL');
  assert.ok(unvalidated.statuses.includes('UNRESOLVED') && !unvalidated.statuses.includes('PROVIDER_REPORTED_VALIDATED'));
  assert.deepEqual(unvalidated.providers[0].record.findings.map((f) => f.code), ['RNAX_NOT_VALIDATED']);
  const failed = await run(XRPL, fakeXrpl({ tx: { meta: { TransactionIndex: 2, TransactionResult: 'tecNO_PERMISSION' } } }));
  assert.deepEqual(failed.providers[0].record.findings.map((f) => f.code), ['RNAX_TRANSACTION_NOT_SUCCESSFUL']);
  const noMemo = fakeXrpl();
  const noAnchor = await run(XRPL, fakeXrpl({ tx: { tx_json: { TransactionType: 'AccountSet', Account: 'rSyntheticAnchorTestAccount1111' } } }));
  assert.deepEqual(noAnchor.providers[0].record.findings.map((f) => f.code), ['RNAX_MISSING_ANCHOR']);
  const other = await run(XRPL, noMemo, undefined, `sha256:${'cd'.repeat(32)}`);
  assert.deepEqual(other.providers[0].record.findings.map((f) => f.code), ['RNAP_COMMITMENT_MISMATCH']);
});

test('XRPL: inconsistent provider data is refused', async () => {
  assert.deepEqual(codes(await run(XRPL, fakeXrpl({ returnedHash: 'F'.repeat(64) }))), ['RNLO_HASH_MISMATCH']);
  assert.deepEqual(codes(await run(XRPL, fakeXrpl({ ledgerHash: 'E'.repeat(64) }))), ['RNLO_LEDGER_MISMATCH']);
  assert.deepEqual(codes(await run(XRPL, fakeXrpl({ ledgerValidated: false }))), ['RNLO_LEDGER_MISMATCH']);
  const ctid = await run(XRPL, fakeXrpl({ tx: { ctid: 'C000138900020001' } }));
  assert.deepEqual(ctid.providers[0].record.findings.map((f) => f.code), ['RNAX_CONTRADICTORY_REFERENCE']);
  const noCtid = await run(XRPL, fakeXrpl({ tx: { ctid: undefined, tx_json: { ...fakeXrplBody(), ctid: undefined } } }));
  assert.equal(noCtid.outcome, 'PASS'); // a missing CTID is allowed; network identity came from server_info
  assert.deepEqual(codes(await run(XRPL, fakeXrpl({ tx: { meta: undefined } }))), ['RNLO_INVALID_RESPONSE']);
  assert.deepEqual(codes(await run(XRPL, fakeXrpl({ tx: { tx_json: undefined, TransactionType: 'AccountSet' } }))), ['RNLO_UNSUPPORTED_API_VERSION']);
});
const fakeXrplBody = () => ({ TransactionType: 'AccountSet', Account: 'rSyntheticAnchorTestAccount1111', Memos: [{ Memo: { MemoType: '726E6E65742E616E63686F722D7061796C6F61642E7631', MemoData: PAYLOAD.toUpperCase() } }] });

test('XRPL: not found, timeouts and malformed envelopes', async () => {
  const notFound = await run(XRPL, fakeXrpl({ notFound: true }));
  assert.equal(notFound.outcome, 'FAIL');
  assert.equal(notFound.providers[0].outcome, 'NOT_FOUND');
  const timeout = await run(XRPL, fakeXrpl({ fail: { tx: () => { throw Object.assign(new Error('t'), { code: 'RNLO_TIMEOUT' }); } } }));
  assert.equal(timeout.outcome, 'INDETERMINATE');
  assert.equal(timeout.agreement, 'SOURCE_UNAVAILABLE');
  const envelope = await run(XRPL, fakeXrpl({ fail: { tx: () => json(200, { result: { status: 'weird' } }) } }));
  assert.deepEqual(codes(envelope), ['RNLO_INVALID_RESPONSE']);
});

// --- Sepolia -------------------------------------------------------------------------------------

test('Sepolia: an included, successful anchor in the finalized ancestry passes as provider-reported', async () => {
  const fake = fakeEvm();
  const report = await run(EVM, fake);
  assert.equal(report.outcome, 'PASS');
  assert.deepEqual(report.providers[0].finality, { finalized: 'IN_ANCESTRY', safe: 'IN_ANCESTRY' });
  assert.deepEqual(report.statuses, ['OBSERVED_FROM_RPC', 'PROVIDER_REPORTED_FINALIZED']);
  assert.equal(report.statements.find((s) => s.subject === 'chainInclusionProof').classification, 'UNRESOLVED');
});

test('Sepolia: wrong chain, mismatches, revert and pending fail', async () => {
  assert.deepEqual(codes(await run(EVM, fakeEvm({ chainId: '0x1' }))), ['RNLO_WRONG_NETWORK']);
  assert.deepEqual(codes(await run(EVM, fakeEvm({ transaction: { hash: `0x${'1'.repeat(64)}` } }))), ['RNLO_HASH_MISMATCH']);
  const mismatch = await run(EVM, fakeEvm({ receipt: { transactionHash: `0x${'2'.repeat(64)}` } }));
  assert.deepEqual(mismatch.providers[0].record.findings.map((f) => f.code), ['RNAE_RECEIPT_MISMATCH']);
  const reverted = await run(EVM, fakeEvm({ receipt: { status: '0x0' } }));
  assert.deepEqual(reverted.providers[0].record.findings.map((f) => f.code), ['RNAE_TRANSACTION_REVERTED']);
  const pending = await run(EVM, fakeEvm({ transaction: { blockHash: null, blockNumber: null, transactionIndex: null }, receipt: null }));
  assert.deepEqual(pending.providers[0].record.findings.map((f) => f.code), ['RNAE_PENDING']);
  assert.ok(pending.statuses.includes('UNRESOLVED'));
});

test('Sepolia: block identity and membership are checked against the block itself', async () => {
  assert.deepEqual(codes(await run(EVM, fakeEvm({ transaction: { blockHash: `0x${'3'.repeat(64)}` } }))), ['RNLO_BLOCK_MISMATCH']);
  assert.deepEqual(codes(await run(EVM, fakeEvm({ transaction: { transactionIndex: '0x0' }, receipt: { transactionIndex: '0x0' } }))), ['RNLO_BLOCK_MISMATCH']);
  const fake = fakeEvm();
  const lying = fakeEvm({ blockOverride: (hash) => (hash === fake.byNumber.get(110).hash ? { ...fake.byNumber.get(110), number: '0x6f' } : undefined) });
  assert.deepEqual(codes(await run(EVM, lying)), ['RNLO_BLOCK_MISMATCH']);
});

test('Sepolia: finality comes only from parent-hash ancestry, never from block numbers', async () => {
  const base = fakeEvm();
  // A finalized head on a competing fork at a higher number: the transaction's block is not its ancestor.
  const forked = await run(EVM, fakeEvm({ finalized: base.fork.get(130), safe: base.fork.get(135) }));
  assert.equal(forked.outcome, 'FAIL');
  assert.deepEqual(forked.providers[0].finality, { finalized: 'CONFLICT', safe: 'CONFLICT' });
  assert.ok(codes(forked).includes('RNLO_FINALITY_CONFLICT'));
  const notYet = await run(EVM, fakeEvm({ finalized: base.byNumber.get(105), safe: base.byNumber.get(108) }));
  assert.deepEqual(notYet.providers[0].finality, { finalized: 'NOT_REACHED', safe: 'NOT_REACHED' });
  assert.equal(notYet.outcome, 'PASS');
  assert.ok(notYet.statuses.includes('UNRESOLVED') && !notYet.statuses.includes('PROVIDER_REPORTED_FINALIZED'));
  const unsupported = await run(EVM, fakeEvm({ unsupportedTags: true }));
  assert.deepEqual(unsupported.providers[0].finality, { finalized: 'UNRESOLVED', safe: 'UNRESOLVED' });
  // A parent link that does not lead where it claims is an inconsistency.
  const broken = fakeEvm({ blockOverride: (hash) => (hash === base.byNumber.get(120).hash ? { ...base.byNumber.get(120), number: '0x77' } : undefined) });
  assert.deepEqual(codes(await run(EVM, broken)), ['RNLO_BLOCK_MISMATCH']);
});

test('Sepolia: oversized responses and timeouts make the provider unavailable', async () => {
  const big = await run(EVM, fakeEvm({ fail: { eth_getTransactionByHash: () => json(200, `{"jsonrpc":"2.0","id":1,"result":"${'x'.repeat(300_000)}"}`) } }));
  assert.deepEqual(codes(big), ['RNLO_RESPONSE_TOO_LARGE']);
  assert.equal(big.outcome, 'INDETERMINATE');
  const timeout = await run(EVM, fakeEvm({ fail: { eth_chainId: () => { throw Object.assign(new Error('t'), { code: 'RNLO_TIMEOUT' }); } } }));
  assert.equal(timeout.agreement, 'SOURCE_UNAVAILABLE');
});

// --- providers --------------------------------------------------------------------------------------

test('two providers: agreement, disagreement and unavailable sources', async () => {
  const a = fakeEvm();
  const b = fakeEvm({ receipt: { status: '0x0' } });
  const both = (fa, fb) => verifyLiveAnchor({
    network: EVM, transactionHash: fa.hash, expectedCommitment: COMMITMENT,
    providers: [provider('pa', EVM), provider('pb', EVM)],
    transport: (request) => (request.providerId === 'pa' ? fa : fb).transport(request),
  });
  const agree = await both(a, fakeEvm());
  assert.equal(agree.agreement, 'AGREEMENT');
  assert.ok(agree.statuses.includes('MULTI_PROVIDER_AGREEMENT'));
  assert.equal(agree.outcome, 'PASS');
  const disagree = await both(a, b);
  assert.equal(disagree.agreement, 'DISAGREEMENT');
  assert.equal(disagree.outcome, 'FAIL');
  assert.ok(codes(disagree).includes('RNLO_PROVIDER_DISAGREEMENT'));
  const seenVsNot = await both(a, fakeEvm({ notFound: true }));
  assert.equal(seenVsNot.agreement, 'DISAGREEMENT');
  const oneDown = await both(a, fakeEvm({ fail: { eth_chainId: () => json(503, 'busy') } }));
  assert.equal(oneDown.agreement, 'INSUFFICIENT_SOURCES');
  assert.equal(oneDown.outcome, 'PASS');
  assert.equal(oneDown.providers[1].error, 'RNLO_HTTP_STATUS');
});

test('retries are bounded and only for retryable failures; rate limits surface', async () => {
  let attempts = 0;
  const limited = await run(XRPL, fakeXrpl({ fail: { server_info: () => { attempts += 1; return json(429, 'slow down'); } } }));
  assert.equal(attempts, 2);
  assert.deepEqual(codes(limited), ['RNLO_RATE_LIMITED']);
  attempts = 0;
  await run(XRPL, fakeXrpl({ fail: { server_info: () => { attempts += 1; return json(400, 'no'); } } }));
  assert.equal(attempts, 1);
  attempts = 0;
  await run(XRPL, fakeXrpl({ fail: { server_info: () => { attempts += 1; return json(301, 'moved'); } } }));
  assert.equal(attempts, 1);
});

// --- strict parsing, methods, endpoints ---------------------------------------------------------------

test('strict RPC JSON: duplicate keys, malformed input, depth and fractions', () => {
  const p = (text) => parseRpcJson(new Uint8Array(Buffer.from(text)), 1000);
  assert.throws(() => p('{"a":1,"a":2}'), { code: 'RNLO_INVALID_JSON' });
  assert.throws(() => p('{"a":1} x'), { code: 'RNLO_INVALID_JSON' });
  assert.throws(() => p(`${'['.repeat(70)}${']'.repeat(70)}`), { code: 'RNLO_INVALID_JSON' });
  assert.throws(() => p('{"__proto__":1,"__proto__":2}'), { code: 'RNLO_INVALID_JSON' });
  assert.throws(() => p('"\\x41"'), { code: 'RNLO_INVALID_JSON' });
  assert.throws(() => parseRpcJson(new Uint8Array(1001), 1000), { code: 'RNLO_INVALID_JSON' });
  assert.ok(p('{"x":1.5}').x instanceof RawNumber);
  assert.ok(p('{"x":12345678901234567890}').x instanceof RawNumber);
  assert.equal(Object.getPrototypeOf(p('{"__proto__":{"polluted":1}}')), null);
});

test('a response value with no canonical form never becomes an observation', async () => {
  // A fractional fee parses (as a RawNumber) but has no canonical form, so normalization refuses it.
  const report = await run(XRPL, fakeXrpl({ tx: { tx_json: { ...fakeXrplBody(), Fee: 1.5 } } }));
  assert.equal(report.providers[0].outcome, 'INVALID_RESPONSE');
  assert.equal(report.providers[0].error, 'RNLO_INVALID_RESPONSE');
});

test('only allowlisted read-only methods can be built', () => {
  assert.deepEqual(READ_ONLY_METHODS['xrpl:testnet'], ['server_info', 'tx', 'ledger']);
  for (const method of ['submit', 'sign', 'wallet_propose', 'submit_multisigned', 'channel_authorize']) {
    assert.throws(() => requestBytes('xrpl:testnet', method, {}), TypeError, method);
  }
  for (const method of ['eth_sendRawTransaction', 'eth_sendTransaction', 'eth_sign', 'personal_sign', 'eth_signTypedData_v4', 'eth_accounts', 'eth_call', 'ETH_CHAINID', 'eth_chainId ']) {
    assert.throws(() => requestBytes('evm:11155111', method, []), TypeError, method);
  }
  assert.throws(() => requestBytes('evm:1', 'eth_chainId', []), TypeError);
});

test('endpoint configuration: https, no credentials, no addresses, no query, no unknown networks', () => {
  const cfg = (url, network = 'xrpl:testnet') => ({ format: 'rnnet.rpc-endpoints.v1', providers: [{ id: 'p', network, url, operator: 'o' }] });
  assert.equal(loadEndpointConfig(cfg('https://s.altnet.rippletest.net:51234/'))[0].origin, 'https://s.altnet.rippletest.net:51234');
  for (const url of ['http://example.org/', 'https://user:pass@example.org/', 'https://example.org/?key=1', 'https://example.org/#x', 'https://127.0.0.1/', 'https://[::1]/', 'https://localhost/', 'https://10.0.0.1/', 'HTTPS://Example.org/', 'https://example.org/v3/../x', 'file:///etc/passwd']) {
    assert.throws(() => loadEndpointConfig(cfg(url)), TypeError, url);
  }
  assert.throws(() => loadEndpointConfig(cfg('https://example.org/', 'evm:1')), TypeError);
  assert.throws(() => loadEndpointConfig({ format: 'rnnet.rpc-endpoints.v1', providers: [{ id: 'p', network: 'xrpl:testnet', url: 'https://a.org/', operator: 'o' }, { id: 'p', network: 'xrpl:testnet', url: 'https://b.org/', operator: 'o' }] }), TypeError);
});

test('providers for another network are refused before any request', async () => {
  const fake = fakeXrpl();
  await assert.rejects(() => verifyLiveAnchor({ network: XRPL, transactionHash: fake.hash, expectedCommitment: COMMITMENT, providers: [provider('p', EVM)], transport: fake.transport }), TypeError);
  assert.equal(fake.calls.length, 0);
  await assert.rejects(() => verifyLiveAnchor({ network: 'evm:1', transactionHash: fake.hash, expectedCommitment: COMMITMENT, providers: [provider('p', 'evm:1')], transport: fake.transport }), TypeError);
});

// --- capture and replay -------------------------------------------------------------------------------

test('a capture replays offline to a byte-identical report, and refuses other requests', async () => {
  const fake = fakeEvm();
  const exchanges = [];
  const live = await verifyLiveAnchor({ network: EVM, transactionHash: fake.hash, expectedCommitment: COMMITMENT, providers: [provider('pa', EVM)], transport: recordingTransport(fake.transport, exchanges) });
  const capture = checkCapture({ format: 'rnnet.rpc-capture.v1', network: EVM, transactionHash: fake.hash, providers: [{ id: 'pa', operator: 'operator of pa', origin: 'https://pa.example.org' }], exchanges });
  const replayed = await verifyLiveAnchor({ network: EVM, transactionHash: fake.hash, expectedCommitment: COMMITMENT, providers: [provider('pa', EVM)], transport: replayTransport(structuredClone(capture)) });
  assert.deepEqual(encodeLiveReport(replayed), encodeLiveReport(live));
  // Another transaction or a tampered response cannot be replayed from this capture.
  await assert.rejects(() => verifyLiveAnchor({ network: EVM, transactionHash: `0x${'9'.repeat(64)}`, expectedCommitment: COMMITMENT, providers: [provider('pa', EVM)], transport: replayTransport(structuredClone(capture)) }), ReplayMismatch);
  const tampered = structuredClone(capture);
  tampered.exchanges[1].response.body = Buffer.from('{"jsonrpc":"2.0","id":1,"result":null}').toString('base64');
  await assert.rejects(() => verifyLiveAnchor({ network: EVM, transactionHash: fake.hash, expectedCommitment: COMMITMENT, providers: [provider('pa', EVM)], transport: replayTransport(tampered) }), ReplayMismatch);
  assert.throws(() => checkCapture({ ...capture, format: 'x' }), TypeError);
});

test('the anchor payload bytes are exactly RN-NET-03A v1', () => {
  assert.equal(PAYLOAD, Buffer.from(encodeAnchorPayload(COMMITMENT)).toString('hex'));
  assert.equal(PAYLOAD.slice(0, 20), '524e4e4554414e430101');
});
