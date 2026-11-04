// Builds fixtures/gate-f-b1/cases.json: offline gate-F B1 cases (ADR-RN-020; spec
// rnnet.gate-f-sepolia-verification.v1). RN-NET-03B2-WP4-B1.
//
//   node tools/gate-f/build-gate-f-fixtures.mjs           # check the committed file is current
//   node tools/gate-f/build-gate-f-fixtures.mjs --write   # write it (refuses to overwrite)
//
// Everything is SYNTHETIC:
//   - the subject is the committed signing-b1 Sepolia intent (a synthetic preparation, a test key,
//     never submitted), standing in for a hypothetical Stage B subject through the TEST-ONLY seam;
//   - its signed bytes, txverify record and broadcast-b3 submission record are the committed
//     fixtures;
//   - the provider answers come from a simulated chain built here, read by the EXISTING reader
//     (verifyLiveAnchor) through the existing recordingTransport, so each capture and report is a
//     genuine rnnet.rpc-capture.v1 / live-report pair;
//   - no request reaches any network: the provider origins only name the reviewed providers.
// Each case states its expected outcome BY HAND. The committed file holds each case's expected record
// and digest only; the captures are regenerated deterministically here, and the record's evidence
// digests bind them.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalBytes, canonicalize } from '../../packages/canonical/src/index.mjs';
import { CAPTURE_FORMAT, recordingTransport, verifyLiveAnchor } from '../../packages/chain-readonly/src/index.mjs';
import { verifyGateFHypotheticalStageB } from './test-seam.mjs';
import { verifyGateF } from './verify.mjs';

export const PATH = fileURLToPath(new URL('../../fixtures/gate-f-b1/cases.json', import.meta.url));
export const FIXTURES_FORMAT = 'rnnet.gate-f-b1-fixtures.v1';
const fixture = (p) => JSON.parse(readFileSync(new URL(`../../fixtures/${p}`, import.meta.url), 'utf8'));

// The committed subject and its artifacts.
const golden = fixture('signing-b1/golden.json').signed.sepolia;
export const INTENT = fixture('signing-b1/sepolia-intent.json');
export const INTENT_TEXT = canonicalize(INTENT);
const b3 = fixture('broadcast-b3/cases.json');
export const SUBMISSION = b3.submit.find((c) => c.id === 'sepolia-accepted').expected.record;
const STATUS = b3.statusChecks.find((c) => c.inputs.intent.includes('"network":"evm:11155111"')).expected.record;
const TX_HASH = golden.transactionHash;

const PROVIDERS = [
  { id: 'sepolia-publicnode', network: 'evm:11155111', url: 'https://ethereum-sepolia-rpc.publicnode.com/', operator: 'PublicNode' },
  { id: 'sepolia-1rpc', network: 'evm:11155111', url: 'https://public.1rpc.io/sepolia', operator: 'Automata 1RPC' },
];
const origin = (url) => new URL(url).origin;

// --- the simulated chain -------------------------------------------------------------------------
const h = (label) => `0x${createHash('sha256').update(`rnnet:gate-f-b1-synthetic:${label}`).digest('hex')}`;
const q = (n) => `0x${BigInt(n).toString(16)}`;
export const T0 = 1_793_500_000; // synthetic, after amsterdamTime (WP4-B2 uses it); B1 only reads it
const TX_BLOCK = 1010;
const TX_INDEX = 1;
const OTHER_TX = h('other-transaction');

/** One simulated Sepolia provider. `o` alters its answers. Returns a transport. */
function chain(o = {}) {
  const blocks = new Map();
  const byNumber = new Map();
  const add = (b) => {
    blocks.set(b.hash, b);
    return b;
  };
  let parent = h('parent-999');
  for (let n = 1000; n <= 1400; n++) {
    const b = add({ hash: h(`block-${n}`), number: q(n), parentHash: parent, timestamp: q(T0 + 12 * (n - TX_BLOCK)), transactions: n === TX_BLOCK ? [OTHER_TX, TX_HASH] : [] });
    byNumber.set(n, b);
    parent = b.hash;
  }
  let forkParent = byNumber.get(TX_BLOCK - 1).hash;
  const fork = new Map();
  for (let n = TX_BLOCK; n <= 1040; n++) {
    const b = add({ hash: h(`fork-${n}`), number: q(n), parentHash: forkParent, timestamp: q(T0 + 12 * (n - TX_BLOCK) + 1), transactions: [] });
    fork.set(n, b);
    forkParent = b.hash;
  }
  const included = byNumber.get(TX_BLOCK);
  const t = INTENT.transaction;
  const transaction = {
    hash: TX_HASH, type: t.type, chainId: t.chainId, nonce: t.nonce, from: t.from, to: t.to, value: t.value, input: t.input, gas: t.gas,
    maxFeePerGas: t.maxFeePerGas, maxPriorityFeePerGas: t.maxPriorityFeePerGas, accessList: t.accessList,
    blockHash: included.hash, blockNumber: included.number, transactionIndex: q(TX_INDEX), yParity: '0x0', v: '0x0', r: h('r'), s: h('s'),
    ...o.transaction,
  };
  for (const k of o.dropTransactionFields ?? []) delete transaction[k];
  const receipt = o.receipt === null ? null : {
    transactionHash: TX_HASH, blockHash: transaction.blockHash, blockNumber: transaction.blockNumber, transactionIndex: transaction.transactionIndex,
    from: t.from, to: t.to, status: '0x1', contractAddress: null, logs: [], gasUsed: '0x3960', cumulativeGasUsed: '0x3960', effectiveGasPrice: '0x3b9aca00', type: '0x2', ...o.receipt,
  };
  const head = (tag) => {
    const sel = o[tag] ?? (tag === 'finalized' ? 1040 : 1050);
    if (sel === null) return null;
    if (typeof sel === 'object') return fork.get(sel.fork);
    return byNumber.get(sel);
  };
  return async (request) => {
    const { method, params } = JSON.parse(Buffer.from(request.body).toString('utf8'));
    const answer = (result) => ({ status: 200, body: new Uint8Array(Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result }))) });
    if (o.unavailable) throw Object.assign(new Error('synthetic timeout'), { code: 'RNLO_TIMEOUT' });
    if (method === 'eth_chainId') return answer(o.chainId ?? '0xaa36a7');
    if (method === 'eth_getTransactionByHash') return answer(o.notFound ? null : transaction);
    if (method === 'eth_getTransactionReceipt') return answer(o.notFound ? null : receipt);
    if (method === 'eth_getBlockByHash') {
      let b = blocks.get(params[0]) ?? null;
      if (b && o.block) b = o.block(b) ?? b;
      return answer(b);
    }
    if (method === 'eth_getBlockByNumber') {
      if (o.unsupportedTags) return { status: 200, body: new Uint8Array(Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32602, message: 'unknown block tag' } }))) };
      return answer(head(params[0]));
    }
    throw new Error(`unexpected method ${method}`);
  };
}

/** Reads both providers through the existing reader, recording a genuine capture and report. */
async function acquire(opts = [{}, {}]) {
  const servers = { [PROVIDERS[0].id]: chain(opts[0]), [PROVIDERS[1].id]: chain(opts[1]) };
  const exchanges = [];
  const transport = recordingTransport(async (request) => servers[request.providerId](request), exchanges);
  const report = await verifyLiveAnchor({ network: 'evm:11155111', transactionHash: TX_HASH, expectedCommitment: INTENT.commitment, providers: PROVIDERS, transport });
  const capture = {
    format: CAPTURE_FORMAT,
    network: 'evm:11155111',
    transactionHash: TX_HASH,
    providers: PROVIDERS.map((p) => ({ id: p.id, operator: p.operator, origin: origin(p.url) })),
    retrieval: { startedAt: '2026-11-04T00:00:00Z', finishedAt: '2026-11-04T00:00:01Z', tool: 'tools/gate-f/build-gate-f-fixtures.mjs (SYNTHETIC)' },
    exchanges,
  };
  return { capture, liveReport: Buffer.from(canonicalBytes(report)).toString('utf8') };
}

export const baseInputs = async (opts) => ({
  intent: INTENT_TEXT,
  approvedDigest: golden.intentDigest,
  signedTransaction: golden.signedTransaction,
  txverifyRecord: golden.verification,
  submissionRecord: SUBMISSION,
  ...(await acquire(opts)),
  reviewHistory: [],
  preliminaryStatus: null,
  supersedes: null,
});

const flipLastHex = (s) => s.slice(0, -1) + (s.at(-1) === '0' ? '1' : '0');
const candidate = () => fixture('preparation-v2/cases.json').preparations.find((c) => c.id === 'amsterdam-pass-estimate-14847').expected;
const rawIntentDigest = (v) => `sha256:${createHash('sha256').update('rnnet:unsigned-tx-intent:v1\0').update(Buffer.from(canonicalBytes(v))).digest('hex')}`;

// expect: [disposition, inclusion.status, finality.disposition, [finding codes], timestamp?]
// `entry`: 'seam' (hypothetical Stage B) or 'operational'.
export const CASES = [
  // Positive structure (still UNRESOLVED: B1 evaluates no gas).
  { id: 'both-finalized', expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_RULES_AUTHORITY_ABSENT'], T0] },
  { id: 'both-finalized-with-review-history', inputs: (i) => ({ ...i, reviewHistory: [{ synthetic: 'TEST ONLY review placeholder; B1 does not read it' }] }), expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', [], T0] },
  { id: 'finalized-at-the-transaction-block', chain: [{ finalized: TX_BLOCK }, { finalized: TX_BLOCK }], expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_RULES_AUTHORITY_ABSENT'], T0] },
  { id: 'walk-255-steps', chain: [{ finalized: TX_BLOCK + 255 }, { finalized: TX_BLOCK + 255 }], expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_RULES_AUTHORITY_ABSENT'], T0] },
  { id: 'walk-256-steps', chain: [{ finalized: TX_BLOCK + 256 }, { finalized: TX_BLOCK + 256 }], expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_RULES_AUTHORITY_ABSENT'], T0] },
  { id: 'preliminary-status-included', inputs: (i) => ({ ...i, preliminaryStatus: STATUS }), expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_RULES_AUTHORITY_ABSENT'], T0] },
  // Finality outcomes.
  { id: 'publicnode-conflict', chain: [{ finalized: { fork: 1040 } }, {}], expect: ['FAIL', 'ESTABLISHED', 'CONFLICT', ['RNLO_FINALITY_CONFLICT'], null] },
  { id: '1rpc-conflict-publicnode-finalized', chain: [{}, { finalized: { fork: 1040 } }], expect: ['FAIL', 'ESTABLISHED', 'CONFLICT', ['RNLO_FINALITY_CONFLICT'], null] },
  { id: '1rpc-not-reached', chain: [{}, { finalized: 1005 }], expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED_SINGLE', ['RNGF_RULES_AUTHORITY_ABSENT'], T0] },
  { id: '1rpc-unavailable', chain: [{}, { unavailable: true }], expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED_SINGLE', ['RNGF_RULES_AUTHORITY_ABSENT'], T0] },
  { id: 'neither-finalized', chain: [{ finalized: 1005 }, { finalized: 1005 }], expect: ['UNRESOLVED', 'ESTABLISHED', 'NOT_ESTABLISHED', ['RNGF_RULES_AUTHORITY_ABSENT'], null] },
  { id: 'publicnode-not-reached-1rpc-finalized', chain: [{ finalized: 1005 }, {}], expect: ['UNRESOLVED', 'ESTABLISHED', 'NOT_ESTABLISHED', ['RNGF_RULES_AUTHORITY_ABSENT'], null] },
  { id: 'walk-beyond-depth', chain: [{ finalized: TX_BLOCK + 257 }, { finalized: TX_BLOCK + 257 }], expect: ['UNRESOLVED', 'ESTABLISHED', 'NOT_ESTABLISHED', ['RNGF_RULES_AUTHORITY_ABSENT'], null] },
  { id: 'tags-unsupported', chain: [{ unsupportedTags: true }, { unsupportedTags: true }], expect: ['UNRESOLVED', 'ESTABLISHED', 'NOT_ESTABLISHED', ['RNGF_RULES_AUTHORITY_ABSENT'], null] },
  // Inclusion.
  { id: 'not-found', chain: [{ notFound: true }, { notFound: true }], expect: ['UNRESOLVED', 'NOT_ESTABLISHED', 'NOT_ESTABLISHED', [], null] },
  { id: 'pending', chain: [{ receipt: null, transaction: { blockHash: null, blockNumber: null, transactionIndex: null } }, { receipt: null, transaction: { blockHash: null, blockNumber: null, transactionIndex: null } }], expect: ['UNRESOLVED', 'NOT_ESTABLISHED', 'NOT_ESTABLISHED', [], null] },
  { id: 'wrong-transaction-at-index', chain: [{ block: (b) => (b.number === q(TX_BLOCK) ? { ...b, transactions: [OTHER_TX, OTHER_TX] } : b) }, {}], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_BLOCK_MISMATCH'], null] },
  { id: 'wrong-transaction-index', chain: [{ transaction: { transactionIndex: '0x0' }, receipt: { transactionIndex: '0x0' } }, { transaction: { transactionIndex: '0x0' }, receipt: { transactionIndex: '0x0' } }], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_BLOCK_MISMATCH'], null] },
  { id: 'wrong-block-hash', chain: [{ transaction: { blockHash: h('block-1011') }, receipt: { blockHash: h('block-1011') } }, {}], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_BLOCK_MISMATCH'], null] },
  { id: 'invalid-parent-hash', chain: [{ block: (b) => (b.number === q(1030) ? { ...b, parentHash: h('nowhere') } : b) }, {}], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_BLOCK_MISMATCH'], null] },
  { id: 'providers-disagree-on-block', chain: [{}, { transaction: { blockNumber: q(TX_BLOCK + 1), blockHash: h(`block-${TX_BLOCK + 1}`) }, receipt: { blockNumber: q(TX_BLOCK + 1), blockHash: h(`block-${TX_BLOCK + 1}`) }, block: (b) => (b.number === q(TX_BLOCK + 1) ? { ...b, transactions: [OTHER_TX, TX_HASH] } : b) }], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_PROVIDER_DISAGREEMENT'], null] },
  { id: 'one-provider-not-found', chain: [{}, { notFound: true }], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_PROVIDER_DISAGREEMENT'], null] },
  { id: 'wrong-chain', chain: [{ chainId: '0x1' }, {}], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_WRONG_NETWORK'], null] },
  { id: 'wrong-commitment-in-transaction', chain: [{ transaction: { input: `${INTENT.transaction.input.slice(0, -2)}00` } }, { transaction: { input: `${INTENT.transaction.input.slice(0, -2)}00` } }], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNAP_COMMITMENT_MISMATCH'], null] },
  { id: 'reverted', chain: [{ receipt: { status: '0x0' } }, { receipt: { status: '0x0' } }], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNAE_TRANSACTION_REVERTED'], null] },
  // The inclusion timestamp.
  { id: 'timestamps-contradict', chain: [{}, { block: (b) => (b.number === q(TX_BLOCK) ? { ...b, timestamp: q(T0 + 1) } : b) }], expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_EVIDENCE_CONTRADICTORY'], null] },
  { id: 'timestamp-missing', chain: [{ block: (b) => (b.number === q(TX_BLOCK) ? Object.fromEntries(Object.entries(b).filter(([k]) => k !== 'timestamp')) : b) }, {}], expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_INCLUSION_TIMESTAMP_INVALID'], null] },
  { id: 'timestamp-malformed', chain: [{ block: (b) => (b.number === q(TX_BLOCK) ? { ...b, timestamp: '0x0abc' } : b) }, {}], expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_INCLUSION_TIMESTAMP_INVALID'], null] },
  { id: 'timestamp-out-of-range', chain: [{ block: (b) => (b.number === q(TX_BLOCK) ? { ...b, timestamp: q(2 ** 40) } : b) }, { block: (b) => (b.number === q(TX_BLOCK) ? { ...b, timestamp: q(2 ** 40) } : b) }], expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_INCLUSION_TIMESTAMP_INVALID'], null] },
  // Provider transaction binding.
  { id: 'provider-max-fee-differs', chain: [{ transaction: { maxFeePerGas: '0x1' } }, { transaction: { maxFeePerGas: '0x1' } }], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_BINDING_MISMATCH'], null] },
  { id: 'provider-missing-max-fee', chain: [{ dropTransactionFields: ['maxFeePerGas'] }, { dropTransactionFields: ['maxFeePerGas'] }], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_EVIDENCE_INVALID'], null] },
  { id: 'receipt-logs', chain: [{ receipt: { logs: [{ address: INTENT.transaction.from, topics: [], data: '0x' }] } }, {}], expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_EXECUTION_OBSERVED', 'RNGF_RULES_AUTHORITY_ABSENT'], T0] },
  // Subject and binding.
  { id: 'operational-refuses-every-subject', entry: 'operational', expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_SUBJECT_NOT_ELIGIBLE'], null] },
  { id: 'candidate-as-intent', inputs: (i) => ({ ...i, intent: canonicalize(candidate().candidate), approvedDigest: candidate().digest }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNTX_INTENT_INVALID'], null] },
  { id: 'candidate-relabelled-as-intent', inputs: (i) => { const r = { ...candidate().candidate, format: 'rnnet.unsigned-tx-intent.v1' }; return { ...i, intent: canonicalize(r), approvedDigest: rawIntentDigest(r) }; }, expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNTX_INTENT_INVALID'], null] },
  { id: 'unknown-preparation-version', inputs: (i) => { const r = { ...INTENT, preparation: { format: 'rnnet.tx-preparation.v9' } }; return { ...i, intent: canonicalize(r), approvedDigest: rawIntentDigest(r) }; }, expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNTX_INTENT_INVALID'], null] },
  { id: 'intent-not-canonical', inputs: (i) => ({ ...i, intent: JSON.stringify(INTENT, null, 1) }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNTX_INTENT_INVALID'], null] },
  { id: 'approved-digest-differs', inputs: (i) => ({ ...i, approvedDigest: `sha256:${'5'.repeat(64)}` }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNTX_INTENT_DIGEST_MISMATCH'], null] },
  { id: 'signed-bytes-modified', inputs: (i) => ({ ...i, signedTransaction: flipLastHex(i.signedTransaction) }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNTX_SENDER_MISMATCH'], null] },
  { id: 'candidate-digest-as-approval', inputs: (i) => ({ ...i, approvedDigest: candidate().digest }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNTX_INTENT_DIGEST_MISMATCH'], null] },
  { id: 'signature-s-equals-curve-order', inputs: (i) => ({ ...i, signedTransaction: `${i.signedTransaction.slice(0, -64)}fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141` }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNTX_SIGNATURE_INVALID'], null] },
  { id: 'txverify-record-differs', inputs: (i) => ({ ...i, txverifyRecord: { ...i.txverifyRecord, blobSha256: `sha256:${'6'.repeat(64)}` } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_BINDING_MISMATCH'], null] },
  { id: 'txverify-record-fail-claimed-pass', inputs: (i) => ({ ...i, signedTransaction: flipLastHex(i.signedTransaction), txverifyRecord: i.txverifyRecord }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNTX_SENDER_MISMATCH'], null] },
  { id: 'submission-intent-differs', inputs: (i) => ({ ...i, submissionRecord: { ...i.submissionRecord, intentDigest: `sha256:${'7'.repeat(64)}` } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_BINDING_MISMATCH'], null] },
  { id: 'submission-dry-run', inputs: (i) => ({ ...i, submissionRecord: { ...i.submissionRecord, dryRun: true } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_BINDING_MISMATCH'], null] },
  { id: 'submission-not-sent', inputs: (i) => ({ ...i, submissionRecord: { ...i.submissionRecord, outcome: 'NOT_SENT' } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_BINDING_MISMATCH'], null] },
  // Capture and replay.
  { id: 'capture-transaction-hash-differs', inputs: (i) => ({ ...i, capture: { ...i.capture, transactionHash: flipLastHex(i.capture.transactionHash) } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_EVIDENCE_INVALID'], null] },
  { id: 'capture-format-unknown', inputs: (i) => ({ ...i, capture: { ...i.capture, format: 'rnnet.rpc-capture.v2' } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_EVIDENCE_INVALID'], null] },
  { id: 'capture-provider-unreviewed', inputs: (i) => ({ ...i, capture: { ...i.capture, providers: i.capture.providers.map((p, k) => (k === 1 ? { ...p, id: 'sepolia-other' } : p)), exchanges: i.capture.exchanges.map((e) => (e.providerId === 'sepolia-1rpc' ? { ...e, providerId: 'sepolia-other' } : e)) } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_EVIDENCE_INVALID'], null] },
  { id: 'capture-providers-swapped', inputs: (i) => ({ ...i, capture: { ...i.capture, providers: [...i.capture.providers].reverse() } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_EVIDENCE_INVALID'], null] },
  { id: 'capture-response-digest-differs', inputs: (i) => ({ ...i, capture: { ...i.capture, exchanges: i.capture.exchanges.map((e, k) => (k === 1 ? { ...e, response: { ...e.response, sha256: `sha256:${'8'.repeat(64)}` } } : e)) } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_REPLAY_MISMATCH'], null] },
  { id: 'capture-exchanges-reordered', inputs: (i) => { const x = [...i.capture.exchanges]; [x[1], x[2]] = [x[2], x[1]]; return { ...i, capture: { ...i.capture, exchanges: x } }; }, expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_REPLAY_MISMATCH'], null] },
  { id: 'capture-response-reassigned', inputs: (i) => { const x = i.capture.exchanges.map((e) => ({ ...e })); [x[1].response, x[2].response] = [x[2].response, x[1].response]; return { ...i, capture: { ...i.capture, exchanges: x } }; }, expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_REPLAY_MISMATCH'], null] },
  { id: 'capture-exchange-moved-to-other-provider', inputs: (i) => ({ ...i, capture: { ...i.capture, exchanges: i.capture.exchanges.map((e, k) => (k === 0 ? { ...e, providerId: 'sepolia-1rpc' } : e)) } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_REPLAY_MISMATCH'], null] },
  { id: 'capture-exchange-left-over', inputs: (i) => ({ ...i, capture: { ...i.capture, exchanges: [...i.capture.exchanges, i.capture.exchanges[0]] } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_REPLAY_MISMATCH'], null] },
  { id: 'live-report-differs', inputs: (i) => ({ ...i, liveReport: i.liveReport.replace('"agreement":"AGREEMENT"', '"agreement":"INSUFFICIENT_SOURCES"') }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_EVIDENCE_INVALID'], null] },
];

export async function runCase(c) {
  const inputs = c.inputs ? c.inputs(await baseInputs(c.chain)) : await baseInputs(c.chain);
  const { record, digest } = await (c.entry === 'operational' ? verifyGateF(inputs) : verifyGateFHypotheticalStageB(inputs));
  return { inputs, record, digest };
}

const matches = (record, [disposition, inclusion, finality, codes, timestamp]) => record.disposition === disposition && record.inclusion.status === inclusion
  && record.finality.disposition === finality && JSON.stringify(record.findings.map((f) => f.code)) === JSON.stringify(codes) && record.inclusion.timestamp === timestamp;

export async function build() {
  const cases = [];
  for (const c of CASES) {
    const { record, digest } = await runCase(c);
    if (!matches(record, c.expect)) throw new Error(`${c.id}: expected ${JSON.stringify(c.expect)}, got ${JSON.stringify([record.disposition, record.inclusion.status, record.finality.disposition, record.findings.map((f) => f.code), record.inclusion.timestamp])}`);
    // Inputs are regenerated deterministically by this builder; the record names each by digest.
    cases.push({ id: c.id, entry: c.entry ?? 'seam', expected: { record, digest } });
  }
  const doc = {
    format: FIXTURES_FORMAT,
    status: 'SYNTHETIC: simulated providers and made-up blocks; the subject is the signing-b1 test intent standing in for a hypothetical Stage B subject (TEST ONLY); never read from or sent to a network',
    cases,
  };
  return `${Buffer.from(canonicalBytes(doc)).toString('utf8')}\n`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = await build();
  if (process.argv.includes('--write')) {
    if (existsSync(PATH)) throw new Error(`${PATH} exists; remove it first to rebuild`);
    writeFileSync(PATH, text, { flag: 'wx' });
    console.log(`wrote ${PATH}`);
  } else {
    const current = existsSync(PATH) && readFileSync(PATH, 'utf8') === text;
    console.log(current ? 'gate-F B1 fixtures: current' : 'gate-F B1 fixtures: NOT current');
    process.exit(current ? 0 : 1);
  }
}
