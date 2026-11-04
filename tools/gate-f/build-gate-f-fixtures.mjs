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
import { CAPTURE_FORMAT, Network, PREPARATION_REQUESTS, recordingTransport, verifyLiveAnchor } from '../../packages/chain-readonly/src/index.mjs';
import { REVIEWED_GAS_RULE_SOURCES } from '../../packages/tx-intent/src/index.mjs';
import { verifyGateFHypotheticalStageB, verifyGateFHypotheticalStageBGas } from './test-seam.mjs';
import { verifyGateF } from './verify.mjs';

export const PATH = fileURLToPath(new URL('../../fixtures/gate-f-b1/cases.json', import.meta.url));
/** WP4-B1-SEC-01: regression cases in their own file, so the merged B1 fixtures stay byte-identical. */
export const PATH_SEC01 = fileURLToPath(new URL('../../fixtures/gate-f-b1-sec01/cases.json', import.meta.url));
/** WP4-B2: the gas vectors, in their own file (the B1 and SEC-01 files stay byte-identical). */
export const PATH_B2 = fileURLToPath(new URL('../../fixtures/gate-f-b2/cases.json', import.meta.url));
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
    const b = add({ hash: h(`block-${n}`), number: q(n), parentHash: parent, timestamp: q((o.t0 ?? T0) + 12 * (n - TX_BLOCK)), transactions: n === TX_BLOCK ? [OTHER_TX, TX_HASH] : [] });
    byNumber.set(n, b);
    parent = b.hash;
  }
  let forkParent = byNumber.get(TX_BLOCK - 1).hash;
  const fork = new Map();
  for (let n = TX_BLOCK; n <= 1040; n++) {
    const b = add({ hash: h(`fork-${n}`), number: q(n), parentHash: forkParent, timestamp: q((o.t0 ?? T0) + 12 * (n - TX_BLOCK) + 1), transactions: [] });
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
  if (receipt !== null) for (const k of o.dropReceiptFields ?? []) delete receipt[k];
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

const DISAGREE_ON_BLOCK = { transaction: { blockNumber: q(TX_BLOCK + 1), blockHash: h(`block-${TX_BLOCK + 1}`) }, receipt: { blockNumber: q(TX_BLOCK + 1), blockHash: h(`block-${TX_BLOCK + 1}`) }, block: (b) => (b.number === q(TX_BLOCK + 1) ? { ...b, transactions: [OTHER_TX, TX_HASH] } : b) };
const PENDING = { receipt: null, transaction: { blockHash: null, blockNumber: null, transactionIndex: null } };
const s1Preparation = (id) => fixture('s1-preparation/cases.json').cases.find((c) => c.id === id).preparation;
const withPreparation = (i, preparation) => {
  const r = { ...INTENT, preparation };
  return { ...i, intent: canonicalize(r), approvedDigest: rawIntentDigest(r) };
};

// WP4-B1-SEC-01. R1: the provider comparison table (spec §3.3.1). R2: fixed subject rules.
export const SEC01_CASES = [
  // R1 — a missing observation: contradicted (FAIL) or not (NOT_OBSERVED).
  { id: 'r1-publicnode-not-found-1rpc-observed', chain: [{ notFound: true }, {}], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_PROVIDER_DISAGREEMENT'], null] },
  { id: 'r1-publicnode-unavailable-1rpc-finalized', chain: [{ unavailable: true }, {}], expect: ['UNRESOLVED', 'ESTABLISHED', 'NOT_ESTABLISHED', ['RNGF_RULES_AUTHORITY_ABSENT'], null] },
  { id: 'r1-both-unavailable', chain: [{ unavailable: true }, { unavailable: true }], expect: ['UNRESOLVED', 'NOT_ESTABLISHED', 'NOT_ESTABLISHED', [], null] },
  { id: 'r1-not-found-and-unavailable', chain: [{ notFound: true }, { unavailable: true }], expect: ['UNRESOLVED', 'NOT_ESTABLISHED', 'NOT_ESTABLISHED', [], null] },
  // R1 — a material difference is FAIL, including pending against included.
  { id: 'r1-pending-against-included', chain: [{}, PENDING], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_PROVIDER_DISAGREEMENT'], null] },
  // R1 — finality-only differences are decided by §3.4, never by the report's DISAGREEMENT.
  { id: 'r1-safe-walk-differs-only', chain: [{}, { safe: 1005 }], expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_RULES_AUTHORITY_ABSENT'], T0] },
  { id: 'r1-1rpc-walk-unresolved', chain: [{}, { unsupportedTags: true }], expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED_SINGLE', ['RNGF_RULES_AUTHORITY_ABSENT'], T0] },
  { id: 'r1-publicnode-walk-unresolved-1rpc-finalized', chain: [{ unsupportedTags: true }, {}], expect: ['UNRESOLVED', 'ESTABLISHED', 'NOT_ESTABLISHED', ['RNGF_RULES_AUTHORITY_ABSENT'], null] },
  // R1 — CONFLICT is always FAIL and always recorded: finalized, safe, both providers, or behind an evidence failure.
  { id: 'r1-both-providers-conflict', chain: [{ finalized: { fork: 1040 } }, { finalized: { fork: 1040 } }], expect: ['FAIL', 'ESTABLISHED', 'CONFLICT', ['RNLO_FINALITY_CONFLICT', 'RNLO_FINALITY_CONFLICT'], null] },
  // The reader walks safe only when finalized is NOT_REACHED or UNRESOLVED (a finalized IN_ANCESTRY or CONFLICT holds for safe).
  { id: 'r1-safe-conflict-publicnode-finalized-not-reached', chain: [{ finalized: 1005, safe: { fork: 1040 } }, {}], expect: ['FAIL', 'ESTABLISHED', 'NOT_ESTABLISHED', ['RNLO_FINALITY_CONFLICT'], null] },
  { id: 'r1-safe-conflict-1rpc-finalized-not-reached', chain: [{}, { finalized: 1005, safe: { fork: 1040 } }], expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED_SINGLE', ['RNLO_FINALITY_CONFLICT'], null] },
  { id: 'r1-conflict-behind-material-disagreement', chain: [{ finalized: { fork: 1040 } }, DISAGREE_ON_BLOCK], expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNLO_PROVIDER_DISAGREEMENT', 'RNLO_FINALITY_CONFLICT'], null] },
  // R2 — fixed subject rules: an approved v1 rpc-read intent is refused by both entries.
  { id: 'r2-operational-refuses-v1-rpc-read', entry: 'operational', inputs: (i) => withPreparation(i, s1Preparation('historical-sepolia-v1')), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_SUBJECT_NOT_ELIGIBLE'], null] },
  { id: 'r2-seam-refuses-v1-rpc-read', inputs: (i) => withPreparation(i, s1Preparation('historical-sepolia-v1')), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_SUBJECT_NOT_ELIGIBLE'], null] },
  { id: 'r2-operational-refuses-synthetic-with-note', entry: 'operational', inputs: (i) => withPreparation(i, s1Preparation('historical-synthetic-with-note')), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_SUBJECT_NOT_ELIGIBLE'], null] },
];

// --- WP4-B2: synthetic gas vectors (TEST ONLY) -----------------------------------------------------
// Times, by hand. A is the reviewed Sepolia amsterdamTime (WP2 table); it is restated here only as
// a test input, never read by gate F from anywhere but the WP2 table.
export const A = 1791294816;
export const DAY = 86400;
const SOURCES = REVIEWED_GAS_RULE_SOURCES.map((s) => ({ source: s.source, revision: s.revision, sha256: s.sha256 }));
export const synthReview = (tag, reviewedAt, horizon, unreviewed = []) => Object.freeze({ reviewedAt, reviewer: `TEST ONLY: synthetic WP4-B2 review ${tag}, not a recorded review`, horizon, sources: Object.freeze(SOURCES.map((s) => Object.freeze({ ...s }))), knownUnreviewedActivations: Object.freeze([...unreviewed]) });
/** R covers [.., H): reviewed at A − 6 days, horizon H = A + 24 days (30 days after the review). */
export const REVIEW = synthReview('R', A - 6 * DAY, A + 24 * DAY);
export const H = REVIEW.horizon;
/** An earlier review (October 2025, under bpo1/bpo2), for a preparation it alone covers. */
export const REVIEW_OLD = synthReview('OLD', 1761100000, 1761100000 + 30 * DAY);
/** A review that knows an unreviewed activation at A + 10 days, so its horizon stops there. */
export const REVIEW_UNREVIEWED = synthReview('U', A + DAY, A + 10 * DAY, [A + 10 * DAY]);
/** The Genesis-payload values for this 42-byte, all-non-zero calldata, by hand (spec §7). */
export const VALUES = Object.freeze({ prague: { standard: 21672, floor: 22680, need: 22680 }, amsterdam: { standard: 12672, floor: 14688, need: 14688 } });
const digestOf = (v) => `sha256:${createHash('sha256').update(Buffer.from(canonicalBytes(v))).digest('hex')}`;
const label = (s) => `sha256:${createHash('sha256').update(`rnnet:gate-f-b2-synthetic:${s}`).digest('hex')}`;

/** A synthetic rnnet.tx-preparation.v2 record the hypothetical Stage B intent would carry. */
export function v2Preparation({ ruleSetId, fork, pin, observedAt = pin + 60, review = REVIEW, values = VALUES[ruleSetId], baseFee = '0x11', code = '0x', estimate = values.need + 159 }) {
  const block = { number: q(5000), hash: h(`pin-${pin}`), timestamp: q(pin), baseFeePerGas: baseFee };
  return {
    format: 'rnnet.tx-preparation.v2',
    source: 'rpc-read',
    rules: 'ADR-RN-018-C2',
    observedAt,
    gas: { ruleSetId, fork, reviewDigest: digestOf(review), review: JSON.parse(JSON.stringify(review)), standard: values.standard, floor: values.floor, need: values.need, gasLimit: 30000 },
    providers: PROVIDERS.map((p) => ({
      id: p.id,
      operator: p.operator,
      block: { ...block },
      code,
      estimateGas: q(estimate),
      exchanges: PREPARATION_REQUESTS[Network.SEPOLIA].map((method, i) => ({ method, requestSha256: label(`${p.id}-${pin}-${i}-request`), responseSha256: label(`${p.id}-${pin}-${i}-response`) })),
    })),
  };
}
/** Prague (pinned under bpo2, 5 days before A) and Amsterdam (2 days after A) preparations under R. */
export const PREP_PRAGUE = () => v2Preparation({ ruleSetId: 'prague', fork: 'bpo2', pin: A - 5 * DAY });
export const PREP_AMSTERDAM = () => v2Preparation({ ruleSetId: 'amsterdam', fork: 'amsterdam', pin: A + 2 * DAY });
const PREP_OLD = () => v2Preparation({ ruleSetId: 'prague', fork: 'bpo1', pin: 1761200000, review: REVIEW_OLD });
const PREP_UNREVIEWED = () => v2Preparation({ ruleSetId: 'amsterdam', fork: 'amsterdam', pin: A + 2 * DAY, review: REVIEW_UNREVIEWED });
const T_PRAGUE = A - 4 * DAY;
const T_AMSTERDAM = A + 3 * DAY;
const both = (o) => [o, o];
const at = (t0, o = {}) => both({ t0, ...o });
const used = (n) => ({ receipt: { gasUsed: q(n) } });
const edit = (make, fn) => () => {
  const p = make();
  fn(p);
  return p;
};
const ALL_INVALID = (t) => ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RECORD_INVALID'], t];
const INVALID_GAS = ['GAS_RECORD_INVALID', 'NOT_EVALUATED', 'NOT_EVALUATED', null, 14688];
const NOT_EVALUATED_GAS = ['NOT_EVALUATED', 'NOT_EVALUATED', 'NOT_EVALUATED', null, null];

// gas: [record, rules, accounting, expected, gasUsed]; recordedSubject: the GAS_RECORD_INVALID subject.
export const B2_CASES = [
  // Positive (spec §7.1). The hypothetical full-contract result, through the TEST ONLY stand-in.
  { id: 'b2-p1-amsterdam-same', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM), expect: ['ELIGIBLE_FOR_FOUNDER_REVIEW', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', [], T_AMSTERDAM], gas: ['VALID', 'SAME', 'GAS_ACCOUNTED', 14688, 14688] },
  { id: 'b2-p2-prague-same', preparation: PREP_PRAGUE, chain: at(T_PRAGUE, used(22680)), expect: ['ELIGIBLE_FOR_FOUNDER_REVIEW', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', [], T_PRAGUE], gas: ['VALID', 'SAME', 'GAS_ACCOUNTED', 22680, 22680] },
  { id: 'b2-p3-prague-crossed-to-amsterdam', preparation: PREP_PRAGUE, chain: at(T_AMSTERDAM), expect: ['ELIGIBLE_FOR_FOUNDER_REVIEW', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RULES_CROSSED'], T_AMSTERDAM], gas: ['VALID', 'GAS_RULES_CROSSED', 'GAS_ACCOUNTED', 14688, 14688] },
  { id: 'b2-p10-same-rule-set-other-fork-label', preparation: PREP_OLD, history: [REVIEW_OLD], chain: at(1761700000, used(22680)), expect: ['ELIGIBLE_FOR_FOUNDER_REVIEW', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', [], 1761700000], gas: ['VALID', 'SAME', 'GAS_ACCOUNTED', 22680, 22680] },
  { id: 'b2-crossed-under-a-successor-review', preparation: PREP_OLD, history: [REVIEW_OLD, REVIEW], chain: at(T_AMSTERDAM), expect: ['ELIGIBLE_FOR_FOUNDER_REVIEW', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RULES_CROSSED'], T_AMSTERDAM], gas: ['VALID', 'GAS_RULES_CROSSED', 'GAS_ACCOUNTED', 14688, 14688] },
  { id: 'b2-p11-authority-absent', preparation: PREP_AMSTERDAM, history: [], chain: at(T_AMSTERDAM), expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_RULES_AUTHORITY_ABSENT'], T_AMSTERDAM], gas: NOT_EVALUATED_GAS },
  { id: 'b2-single-provider-accounted', preparation: PREP_AMSTERDAM, chain: [{ t0: T_AMSTERDAM }, { t0: T_AMSTERDAM, finalized: 1005 }], expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED_SINGLE', [], T_AMSTERDAM], gas: ['VALID', 'SAME', 'GAS_ACCOUNTED', 14688, 14688] },
  { id: 'b2-n32-execution-observed-accounted', preparation: PREP_AMSTERDAM, chain: [{ t0: T_AMSTERDAM, receipt: { logs: [{ address: INTENT.transaction.from, topics: [], data: '0x' }] } }, { t0: T_AMSTERDAM }], expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_EXECUTION_OBSERVED'], T_AMSTERDAM], gas: ['VALID', 'SAME', 'GAS_ACCOUNTED', 14688, 14688] },
  // Integrity of the recorded member (§4.1): GAS_RECORD_INVALID, FAIL; inclusion and finality kept.
  { id: 'b2-n1-need-changed', preparation: edit(PREP_AMSTERDAM, (p) => { p.gas.need += 1; }), recordedSubject: 'gas.need', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-n2-standard-changed', preparation: edit(PREP_AMSTERDAM, (p) => { p.gas.standard -= 1; }), recordedSubject: 'gas.standard', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-n3-floor-changed', preparation: edit(PREP_AMSTERDAM, (p) => { p.gas.floor += 16; }), recordedSubject: 'gas.floor', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-n4-gas-limit-changed', preparation: edit(PREP_AMSTERDAM, (p) => { p.gas.gasLimit = 29999; }), recordedSubject: 'gas.gasLimit', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-n5-review-digest-changed', preparation: edit(PREP_AMSTERDAM, (p) => { p.gas.reviewDigest = label('other-review'); }), recordedSubject: 'gas.reviewDigest', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-n6-review-source-digest-changed', preparation: edit(PREP_AMSTERDAM, (p) => { p.gas.review.sources[3].sha256 = label('source-3'); p.gas.reviewDigest = digestOf(p.gas.review); }), recordedSubject: 'gas.review', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-n7-unknown-rule-set', preparation: edit(PREP_AMSTERDAM, (p) => { p.gas.ruleSetId = 'glamsterdam'; }), recordedSubject: 'gas.ruleSetId', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-n8-wrong-fork', preparation: edit(PREP_AMSTERDAM, (p) => { p.gas.fork = 'osaka'; }), recordedSubject: 'gas.fork', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-n9-review-not-in-history', preparation: PREP_AMSTERDAM, history: [REVIEW_OLD], recordedSubject: 'gas.review', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-n10-future-dated-review', preparation: () => v2Preparation({ ruleSetId: 'amsterdam', fork: 'amsterdam', pin: A + 2 * DAY, review: synthReview('F', A + 2 * DAY + 3600, A + 20 * DAY) }), history: [REVIEW, synthReview('F', A + 2 * DAY + 3600, A + 20 * DAY)], recordedSubject: 'gas.review', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-n11-preparation-after-the-horizon', preparation: () => v2Preparation({ ruleSetId: 'amsterdam', fork: 'amsterdam', pin: H - 30, observedAt: H + 10 }), recordedSubject: 'gas.review', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-n12-pin-under-another-rule-set', preparation: () => v2Preparation({ ruleSetId: 'prague', fork: 'bpo2', pin: A + 2 * DAY, values: VALUES.prague }), recordedSubject: 'gas.ruleSetId', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-pin-after-observed-at', preparation: () => v2Preparation({ ruleSetId: 'amsterdam', fork: 'amsterdam', pin: A + 2 * DAY, observedAt: A + 2 * DAY - 60 }), recordedSubject: 'observedAt', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-activation-in-the-boundary-window', preparation: () => v2Preparation({ ruleSetId: 'amsterdam', fork: 'amsterdam', pin: A + 1000 }), recordedSubject: 'gas.fork', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-sender-had-code', preparation: () => v2Preparation({ ruleSetId: 'amsterdam', fork: 'amsterdam', pin: A + 2 * DAY, code: '0x60' }), recordedSubject: 'transaction', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-estimate-below-need', preparation: () => v2Preparation({ ruleSetId: 'amsterdam', fork: 'amsterdam', pin: A + 2 * DAY, estimate: 14687 }), recordedSubject: 'providers', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-fee-not-from-the-pin', preparation: () => v2Preparation({ ruleSetId: 'amsterdam', fork: 'amsterdam', pin: A + 2 * DAY, baseFee: '0x12' }), recordedSubject: 'transaction.maxFeePerGas', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-negative-need', preparation: edit(PREP_AMSTERDAM, (p) => { p.gas.need = -1; }), recordedSubject: 'gas', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-gas-member-extra-field', preparation: edit(PREP_AMSTERDAM, (p) => { p.gas.expected = 14688; }), recordedSubject: 'gas', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-providers-pin-different-blocks', preparation: edit(PREP_AMSTERDAM, (p) => { p.providers[1].block.hash = h('other-pin'); }), recordedSubject: 'providers', chain: at(T_AMSTERDAM), expect: ALL_INVALID(T_AMSTERDAM), gas: INVALID_GAS },
  { id: 'b2-integrity-before-accounting', preparation: edit(PREP_PRAGUE, (p) => { p.gas.need = 14688; }), recordedSubject: 'gas.need', chain: at(T_PRAGUE, used(14688)), expect: ALL_INVALID(T_PRAGUE), gas: INVALID_GAS },
  // §3.1 step 3: not a v2 record → not eligible (no fallback to v1, no unknown version, no candidate).
  { id: 'b2-n13-preparation-relabelled-v1', preparation: edit(PREP_AMSTERDAM, (p) => { p.format = 'rnnet.tx-preparation.v1'; }), chain: at(T_AMSTERDAM), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_SUBJECT_NOT_ELIGIBLE'], null], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n14-unknown-preparation-format', preparation: edit(PREP_AMSTERDAM, (p) => { p.format = 'rnnet.tx-preparation.v9'; }), chain: at(T_AMSTERDAM), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_SUBJECT_NOT_ELIGIBLE'], null], gas: NOT_EVALUATED_GAS },
  { id: 'b2-preparation-source-not-rpc-read', preparation: edit(PREP_AMSTERDAM, (p) => { p.source = 'synthetic'; }), chain: at(T_AMSTERDAM), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_SUBJECT_NOT_ELIGIBLE'], null], gas: NOT_EVALUATED_GAS },
  { id: 'b2-preparation-extra-member', preparation: edit(PREP_AMSTERDAM, (p) => { p.note = 'x'; }), chain: at(T_AMSTERDAM), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_SUBJECT_NOT_ELIGIBLE'], null], gas: NOT_EVALUATED_GAS },
  { id: 'b2-candidate-envelope-as-preparation', preparation: () => fixture('preparation-v2/cases.json').preparations.find((x) => x.id === 'amsterdam-pass-estimate-14847').expected.candidate, chain: at(T_AMSTERDAM), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_SUBJECT_NOT_ELIGIBLE'], null], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n39-candidate-as-intent', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM), inputs: (i) => ({ ...i, intent: canonicalize(candidate().candidate), approvedDigest: candidate().digest }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNTX_INTENT_INVALID'], null], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n15-candidate-digest-as-approval', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM), inputs: (i) => ({ ...i, approvedDigest: candidate().digest }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNTX_INTENT_DIGEST_MISMATCH'], null], gas: NOT_EVALUATED_GAS },
  // Inclusion rule set (§4.2) and boundaries (§7.3): recorded prague, A = amsterdamTime, H = R's horizon.
  { id: 'b2-boundary-a-minus-1', preparation: PREP_PRAGUE, chain: at(A - 1, used(22680)), expect: ['ELIGIBLE_FOR_FOUNDER_REVIEW', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', [], A - 1], gas: ['VALID', 'SAME', 'GAS_ACCOUNTED', 22680, 22680] },
  { id: 'b2-boundary-a', preparation: PREP_PRAGUE, chain: at(A), expect: ['ELIGIBLE_FOR_FOUNDER_REVIEW', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RULES_CROSSED'], A], gas: ['VALID', 'GAS_RULES_CROSSED', 'GAS_ACCOUNTED', 14688, 14688] },
  { id: 'b2-boundary-a-plus-1', preparation: PREP_PRAGUE, chain: at(A + 1), expect: ['ELIGIBLE_FOR_FOUNDER_REVIEW', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RULES_CROSSED'], A + 1], gas: ['VALID', 'GAS_RULES_CROSSED', 'GAS_ACCOUNTED', 14688, 14688] },
  { id: 'b2-boundary-h-minus-1', preparation: PREP_AMSTERDAM, chain: at(H - 1), expect: ['ELIGIBLE_FOR_FOUNDER_REVIEW', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', [], H - 1], gas: ['VALID', 'SAME', 'GAS_ACCOUNTED', 14688, 14688] },
  { id: 'b2-boundary-h', preparation: PREP_AMSTERDAM, chain: at(H), expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RULES_UNRESOLVED'], H], gas: ['VALID', 'GAS_RULES_UNRESOLVED', 'UNRESOLVED', null, 14688] },
  { id: 'b2-boundary-h-plus-1', preparation: PREP_AMSTERDAM, chain: at(H + 1), expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RULES_UNRESOLVED'], H + 1], gas: ['VALID', 'GAS_RULES_UNRESOLVED', 'UNRESOLVED', null, 14688] },
  { id: 'b2-n18-inclusion-before-the-table', preparation: PREP_PRAGUE, chain: at(1741159775, used(22680)), expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RULES_UNRESOLVED'], 1741159775], gas: ['VALID', 'GAS_RULES_UNRESOLVED', 'UNRESOLVED', null, 22680] },
  { id: 'b2-n19-unreviewed-activation-before-inclusion', preparation: PREP_UNREVIEWED, history: [REVIEW_UNREVIEWED], chain: at(A + 12 * DAY), expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RULES_UNRESOLVED'], A + 12 * DAY], gas: ['VALID', 'GAS_RULES_UNRESOLVED', 'UNRESOLVED', null, 14688] },
  { id: 'b2-covered-before-the-unreviewed-activation', preparation: PREP_UNREVIEWED, history: [REVIEW_UNREVIEWED], chain: at(A + 9 * DAY), expect: ['ELIGIBLE_FOR_FOUNDER_REVIEW', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', [], A + 9 * DAY], gas: ['VALID', 'SAME', 'GAS_ACCOUNTED', 14688, 14688] },
  { id: 'b2-n23-provider-fork-label-ignored', preparation: PREP_PRAGUE, chain: at(T_AMSTERDAM, { block: (b) => (b.number === q(TX_BLOCK) ? { ...b, fork: 'prague', blockAccessListHash: h('bal'), slotNumber: '0x1' } : b) }), expect: ['ELIGIBLE_FOR_FOUNDER_REVIEW', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RULES_CROSSED'], T_AMSTERDAM], gas: ['VALID', 'GAS_RULES_CROSSED', 'GAS_ACCOUNTED', 14688, 14688] },
  // Gas needs a linked t_i (§3.5): finality NOT_ESTABLISHED leaves it NOT_EVALUATED (spec N20, clarified).
  { id: 'b2-n20-finality-not-established-gas-not-evaluated', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM, { finalized: 1005 }), expect: ['UNRESOLVED', 'ESTABLISHED', 'NOT_ESTABLISHED', [], null], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n33-inclusion-not-established', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM, { notFound: true }), expect: ['UNRESOLVED', 'NOT_ESTABLISHED', 'NOT_ESTABLISHED', [], null], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n22-timestamps-contradict', preparation: PREP_AMSTERDAM, chain: [{ t0: T_AMSTERDAM }, { t0: T_AMSTERDAM + 1 }], expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_EVIDENCE_CONTRADICTORY'], null], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n21-inclusion-block-missing', preparation: PREP_AMSTERDAM, chain: [{ t0: T_AMSTERDAM, block: (b) => (b.number === q(TX_BLOCK) ? Object.fromEntries(Object.entries(b).filter(([k]) => k !== 'timestamp')) : b) }, { t0: T_AMSTERDAM }], expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_INCLUSION_TIMESTAMP_INVALID'], null], gas: NOT_EVALUATED_GAS },
  // Receipt gas evidence (§3.6): FAIL as evidence, never a rule problem.
  { id: 'b2-n25-gas-used-missing', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM, { dropReceiptFields: ['gasUsed'] }), expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_EVIDENCE_INVALID'], T_AMSTERDAM], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n26-gas-used-malformed', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM, { receipt: { gasUsed: '0xzz' } }), expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_EVIDENCE_INVALID'], T_AMSTERDAM], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n27-gas-used-not-canonical', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM, { receipt: { gasUsed: '0x03960' } }), expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_EVIDENCE_INVALID'], T_AMSTERDAM], gas: NOT_EVALUATED_GAS },
  { id: 'b2-gas-used-overflow', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM, { receipt: { gasUsed: q(2 ** 53) } }), expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_EVIDENCE_INVALID'], T_AMSTERDAM], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n28-gas-used-differs-between-providers', preparation: PREP_AMSTERDAM, chain: [{ t0: T_AMSTERDAM }, { t0: T_AMSTERDAM, ...used(14689) }], expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_EVIDENCE_CONTRADICTORY'], T_AMSTERDAM], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n28b-1rpc-gas-used-matches-the-recorded-need', preparation: PREP_PRAGUE, chain: [{ t0: T_AMSTERDAM }, { t0: T_AMSTERDAM, ...used(22680) }], expect: ['FAIL', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_EVIDENCE_CONTRADICTORY'], T_AMSTERDAM], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n29-receipt-for-another-transaction', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM, { receipt: { transactionHash: OTHER_TX } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNAE_RECEIPT_MISMATCH'], null], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n30-receipt-block-hash-differs', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM, { receipt: { blockHash: h('block-1011') } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNAE_CONFLICTING_BLOCK_REFERENCE'], null], gas: NOT_EVALUATED_GAS },
  { id: 'b2-n31-receipt-reverted', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM, { receipt: { status: '0x0' } }), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNAE_TRANSACTION_REVERTED'], null], gas: NOT_EVALUATED_GAS },
  // Numerical mismatches (§4.3): UNRESOLVED, inclusion and finality stand.
  { id: 'b2-n34-same-need-minus-1', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM, used(14687)), expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_ACCOUNTING_MISMATCH'], T_AMSTERDAM], gas: ['VALID', 'SAME', 'GAS_ACCOUNTING_MISMATCH', 14688, 14687] },
  { id: 'b2-n35-same-need-plus-1', preparation: PREP_AMSTERDAM, chain: at(T_AMSTERDAM, used(14689)), expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_ACCOUNTING_MISMATCH'], T_AMSTERDAM], gas: ['VALID', 'SAME', 'GAS_ACCOUNTING_MISMATCH', 14688, 14689] },
  { id: 'b2-n36-crossed-gas-used-is-the-recorded-need', preparation: PREP_PRAGUE, chain: at(T_AMSTERDAM, used(22680)), expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RULES_CROSSED', 'GAS_ACCOUNTING_MISMATCH'], T_AMSTERDAM], gas: ['VALID', 'GAS_RULES_CROSSED', 'GAS_ACCOUNTING_MISMATCH', 14688, 22680] },
  { id: 'b2-n37-crossed-need-minus-1', preparation: PREP_PRAGUE, chain: at(T_AMSTERDAM, used(14687)), expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RULES_CROSSED', 'GAS_ACCOUNTING_MISMATCH'], T_AMSTERDAM], gas: ['VALID', 'GAS_RULES_CROSSED', 'GAS_ACCOUNTING_MISMATCH', 14688, 14687] },
  { id: 'b2-n38-crossed-need-plus-1', preparation: PREP_PRAGUE, chain: at(T_AMSTERDAM, used(14689)), expect: ['UNRESOLVED', 'ESTABLISHED', 'PROVIDER_REPORTED_FINALIZED', ['GAS_RULES_CROSSED', 'GAS_ACCOUNTING_MISMATCH'], T_AMSTERDAM], gas: ['VALID', 'GAS_RULES_CROSSED', 'GAS_ACCOUNTING_MISMATCH', 14688, 14689] },
  // Authorization (§3.1): the operational verifier refuses the same synthetic subject, whatever its gas.
  { id: 'b2-n41-operational-refuses-the-p1-subject', entry: 'operational', preparation: PREP_AMSTERDAM, history: [], chain: at(T_AMSTERDAM), expect: ['FAIL', 'NOT_EVALUATED', 'NOT_EVALUATED', ['RNGF_SUBJECT_NOT_ELIGIBLE'], null], gas: NOT_EVALUATED_GAS },
];

export async function runCase(c) {
  const base = await baseInputs(c.chain);
  const withHistory = c.preparation ? { ...base, reviewHistory: c.history ?? [REVIEW] } : base;
  const inputs = c.inputs ? c.inputs(withHistory) : withHistory;
  let result;
  if (c.entry === 'operational') result = await verifyGateF(inputs);
  else if (c.preparation) result = await verifyGateFHypotheticalStageBGas(inputs, c.preparation());
  else result = await verifyGateFHypotheticalStageB(inputs);
  return { inputs, record: result.record, digest: result.digest };
}

export const gasOf = (record) => [record.gas.record, record.gas.rules, record.gas.accounting, record.gas.expected, record.gas.gasUsed];
const matches = (record, [disposition, inclusion, finality, codes, timestamp], c = {}) => record.disposition === disposition && record.inclusion.status === inclusion
  && record.finality.disposition === finality && JSON.stringify(record.findings.map((f) => f.code)) === JSON.stringify(codes) && record.inclusion.timestamp === timestamp
  && (c.gas === undefined || JSON.stringify(gasOf(record)) === JSON.stringify(c.gas))
  && (c.recordedSubject === undefined || record.findings.find((f) => f.code === 'GAS_RECORD_INVALID')?.subject === c.recordedSubject);

export async function build(list = CASES) {
  const cases = [];
  for (const c of list) {
    const { record, digest } = await runCase(c);
    if (!matches(record, c.expect, c)) throw new Error(`${c.id}: expected ${JSON.stringify([c.expect, c.gas ?? null, c.recordedSubject ?? null])}, got ${JSON.stringify([[record.disposition, record.inclusion.status, record.finality.disposition, record.findings.map((f) => f.code), record.inclusion.timestamp], gasOf(record), record.findings.map((f) => f.subject)])}`);
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

export const SETS = [{ path: PATH, cases: CASES }, { path: PATH_SEC01, cases: SEC01_CASES }, { path: PATH_B2, cases: B2_CASES }];

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let allCurrent = true;
  for (const { path, cases } of SETS) {
    const text = await build(cases);
    if (process.argv.includes('--write')) {
      if (existsSync(path)) {
        console.log(`${path} exists; left unchanged (remove it first to rebuild)`);
        continue;
      }
      writeFileSync(path, text, { flag: 'wx' });
      console.log(`wrote ${path}`);
    } else {
      const current = existsSync(path) && readFileSync(path, 'utf8') === text;
      allCurrent &&= current;
      console.log(`${path.slice(path.indexOf('fixtures/'))}: ${current ? 'current' : 'NOT current'}`);
    }
  }
  if (!process.argv.includes('--write')) process.exit(allCurrent ? 0 : 1);
}
