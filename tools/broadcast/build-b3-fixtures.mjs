// Builds fixtures/broadcast-b3/cases.json: synthetic broadcaster runs for RN-NET-03B2-B3, each
// with its hand-stated outcome and code (design §8).
//
//   node tools/broadcast/build-b3-fixtures.mjs           # check the committed file is current
//   node tools/broadcast/build-b3-fixtures.mjs --write   # write it (refuses to overwrite)
//
// Everything is synthetic and offline. Every run goes to simulated providers on
// `*.fixture.invalid` hosts through an injected transport; nothing here was, or can be, sent to a
// network. The signed transactions are the B1 fixtures (fixtures/signing-b1) and two replacement
// transactions signed here with the same label-derived test keys, which anyone can recompute and
// which must never be funded. The broadcaster itself never sees a key.
//
// Each case records its inputs, the log before the run, every exchange (request text and response
// or transport error), and the expected result: outcome, code, request and write counts, the
// submission record and the log entries the run appended. tools/broadcast.test.mjs replays every
// case through tools/submit/; tools/reference/rnnet_broadcast_reference.py reproduces every case
// without the JavaScript code.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, parse } from '../../packages/canonical/src/index.mjs';
import { entryDigest } from '../../packages/chain-submit/src/index.mjs';
import { intentDigest } from '../../packages/tx-intent/src/index.mjs';
import { createSigner } from '../../signer/src/sign.mjs';
import { fixtureKey } from '../../signer/test/fixture-keys.mjs';
import { runBroadcast } from '../submit/broadcaster.mjs';
import { appendEntry, readLog } from '../submit/store.mjs';
import { runStatusCheck } from '../submit/status.mjs';
import { verifySignedTransaction } from '../../txverify/src/index.mjs';
import {
  ENDPOINTS,
  NOW,
  sepoliaBroadcastServer,
  sepoliaErrorReply,
  sepoliaSendReply,
  simulatedTransport,
  transportError,
  xrplBroadcastServer,
  xrplEngine,
  xrplIncludedTx,
  xrplSubmitReply,
} from './simulated.mjs';

export const FILE = fileURLToPath(new URL('../../fixtures/broadcast-b3/cases.json', import.meta.url));
const B1 = fileURLToPath(new URL('../../fixtures/signing-b1/', import.meta.url));
const SCOPE = 'Synthetic RN-NET-03B2-B3 fixture. Simulated providers only; never submitted to any network.';
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

// --- intents and signed transactions -------------------------------------------------------------

function material() {
  const golden = JSON.parse(readFileSync(`${B1}golden.json`, 'utf8'));
  const load = (name) => JSON.parse(readFileSync(B1 + golden.signed[name].intentFile, 'utf8'));
  const tx = {};
  for (const name of ['xrpl', 'sepolia']) {
    const intent = load(name);
    tx[name] = { intent, text: canonicalize(intent), digest: golden.signed[name].intentDigest, signed: golden.signed[name].signedTransaction, blobSha256: golden.signed[name].blobSha256, hash: golden.signed[name].transactionHash, record: golden.signed[name].verification };
  }
  // Replacements: new gate-D bytes for the same Sequence or nonce (made-up values).
  const replace = (name, edit, label) => {
    const intent = JSON.parse(JSON.stringify(tx[name].intent));
    edit(intent.transaction);
    intent.preparation = { note: 'RN-NET-03B2-B3 fixture: a replacement for the same Sequence or nonce; never submitted', source: 'synthetic' };
    const digest = intentDigest(intent);
    const signed = createSigner().sign(intent, digest, fixtureKey(intent.network, label));
    return { intent, text: canonicalize(intent), digest, signed: signed.signedTransaction, blobSha256: signed.blobSha256, hash: signed.transactionHash, record: signed.verification };
  };
  tx.xrplReplacement = replace('xrpl', (t) => { t.LastLedgerSequence = 1_000_040; }, 'rn-net-03b2b1-xrpl-1');
  tx.sepoliaReplacement = replace('sepolia', (t) => { t.maxFeePerGas = '0x3b9aca44'; }, 'rn-net-03b2b1-sepolia-1');
  return { golden, tx };
}

function authorization(t, overrides = {}) {
  const xrpl = t.intent.network === 'xrpl:testnet';
  return {
    format: 'rnnet.broadcast-authorization.v1',
    authorizationId: 'fixture',
    network: t.intent.network,
    providerId: xrpl ? 'fixture-xrpl-a' : 'fixture-sepolia-a',
    attempt: 1,
    previousAttempt: null,
    kind: 'first',
    sender: xrpl ? t.intent.transaction.Account : t.intent.transaction.from,
    sequence: xrpl ? String(t.intent.transaction.Sequence) : String(BigInt(t.intent.transaction.nonce)),
    intentDigest: t.digest,
    blobSha256: t.blobSha256,
    transactionHash: t.hash,
    validity: xrpl ? { lastLedgerSequence: t.intent.transaction.LastLedgerSequence } : { notAfter: '2026-11-01T01:00:00Z' },
    dryRun: false,
    scope: SCOPE,
    ...overrides,
  };
}

// --- running one case ---------------------------------------------------------------------------

function privateDirs() {
  const root = mkdtempSync(join(tmpdir(), 'rnnet-b3-'));
  chmodSync(root, 0o700);
  const logDir = join(root, 'log');
  const evidenceDir = join(root, 'evidence');
  mkdirSync(logDir, { mode: 0o700 });
  mkdirSync(evidenceDir, { mode: 0o700 });
  return { root, logDir, evidenceDir };
}

/** Writes `log` into a fresh private log directory and runs `fn(dirs)`; returns { result, log }. */
export async function withLog(log, fn) {
  const dirs = privateDirs();
  try {
    for (const entry of log) appendEntry(dirs.logDir, entry);
    const result = await fn(dirs);
    return { result, log: readLog(dirs.logDir) };
  } finally {
    rmSync(dirs.root, { recursive: true, force: true });
  }
}

const INTENT_INVALID_RECORD = Object.freeze({ format: 'rnnet.signed-tx-verification.v1', network: null, intentDigest: null, blobSha256: null, transactionHash: null, outcome: 'FAIL', code: 'RNTX_INTENT_INVALID' });

/** The record the Python reference gives for these inputs: non-canonical intent text is invalid. */
function referenceRecordOf(inputs) {
  let value;
  try {
    value = parse(inputs.intent);
    if (canonicalize(value) !== inputs.intent) return INTENT_INVALID_RECORD;
  } catch {
    return INTENT_INVALID_RECORD;
  }
  return verifySignedTransaction({ intent: value, approvedDigest: inputs.approvedDigest, signedTransaction: inputs.signedTransaction });
}

async function submitCase(c, state) {
  const exchanges = [];
  const before = c.after ? (c.logEdit ?? ((l) => l))(state.logs.get(c.after)) : [];
  const inputs = { intent: c.t.text, approvedDigest: c.t.digest, signedTransaction: c.t.signed, authorization: `${canonicalize(c.auth)}\n`, ...c.inputs };
  const referenceRecord = c.referenceRecord ?? referenceRecordOf(inputs);
  // The clock may advance by a fixed step per request, so validity can lapse during the reads.
  const step = c.clockStep ?? 0;
  const inner = simulatedTransport(c.servers ?? {}, exchanges);
  const environment = {
    endpoints: ENDPOINTS, now: () => (c.now ?? NOW) + step * exchanges.length, referenceVerifier: () => JSON.parse(JSON.stringify(referenceRecord)),
    transport: inner, ...c.environment,
  };
  const { result, log } = await withLog(before, (dirs) => runBroadcast({ inputs, environment: { ...environment, logDir: dirs.logDir, evidenceDir: dirs.evidenceDir, ...c.dirs?.(dirs) } }));
  if (result.outcome !== c.expect[0] || result.code !== c.expect[1]) throw new Error(`${c.id}: expected ${c.expect.join(' ')}, got ${result.outcome} ${result.code}`);
  state.logs.set(c.id, log);
  return {
    id: c.id,
    inputs,
    referenceRecord,
    referenceTampered: c.referenceRecord !== undefined,
    environmentExtra: c.environment ?? null,
    clockStepPerRequest: step,
    now: c.now ?? NOW,
    logBefore: before,
    exchanges,
    expected: { outcome: result.outcome, code: result.code, requests: result.requests, writes: result.writes, record: result.record, recordDigest: result.recordDigest, appended: log.slice(before.length) },
  };
}

async function statusCase(c, state) {
  const exchanges = [];
  const before = state.logs.get(c.after);
  const attempt = before.filter((e) => e.kind === 'ATTEMPTING').at(-1);
  const auth = {
    format: 'rnnet.status-authorization.v1', authorizationId: c.id, network: attempt.network,
    providerIds: attempt.network === 'xrpl:testnet' ? ['fixture-xrpl-a', 'fixture-xrpl-b'] : ['fixture-sepolia-a', 'fixture-sepolia-b'],
    attemptEntry: c.attemptEntry ?? entryDigest(attempt), sender: attempt.sender, sequence: attempt.sequence, transactionHash: attempt.transactionHash, scope: SCOPE, ...c.auth,
  };
  const inputs = { authorization: `${canonicalize(auth)}\n`, intent: c.t.text };
  const environment = { endpoints: ENDPOINTS, now: () => NOW + 600, transport: simulatedTransport(c.servers, exchanges) };
  const { result, log } = await withLog(before, (dirs) => runStatusCheck({ inputs, environment: { ...environment, logDir: dirs.logDir, evidenceDir: dirs.evidenceDir } }));
  if (result.finding !== c.expect[0] || result.code !== c.expect[1]) throw new Error(`${c.id}: expected ${c.expect.join(' ')}, got ${result.finding} ${result.code}`);
  state.logs.set(c.id, log);
  return {
    id: c.id,
    inputs,
    now: NOW + 600,
    logBefore: before,
    exchanges,
    expected: { finding: result.finding, code: result.code, record: result.record, recordDigest: result.recordDigest, appended: log.slice(before.length) },
  };
}

// --- the cases ------------------------------------------------------------------------------------

function cases(m) {
  const { tx } = m;
  const X = tx.xrpl;
  const S = tx.sepolia;
  const xs = (opts = {}, b = {}) => ({ 'fixture-xrpl-a': xrplBroadcastServer({ submit: () => xrplSubmitReply(X.signed, X.hash), ...opts }), 'fixture-xrpl-b': xrplBroadcastServer(b) });
  const xsub = (fn) => xs({ submit: fn });
  const engine = (e, code, flags) => xsub(() => xrplSubmitReply(X.signed, X.hash, xrplEngine(e, code, flags)));
  const ss = (opts = {}, b = {}) => ({ 'fixture-sepolia-a': sepoliaBroadcastServer({ send: () => sepoliaSendReply(S.hash), ...opts }), 'fixture-sepolia-b': sepoliaBroadcastServer(b) });
  const NS = 'NOT_SENT';
  const AP = 'ACCEPTED_PROVISIONAL';
  const UN = 'UNCERTAIN';
  const RJ = 'REJECTED';
  const list = [];
  const xcase = (id, expect, o = {}) => list.push({ ...o, kind: 'submit', id, t: o.t ?? X, auth: authorization(o.t ?? X, { authorizationId: o.authId ?? id, ...o.auth }), servers: o.servers ?? xs(), expect });
  const scase = (id, expect, o = {}) => list.push({ ...o, kind: 'submit', id, t: o.t ?? S, auth: authorization(o.t ?? S, { authorizationId: o.authId ?? id, ...o.auth }), servers: o.servers ?? ss(), expect });
  const status = (id, after, expect, o) => list.push({ ...o, kind: 'status', id, after, expect });

  // XRPL: the write and its classification.
  xcase('xrpl-accepted', [AP, 'RNBC_ACCEPTED']);
  xcase('xrpl-dry-run', [NS, 'RNBC_DRY_RUN'], { auth: { dryRun: true } });
  xcase('xrpl-ter-queued', [UN, 'RNBC_UNCERTAIN_ENGINE_RESULT'], { servers: engine('terQUEUED', -89, { accepted: true, queued: true, kept: true }) });
  xcase('xrpl-tec', [UN, 'RNBC_UNCERTAIN_ENGINE_RESULT'], { servers: engine('tecINSUFF_FEE', 136, { accepted: true, applied: true, broadcast: true }) });
  xcase('xrpl-tem', [RJ, 'RNBC_REJECTED'], { servers: engine('temBAD_FEE', -298) });
  xcase('xrpl-tel-insuf-fee', [RJ, 'RNBC_REJECTED'], { servers: engine('telINSUF_FEE_P', -394) });
  xcase('xrpl-tel-can-not-queue', [RJ, 'RNBC_REJECTED'], { servers: engine('telCAN_NOT_QUEUE', -392) });
  xcase('xrpl-ter-pre-seq', [RJ, 'RNBC_REJECTED'], { servers: engine('terPRE_SEQ', -92) });
  xcase('xrpl-tef-max-ledger', [RJ, 'RNBC_REJECTED'], { servers: engine('tefMAX_LEDGER', -186) });
  xcase('xrpl-tef-already', [UN, 'RNBC_UNCERTAIN_ENGINE_RESULT'], { servers: engine('tefALREADY', -198) });
  xcase('xrpl-tef-past-seq', [UN, 'RNBC_UNCERTAIN_ENGINE_RESULT'], { servers: engine('tefPAST_SEQ', -190) });
  xcase('xrpl-accepted-false', [UN, 'RNBC_UNCERTAIN_FLAGS'], { servers: xsub(() => xrplSubmitReply(X.signed, X.hash, (r) => { r.accepted = false; })) });
  xcase('xrpl-broadcast-false', [UN, 'RNBC_UNCERTAIN_FLAGS'], { servers: xsub(() => xrplSubmitReply(X.signed, X.hash, (r) => { r.broadcast = false; })) });
  xcase('xrpl-queued-with-success', [UN, 'RNBC_UNCERTAIN_FLAGS'], { servers: xsub(() => xrplSubmitReply(X.signed, X.hash, (r) => { r.queued = true; })) });
  xcase('xrpl-rejected-but-kept', [UN, 'RNBC_UNCERTAIN_FLAGS'], { servers: engine('temBAD_FEE', -298, { kept: true }) });
  xcase('xrpl-flags-missing', [UN, 'RNBC_UNCERTAIN_FLAGS'], { servers: xsub(() => xrplSubmitReply(X.signed, X.hash, (r) => { delete r.kept; })) });
  xcase('xrpl-hash-differs', [UN, 'RNBC_UNCERTAIN_HASH_MISMATCH'], { servers: xsub(() => xrplSubmitReply(X.signed, 'A'.repeat(64))) });
  xcase('xrpl-blob-differs', [UN, 'RNBC_UNCERTAIN_BLOB_MISMATCH'], { servers: xsub(() => xrplSubmitReply(X.signed.toLowerCase(), X.hash)) });
  xcase('xrpl-engine-code-inconsistent', [UN, 'RNBC_UNCERTAIN_RESPONSE'], { servers: xsub(() => xrplSubmitReply(X.signed, X.hash, (r) => { r.engine_result_code = -298; })) });
  xcase('xrpl-engine-result-missing', [UN, 'RNBC_UNCERTAIN_RESPONSE'], { servers: xsub(() => xrplSubmitReply(X.signed, X.hash, (r) => { delete r.engine_result; })) });
  xcase('xrpl-rpc-error', [UN, 'RNBC_UNCERTAIN_RPC_ERROR'], { servers: xsub(() => ({ status: 200, body: new Uint8Array(Buffer.from('{"result":{"error":"invalidTransaction","error_exception":"fails local checks","status":"error"}}')) })) });
  xcase('xrpl-http-500', [UN, 'RNBC_UNCERTAIN_HTTP_STATUS'], { servers: xsub(() => ({ status: 500, body: new Uint8Array(Buffer.from('internal error')) })) });
  xcase('xrpl-http-429', [UN, 'RNBC_UNCERTAIN_HTTP_STATUS'], { servers: xsub(() => ({ status: 429, body: new Uint8Array(Buffer.from('slow down')) })) });
  xcase('xrpl-write-timeout', [UN, 'RNBC_UNCERTAIN_TRANSPORT'], { servers: xsub(transportError('RNLO_TIMEOUT')) });
  xcase('xrpl-write-connection-lost', [UN, 'RNBC_UNCERTAIN_TRANSPORT'], { servers: xsub(transportError('RNLO_CONNECTION')) });
  xcase('xrpl-write-redirect', [UN, 'RNBC_UNCERTAIN_TRANSPORT'], { servers: xsub(transportError('RNLO_REDIRECT')) });
  xcase('xrpl-write-too-large', [UN, 'RNBC_UNCERTAIN_TRANSPORT'], { servers: xsub(transportError('RNLO_RESPONSE_TOO_LARGE')) });
  xcase('xrpl-write-blocked-address', [NS, 'RNBC_NOT_SENT_BLOCKED_ADDRESS'], { servers: xsub(transportError('RNLO_BLOCKED_ADDRESS')) });
  xcase('xrpl-write-invalid-json', [UN, 'RNBC_UNCERTAIN_RESPONSE'], { servers: xsub(() => ({ status: 200, body: new Uint8Array(Buffer.from('{"result":')) })) });
  xcase('xrpl-write-duplicate-key', [UN, 'RNBC_UNCERTAIN_RESPONSE'], { servers: xsub(() => ({ status: 200, body: new Uint8Array(Buffer.from(Buffer.from(xrplSubmitReply(X.signed, X.hash).body).toString().replace('"status":"success"', '"status":"success","status":"success"'))) })) });

  // XRPL: pre-submit reads.
  xcase('xrpl-read-wrong-network', [NS, 'RNLO_WRONG_NETWORK'], { servers: xs({}, { info: (i) => { i.network_id = 0; } }) });
  xcase('xrpl-read-network-unknown', [NS, 'RNLO_NETWORK_UNKNOWN'], { servers: xs({ info: (i) => { delete i.network_id; } }) });
  xcase('xrpl-read-sequence-moved', [NS, 'RNBC_PRESUBMIT_SEQUENCE'], { servers: xs({ sequence: 1_000_002 }) });
  xcase('xrpl-read-account-not-validated', [NS, 'RNBC_PRESUBMIT_ACCOUNT'], { servers: xs({}, { account: (r) => { r.validated = false; } }) });
  xcase('xrpl-read-ledger-margin', [NS, 'RNBC_AUTHORIZATION_EXPIRED'], { servers: xs({}, { seq: 1_000_016 }) });
  xcase('xrpl-read-already-known', [NS, 'RNBC_PRESUBMIT_ALREADY_KNOWN'], { servers: xs({}, { included: xrplIncludedTx(X.intent, X.hash, 1_000_005) }) });
  xcase('xrpl-read-timeout', [NS, 'RNLO_TIMEOUT'], { servers: xs({ raw: { server_info: transportError('RNLO_TIMEOUT') } }) });
  xcase('xrpl-read-invalid-json', [NS, 'RNLO_INVALID_JSON'], { servers: xs({}, { raw: { account_info: () => ({ status: 200, body: new Uint8Array(Buffer.from('{"result":{"status":"success","status":"success"}}')) }) } }) });
  xcase('xrpl-read-http-503', [NS, 'RNLO_HTTP_STATUS'], { servers: xs({ raw: { server_info: () => ({ status: 503, body: new Uint8Array(Buffer.from('unavailable')) }) } }) });
  xcase('xrpl-read-redirect', [NS, 'RNLO_REDIRECT'], { servers: xs({}, { raw: { server_info: transportError('RNLO_REDIRECT') } }) });
  xcase('xrpl-read-too-large', [NS, 'RNLO_RESPONSE_TOO_LARGE'], { servers: xs({ raw: { tx: transportError('RNLO_RESPONSE_TOO_LARGE') } }) });
  xcase('xrpl-read-account-not-found', [NS, 'RNLO_RPC_ERROR'], { servers: xs({ raw: { account_info: () => ({ status: 200, body: new Uint8Array(Buffer.from('{"result":{"error":"actNotFound","status":"error"}}')) }) } }) });

  // XRPL: inputs and the authorization.
  for (const name of ['secret', 'seed', 'seed_hex', 'passphrase', 'key_type', 'keyFile', 'privateKey', 'tx_json']) {
    xcase(`xrpl-input-${name.replace('_', '-').toLowerCase()}`, [NS, 'RNBC_INPUT_INVALID'], { inputs: { [name]: 'not-a-key-synthetic-fixture-value' } });
  }
  xcase('xrpl-environment-extra', [NS, 'RNBC_INPUT_INVALID'], { environment: { keyFile: '/tmp/key' } });
  xcase('xrpl-authorization-not-canonical', [NS, 'RNBC_AUTHORIZATION_INVALID'], { inputs: { authorization: ` ${canonicalize(authorization(X, { authorizationId: 'xrpl-authorization-not-canonical' }))}` } });
  xcase('xrpl-authorization-extra-field', [NS, 'RNBC_AUTHORIZATION_INVALID'], { auth: { secret: 'x' } });
  xcase('xrpl-authorization-kind-first-attempt-2', [NS, 'RNBC_AUTHORIZATION_INVALID'], { auth: { attempt: 2 } });
  xcase('xrpl-authorization-sepolia-validity', [NS, 'RNBC_AUTHORIZATION_INVALID'], { auth: { validity: { notAfter: '2026-11-01T01:00:00Z' } } });
  xcase('xrpl-authorization-blob-differs', [NS, 'RNBC_AUTHORIZATION_MISMATCH'], { auth: { blobSha256: tx.xrplReplacement.blobSha256 } });
  xcase('xrpl-authorization-intent-differs', [NS, 'RNBC_AUTHORIZATION_MISMATCH'], { auth: { intentDigest: tx.xrplReplacement.digest } });
  xcase('xrpl-authorization-hash-differs', [NS, 'RNBC_AUTHORIZATION_MISMATCH'], { auth: { transactionHash: tx.xrplReplacement.hash } });
  xcase('xrpl-authorization-sequence-differs', [NS, 'RNBC_AUTHORIZATION_MISMATCH'], { auth: { sequence: '1000002' } });
  xcase('xrpl-authorization-sender-differs', [NS, 'RNBC_AUTHORIZATION_MISMATCH'], { auth: { sender: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh' } });
  xcase('xrpl-authorization-last-ledger-differs', [NS, 'RNBC_AUTHORIZATION_MISMATCH'], { auth: { validity: { lastLedgerSequence: 1_000_040 } } });
  xcase('xrpl-provider-unknown', [NS, 'RNBC_PROVIDER_NOT_ALLOWED'], { auth: { providerId: 'fixture-xrpl-c' } });
  xcase('xrpl-provider-other-network', [NS, 'RNBC_PROVIDER_NOT_ALLOWED'], { auth: { providerId: 'fixture-sepolia-a' } });
  xcase('xrpl-digest-not-approved', [NS, 'RNTX_INTENT_DIGEST_MISMATCH'], { inputs: { approvedDigest: tx.xrplReplacement.digest } });
  xcase('xrpl-intent-not-canonical', [NS, 'RNTX_INTENT_INVALID'], { inputs: { intent: `${X.text}\n` } });
  xcase('xrpl-supplied-record-other-bytes', [NS, 'RNBC_SUPPLIED_RECORD_MISMATCH'], { inputs: { verificationRecords: [tx.xrplReplacement.record] } });
  xcase('xrpl-supplied-records-differ', [NS, 'RNBC_SUPPLIED_RECORD_MISMATCH'], { inputs: { verificationRecords: [X.record, { ...X.record, transactionHash: 'B'.repeat(64) }] } });
  xcase('xrpl-supplied-records-agree', [AP, 'RNBC_ACCEPTED'], { inputs: { verificationRecords: [X.record, X.record] } });
  xcase('xrpl-supplied-too-many-records', [NS, 'RNBC_INPUT_INVALID'], { inputs: { verificationRecords: [X.record, X.record, X.record] } });
  xcase('xrpl-python-disagrees', [NS, 'RNBC_VERIFIER_DISAGREEMENT'], { referenceRecord: { ...X.record, outcome: 'FAIL', code: 'RNTX_SIGNATURE_INVALID' } });
  xcase('xrpl-supplied-pass-for-bad-bytes', [NS, 'RNTX_SIGNATURE_INVALID'], {
    inputs: { signedTransaction: m.golden.negative.find((n) => n.id === 'xrpl-signature-bit-flip').signedTransaction, verificationRecords: [X.record, X.record] },
  });

  // XRPL: the log.
  xcase('xrpl-authorization-reused', [NS, 'RNBC_AUTHORIZATION_USED'], { after: 'xrpl-accepted', authId: 'xrpl-accepted' });
  xcase('xrpl-dry-run-reused', [NS, 'RNBC_AUTHORIZATION_USED'], { after: 'xrpl-dry-run', authId: 'xrpl-dry-run', auth: { dryRun: true } });
  xcase('xrpl-first-after-attempt', [NS, 'RNBC_LOG_ATTEMPT_NUMBER'], { after: 'xrpl-tel-insuf-fee' });
  xcase('xrpl-resend-after-rejected', [AP, 'RNBC_ACCEPTED'], { after: 'xrpl-tel-insuf-fee', linkTo: 'latest', auth: { attempt: 2, kind: 'resend' } });
  xcase('xrpl-resend-wrong-link', [NS, 'RNBC_LOG_LINK_MISMATCH'], { after: 'xrpl-tel-insuf-fee', linkTo: 'attempting', auth: { attempt: 2, kind: 'resend' } });
  xcase('xrpl-resend-skips-attempt', [NS, 'RNBC_LOG_ATTEMPT_NUMBER'], { after: 'xrpl-tel-insuf-fee', linkTo: 'latest', auth: { attempt: 3, kind: 'resend' } });
  xcase('xrpl-resend-after-uncertain', [NS, 'RNBC_LOG_CASE_NOT_PERMITTED'], { after: 'xrpl-write-timeout', linkTo: 'latest', auth: { attempt: 2, kind: 'resend' } });
  xcase('xrpl-resend-after-accepted', [NS, 'RNBC_LOG_CASE_NOT_PERMITTED'], { after: 'xrpl-accepted', linkTo: 'latest', auth: { attempt: 2, kind: 'resend' } });
  xcase('xrpl-resend-after-blocked', [AP, 'RNBC_ACCEPTED'], { after: 'xrpl-write-blocked-address', linkTo: 'latest', auth: { attempt: 2, kind: 'resend' } });
  xcase('xrpl-replacement-without-resolution', [NS, 'RNBC_LOG_CASE_NOT_PERMITTED'], { t: tx.xrplReplacement, after: 'xrpl-tel-insuf-fee', linkTo: 'latest', auth: { attempt: 2, kind: 'replacement' } });
  xcase('xrpl-after-crash', [NS, 'RNBC_LOG_UNRESOLVED_ATTEMPT'], { after: 'xrpl-accepted', logEdit: (l) => l.filter((e) => e.kind !== 'RESULT'), linkTo: 'attempting', auth: { attempt: 2, kind: 'resend' } });
  xcase('xrpl-log-tampered', [NS, 'RNBC_LOG_INVALID'], { after: 'xrpl-accepted', logEdit: (l) => l.filter((e) => e.kind !== 'ATTEMPTING').map((e, index) => ({ ...e, index })) });

  // XRPL: status checks, and what they permit.
  const xIncluded = () => ({ 'fixture-xrpl-a': xrplBroadcastServer({ included: xrplIncludedTx(X.intent, X.hash, 1_000_012) }), 'fixture-xrpl-b': xrplBroadcastServer({ included: xrplIncludedTx(X.intent, X.hash, 1_000_012) }) });
  const xExpired = (a = {}, b = {}) => ({ 'fixture-xrpl-a': xrplBroadcastServer({ seq: 1_000_025, ...a }), 'fixture-xrpl-b': xrplBroadcastServer({ seq: 1_000_025, ...b }) });
  status('status-xrpl-included', 'xrpl-accepted', ['INCLUDED', null], { t: X, servers: xIncluded() });
  status('status-xrpl-expired-after-crash', 'xrpl-after-crash', ['EXPIRED', null], { t: X, servers: xExpired() });
  status('status-xrpl-not-searched-all', 'xrpl-write-timeout', ['UNRESOLVED', 'RNBC_STATUS_UNRESOLVED'], { t: X, servers: xExpired({}, { searchedAll: false }) });
  status('status-xrpl-sequence-used', 'xrpl-write-timeout', ['UNRESOLVED', 'RNBC_STATUS_UNRESOLVED'], { t: X, servers: xExpired({ sequenceAt: 1_000_002 }) });
  status('status-xrpl-not-past-last-ledger', 'xrpl-write-timeout', ['UNRESOLVED', 'RNBC_STATUS_UNRESOLVED'], { t: X, servers: xExpired({ seq: 1_000_015 }, { seq: 1_000_015 }) });
  status('status-xrpl-unknown-attempt', 'xrpl-write-timeout', [null, 'RNBC_STATUS_MISMATCH'], { t: X, servers: xIncluded(), attemptEntry: `sha256:${'0'.repeat(64)}` });
  status('status-xrpl-wrong-intent', 'xrpl-write-timeout', [null, 'RNBC_STATUS_MISMATCH'], { t: tx.xrplReplacement, servers: xIncluded() });
  xcase('xrpl-after-included', [NS, 'RNBC_LOG_ALREADY_INCLUDED'], { after: 'status-xrpl-included', linkTo: 'latest', auth: { attempt: 2, kind: 'resend' } });
  xcase('xrpl-replacement-after-expired', [AP, 'RNBC_ACCEPTED'], {
    t: tx.xrplReplacement, after: 'status-xrpl-expired-after-crash', linkTo: 'latest', auth: { attempt: 2, kind: 'replacement' },
    servers: xs({ submit: () => xrplSubmitReply(tx.xrplReplacement.signed, tx.xrplReplacement.hash) }),
  });
  xcase('xrpl-resend-after-expired', [NS, 'RNBC_LOG_CASE_NOT_PERMITTED'], { after: 'status-xrpl-expired-after-crash', linkTo: 'latest', auth: { attempt: 2, kind: 'resend' } });
  xcase('xrpl-after-unresolved-status', [NS, 'RNBC_LOG_CASE_NOT_PERMITTED'], { after: 'status-xrpl-not-searched-all', linkTo: 'latest', auth: { attempt: 2, kind: 'resend' } });

  // Sepolia: the write.
  scase('sepolia-accepted', [AP, 'RNBC_ACCEPTED']);
  scase('sepolia-dry-run', [NS, 'RNBC_DRY_RUN'], { auth: { dryRun: true } });
  scase('sepolia-error-already-known', [UN, 'RNBC_UNCERTAIN_RPC_ERROR'], { servers: ss({ send: () => sepoliaErrorReply(-32000, 'already known') }) });
  scase('sepolia-error-nonce-too-low', [UN, 'RNBC_UNCERTAIN_RPC_ERROR'], { servers: ss({ send: () => sepoliaErrorReply(-32000, 'nonce too low') }) });
  scase('sepolia-error-underpriced', [UN, 'RNBC_UNCERTAIN_RPC_ERROR'], { servers: ss({ send: () => sepoliaErrorReply(-32000, 'replacement transaction underpriced') }) });
  scase('sepolia-hash-differs', [UN, 'RNBC_UNCERTAIN_HASH_MISMATCH'], { servers: ss({ send: () => sepoliaSendReply(tx.sepoliaReplacement.hash) }) });
  scase('sepolia-hash-upper-case', [UN, 'RNBC_UNCERTAIN_HASH_MISMATCH'], { servers: ss({ send: () => sepoliaSendReply(`0x${S.hash.slice(2).toUpperCase()}`) }) });
  scase('sepolia-result-and-error', [UN, 'RNBC_UNCERTAIN_RESPONSE'], { servers: ss({ send: () => ({ status: 200, body: new Uint8Array(Buffer.from(`{"jsonrpc":"2.0","id":1,"result":"${S.hash}","error":{"code":-32000,"message":"x"}}`)) }) }) });
  scase('sepolia-wrong-id', [UN, 'RNBC_UNCERTAIN_RESPONSE'], { servers: ss({ send: () => ({ status: 200, body: new Uint8Array(Buffer.from(`{"jsonrpc":"2.0","id":2,"result":"${S.hash}"}`)) }) }) });
  scase('sepolia-http-502', [UN, 'RNBC_UNCERTAIN_HTTP_STATUS'], { servers: ss({ send: () => ({ status: 502, body: new Uint8Array(Buffer.from('bad gateway')) }) }) });
  scase('sepolia-write-connection-lost', [UN, 'RNBC_UNCERTAIN_TRANSPORT'], { servers: ss({ send: transportError('RNLO_CONNECTION') }) });
  scase('sepolia-write-blocked-address', [NS, 'RNBC_NOT_SENT_BLOCKED_ADDRESS'], { servers: ss({ send: transportError('RNLO_BLOCKED_ADDRESS') }) });

  // Sepolia: pre-submit reads and validity.
  scase('sepolia-read-wrong-chain', [NS, 'RNLO_WRONG_NETWORK'], { servers: ss({}, { chainId: '0x1' }) });
  scase('sepolia-read-nonce-latest', [NS, 'RNBC_PRESUBMIT_NONCE'], { servers: ss({ nonce: '0x1', pending: '0x0' }) });
  scase('sepolia-read-nonce-pending', [NS, 'RNBC_PRESUBMIT_NONCE'], { servers: ss({}, { pending: '0x1' }) });
  scase('sepolia-read-already-known', [NS, 'RNBC_PRESUBMIT_ALREADY_KNOWN'], { servers: ss({}, { known: { hash: S.hash, blockHash: null } }) });
  scase('sepolia-read-base-fee', [NS, 'RNBC_PRESUBMIT_BASE_FEE'], { servers: ss({ baseFee: '0x23' }) });
  scase('sepolia-read-balance', [NS, 'RNBC_PRESUBMIT_BALANCE'], { servers: ss({}, { balance: '0x1b48eb57e000' }) });
  scase('sepolia-read-malformed-quantity', [NS, 'RNLO_INVALID_RESPONSE'], { servers: ss({ balance: '0x01' }) });
  scase('sepolia-read-rpc-error', [NS, 'RNLO_RPC_ERROR'], { servers: ss({ raw: { eth_getBalance: () => sepoliaErrorReply(-32603, 'internal') } }) });
  scase('sepolia-authorization-expired', [NS, 'RNBC_AUTHORIZATION_EXPIRED'], { now: NOW + 3601 });
  // notAfter is NOW + 3600: starting 60 s before it, 10 s per request, it passes during the 12 reads.
  scase('sepolia-authorization-expires-during-reads', [NS, 'RNBC_AUTHORIZATION_EXPIRED'], { now: NOW + 3540, clockStep: 10 });
  scase('sepolia-authorization-valid-through-reads', [AP, 'RNBC_ACCEPTED'], { now: NOW + 3540, clockStep: 4 });
  scase('sepolia-authorization-bad-time', [NS, 'RNBC_AUTHORIZATION_INVALID'], { auth: { validity: { notAfter: '2026-02-30T00:00:00Z' } } });
  scase('sepolia-provider-other-network', [NS, 'RNBC_PROVIDER_NOT_ALLOWED'], { auth: { providerId: 'fixture-xrpl-a' } });
  scase('sepolia-python-disagrees', [NS, 'RNBC_VERIFIER_DISAGREEMENT'], { referenceRecord: { ...S.record, transactionHash: tx.sepoliaReplacement.hash } });

  // Sepolia: status checks and replacement.
  const chain = (finalizedA, finalizedB) => ({
    'fixture-sepolia-a': sepoliaBroadcastServer({ chain: { txHash: S.hash, from: S.intent.transaction.from, input: S.intent.transaction.input, block: 9_437_190, finalized: finalizedA } }),
    'fixture-sepolia-b': sepoliaBroadcastServer({ chain: { txHash: S.hash, from: S.intent.transaction.from, input: S.intent.transaction.input, block: 9_437_190, finalized: finalizedB } }),
  });
  status('status-sepolia-included', 'sepolia-accepted', ['INCLUDED', null], { t: S, servers: chain(9_437_192, 9_437_192) });
  status('status-sepolia-one-provider-lags', 'sepolia-accepted', ['UNRESOLVED', 'RNBC_STATUS_UNRESOLVED'], { t: S, servers: chain(9_437_192, 9_437_189) });
  status('status-sepolia-pending', 'sepolia-error-already-known', ['PENDING', null], { t: S, servers: ss() });
  status('status-sepolia-nonce-used', 'sepolia-error-already-known', ['UNRESOLVED', 'RNBC_STATUS_UNRESOLVED'], { t: S, servers: ss({}, { nonce: '0x1' }) });
  scase('sepolia-replacement-after-pending', [AP, 'RNBC_ACCEPTED'], {
    t: tx.sepoliaReplacement, after: 'status-sepolia-pending', linkTo: 'latest', auth: { attempt: 2, kind: 'replacement' },
    servers: ss({ send: () => sepoliaSendReply(tx.sepoliaReplacement.hash) }),
  });
  scase('sepolia-resend-after-pending', [AP, 'RNBC_ACCEPTED'], { after: 'status-sepolia-pending', linkTo: 'latest', auth: { attempt: 2, kind: 'resend' } });
  scase('sepolia-replacement-reuses-blob', [NS, 'RNBC_LOG_CASE_NOT_PERMITTED'], { after: 'status-sepolia-pending', linkTo: 'latest', auth: { attempt: 2, kind: 'replacement' } });
  scase('sepolia-after-included', [NS, 'RNBC_LOG_ALREADY_INCLUDED'], { after: 'status-sepolia-included', linkTo: 'latest', auth: { attempt: 2, kind: 'resend' } });

  // Bytes: every altered transaction of the B1 corpus, refused before any read or write.
  for (const n of m.golden.negative) {
    let text;
    try {
      text = canonicalize(n.intent);
    } catch {
      continue; // an intent with no canonical text cannot be given to the broadcaster as text
    }
    const base = n.intent.network === 'xrpl:testnet' ? X : S;
    list.push({
      kind: 'submit', id: `bytes-${n.id}`, t: base, auth: authorization(base, { authorizationId: `bytes-${n.id}` }), servers: {},
      inputs: { intent: text, approvedDigest: n.approvedDigest, signedTransaction: n.signedTransaction }, expect: [NS, n.expectedCode],
    });
  }
  return list;
}

/** Fills `previousAttempt` from the log a case runs after. */
function link(c, state) {
  if (!c.linkTo) return;
  const log = (c.logEdit ?? ((l) => l))(state.logs.get(c.after));
  const pick = c.linkTo === 'latest' ? log.filter((e) => e.kind === 'RESULT' || e.kind === 'RESOLVED').at(-1) : log.filter((e) => e.kind === 'ATTEMPTING').at(-1);
  c.auth = { ...c.auth, previousAttempt: entryDigest(pick) };
}

export async function build() {
  const m = material();
  const state = { logs: new Map() };
  const out = { format: 'rnnet.broadcast-b3-fixtures.v1', status: 'SYNTHETIC: simulated providers only; nothing here was, or can be, submitted to a network', endpoints: ENDPOINTS, submit: [], statusChecks: [] };
  for (const c of cases(m)) {
    if (c.kind === 'status') {
      out.statusChecks.push(await statusCase(c, state));
      continue;
    }
    link(c, state);
    if (!c.inputs?.authorization) c.inputs = { ...c.inputs, authorization: `${canonicalize(c.auth)}\n` };
    out.submit.push(await submitCase(c, state));
  }
  return Buffer.from(`${canonicalize(out)}\n`, 'utf8');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const built = await build();
  if (process.argv.includes('--write')) {
    mkdirSync(new URL('../../fixtures/broadcast-b3/', import.meta.url), { recursive: true });
    writeFileSync(FILE, built, { flag: 'wx' });
    console.log(`wrote ${FILE} (${built.length} bytes, sha256 ${sha(built)})`);
  } else {
    if (!existsSync(FILE) || !readFileSync(FILE).equals(built)) {
      console.error('stale or missing: fixtures/broadcast-b3/cases.json');
      process.exit(1);
    }
    console.log('broadcast-b3 fixtures are current');
  }
}
