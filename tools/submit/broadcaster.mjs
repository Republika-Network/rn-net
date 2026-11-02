// The keyless broadcaster's run (RN-NET-03B2-B3, ADR-RN-019; spec/rnnet.broadcast.v1.md §9).
//
// OFFLINE ONLY IN B3. This is a library: it has no command line, and it never constructs a
// network transport. The transport is injected by its caller, and in this repository the only
// callers are tests and the fixture generator, which inject simulated providers. The guard
// (tools/guards/dependency-boundaries.mjs) refuses any file that joins chain-submit to the
// network transport in tools/live/; a live entry point needs ADR-RN-019 gate E and its own review.
//
// The broadcaster is keyless: it receives no key, key file, seed or passphrase (an input it does
// not know is refused), it imports nothing from signer/, and it can only pass the received
// bytes through unchanged, or refuse. It sends at most one write per authorization.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalize, parse } from '../../packages/canonical/src/index.mjs';
import { checkHandoff } from '../../packages/broadcast-handoff/src/index.mjs';
import { call, JsonError, loadEndpointConfig, parseRpcJson, ReadError, recordingTransport, TRANSPORT_CODES } from '../../packages/chain-readonly/src/index.mjs';
import {
  BroadcastCode as C,
  BroadcastError,
  checkAuthorizationMatch,
  checkLog,
  checkUnused,
  classifySubmitResponse,
  decideAttempt,
  entryDigest,
  EntryKind,
  makeEntry,
  Outcome,
  readAuthorization,
  sepoliaAuthorizationExpired,
  SUBMIT_LIMITS,
  submissionRecord,
  submissionRecordDigest,
  submitRequestBytes,
  SubmitNetwork,
  xrplAuthorizationExpired,
} from '../../packages/chain-submit/src/index.mjs';
import {
  approvedIntent,
  decodeXrplTx,
  IntentNetwork,
  intentSender,
  intentSequence,
  TxError,
} from '../../packages/tx-intent/src/index.mjs';
import { CanonicalError } from '../../packages/canonical/src/index.mjs';
import { verifySepoliaSignature, verifySignedTransaction, verifyXrplSignature } from '../../txverify/src/index.mjs';
import { appendEntry, checkPrivateDirectory, createRunDirectory, readLog, storedText, writeNewFile } from './store.mjs';

/** The only inputs a run accepts (ADR-RN-019 §2); verificationRecords is optional. */
export const INPUT_FIELDS = Object.freeze(['approvedDigest', 'authorization', 'intent', 'signedTransaction', 'verificationRecords']);
const REQUIRED_INPUTS = ['approvedDigest', 'authorization', 'intent', 'signedTransaction'];
export const ENVIRONMENT_FIELDS = Object.freeze(['endpoints', 'evidenceDir', 'logDir', 'now', 'referenceVerifier', 'transport']);
/** Pre-submit read requests per provider (ADR-RN-019 §6): XRPL 3, Sepolia 6; two providers each. */
export const PRESUBMIT_REQUESTS = Object.freeze({ [SubmitNetwork.XRPL_TESTNET]: 3, [SubmitNetwork.SEPOLIA]: 6 });
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const isoTime = (seconds) => new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const sameRecord = (a, b) => {
  try {
    return canonicalize(a) === canonicalize(b);
  } catch {
    return false;
  }
};

/** A gate that lets exactly one write through per run; a second is refused by the harness. */
export function createWriteGate() {
  let used = false;
  return Object.freeze({
    send(fn) {
      if (used) throw new BroadcastError(C.NOT_SENT_HARNESS, 'a second write in one run');
      used = true;
      return fn();
    },
    get used() {
      return used;
    },
  });
}

/**
 * Runs one broadcast. Never throws for a refusal: it returns
 * { outcome, code, record, recordDigest, requests, writes, runDirectory }.
 * @param {{ inputs: object, environment: object }} run
 */
export async function runBroadcast({ inputs, environment } = {}) {
  const counters = { requests: 0, writes: 0 };
  const state = { counters, authorizationDigest: null, authorization: null, runDirectory: null, exchanges: [], providers: [] };
  const finish = (outcome, code, extra = {}) => finishRun(state, environment, outcome, code, extra);
  try {
    return await execute(state, inputs, environment, finish);
  } catch (error) {
    if (error instanceof BroadcastError || error instanceof TxError || error instanceof ReadError) return finish(Outcome.NOT_SENT, error.code);
    throw error;
  }
}

async function execute(state, inputs, environment, finish) {
  // 1. Inputs: exactly the known ones. A key, seed, passphrase or key file is never an input.
  const exact = (value, fields, required) =>
    value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every((k) => fields.includes(k)) && required.every((k) => Object.hasOwn(value, k));
  if (!exact(inputs, INPUT_FIELDS, REQUIRED_INPUTS) || !exact(environment, ENVIRONMENT_FIELDS, ENVIRONMENT_FIELDS)) return finish(Outcome.NOT_SENT, C.INPUT_INVALID);
  const supplied = inputs.verificationRecords ?? [];
  if (!Array.isArray(supplied) || supplied.length > 2 || typeof inputs.intent !== 'string') return finish(Outcome.NOT_SENT, C.INPUT_INVALID);
  if (typeof environment.transport !== 'function' || typeof environment.referenceVerifier !== 'function' || typeof environment.now !== 'function') return finish(Outcome.NOT_SENT, C.INPUT_INVALID);

  // 2. The authorization, and the private directories.
  const { authorization, digest } = readAuthorization(inputs.authorization);
  checkPrivateDirectory(environment.logDir, C.LOG_DIRECTORY);
  checkPrivateDirectory(environment.evidenceDir, C.EVIDENCE_DIRECTORY);

  // 3. RUN_STARTED, first, before any read: every run consumes its authorization.
  const before = readLog(environment.logDir);
  checkLog(before);
  checkUnused(before, digest);
  const started = makeEntry(before.length, EntryKind.RUN_STARTED, {
    authorizationDigest: digest, network: authorization.network, sender: authorization.sender, sequence: authorization.sequence, mode: 'submit',
  });
  appendEntry(environment.logDir, started);
  state.authorizationDigest = digest;
  state.authorization = authorization;
  state.runDirectory = createRunDirectory(environment.evidenceDir, `run-${String(started.index).padStart(6, '0')}`);

  // 4. The provider, by id from the reviewed configuration only.
  let configured;
  try {
    configured = loadEndpointConfig(environment.endpoints).filter((p) => p.network === authorization.network);
  } catch {
    throw new BroadcastError(C.PROVIDER_NOT_ALLOWED, 'endpoint configuration');
  }
  const provider = configured.find((p) => p.id === authorization.providerId);
  if (!provider || configured.length !== 2) throw new BroadcastError(C.PROVIDER_NOT_ALLOWED, authorization.providerId);
  state.providers = configured;

  // 5. Everything again, by the broadcaster itself (ADR-RN-019 §3).
  const verified = verifyEverything(inputs, environment.referenceVerifier, supplied);
  state.verified = verified;

  // 6. The authorization matches exactly what was recomputed, and is still valid.
  checkAuthorizationMatch(authorization, verified);
  if (authorization.network === SubmitNetwork.SEPOLIA && sepoliaAuthorizationExpired(authorization, environment.now())) throw new BroadcastError(C.AUTHORIZATION_EXPIRED, 'notAfter');

  // 7. The log permits this attempt.
  decideAttempt(readLog(environment.logDir), authorization);

  // 8. Pre-submit reads, both providers, one attempt each, budgeted.
  const transport = countingTransport(recordingTransport(environment.transport, state.exchanges), state.counters);
  const observedLedger = await presubmitReads(configured, transport, authorization, verified);

  if (authorization.dryRun) return finish(Outcome.NOT_SENT, C.DRY_RUN);

  // 9. ATTEMPTING, immediately before the write, decided on the log as it now stands.
  const log = readLog(environment.logDir);
  decideAttempt(log, authorization);
  const attempting = makeEntry(log.length, EntryKind.ATTEMPTING, {
    authorizationDigest: digest, network: authorization.network, sender: authorization.sender, sequence: authorization.sequence,
    attempt: authorization.attempt, providerId: provider.id, intentDigest: verified.intentDigest, blobSha256: verified.blobSha256,
    transactionHash: verified.transactionHash, observedLedger,
  });
  appendEntry(environment.logDir, attempting);
  state.attemptEntry = entryDigest(attempting);

  // 10. The one write: one request, one attempt, no retry, no fallback, no polling.
  const write = await sendWrite(provider, environment.transport, state, verified.signedTransaction);
  const classification = classifySubmitResponse(authorization.network, write.response, verified);
  return finish(classification.outcome, classification.code, { classification, requestSha256: write.requestSha256, responseSha256: write.responseSha256 });
}

/**
 * Recomputes every check in the fixed order of ADR-RN-019 §3 and runs both verifiers; returns
 * the verified values. Throws the first failure's code.
 */
function verifyEverything(inputs, referenceVerifier, supplied) {
  // The intent is canonical JSON text; anything else is an invalid intent.
  let intentValue;
  try {
    intentValue = parse(inputs.intent);
    if (canonicalize(intentValue) !== inputs.intent) throw new TxError('RNTX_INTENT_INVALID', 'not in canonical form');
  } catch (error) {
    if (error instanceof CanonicalError) throw new TxError('RNTX_INTENT_INVALID', 'not rnnet.canonical-json.v1');
    throw error;
  }
  const { approvedDigest, signedTransaction } = inputs;
  // The JavaScript verifier (txverify/) and the independent Python reference, on the same inputs.
  const js = verifySignedTransaction({ intent: intentValue, approvedDigest, signedTransaction });
  let python;
  try {
    python = referenceVerifier(inputs.intent, approvedDigest, signedTransaction);
  } catch {
    throw new BroadcastError(C.VERIFIER_DISAGREEMENT, 'the Python reference did not run');
  }
  if (!sameRecord(js, python)) throw new BroadcastError(C.VERIFIER_DISAGREEMENT, 'JavaScript and Python records differ');
  if (js.outcome !== 'PASS') throw new TxError(js.code, 'verification failed');

  // Steps 1 to 4 again, here: the hand-off recomputes the intent, blob hash, decoding, every
  // field and the XRPL hash; the signature and the Sepolia hash are checked with txverify/.
  const checked = approvedIntent(intentValue, approvedDigest);
  const handoff = checkHandoff({ intent: checked, approvedDigest, signedTransaction, verifications: [js, python] });
  const bytes = checked.network === IntentNetwork.XRPL_TESTNET ? Buffer.from(signedTransaction, 'hex') : Buffer.from(signedTransaction.slice(2), 'hex');
  let transactionHash = handoff.transactionHash;
  if (checked.network === IntentNetwork.XRPL_TESTNET) {
    verifyXrplSignature(decodeXrplTx(bytes));
  } else {
    const own = verifySepoliaSignature(bytes);
    if (own.sender !== checked.transaction.from) throw new TxError('RNTX_SENDER_MISMATCH', 'recovered sender differs from the intent');
    transactionHash = own.transactionHash;
  }
  const own = { blobSha256: sha256(bytes), transactionHash };
  if (own.blobSha256 !== js.blobSha256 || own.transactionHash !== js.transactionHash) throw new BroadcastError(C.VERIFIER_DISAGREEMENT, 'own hashes differ from the records');

  // Supplied records are compared, never trusted.
  for (const record of supplied) if (!sameRecord(record, js)) throw new BroadcastError(C.SUPPLIED_RECORD_MISMATCH);

  return Object.freeze({
    network: checked.network,
    sender: intentSender(checked),
    sequence: String(intentSequence(checked)),
    intentDigest: approvedDigest,
    blobSha256: own.blobSha256,
    transactionHash: own.transactionHash,
    signedTransaction,
    lastLedgerSequence: checked.network === IntentNetwork.XRPL_TESTNET ? checked.transaction.LastLedgerSequence : null,
    transaction: checked.transaction,
  });
}

/** A transport that counts every request; the per-provider budgets of the reads bound them. */
function countingTransport(inner, counters) {
  return async (request) => {
    counters.requests += 1;
    return inner(request);
  };
}

const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const isUint32 = (v) => Number.isInteger(v) && v > 0 && v <= 0xffff_ffff;
const quantity = (value) => {
  if (typeof value !== 'string' || !QUANTITY.test(value)) throw new ReadError('RNLO_INVALID_RESPONSE', 'quantity');
  return BigInt(value);
};

/** ADR-RN-019 §6 pre-submit reads; returns the highest validated XRPL ledger seen (Sepolia: null). */
async function presubmitReads(providers, transport, authorization, verified) {
  let observedLedger = null;
  for (const provider of providers) {
    const context = { provider, transport, budget: { remaining: PRESUBMIT_REQUESTS[provider.network] }, maxAttempts: 1 };
    if (provider.network === SubmitNetwork.XRPL_TESTNET) {
      const info = await call(context, 'server_info', { api_version: 2 });
      const server = info !== null && typeof info.info === 'object' && info.info !== null && !Array.isArray(info.info) ? info.info : null;
      if (server === null) throw new ReadError('RNLO_INVALID_RESPONSE', 'info');
      if (server.network_id === undefined) throw new ReadError('RNLO_NETWORK_UNKNOWN');
      if (server.network_id !== 1) throw new ReadError('RNLO_WRONG_NETWORK');
      const validated = server.validated_ledger?.seq;
      if (!isUint32(validated)) throw new ReadError('RNLO_INVALID_RESPONSE', 'validated_ledger.seq');
      const account = await call(context, 'account_info', { account: verified.sender, ledger_index: 'validated', api_version: 2 });
      const data = account.account_data !== null && typeof account.account_data === 'object' && !Array.isArray(account.account_data) ? account.account_data : null;
      if (!isUint32(account.ledger_index) || data === null || !isUint32(data.Sequence)) throw new ReadError('RNLO_INVALID_RESPONSE', 'account_info');
      if (account.validated !== true || data.Account !== verified.sender) throw new BroadcastError(C.PRESUBMIT_ACCOUNT);
      if (String(data.Sequence) !== verified.sequence) throw new BroadcastError(C.PRESUBMIT_SEQUENCE);
      const ledger = Math.max(validated, account.ledger_index);
      if (xrplAuthorizationExpired(authorization, ledger)) throw new BroadcastError(C.AUTHORIZATION_EXPIRED, 'fewer than 4 ledgers remain');
      observedLedger = Math.max(observedLedger ?? 0, ledger);
      try {
        await call(context, 'tx', { transaction: verified.transactionHash, binary: false, api_version: 2 });
      } catch (error) {
        if (error instanceof ReadError && error.code === 'RNLO_NOT_FOUND') continue;
        throw error;
      }
      throw new BroadcastError(C.PRESUBMIT_ALREADY_KNOWN);
    }
    const tx = verified.transaction;
    const chainId = await call(context, 'eth_chainId', []);
    if (typeof chainId !== 'string' || !QUANTITY.test(chainId)) throw new ReadError('RNLO_INVALID_RESPONSE', 'chainId');
    if (chainId !== '0xaa36a7') throw new ReadError('RNLO_WRONG_NETWORK');
    const block = await call(context, 'eth_getBlockByNumber', ['latest', false]);
    if (block === null || typeof block !== 'object' || Array.isArray(block)) throw new ReadError('RNLO_INVALID_RESPONSE', 'block');
    // A sanity check on the latest block only: the next block's base fee can be 12.5% higher.
    if (quantity(block.baseFeePerGas) > BigInt(tx.maxFeePerGas) - BigInt(tx.maxPriorityFeePerGas)) throw new BroadcastError(C.PRESUBMIT_BASE_FEE);
    if (quantity(await call(context, 'eth_getTransactionCount', [tx.from, 'latest'])) !== BigInt(tx.nonce)) throw new BroadcastError(C.PRESUBMIT_NONCE, 'latest');
    if (quantity(await call(context, 'eth_getTransactionCount', [tx.from, 'pending'])) !== BigInt(tx.nonce)) throw new BroadcastError(C.PRESUBMIT_NONCE, 'pending');
    if ((await call(context, 'eth_getTransactionByHash', [verified.transactionHash])) !== null) throw new BroadcastError(C.PRESUBMIT_ALREADY_KNOWN);
    if (quantity(await call(context, 'eth_getBalance', [tx.from, 'latest'])) < BigInt(tx.gas) * BigInt(tx.maxFeePerGas)) throw new BroadcastError(C.PRESUBMIT_BALANCE);
  }
  return observedLedger;
}

/** Sends the one write through the write gate and describes what happened, for the classifier. */
async function sendWrite(provider, transport, state, signedTransaction) {
  const body = submitRequestBytes(provider.network, signedTransaction);
  const requestSha256 = sha256(body);
  const recorded = recordingTransport(transport, state.exchanges);
  const gate = state.writeGate ?? (state.writeGate = createWriteGate());
  let response;
  try {
    response = await gate.send(() => {
      state.counters.requests += 1;
      state.counters.writes += 1;
      return recorded({ providerId: provider.id, url: provider.url, body, timeoutMs: SUBMIT_LIMITS.timeoutMs, maxResponseBytes: SUBMIT_LIMITS.maxResponseBytes });
    });
  } catch (error) {
    if (error instanceof BroadcastError && error.code === C.NOT_SENT_HARNESS) return { requestSha256: null, responseSha256: null, response: { harnessRefused: error.code } };
    return { requestSha256, responseSha256: null, response: { transportError: TRANSPORT_CODES.includes(error?.code) ? error.code : 'RNLO_CONNECTION' } };
  }
  if (response === null || typeof response !== 'object' || !Number.isInteger(response.status) || !(response.body instanceof Uint8Array)) {
    return { requestSha256, responseSha256: null, response: { transportError: 'RNLO_CONNECTION' } };
  }
  const responseSha256 = sha256(response.body);
  if (response.body.length > SUBMIT_LIMITS.maxResponseBytes) return { requestSha256, responseSha256, response: { transportError: 'RNLO_RESPONSE_TOO_LARGE' } };
  try {
    return { requestSha256, responseSha256, response: { status: response.status, envelope: parseRpcJson(response.body, SUBMIT_LIMITS.maxResponseBytes) } };
  } catch (error) {
    if (error instanceof JsonError) return { requestSha256, responseSha256, response: { status: response.status, invalidJson: true } };
    throw error;
  }
}

/** Writes the record and the capture, then RESULT (after an attempt), and returns the run's result. */
function finishRun(state, environment, outcome, code, extra) {
  const a = state.authorization;
  const v = state.verified;
  const record = submissionRecord({
    authorizationDigest: state.authorizationDigest,
    network: a?.network ?? null,
    providerId: a?.providerId ?? null,
    intentDigest: v?.intentDigest ?? a?.intentDigest ?? null,
    blobSha256: v?.blobSha256 ?? a?.blobSha256 ?? null,
    transactionHash: v?.transactionHash ?? a?.transactionHash ?? null,
    requestSha256: extra.requestSha256 ?? null,
    responseSha256: extra.responseSha256 ?? null,
    classification: extra.classification,
    outcome,
    code,
    dryRun: a?.dryRun === true,
    recordedAt: typeof environment?.now === 'function' ? isoTime(environment.now()) : null,
  });
  const recordDigest = submissionRecordDigest(record);
  if (state.runDirectory) {
    writeNewFile(`${state.runDirectory}/submission-record.json`, storedText(record));
    const capture = {
      format: 'rnnet.rpc-capture.v1',
      network: a.network,
      transactionHash: record.expectedTransactionHash ?? '',
      providers: state.providers.map((p) => ({ id: p.id, operator: p.operator, origin: p.origin })),
      exchanges: state.exchanges,
    };
    writeNewFile(`${state.runDirectory}/capture.json`, `${JSON.stringify(capture)}\n`);
  }
  if (state.attemptEntry) {
    // RESULT is written after the write whatever its outcome. A conflicting index is retried at the
    // next free one: the entry must exist, and its content does not depend on the log's state.
    for (let tries = 0; ; tries++) {
      const log = readLog(environment.logDir);
      try {
        appendEntry(environment.logDir, makeEntry(log.length, EntryKind.RESULT, {
          authorizationDigest: state.authorizationDigest, network: a.network, sender: a.sender, sequence: a.sequence,
          attemptEntry: state.attemptEntry, outcome, code, record: recordDigest,
        }));
        break;
      } catch (error) {
        if (!(error instanceof BroadcastError && error.code === C.LOG_CONFLICT) || tries >= 2) throw error;
      }
    }
  }
  return Object.freeze({ outcome, code, record, recordDigest, requests: state.counters.requests, writes: state.counters.writes, runDirectory: state.runDirectory });
}
