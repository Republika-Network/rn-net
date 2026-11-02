// The read-only status check after a submission (RN-NET-03B2-B3, ADR-RN-019 §8;
// spec/rnnet.broadcast.v1.md §10). It never writes to a network: every request is a read built by
// packages/chain-readonly. It runs only under its own rnnet.status-authorization.v1, consumes it
// (RUN_STARTED), and writes a RESOLVED entry only for a finding both providers support:
//
//   INCLUDED  verify-live-anchor's report: PASS, AGREEMENT, and PROVIDER_REPORTED_VALIDATED
//             (XRPL) or PROVIDER_REPORTED_FINALIZED (Sepolia, the parent-hash walk) on both;
//   EXPIRED   XRPL only, both providers not finding it, then on each: a validated ledger past
//             LastLedgerSequence, a ledger-ranged `tx` returning txnNotFound with
//             searched_all: true, and account_info at that ledger with the Sequence unchanged;
//   PENDING   Sepolia only, both providers not finding it, and on each the latest nonce still
//             equal to the transaction's (the nonce is unused).
//
// Anything else is UNRESOLVED and writes no RESOLVED entry. Agreement is not a consensus proof
// (ADR-RN-015); CHAIN_PROVEN is never produced. OFFLINE ONLY IN B3: the transport is injected.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalize, parse } from '../../packages/canonical/src/index.mjs';
import { call, encodeLiveReport, loadEndpointConfig, ReadError, verifyLiveAnchor } from '../../packages/chain-readonly/src/index.mjs';
import {
  attemptForStatus,
  BroadcastCode as C,
  BroadcastError,
  checkLog,
  checkUnused,
  EntryKind,
  makeEntry,
  readStatusAuthorization,
  statusRecord,
  statusRecordDigest,
  SubmitNetwork,
} from '../../packages/chain-submit/src/index.mjs';
import { intentDigest, makeIntent } from '../../packages/tx-intent/src/index.mjs';
import { appendEntry, checkPrivateDirectory, createRunDirectory, readLog, storedText, writeNewFile } from './store.mjs';

export const STATUS_INPUT_FIELDS = Object.freeze(['authorization', 'intent']);
export const STATUS_ENVIRONMENT_FIELDS = Object.freeze(['endpoints', 'evidenceDir', 'logDir', 'now', 'transport']);
/** XRPL's `tx` searches at most 1000 ledgers in one ranged lookup. */
export const MAX_LEDGER_RANGE = 1000;
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const isoTime = (seconds) => new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const isUint32 = (v) => Number.isInteger(v) && v > 0 && v <= 0xffff_ffff;

/**
 * Decides a finding from what each provider showed (pure; reproduced by the Python reference).
 * `report` is the live-observation report's summary { outcome, agreement, statuses, outcomes[] };
 * `absence` is, per provider, true when it showed expiry (XRPL) or an unused nonce (Sepolia).
 */
export function decideFinding(network, report, absence) {
  const final = network === SubmitNetwork.XRPL_TESTNET ? 'PROVIDER_REPORTED_VALIDATED' : 'PROVIDER_REPORTED_FINALIZED';
  if (report.outcome === 'PASS' && report.agreement === 'AGREEMENT' && report.statuses.includes(final) && report.outcomes.every((o) => o === 'OBSERVED')) return 'INCLUDED';
  const unseen = report.outcomes.length === 2 && report.outcomes.every((o) => o === 'NOT_FOUND');
  if (unseen && absence.length === 2 && absence.every((a) => a === true)) return network === SubmitNetwork.XRPL_TESTNET ? 'EXPIRED' : 'PENDING';
  return 'UNRESOLVED';
}

/** Runs one status check; returns { finding, code, record, recordDigest, runDirectory }. */
export async function runStatusCheck({ inputs, environment } = {}) {
  const exact = (value, fields) => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
  if (!exact(inputs, STATUS_INPUT_FIELDS) || !exact(environment, STATUS_ENVIRONMENT_FIELDS) || typeof environment.transport !== 'function') {
    return Object.freeze({ finding: null, code: C.INPUT_INVALID, record: null, recordDigest: null, runDirectory: null });
  }
  let digest;
  let authorization;
  let runDirectory = null;
  try {
    ({ authorization, digest } = readStatusAuthorization(inputs.authorization));
    checkPrivateDirectory(environment.logDir, C.LOG_DIRECTORY);
    checkPrivateDirectory(environment.evidenceDir, C.EVIDENCE_DIRECTORY);
    const before = readLog(environment.logDir);
    checkLog(before);
    checkUnused(before, digest);
    const started = makeEntry(before.length, EntryKind.RUN_STARTED, {
      authorizationDigest: digest, network: authorization.network, sender: authorization.sender, sequence: authorization.sequence, mode: 'status',
    });
    appendEntry(environment.logDir, started);
    runDirectory = createRunDirectory(environment.evidenceDir, `status-${String(started.index).padStart(6, '0')}`);
  } catch (error) {
    if (error instanceof BroadcastError) return Object.freeze({ finding: null, code: error.code, record: null, recordDigest: null, runDirectory });
    throw error;
  }
  const exchanges = [];
  const recordOf = (finding, code, extra = {}) => {
    const record = statusRecord({
      authorizationDigest: digest, network: authorization.network, attemptEntry: authorization.attemptEntry, transactionHash: authorization.transactionHash,
      finding, code, liveReportSha256: extra.liveReportSha256 ?? null, live: extra.live ?? null, providers: extra.providers ?? [], recordedAt: isoTime(environment.now()),
    });
    const recordDigest = statusRecordDigest(record);
    writeNewFile(`${runDirectory}/status-record.json`, storedText(record));
    writeNewFile(`${runDirectory}/capture.json`, `${JSON.stringify({ format: 'rnnet.rpc-capture.v1', network: authorization.network, transactionHash: authorization.transactionHash, providers: extra.capturedProviders ?? [], exchanges })}\n`);
    if (finding !== null && finding !== 'UNRESOLVED') {
      const log = readLog(environment.logDir);
      appendEntry(environment.logDir, makeEntry(log.length, EntryKind.RESOLVED, {
        authorizationDigest: digest, network: authorization.network, sender: authorization.sender, sequence: authorization.sequence,
        attemptEntry: authorization.attemptEntry, finding, record: recordDigest,
      }));
    }
    return Object.freeze({ finding, code, record, recordDigest, runDirectory });
  };
  try {
    const { entry: attempt } = attemptForStatus(readLog(environment.logDir), authorization);
    // The intent gives the commitment, LastLedgerSequence and nonce; it must be the attempt's.
    let intent;
    try {
      const value = parse(inputs.intent);
      if (canonicalize(value) !== inputs.intent) throw new Error('not canonical');
      intent = makeIntent(value);
    } catch {
      throw new BroadcastError(C.STATUS_MISMATCH, 'intent');
    }
    if (intentDigest(intent) !== attempt.intentDigest) throw new BroadcastError(C.STATUS_MISMATCH, 'intent digest');
    let providers;
    try {
      const configured = loadEndpointConfig(environment.endpoints);
      providers = authorization.providerIds.map((id) => configured.find((p) => p.id === id && p.network === authorization.network));
    } catch {
      providers = [undefined];
    }
    if (providers.some((p) => p === undefined)) throw new BroadcastError(C.PROVIDER_NOT_ALLOWED);
    const capturedProviders = providers.map((p) => ({ id: p.id, operator: p.operator, origin: p.origin }));
    const transport = recordingTransportFor(environment.transport, exchanges);

    const report = await verifyLiveAnchor({ network: authorization.network, transactionHash: authorization.transactionHash, expectedCommitment: intent.commitment, providers, transport });
    const summary = { outcome: report.outcome, agreement: report.agreement, statuses: report.statuses, outcomes: report.providers.map((p) => p.outcome) };
    const absence = [];
    if (summary.outcomes.every((o) => o === 'NOT_FOUND')) {
      for (const provider of providers) absence.push(await showsAbsence(provider, transport, intent, attempt));
    }
    const finding = decideFinding(authorization.network, summary, absence);
    const perProvider = providers.map((p, i) => ({ id: p.id, observation: summary.outcomes[i], absence: absence[i] ?? null }));
    return recordOf(finding, finding === 'UNRESOLVED' ? C.STATUS_UNRESOLVED : null, { liveReportSha256: sha256(encodeLiveReport(report)), live: summary, providers: perProvider, capturedProviders });
  } catch (error) {
    if (error instanceof BroadcastError) return recordOf(null, error.code);
    throw error;
  }
}

function recordingTransportFor(inner, exchanges) {
  return async (request) => {
    const entry = { providerId: request.providerId, request: Buffer.from(request.body).toString('base64') };
    exchanges.push(entry);
    try {
      const response = await inner(request);
      entry.response = { status: response.status, body: Buffer.from(response.body).toString('base64'), sha256: sha256(response.body) };
      return response;
    } catch (error) {
      entry.error = typeof error?.code === 'string' ? error.code : 'RNLO_CONNECTION';
      throw error;
    }
  };
}

/** Whether one provider shows the attempt cannot be included any more (XRPL) or is unused (Sepolia). */
async function showsAbsence(provider, transport, intent, attempt) {
  const context = { provider, transport, budget: { remaining: 3 }, maxAttempts: 1 };
  const tx = intent.transaction;
  try {
    if (provider.network === SubmitNetwork.XRPL_TESTNET) {
      const info = await call(context, 'server_info', { api_version: 2 });
      if (info?.info?.network_id !== 1) return false;
      const validated = info.info.validated_ledger?.seq;
      if (!isUint32(validated) || validated <= tx.LastLedgerSequence) return false;
      const from = attempt.observedLedger;
      if (!isUint32(from) || from > validated || validated - from > MAX_LEDGER_RANGE) return false;
      try {
        await call(context, 'tx', { transaction: attempt.transactionHash, binary: false, min_ledger: from, max_ledger: validated, api_version: 2 });
        return false;
      } catch (error) {
        // Only a search of the whole range proves absence; a plain txnNotFound proves nothing.
        if (!(error instanceof ReadError) || error.code !== 'RNLO_NOT_FOUND' || error.detail !== 'searched_all') return false;
      }
      const account = await call(context, 'account_info', { account: tx.Account, ledger_index: validated, api_version: 2 });
      return account.validated === true && account.ledger_index === validated && account.account_data?.Account === tx.Account && account.account_data?.Sequence === tx.Sequence;
    }
    const nonce = await call(context, 'eth_getTransactionCount', [tx.from, 'latest']);
    return nonce === tx.nonce;
  } catch (error) {
    if (error instanceof ReadError) return false;
    throw error;
  }
}
