// rnnet.live-observation-report.v1 (spec/rnnet.live-observation-report.v1.md §7): one transaction,
// read from one or more configured providers, normalized, checked by the RN-NET-03A adapter, and
// compared across providers. The report is a function of the bytes the providers returned; time and
// retrieval details live only in the capture.
import { createHash } from 'node:crypto';
import { verifyEvmObservation, verifyXrplObservation } from '../../anchor/src/index.mjs';
import { canonicalBytes } from '../../canonical/src/index.mjs';
import { ReplayMismatch } from './capture.mjs';
import { readEvm, readXrpl } from './readers.mjs';
import { LIMITS, Network, ReadError } from './rpc.mjs';

export const LIVE_REPORT_FORMAT = 'rnnet.live-observation-report.v1';
const COMMITMENT = /^sha256:[0-9a-f]{64}$/;
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

const OUTCOME_OF_ERROR = {
  RNLO_NOT_FOUND: 'NOT_FOUND',
  RNLO_WRONG_NETWORK: 'WRONG_NETWORK',
  RNLO_NETWORK_UNKNOWN: 'WRONG_NETWORK',
  RNLO_HASH_MISMATCH: 'INCONSISTENT',
  RNLO_LEDGER_MISMATCH: 'INCONSISTENT',
  RNLO_BLOCK_MISMATCH: 'INCONSISTENT',
  RNLO_INVALID_JSON: 'INVALID_RESPONSE',
  RNLO_INVALID_RESPONSE: 'INVALID_RESPONSE',
  RNLO_RPC_ERROR: 'INVALID_RESPONSE',
  RNLO_UNSUPPORTED_API_VERSION: 'INVALID_RESPONSE',
};
// Everything else (timeouts, connection failures, rate limits, HTTP errors, blocked addresses,
// redirects, oversized responses, an exhausted request budget) means the provider was unavailable.
const outcomeOf = (code) => OUTCOME_OF_ERROR[code] ?? 'UNAVAILABLE';

const BASIS = Object.freeze({
  observed: 'As returned by the named RPC providers; not authenticated.',
  agreement: 'The providers returned the same material data. Their operational independence is not established, and agreement is not a consensus proof.',
  validated: 'The provider reports the transaction in a validated ledger, and its ledger read agrees; not authenticated.',
  finalized: "The provider's finalized block descends, by parent hashes it returned, from the transaction's block; not authenticated.",
  unresolvedFinality: 'Validation or finality could not be established from the providers.',
  proof: 'No authenticated proof of inclusion (validated ledger header and validator signatures, or a consensus light client) was verified.',
});

/**
 * @param {{ network: string, transactionHash: string, expectedCommitment: string,
 *   providers: ReadonlyArray<{ id, network, url, operator }>, transport: (request: object) => Promise<object> }} input
 * @returns {Promise<Readonly<object>>} an rnnet.live-observation-report.v1 report
 */
export async function verifyLiveAnchor({ network, transactionHash, expectedCommitment, providers, transport }) {
  if (!Object.values(Network).includes(network)) throw new TypeError('network must be xrpl:testnet or evm:11155111.');
  if (typeof expectedCommitment !== 'string' || !COMMITMENT.test(expectedCommitment)) throw new TypeError('expectedCommitment must be sha256:<64 lowercase hex>.');
  if (!Array.isArray(providers) || providers.length === 0) throw new TypeError('at least one provider is required.');
  if (providers.some((p) => p.network !== network)) throw new TypeError('every provider must be configured for the requested network.');
  if (typeof transport !== 'function') throw new TypeError('transport must be a function.');
  const read = network === Network.XRPL_TESTNET ? readXrpl : readEvm;
  const check = network === Network.XRPL_TESTNET ? verifyXrplObservation : verifyEvmObservation;

  const entries = [];
  // Providers are read one after another: at most one request is in flight.
  for (const provider of providers) {
    const context = { provider, transport, budget: { remaining: LIMITS.maxRequestsPerProvider } };
    const entry = { id: provider.id, operator: provider.operator };
    try {
      const observed = await read(context, transactionHash);
      const record = check(observed.observation, expectedCommitment);
      Object.assign(entry, { outcome: 'OBSERVED', observationSha256: sha256(observed.observation), materialSha256: sha256(observed.material), record });
      if (network === Network.XRPL_TESTNET) entry.providerValidated = observed.validated;
      else entry.finality = observed.finality;
    } catch (error) {
      if (error instanceof ReplayMismatch) throw error;
      if (!(error instanceof ReadError)) throw error;
      Object.assign(entry, { outcome: outcomeOf(error.code), error: error.code });
    }
    entries.push(entry);
  }
  return buildReport({ network, transactionHash, expectedCommitment, entries });
}

function buildReport({ network, transactionHash, expectedCommitment, entries }) {
  // Comparable answers: an observation (by its material digest) or "not found".
  const comparable = entries.filter((e) => e.outcome === 'OBSERVED' || e.outcome === 'NOT_FOUND');
  const answers = new Set(comparable.map((e) => (e.outcome === 'OBSERVED' ? e.materialSha256 : 'NOT_FOUND')));
  let agreement;
  if (comparable.length === 0) agreement = 'SOURCE_UNAVAILABLE';
  else if (answers.size > 1) agreement = 'DISAGREEMENT';
  else if (comparable.length === 1) agreement = 'INSUFFICIENT_SOURCES';
  else agreement = 'AGREEMENT';

  const findings = [];
  for (const e of entries) {
    if (e.outcome !== 'OBSERVED') findings.push({ code: e.error, severity: e.outcome === 'UNAVAILABLE' ? 'unavailable' : 'error', subject: `providers.${e.id}` });
    else if (e.record.outcome !== 'PASS') findings.push({ code: 'RNLO_RECORD_NOT_PASSED', severity: 'error', subject: `providers.${e.id}` });
    if (e.finality && (e.finality.finalized === 'CONFLICT' || e.finality.safe === 'CONFLICT')) {
      findings.push({ code: 'RNLO_FINALITY_CONFLICT', severity: 'error', subject: `providers.${e.id}` });
    }
  }
  if (agreement === 'DISAGREEMENT') findings.push({ code: 'RNLO_PROVIDER_DISAGREEMENT', severity: 'error', subject: 'providers' });

  const observed = entries.filter((e) => e.outcome === 'OBSERVED');
  const hardFailure = findings.some((f) => f.severity === 'error' && f.code !== 'RNLO_RECORD_NOT_PASSED')
    || observed.some((e) => e.record.outcome === 'FAIL')
    || (comparable.length > 0 && observed.length === 0);
  let outcome;
  if (hardFailure) outcome = 'FAIL';
  else if (observed.length === 0) outcome = 'INDETERMINATE';
  else if (observed.some((e) => e.record.outcome === 'UNSUPPORTED')) outcome = 'UNSUPPORTED';
  else outcome = 'PASS';

  const providerFinal = observed.length > 0 && observed.every((e) => (network === Network.XRPL_TESTNET ? e.providerValidated : e.finality.finalized === 'IN_ANCESTRY'));
  const statuses = [];
  if (observed.length > 0) statuses.push('OBSERVED_FROM_RPC');
  if (providerFinal) statuses.push(network === Network.XRPL_TESTNET ? 'PROVIDER_REPORTED_VALIDATED' : 'PROVIDER_REPORTED_FINALIZED');
  if (agreement === 'AGREEMENT') statuses.push('MULTI_PROVIDER_AGREEMENT');
  if (agreement === 'DISAGREEMENT') statuses.push('DISAGREEMENT');
  if (!providerFinal) statuses.push('UNRESOLVED');

  const statements = [];
  const statement = (subject, classification, basis) => statements.push({ subject, classification, basis });
  if (observed.length > 0) statement('providerObservation', 'CLAIMED', BASIS.observed);
  if (agreement === 'AGREEMENT') statement('providerAgreement', 'CLAIMED', BASIS.agreement);
  if (providerFinal) statement('finality', 'CLAIMED', network === Network.XRPL_TESTNET ? BASIS.validated : BASIS.finalized);
  else statement('finality', 'UNRESOLVED', BASIS.unresolvedFinality);
  statement('chainInclusionProof', 'UNRESOLVED', BASIS.proof);

  const report = { format: LIVE_REPORT_FORMAT, network, transactionHash, expectedCommitment, outcome, agreement, statuses, providers: entries, findings, statements };
  return freeze(JSON.parse(new TextDecoder().decode(canonicalBytes(report))));
}

function freeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

/** The report's exact bytes under rnnet.canonical-json.v1. */
export const encodeLiveReport = (report) => canonicalBytes(report);
