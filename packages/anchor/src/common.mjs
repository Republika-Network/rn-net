// Shared pieces of the anchor package: observation parsing (spec/rnnet.anchor-record.v1.md §2),
// findings, statements and deterministic records.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalBytes, parse } from '../../canonical/src/index.mjs';

export const OBSERVATION_FORMAT = 'rnnet.anchor-observation.v1';
export const RECORD_FORMAT = 'rnnet.anchor-record.v1';
export const MAX_OBSERVATION_BYTES = 65_536;
export const COMMITMENT = /^sha256:[0-9a-f]{64}$/;

export const Network = Object.freeze({ XRPL_TESTNET: 'xrpl:testnet', SEPOLIA: 'evm:11155111' });
const NETWORK_MEMBERS = {
  [Network.XRPL_TESTNET]: ['format', 'network', 'tx'],
  [Network.SEPOLIA]: ['format', 'network', 'transaction', 'receipt'],
};

const UNSUPPORTED = new Set([
  'RNAO_UNSUPPORTED_FORMAT',
  'RNAO_UNSUPPORTED_VERSION',
  'RNAX_UNSUPPORTED_TRANSACTION_TYPE',
  'RNAE_UNSUPPORTED_TRANSACTION_TYPE',
  'RNAP_UNSUPPORTED_VERSION',
  'RNAP_UNSUPPORTED_COMMITMENT_FORMAT',
]);

/** A check failure: a stable code and the fixed path of what it concerns. */
export class AnchorError extends Error {
  constructor(code, subject) {
    super(code);
    this.name = 'AnchorError';
    this.code = code;
    this.subject = subject;
  }
}
export const fail = (code, subject) => {
  throw new AnchorError(code, subject);
};
export const finding = (code, subject) => ({ code, severity: UNSUPPORTED.has(code) ? 'unsupported' : 'error', subject });
export const statement = (subject, classification, basis) => ({ subject, classification, basis });
export const kind = (value) => (value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value);
export const sha256Digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

/** One copy of the caller's bytes; a Proxy posing as a Uint8Array is refused. */
export function snapshotBytes(value, name) {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${name} must be a Uint8Array.`);
  try {
    return new Uint8Array(Uint8Array.prototype.slice.call(value));
  } catch {
    throw new TypeError(`${name} must be a Uint8Array.`);
  }
}

export function checkCommitment(value) {
  if (typeof value !== 'string' || !COMMITMENT.test(value)) throw new TypeError('expectedCommitment must be sha256:<64 lowercase hex>.');
  return value;
}

/** §2.1: the parsed observation for `network`, or the first failure. */
export function parseObservation(bytes, network) {
  if (bytes.length > MAX_OBSERVATION_BYTES) fail('RNAO_TOO_LARGE', '');
  const observation = parse(bytes);
  if (kind(observation) !== 'object') fail('RNAO_NOT_OBJECT', '');
  for (const field of ['format', 'network']) {
    if (!Object.hasOwn(observation, field)) fail('RNAO_MISSING_FIELD', field);
    if (typeof observation[field] !== 'string') fail('RNAO_FIELD_TYPE', field);
    if (field === 'format' && observation.format !== OBSERVATION_FORMAT) {
      fail(observation.format.startsWith('rnnet.anchor-observation.') ? 'RNAO_UNSUPPORTED_VERSION' : 'RNAO_UNSUPPORTED_FORMAT', 'format');
    }
  }
  if (observation.network !== network) fail('RNAO_WRONG_NETWORK', 'network');
  const members = NETWORK_MEMBERS[network];
  if (Object.keys(observation).some((key) => !members.includes(key))) fail('RNAO_UNKNOWN_FIELD', '');
  for (const field of members) if (!Object.hasOwn(observation, field)) fail('RNAO_MISSING_FIELD', field);
  return observation;
}

/** Runs one check phase; a failure becomes a finding instead of an exception. */
export function phase(findings, run) {
  try {
    run();
    return true;
  } catch (error) {
    if (!(error instanceof AnchorError) && !/^RNCJ_/.test(error?.code ?? '')) throw error;
    findings.push(finding(error.code, error.subject ?? ''));
    return false;
  }
}

/** The record's outcome from its findings (§5.2). */
export function outcomeOf(findings) {
  if (findings.length === 0) return 'PASS';
  return UNSUPPORTED.has(findings[0].code) ? 'UNSUPPORTED' : 'FAIL';
}

/** A frozen, plain-data copy whose canonical bytes are fixed. */
export function freeze(value) {
  const copy = JSON.parse(new TextDecoder().decode(canonicalBytes(value)));
  const deep = (v) => {
    if (v !== null && typeof v === 'object') {
      for (const child of Object.values(v)) deep(child);
      Object.freeze(v);
    }
    return v;
  };
  return deep(copy);
}

export const hexOf = (bytes) => Buffer.from(bytes).toString('hex');
export const bytesOfHex = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));

// --- records (spec §5) ------------------------------------------------------------------------

/** A new, empty anchor record for one network. */
export function newRecord(network, expected, bytes) {
  return { format: RECORD_FORMAT, network, expectedCommitment: expected, input: { sha256: sha256Digest(bytes) }, findings: [], statements: [] };
}

const BASIS = Object.freeze({
  payload: 'Decoded from the supplied transaction data and equal to the payload of the expected commitment.',
  network: "Named by the supplier of the record and consistent with the transaction's own network fields; not authenticated.",
  status: 'Stated by the supplied transaction data; not authenticated.',
  inclusion: 'The supplied data names the ledger or block that includes the transaction; no inclusion proof was checked.',
  hash: 'Not recomputed from the signed transaction, so not bound to the data that was checked.',
  submitter: 'The sending account as stated by the supplied data.',
});

/** Sets the outcome, assurance and statements (§5.2, §5.3) and freezes the record. */
export function finish(record, finalityBasis, finalityClassification) {
  record.outcome = outcomeOf(record.findings);
  if (record.outcome === 'PASS') {
    record.assurance = 'CONSISTENT_WITH_SUPPLIED_DATA';
    record.statements = [
      statement('anchorPayload', 'VERIFIED', BASIS.payload),
      statement('network', 'CLAIMED', BASIS.network),
      statement('transactionStatus', 'CLAIMED', BASIS.status),
      statement('inclusion', 'CLAIMED', BASIS.inclusion),
      statement('finality', finalityClassification, finalityBasis),
      statement('transactionHash', 'UNRESOLVED', BASIS.hash),
      statement('submitter', 'CLAIMED', BASIS.submitter),
    ];
  }
  return freeze(record);
}
