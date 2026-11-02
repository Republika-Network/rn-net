// rnnet.submission-record.v1 and rnnet.submission-status.v1 (ADR-RN-019 §7 and §8;
// spec/rnnet.broadcast.v1.md §7). Private evidence: never committed or published (publication
// is gate F, as a sanitized record only).
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../../canonical/src/index.mjs';

export const SUBMISSION_RECORD_FORMAT = 'rnnet.submission-record.v1';
export const SUBMISSION_RECORD_DOMAIN = 'rnnet:submission-record:v1\0';
export const STATUS_RECORD_FORMAT = 'rnnet.submission-status.v1';
export const STATUS_RECORD_DOMAIN = 'rnnet:submission-status:v1\0';
/** The findings a status check can record. Only the first three are written to the log as RESOLVED. */
export const STATUS_FINDINGS = Object.freeze(['INCLUDED', 'EXPIRED', 'PENDING', 'UNRESOLVED']);

const digest = (domain, value) => `sha256:${createHash('sha256').update(domain).update(canonicalBytes(value)).digest('hex')}`;
const orNull = (v) => (v === undefined ? null : v);

/**
 * The record of one submit run. `run` holds what is known: the authorization digest and the
 * authorization's network, provider, intent and blob digests and expected hash (or the verified
 * ones), the request and response digests of the write, the classification and the time.
 */
export function submissionRecord(run) {
  const c = run.classification ?? {};
  return {
    format: SUBMISSION_RECORD_FORMAT,
    authorizationDigest: orNull(run.authorizationDigest),
    network: orNull(run.network),
    providerId: orNull(run.providerId),
    intentDigest: orNull(run.intentDigest),
    blobSha256: orNull(run.blobSha256),
    expectedTransactionHash: orNull(run.transactionHash),
    returnedTransactionHash: orNull(c.returnedTransactionHash),
    requestSha256: orNull(run.requestSha256),
    responseSha256: orNull(run.responseSha256),
    httpStatus: orNull(c.httpStatus),
    transportError: orNull(c.transportError),
    outcome: run.outcome,
    code: run.code,
    xrpl: orNull(c.xrpl),
    sepolia: orNull(c.sepolia),
    dryRun: run.dryRun === true,
    recordedAt: run.recordedAt,
  };
}
export const submissionRecordDigest = (record) => digest(SUBMISSION_RECORD_DOMAIN, record);

/** The record of one read-only status check. */
export function statusRecord(check) {
  return {
    format: STATUS_RECORD_FORMAT,
    authorizationDigest: check.authorizationDigest,
    network: check.network,
    attemptEntry: check.attemptEntry,
    transactionHash: check.transactionHash,
    finding: check.finding,
    code: check.code,
    liveReportSha256: orNull(check.liveReportSha256),
    live: orNull(check.live),
    providers: check.providers,
    recordedAt: check.recordedAt,
  };
}
export const statusRecordDigest = (record) => digest(STATUS_RECORD_DOMAIN, record);
