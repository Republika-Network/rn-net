// The submission log's entries and decisions (ADR-RN-019 §5; spec/rnnet.broadcast.v1.md §5).
//
// The log is private, append-only, and kept outside every repository. Its storage (one file per
// entry, created with `wx`, never changed or deleted) is tools/submit/store.mjs; this file
// holds only the pure parts: the entry format, its digest, the consistency check of a whole log,
// and the decisions that refuse a run. Entries are numbered from 0 without gaps, and an entry
// is written at index N only if the decision was taken on exactly entries 0..N-1, so two runs can
// never both act on the same state.
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../../canonical/src/index.mjs';
import { BroadcastCode as C, BroadcastError, Outcome } from './codes.mjs';
import { SubmitNetwork } from './requests.mjs';

export const LOG_ENTRY_FORMAT = 'rnnet.submission-log-entry.v1';
export const LOG_ENTRY_DOMAIN = 'rnnet:submission-log-entry:v1\0';
export const EntryKind = Object.freeze({ RUN_STARTED: 'RUN_STARTED', ATTEMPTING: 'ATTEMPTING', RESULT: 'RESULT', RESOLVED: 'RESOLVED' });
/** The findings a RESOLVED entry may state, per network. */
export const RESOLVED_FINDINGS = Object.freeze({
  [SubmitNetwork.XRPL_TESTNET]: Object.freeze(['INCLUDED', 'EXPIRED']),
  [SubmitNetwork.SEPOLIA]: Object.freeze(['INCLUDED', 'PENDING']),
});

const COMMON = ['authorizationDigest', 'format', 'index', 'kind', 'network', 'sender', 'sequence'];
const FIELDS = Object.freeze({
  RUN_STARTED: [...COMMON, 'mode'],
  ATTEMPTING: [...COMMON, 'attempt', 'blobSha256', 'intentDigest', 'observedLedger', 'providerId', 'transactionHash'],
  RESULT: [...COMMON, 'attemptEntry', 'code', 'outcome', 'record'],
  RESOLVED: [...COMMON, 'attemptEntry', 'finding', 'record'],
});
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const sameKeys = (value, fields) => Object.keys(value).sort().join(',') === [...fields].sort().join(',');

/** The digest an entry is linked by: SHA-256 of the domain and the entry's canonical JSON. */
export const entryDigest = (entry) => `sha256:${createHash('sha256').update(LOG_ENTRY_DOMAIN).update(canonicalBytes(entry)).digest('hex')}`;

/** A new entry for index `index` (the log's current length). */
export function makeEntry(index, kind, fields) {
  const entry = { format: LOG_ENTRY_FORMAT, index, kind, ...fields };
  if (!Object.hasOwn(FIELDS, kind) || !sameKeys(entry, FIELDS[kind])) throw new TypeError(`log entry ${kind}: wrong fields`);
  return entry;
}

const keyOf = (e) => `${e.network}|${e.sender}|${e.sequence}`;

/**
 * Checks a whole log (entries in index order) for consistency; throws LOG_INVALID. Returns the
 * entries with their digests: [{ entry, digest }].
 */
export function checkLog(entries) {
  const fail = (why) => {
    throw new BroadcastError(C.LOG_INVALID, why);
  };
  if (!Array.isArray(entries)) fail('entries');
  const out = [];
  const runs = new Map(); // authorization digest -> RUN_STARTED entry
  const attempts = new Map(); // ATTEMPTING digest -> { entry, result }
  const attemptByAuthorization = new Set();
  entries.forEach((entry, index) => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) fail(`entry ${index}`);
    if (entry.format !== LOG_ENTRY_FORMAT || entry.index !== index || !Object.hasOwn(FIELDS, entry.kind) || !sameKeys(entry, FIELDS[entry.kind])) fail(`entry ${index}: format`);
    if (!Object.values(SubmitNetwork).includes(entry.network) || typeof entry.sender !== 'string' || typeof entry.sequence !== 'string') fail(`entry ${index}: key`);
    if (typeof entry.authorizationDigest !== 'string' || !DIGEST.test(entry.authorizationDigest)) fail(`entry ${index}: authorizationDigest`);
    const run = runs.get(entry.authorizationDigest);
    switch (entry.kind) {
      case EntryKind.RUN_STARTED:
        if (!['submit', 'status'].includes(entry.mode)) fail(`entry ${index}: mode`);
        if (run) fail(`entry ${index}: authorization started twice`);
        runs.set(entry.authorizationDigest, entry);
        break;
      case EntryKind.ATTEMPTING:
        if (!run || run.mode !== 'submit' || keyOf(run) !== keyOf(entry)) fail(`entry ${index}: no submit run`);
        if (attemptByAuthorization.has(entry.authorizationDigest)) fail(`entry ${index}: two attempts in one run`);
        attemptByAuthorization.add(entry.authorizationDigest);
        if (!Number.isInteger(entry.attempt) || entry.attempt < 1) fail(`entry ${index}: attempt`);
        attempts.set(entryDigest(entry), { entry, result: null });
        break;
      case EntryKind.RESULT: {
        const attempt = attempts.get(entry.attemptEntry);
        if (!attempt || attempt.result || attempt.entry.authorizationDigest !== entry.authorizationDigest || keyOf(attempt.entry) !== keyOf(entry)) fail(`entry ${index}: result without its attempt`);
        if (![Outcome.NOT_SENT, Outcome.ACCEPTED_PROVISIONAL, Outcome.REJECTED, Outcome.UNCERTAIN].includes(entry.outcome) || typeof entry.code !== 'string') fail(`entry ${index}: outcome`);
        if (typeof entry.record !== 'string' || !DIGEST.test(entry.record)) fail(`entry ${index}: record`);
        attempt.result = entry;
        break;
      }
      case EntryKind.RESOLVED: {
        const attempt = attempts.get(entry.attemptEntry);
        if (!run || run.mode !== 'status' || keyOf(run) !== keyOf(entry)) fail(`entry ${index}: no status run`);
        if (!attempt || keyOf(attempt.entry) !== keyOf(entry)) fail(`entry ${index}: resolves no attempt`);
        if (!RESOLVED_FINDINGS[entry.network].includes(entry.finding)) fail(`entry ${index}: finding`);
        if (typeof entry.record !== 'string' || !DIGEST.test(entry.record)) fail(`entry ${index}: record`);
        break;
      }
    }
    out.push({ entry, digest: entryDigest(entry) });
  });
  return out;
}

/** Refuses an authorization whose digest already started a run (rule 1: every run consumes it). */
export function checkUnused(entries, authorizationDigest) {
  if (entries.some((e) => e.kind === EntryKind.RUN_STARTED && e.authorizationDigest === authorizationDigest)) throw new BroadcastError(C.AUTHORIZATION_USED);
}

/**
 * Decides whether a submit authorization may attempt now (ADR-RN-019 §5 rules 2 to 5), on the
 * log as it stands. Returns nothing, or throws a BroadcastError (LOG_*).
 *
 * Fail-closed refinements, all stricter than the ADR:
 * - after an UNCERTAIN or ACCEPTED_PROVISIONAL result, nothing more is sent for that sequence until
 *   a RESOLVED entry exists (the next step after uncertainty is a status check, ADR §6);
 * - a resend follows only a REJECTED or NOT_SENT result, or a RESOLVED PENDING (Sepolia);
 * - a replacement follows only a RESOLVED EXPIRED (XRPL) or PENDING (Sepolia) of the latest attempt.
 */
export function decideAttempt(log, authorization) {
  const checked = checkLog(log);
  const key = keyOf(authorization);
  const mine = checked.filter(({ entry }) => entry.kind !== EntryKind.RUN_STARTED && keyOf(entry) === key);
  // Rule 5: nothing after inclusion.
  if (mine.some(({ entry }) => entry.kind === EntryKind.RESOLVED && entry.finding === 'INCLUDED')) throw new BroadcastError(C.LOG_ALREADY_INCLUDED);
  const attempts = mine.filter(({ entry }) => entry.kind === EntryKind.ATTEMPTING);
  // Rule 2: every earlier attempt has a result, or has been resolved since.
  for (const attempt of attempts) {
    const later = mine.filter(({ entry }) => entry.index > attempt.entry.index && entry.attemptEntry === attempt.digest);
    if (!later.some(({ entry }) => entry.kind === EntryKind.RESULT || entry.kind === EntryKind.RESOLVED)) throw new BroadcastError(C.LOG_UNRESOLVED_ATTEMPT);
  }
  if (authorization.attempt !== attempts.length + 1) throw new BroadcastError(C.LOG_ATTEMPT_NUMBER, `expected attempt ${attempts.length + 1}`);
  if (attempts.length === 0) return;
  // Rule 3: the link names the latest RESULT or RESOLVED entry for this sequence.
  const outcomes = mine.filter(({ entry }) => entry.kind === EntryKind.RESULT || entry.kind === EntryKind.RESOLVED);
  const latest = outcomes.at(-1);
  if (!latest || authorization.previousAttempt !== latest.digest) throw new BroadcastError(C.LOG_LINK_MISMATCH);
  // Rule 4: a permitted case.
  const last = attempts.at(-1).entry;
  const resolvesLast = latest.entry.kind === EntryKind.RESOLVED && latest.entry.attemptEntry === attempts.at(-1).digest;
  const sameBlob = authorization.intentDigest === last.intentDigest && authorization.blobSha256 === last.blobSha256;
  if (authorization.kind === 'resend') {
    const afterResult = latest.entry.kind === EntryKind.RESULT && [Outcome.REJECTED, Outcome.NOT_SENT].includes(latest.entry.outcome);
    const afterPending = resolvesLast && latest.entry.finding === 'PENDING';
    if (sameBlob && (afterResult || afterPending)) return;
    throw new BroadcastError(C.LOG_CASE_NOT_PERMITTED, 'resend');
  }
  if (authorization.kind === 'replacement') {
    const wanted = authorization.network === SubmitNetwork.XRPL_TESTNET ? 'EXPIRED' : 'PENDING';
    const usedBlob = attempts.some(({ entry }) => entry.blobSha256 === authorization.blobSha256);
    if (!usedBlob && resolvesLast && latest.entry.finding === wanted) return;
    throw new BroadcastError(C.LOG_CASE_NOT_PERMITTED, 'replacement');
  }
  throw new BroadcastError(C.LOG_CASE_NOT_PERMITTED, authorization.kind);
}

/**
 * Finds the ATTEMPTING entry a status authorization names and checks that it matches; returns it.
 * Throws STATUS_MISMATCH.
 */
export function attemptForStatus(log, authorization) {
  const found = checkLog(log).find(({ entry, digest }) => entry.kind === EntryKind.ATTEMPTING && digest === authorization.attemptEntry);
  if (!found) throw new BroadcastError(C.STATUS_MISMATCH, 'no such attempt');
  for (const field of ['network', 'sender', 'sequence', 'transactionHash']) {
    if (found.entry[field] !== authorization[field]) throw new BroadcastError(C.STATUS_MISMATCH, field);
  }
  return found;
}


