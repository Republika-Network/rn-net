// rnnet.broadcast-authorization.v1 and rnnet.status-authorization.v1 (ADR-RN-019 §5;
// spec/rnnet.broadcast.v1.md §2 and §3). Each is written by the founder for one run: a submit
// authorization for one network, one blob and one attempt; a status authorization for one
// read-only status check of one attempt. Each is given as canonical JSON text, and its digest is
// what the submission log consumes.
import { createHash } from 'node:crypto';
import { canonicalBytes, canonicalize, parse } from '../../canonical/src/index.mjs';
import { BroadcastCode, BroadcastError } from './codes.mjs';
import { SubmitNetwork } from './requests.mjs';

export const AUTHORIZATION_FORMAT = 'rnnet.broadcast-authorization.v1';
export const AUTHORIZATION_DIGEST_DOMAIN = 'rnnet:broadcast-authorization:v1\0';
export const STATUS_AUTHORIZATION_FORMAT = 'rnnet.status-authorization.v1';
export const STATUS_AUTHORIZATION_DIGEST_DOMAIN = 'rnnet:status-authorization:v1\0';

export const AUTHORIZATION_FIELDS = Object.freeze([
  'attempt', 'authorizationId', 'blobSha256', 'dryRun', 'format', 'intentDigest', 'kind', 'network', 'previousAttempt',
  'providerId', 'scope', 'sender', 'sequence', 'transactionHash', 'validity',
]);
export const STATUS_AUTHORIZATION_FIELDS = Object.freeze([
  'attemptEntry', 'authorizationId', 'format', 'network', 'providerIds', 'scope', 'sender', 'sequence', 'transactionHash',
]);
/** first: attempt 1. resend: the same blob again. replacement: new gate-D bytes for the same Sequence or nonce. */
export const AUTHORIZATION_KINDS = Object.freeze(['first', 'resend', 'replacement']);
export const MAX_ATTEMPT = 64;

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const AUTHORIZATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$/;
const PROVIDER_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SCOPE = /^[\x20-\x7e]{1,1000}$/;
const SEQUENCE = /^(?:0|[1-9][0-9]{0,19})$/;
const XRPL_ACCOUNT = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const EVM_ADDRESS = /^0x[0-9a-f]{40}$/;
const XRPL_HASH = /^[0-9A-F]{64}$/;
const EVM_HASH = /^0x[0-9a-f]{64}$/;
const UTC_SECOND = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const exactFields = (value, fields) => isObject(value) && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
const invalid = (why) => new BroadcastError(BroadcastCode.AUTHORIZATION_INVALID, why);
const sha256 = (domain, bytes) => `sha256:${createHash('sha256').update(domain).update(bytes).digest('hex')}`;

/** Seconds since the epoch of a "YYYY-MM-DDTHH:MM:SSZ" time, or null if it is not a real UTC second. */
export function utcSeconds(text) {
  const m = typeof text === 'string' ? UTC_SECOND.exec(text) : null;
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number);
  const ms = Date.UTC(y, mo - 1, d, h, mi, s);
  const back = new Date(ms);
  if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d || back.getUTCHours() !== h || back.getUTCMinutes() !== mi || back.getUTCSeconds() !== s) return null;
  return ms / 1000;
}

/** Parses canonical JSON text (optionally followed by one newline); throws AUTHORIZATION_INVALID. */
function parseCanonicalText(text) {
  if (typeof text !== 'string') throw invalid('an authorization is canonical JSON text');
  const body = text.endsWith('\n') ? text.slice(0, -1) : text;
  let value;
  try {
    value = parse(body);
  } catch {
    throw invalid('not rnnet.canonical-json.v1');
  }
  if (canonicalize(value) !== body) throw invalid('not in canonical form');
  return value;
}

function checkSenderAndHash(network, sender, transactionHash) {
  if (network === SubmitNetwork.XRPL_TESTNET) {
    if (typeof sender !== 'string' || !XRPL_ACCOUNT.test(sender)) throw invalid('sender');
    if (typeof transactionHash !== 'string' || !XRPL_HASH.test(transactionHash)) throw invalid('transactionHash');
  } else {
    if (typeof sender !== 'string' || !EVM_ADDRESS.test(sender)) throw invalid('sender');
    if (typeof transactionHash !== 'string' || !EVM_HASH.test(transactionHash)) throw invalid('transactionHash');
  }
}

/**
 * Checks a submit authorization's shape and returns { authorization (frozen plain data), digest }.
 * Its fields are compared with the verified intent and blob later (checkAuthorizationMatch).
 */
export function readAuthorization(text) {
  const a = parseCanonicalText(text);
  if (!exactFields(a, AUTHORIZATION_FIELDS)) throw invalid(`fields must be exactly ${AUTHORIZATION_FIELDS.join(', ')}`);
  if (a.format !== AUTHORIZATION_FORMAT) throw invalid('format');
  if (typeof a.authorizationId !== 'string' || !AUTHORIZATION_ID.test(a.authorizationId)) throw invalid('authorizationId');
  if (!Object.values(SubmitNetwork).includes(a.network)) throw invalid('network');
  if (typeof a.providerId !== 'string' || !PROVIDER_ID.test(a.providerId)) throw invalid('providerId');
  if (!Number.isInteger(a.attempt) || a.attempt < 1 || a.attempt > MAX_ATTEMPT) throw invalid('attempt');
  if (!AUTHORIZATION_KINDS.includes(a.kind)) throw invalid('kind');
  // Attempt 1 is the first and links to nothing; every later attempt links to the log.
  if ((a.attempt === 1) !== (a.kind === 'first')) throw invalid('kind first is exactly attempt 1');
  if (a.attempt === 1 ? a.previousAttempt !== null : typeof a.previousAttempt !== 'string' || !DIGEST.test(a.previousAttempt)) throw invalid('previousAttempt');
  for (const field of ['intentDigest', 'blobSha256']) if (typeof a[field] !== 'string' || !DIGEST.test(a[field])) throw invalid(field);
  checkSenderAndHash(a.network, a.sender, a.transactionHash);
  if (typeof a.sequence !== 'string' || !SEQUENCE.test(a.sequence)) throw invalid('sequence');
  if (a.network === SubmitNetwork.XRPL_TESTNET) {
    if (!exactFields(a.validity, ['lastLedgerSequence']) || !Number.isInteger(a.validity.lastLedgerSequence) || a.validity.lastLedgerSequence < 1 || a.validity.lastLedgerSequence > 0xffff_ffff) {
      throw invalid('validity is { lastLedgerSequence } on XRPL');
    }
  } else if (!exactFields(a.validity, ['notAfter']) || utcSeconds(a.validity.notAfter) === null) {
    throw invalid('validity is { notAfter: "YYYY-MM-DDTHH:MM:SSZ" } on Sepolia');
  }
  if (typeof a.dryRun !== 'boolean') throw invalid('dryRun');
  if (typeof a.scope !== 'string' || !SCOPE.test(a.scope)) throw invalid('scope is 1 to 1000 printable ASCII characters');
  return Object.freeze({ authorization: deepFreeze(a), digest: sha256(AUTHORIZATION_DIGEST_DOMAIN, canonicalBytes(a)) });
}

/** Checks a status authorization's shape; returns { authorization, digest }. */
export function readStatusAuthorization(text) {
  const a = parseCanonicalText(text);
  if (!exactFields(a, STATUS_AUTHORIZATION_FIELDS)) throw invalid(`fields must be exactly ${STATUS_AUTHORIZATION_FIELDS.join(', ')}`);
  if (a.format !== STATUS_AUTHORIZATION_FORMAT) throw invalid('format');
  if (typeof a.authorizationId !== 'string' || !AUTHORIZATION_ID.test(a.authorizationId)) throw invalid('authorizationId');
  if (!Object.values(SubmitNetwork).includes(a.network)) throw invalid('network');
  if (!Array.isArray(a.providerIds) || a.providerIds.length !== 2 || a.providerIds.some((id) => typeof id !== 'string' || !PROVIDER_ID.test(id)) || a.providerIds[0] === a.providerIds[1]) {
    throw invalid('providerIds names the two providers of the network');
  }
  if (typeof a.attemptEntry !== 'string' || !DIGEST.test(a.attemptEntry)) throw invalid('attemptEntry');
  checkSenderAndHash(a.network, a.sender, a.transactionHash);
  if (typeof a.sequence !== 'string' || !SEQUENCE.test(a.sequence)) throw invalid('sequence');
  if (typeof a.scope !== 'string' || !SCOPE.test(a.scope)) throw invalid('scope is 1 to 1000 printable ASCII characters');
  return Object.freeze({ authorization: deepFreeze(a), digest: sha256(STATUS_AUTHORIZATION_DIGEST_DOMAIN, canonicalBytes(a)) });
}

/**
 * Compares every authorization field with what the broadcaster recomputed. `verified` is
 * { network, sender, sequence (decimal string), intentDigest, blobSha256, transactionHash,
 * lastLedgerSequence (XRPL) }. Throws AUTHORIZATION_MISMATCH naming the first field that differs.
 */
export function checkAuthorizationMatch(authorization, verified) {
  const fields = ['network', 'sender', 'sequence', 'intentDigest', 'blobSha256', 'transactionHash'];
  for (const field of fields) if (authorization[field] !== verified[field]) throw new BroadcastError(BroadcastCode.AUTHORIZATION_MISMATCH, field);
  if (verified.network === SubmitNetwork.XRPL_TESTNET && authorization.validity.lastLedgerSequence !== verified.lastLedgerSequence) {
    throw new BroadcastError(BroadcastCode.AUTHORIZATION_MISMATCH, 'validity.lastLedgerSequence');
  }
}

/** Sepolia: whether the authorization is void at `nowSeconds` (after its notAfter time). */
export const sepoliaAuthorizationExpired = (authorization, nowSeconds) => nowSeconds > utcSeconds(authorization.validity.notAfter);
/** XRPL: void once a validated ledger reaches LastLedgerSequence - 4 (ADR-RN-019 §5). */
export const xrplAuthorizationExpired = (authorization, validatedLedger) => validatedLedger >= authorization.validity.lastLedgerSequence - 4;

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const key of Object.keys(value)) deepFreeze(value[key]);
    Object.freeze(value);
  }
  return value;
}
