// rnnet.preparation-authorization.v1 (RN-NET-03B2-C3; spec/rnnet.preparation-authorization.v1.md).
// The founder's written authorization of ONE read-only preparation run: one network, the two
// reviewed providers in the order they are read, the sender (and, on XRPL, its public key), the
// Genesis commitment, the exact request count and a time after which it is void. It authorizes
// reads only: no key, no signature and no write. It is given as canonical JSON text; its digest is
// SHA-256 over a domain tag and the canonical bytes, and the founder approves a run by typing the
// last 16 hex digits of that digest.
import { createHash } from 'node:crypto';
import { canonicalBytes, canonicalize, parse } from '../../packages/canonical/src/index.mjs';
import { IntentNetwork, PURPOSES } from '../../packages/tx-intent/src/index.mjs';

export const PREPARATION_AUTHORIZATION_FORMAT = 'rnnet.preparation-authorization.v1';
export const PREPARATION_AUTHORIZATION_DOMAIN = 'rnnet:preparation-authorization:v1\0';
export const PREPARATION_AUTHORIZATION_FIELDS = Object.freeze([
  'authorizationId', 'commitment', 'format', 'network', 'notAfter', 'providerIds', 'purpose', 'requestBudget', 'scope', 'sender', 'signingPubKey',
]);

const AUTHORIZATION_ID = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const COMMITMENT = /^sha256:[0-9a-f]{64}$/;
const PROVIDER_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SCOPE = /^[\x20-\x7e]{1,1000}$/;
const XRPL_ACCOUNT = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const XRPL_SIGNING_KEY = /^ED[0-9A-F]{64}$/;
const EVM_ADDRESS = /^0x[0-9a-f]{40}$/;
const UTC_SECOND = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;

/** A refusal of the authorization text, with one detail. */
export class PreparationAuthorizationError extends Error {
  constructor(detail) {
    super(`RNPL_AUTHORIZATION: ${detail}`);
    this.name = 'PreparationAuthorizationError';
    this.detail = detail;
  }
}
const invalid = (detail) => new PreparationAuthorizationError(detail);
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

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

/** The authorization digest: SHA-256 over the domain tag and the canonical bytes. */
export const preparationAuthorizationDigest = (authorization) =>
  `sha256:${createHash('sha256').update(PREPARATION_AUTHORIZATION_DOMAIN).update(canonicalBytes(authorization)).digest('hex')}`;

/**
 * Checks the text of a preparation authorization (canonical JSON, optionally followed by one
 * newline) and returns { authorization (frozen), digest }. Shape only: whether it matches this
 * run (network, providers, budget, time, commitment) is checked by the entry point.
 */
export function readPreparationAuthorization(text) {
  if (typeof text !== 'string') throw invalid('the authorization is canonical JSON text');
  const body = text.endsWith('\n') ? text.slice(0, -1) : text;
  let a;
  try {
    a = parse(body);
  } catch {
    throw invalid('not rnnet.canonical-json.v1');
  }
  if (canonicalize(a) !== body) throw invalid('not in canonical form');
  if (!isObject(a) || Object.keys(a).sort().join(',') !== PREPARATION_AUTHORIZATION_FIELDS.join(',')) throw invalid(`fields must be exactly ${PREPARATION_AUTHORIZATION_FIELDS.join(', ')}`);
  if (a.format !== PREPARATION_AUTHORIZATION_FORMAT) throw invalid('format');
  if (typeof a.authorizationId !== 'string' || !AUTHORIZATION_ID.test(a.authorizationId)) throw invalid('authorizationId is 1 to 64 lower-case letters, digits and inner hyphens');
  if (!Object.values(IntentNetwork).includes(a.network)) throw invalid('network');
  if (!PURPOSES.includes(a.purpose)) throw invalid('purpose');
  if (typeof a.commitment !== 'string' || !COMMITMENT.test(a.commitment)) throw invalid('commitment');
  if (!Array.isArray(a.providerIds) || a.providerIds.length !== 2 || a.providerIds.some((id) => typeof id !== 'string' || !PROVIDER_ID.test(id)) || a.providerIds[0] === a.providerIds[1]) {
    throw invalid('providerIds is two different provider ids, in reading order');
  }
  if (a.network === IntentNetwork.XRPL_TESTNET) {
    if (typeof a.sender !== 'string' || !XRPL_ACCOUNT.test(a.sender)) throw invalid('sender is a classic address on XRPL');
    if (typeof a.signingPubKey !== 'string' || !XRPL_SIGNING_KEY.test(a.signingPubKey)) throw invalid('signingPubKey is ED + 64 upper-case hex on XRPL');
  } else {
    if (typeof a.sender !== 'string' || !EVM_ADDRESS.test(a.sender)) throw invalid('sender is a lower-case address on Sepolia');
    if (a.signingPubKey !== null) throw invalid('signingPubKey is null on Sepolia');
  }
  if (!Number.isSafeInteger(a.requestBudget) || a.requestBudget < 1) throw invalid('requestBudget is a positive integer');
  if (utcSeconds(a.notAfter) === null) throw invalid('notAfter is "YYYY-MM-DDTHH:MM:SSZ"');
  if (typeof a.scope !== 'string' || !SCOPE.test(a.scope)) throw invalid('scope is 1 to 1000 printable ASCII characters');
  const frozen = Object.freeze({ ...a, providerIds: Object.freeze([...a.providerIds]) });
  return Object.freeze({ authorization: frozen, digest: preparationAuthorizationDigest(a) });
}
