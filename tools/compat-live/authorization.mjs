// rnnet.compat-authorization.v1 (RN-NET-03B2-C6-LIVE; spec/rnnet.compat-authorization.v1.md).
// The founder's written H3 authorization of ONE read-only C6 provider compatibility run: the exact
// manifest (by its canonical SHA-256), the four reviewed providers at their reviewed URLs with their
// per-provider request counts, the total of 22 requests, the private evidence directory, "no
// publication" and a time after which it is void. It authorizes reads only: no key, no signature,
// no write, no funding and no publication. Its digest is SHA-256 over a domain tag and its canonical
// bytes; the founder approves the run by typing `c6` and the digest's last 16 hex digits.
import { createHash } from 'node:crypto';
import { canonicalBytes, canonicalize, parse } from '../../packages/canonical/src/index.mjs';

export const COMPAT_AUTHORIZATION_FORMAT = 'rnnet.compat-authorization.v1';
export const COMPAT_AUTHORIZATION_DOMAIN = 'rnnet:compat-authorization:v1\0';
export const COMPAT_AUTHORIZATION_FIELDS = Object.freeze(['authorizationId', 'evidenceDir', 'format', 'manifestSha256', 'notAfter', 'providers', 'publication', 'requestBudget', 'scope']);
export const COMPAT_PROVIDER_FIELDS = Object.freeze(['id', 'requests', 'url']);

const AUTHORIZATION_ID = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const PROVIDER_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const URL_TEXT = /^https:\/\/[\x21-\x7e]{1,200}$/;
const ABSOLUTE_DIR = /^\/[A-Za-z0-9._/-]{1,255}$/;
const SCOPE = /^[\x20-\x7e]{1,1000}$/;
const UTC_SECOND = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;

/** A refusal of the authorization text, with one detail. */
export class CompatAuthorizationError extends Error {
  constructor(detail) {
    super(`RNCL_AUTHORIZATION: ${detail}`);
    this.name = 'CompatAuthorizationError';
    this.detail = detail;
  }
}
const invalid = (detail) => new CompatAuthorizationError(detail);
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const keysAre = (v, fields) => Object.keys(v).sort().join(',') === fields.join(',');

/** Seconds since the epoch of a "YYYY-MM-DDTHH:MM:SSZ" time, or null if it is not a real UTC second. */
export function utcSeconds(text) {
  const m = typeof text === 'string' ? UTC_SECOND.exec(text) : null;
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number);
  const back = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
  if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d || back.getUTCHours() !== h || back.getUTCMinutes() !== mi || back.getUTCSeconds() !== s) return null;
  return back.getTime() / 1000;
}

/** The authorization digest: SHA-256 over the domain tag and the canonical bytes. */
export const compatAuthorizationDigest = (authorization) =>
  `sha256:${createHash('sha256').update(COMPAT_AUTHORIZATION_DOMAIN).update(canonicalBytes(authorization)).digest('hex')}`;

/**
 * Checks the text of a C6 authorization (canonical JSON, optionally followed by one newline) and
 * returns { authorization (frozen), digest }. Shape only: whether it binds THIS manifest, these
 * providers and this budget, and whether it is still valid, is checked by the entry point.
 */
export function readCompatAuthorization(text) {
  if (typeof text !== 'string') throw invalid('the authorization is canonical JSON text');
  const body = text.endsWith('\n') ? text.slice(0, -1) : text;
  let a;
  try {
    a = parse(body);
  } catch {
    throw invalid('not rnnet.canonical-json.v1');
  }
  if (canonicalize(a) !== body) throw invalid('not in canonical form');
  if (!isObject(a) || !keysAre(a, COMPAT_AUTHORIZATION_FIELDS)) throw invalid(`fields must be exactly ${COMPAT_AUTHORIZATION_FIELDS.join(', ')}`);
  if (a.format !== COMPAT_AUTHORIZATION_FORMAT) throw invalid('format');
  if (typeof a.authorizationId !== 'string' || !AUTHORIZATION_ID.test(a.authorizationId)) throw invalid('authorizationId is 1 to 64 lower-case letters, digits and inner hyphens');
  if (typeof a.manifestSha256 !== 'string' || !DIGEST.test(a.manifestSha256)) throw invalid('manifestSha256 is sha256: and 64 lower-case hex digits');
  if (!Array.isArray(a.providers) || a.providers.length !== 4) throw invalid('providers lists the four providers, in manifest order');
  for (const p of a.providers) {
    if (!isObject(p) || !keysAre(p, COMPAT_PROVIDER_FIELDS)) throw invalid(`each provider is exactly ${COMPAT_PROVIDER_FIELDS.join(', ')}`);
    if (typeof p.id !== 'string' || !PROVIDER_ID.test(p.id)) throw invalid('provider id');
    if (typeof p.url !== 'string' || !URL_TEXT.test(p.url)) throw invalid('provider url is an https URL');
    if (!Number.isSafeInteger(p.requests) || p.requests < 1) throw invalid('provider requests is a positive integer');
  }
  if (new Set(a.providers.map((p) => p.id)).size !== 4) throw invalid('provider ids are distinct');
  if (!Number.isSafeInteger(a.requestBudget) || a.requestBudget < 1) throw invalid('requestBudget is a positive integer');
  if (a.providers.reduce((n, p) => n + p.requests, 0) !== a.requestBudget) throw invalid('requestBudget is the sum of the provider requests');
  if (typeof a.evidenceDir !== 'string' || !ABSOLUTE_DIR.test(a.evidenceDir) || a.evidenceDir.split('/').some((s, i) => (i > 0 && s === '') || s === '.' || s === '..')) {
    throw invalid('evidenceDir is a normalized absolute path');
  }
  if (a.publication !== 'none') throw invalid('publication is "none": this authorization publishes nothing');
  if (utcSeconds(a.notAfter) === null) throw invalid('notAfter is "YYYY-MM-DDTHH:MM:SSZ"');
  if (typeof a.scope !== 'string' || !SCOPE.test(a.scope)) throw invalid('scope is 1 to 1000 printable ASCII characters');
  const frozen = Object.freeze({ ...a, providers: Object.freeze(a.providers.map((p) => Object.freeze({ ...p }))) });
  return Object.freeze({ authorization: frozen, digest: compatAuthorizationDigest(a) });
}
