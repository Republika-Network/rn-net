// rnnet.synthetic-evidence.v1: closed-schema validation in the order the specification fixes
// (spec/rnnet.synthetic-evidence.v1.md §6), and the evidence digest (§4).
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalBytes, parse, PROFILE } from '../../canonical/src/index.mjs';
import { EvidenceError, EvidenceErrorCode as E } from './errors.mjs';

export const FORMAT = 'rnnet.synthetic-evidence.v1';
const FORMAT_FAMILY = 'rnnet.synthetic-evidence.';

export const LIMITS = Object.freeze({
  /** Maximum evidence document size in bytes. */
  maxEvidenceBytes: 262_144,
  /** Maximum canonical size of body.payload in bytes. */
  maxPayloadBytes: 65_536,
  /** Maximum number of signature records. */
  maxSignatures: 16,
});

const DIGEST_TAG = 'rnnet:synthetic-evidence:digest:v1';
const SIGNATURE_TAG = 'rnnet:synthetic-evidence:signature:v1';
/** Domain separators: the ASCII tag followed by one 0x00 byte (§4, §5.2). */
export const DIGEST_DOMAIN_SEPARATOR = Uint8Array.from([...Buffer.from(DIGEST_TAG, 'ascii'), 0]);
export const SIGNATURE_DOMAIN_SEPARATOR = Uint8Array.from([...Buffer.from(SIGNATURE_TAG, 'ascii'), 0]);

const DOCUMENT_FIELDS = ['format', 'canonicalization', 'body', 'digest', 'signatures'];
const DOCUMENT_TYPES = { format: 'string', canonicalization: 'string', body: 'object', digest: 'string', signatures: 'array' };
const BODY_FIELDS = ['evidenceId', 'issuer', 'subject', 'action', 'outcome', 'payload'];
const SIGNATURE_FIELDS = ['keyId', 'algorithm', 'publicKey', 'signature'];
export const OUTCOMES = Object.freeze(['succeeded', 'failed', 'rejected', 'unknown']);

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ACTION = /^(?=.{1,128}$)[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)*$/;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;
const OTHER_DIGEST = /^[a-z0-9]+(-[a-z0-9]+)*:/;
const PUBLIC_KEY_HEX = /^[0-9a-f]{64}$/;
const SIGNATURE_HEX = /^[0-9a-f]{128}$/;

const kind = (value) => (value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value);
const fail = (code, message, subject) => {
  throw new EvidenceError(code, message, subject);
};

/** Unknown members (first in UTF-16 order), then missing members, in table order. */
function checkMembers(object, fields, path) {
  const unknown = Object.keys(object).filter((key) => !fields.includes(key)).sort();
  if (unknown.length > 0) fail(E.UNKNOWN_FIELD, 'Member outside the closed schema.', `${path}${unknown[0]}`);
  for (const field of fields) {
    if (!Object.hasOwn(object, field)) fail(E.MISSING_FIELD, 'Required member is absent.', `${path}${field}`);
  }
}

/**
 * Parses and validates evidence bytes (§6, steps 2-15). Size (step 1) is the caller's.
 * Returns the parsed document; throws EvidenceError, or CanonicalError (RNCJ_*), on the first failure.
 * @param {Uint8Array} bytes
 */
export function parseEvidence(bytes) {
  const document = parse(bytes);
  if (kind(document) !== 'object') fail(E.NOT_OBJECT, 'Evidence must be a JSON object.', '');
  if (!Object.hasOwn(document, 'format')) fail(E.MISSING_FIELD, 'Required member is absent.', 'format');
  if (typeof document.format !== 'string') fail(E.FIELD_TYPE, 'format must be a string.', 'format');
  if (document.format !== FORMAT) {
    const code = document.format.startsWith(FORMAT_FAMILY) ? E.UNSUPPORTED_VERSION : E.UNSUPPORTED_FORMAT;
    fail(code, 'Evidence format not supported by this verifier.', 'format');
  }
  checkMembers(document, DOCUMENT_FIELDS, '');
  for (const field of DOCUMENT_FIELDS) {
    if (kind(document[field]) !== DOCUMENT_TYPES[field]) fail(E.FIELD_TYPE, `${field} must be of type ${DOCUMENT_TYPES[field]}.`, field);
  }
  if (document.canonicalization !== PROFILE) fail(E.UNSUPPORTED_CANONICALIZATION, 'Canonicalization profile not supported.', 'canonicalization');
  if (!SHA256_DIGEST.test(document.digest)) {
    const unsupported = OTHER_DIGEST.test(document.digest) && !document.digest.startsWith('sha256:');
    fail(unsupported ? E.UNSUPPORTED_DIGEST_ALGORITHM : E.INVALID_DIGEST, 'digest is not a sha256 digest.', 'digest');
  }
  checkBody(document.body);
  checkSignatures(document.signatures);
  return document;
}

function checkBody(body) {
  checkMembers(body, BODY_FIELDS, 'body.');
  for (const field of BODY_FIELDS) {
    const expected = field === 'payload' ? 'object' : 'string';
    if (kind(body[field]) !== expected) fail(E.FIELD_TYPE, `body.${field} must be of type ${expected}.`, `body.${field}`);
  }
  for (const field of ['evidenceId', 'issuer', 'subject']) {
    if (!IDENTIFIER.test(body[field])) fail(E.INVALID_FIELD_VALUE, 'Not an identifier.', `body.${field}`);
  }
  if (!ACTION.test(body.action)) fail(E.INVALID_FIELD_VALUE, 'Not an action name.', 'body.action');
  if (!OUTCOMES.includes(body.outcome)) fail(E.INVALID_FIELD_VALUE, 'Not a defined outcome.', 'body.outcome');
  if (canonicalBytes(body.payload).length > LIMITS.maxPayloadBytes) fail(E.PAYLOAD_TOO_LARGE, 'Payload too large.', 'body.payload');
}

function checkSignatures(signatures) {
  if (signatures.length > LIMITS.maxSignatures) fail(E.TOO_MANY_SIGNATURES, 'Too many signature records.', 'signatures');
  signatures.forEach((record, i) => {
    const path = `signatures[${i}]`;
    if (kind(record) !== 'object') fail(E.FIELD_TYPE, 'A signature record must be an object.', path);
    checkMembers(record, SIGNATURE_FIELDS, `${path}.`);
    for (const field of SIGNATURE_FIELDS) {
      if (typeof record[field] !== 'string') fail(E.FIELD_TYPE, `${field} must be a string.`, `${path}.${field}`);
    }
    if (record.algorithm !== 'ed25519') fail(E.UNSUPPORTED_SIGNATURE_ALGORITHM, 'Signature algorithm not supported.', `${path}.algorithm`);
    if (!IDENTIFIER.test(record.keyId)) fail(E.INVALID_FIELD_VALUE, 'Not an identifier.', `${path}.keyId`);
    if (!PUBLIC_KEY_HEX.test(record.publicKey)) fail(E.INVALID_PUBLIC_KEY_ENCODING, 'Not 64 lowercase hex digits.', `${path}.publicKey`);
    if (!SIGNATURE_HEX.test(record.signature)) fail(E.INVALID_SIGNATURE_ENCODING, 'Not 128 lowercase hex digits.', `${path}.signature`);
  });
  for (let i = 1; i < signatures.length; i++) {
    const [previous, current] = [signatures[i - 1].keyId, signatures[i].keyId];
    if (previous === current) fail(E.DUPLICATE_KEY_ID, 'keyId repeated.', `signatures[${i}].keyId`);
    if (previous > current) fail(E.SIGNATURES_NOT_SORTED, 'Records not in ascending keyId order.', `signatures[${i}].keyId`);
  }
  const seen = new Set();
  signatures.forEach((record, i) => {
    if (seen.has(record.publicKey)) fail(E.DUPLICATE_PUBLIC_KEY, 'publicKey repeated.', `signatures[${i}].publicKey`);
    seen.add(record.publicKey);
  });
}

/** The 32 raw bytes of the evidence digest of a body (§4). */
export function evidenceDigestBytes(body) {
  return new Uint8Array(createHash('sha256').update(DIGEST_DOMAIN_SEPARATOR).update(canonicalBytes(body)).digest());
}

/** The evidence digest of a body as `sha256:<hex>` (§4). */
export function computeEvidenceDigest(body) {
  return `sha256:${Buffer.from(evidenceDigestBytes(body)).toString('hex')}`;
}

/** The exact bytes a signature record signs, given the 32 digest bytes (§5.2). */
export function signingMessage(digestBytes) {
  if (!(digestBytes instanceof Uint8Array) || digestBytes.length !== 32) throw new TypeError('digestBytes must be 32 bytes.');
  return Uint8Array.from([...SIGNATURE_DOMAIN_SEPARATOR, ...digestBytes]);
}
