// Closed-schema validation of the rnnet.evidence-commitment.v1 envelope (spec §3–§4).
// Checks run in the order the specification fixes, so every conforming implementation
// reports the same first error for the same input.
import { canonicalize, parse } from '../../canonical/src/index.mjs';
import { CommitmentError, CommitmentErrorCode as E } from './errors.mjs';

export const FORMAT = 'rnnet.evidence-commitment.v1';
const FORMAT_FAMILY = 'rnnet.evidence-commitment.';

/** Envelope fields, in specification order. */
export const FIELDS = Object.freeze([
  'format',
  'sourceFormat',
  'sourceCanonicalization',
  'sourceEvidenceDigest',
  'sourceFileSha256',
  'sourceRef',
]);

const FORMAT_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)+$/;
const CANONICALIZATION_ID = /^[a-z0-9]+(?:[._/-][a-z0-9]+)*$/;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;
const SOURCE_REF = /^[a-z][a-z0-9+.-]*:[\x21-\x7e]+$/;

const MAX_IDENTIFIER = 128;
const MAX_SOURCE_REF = 512;

export const isSha256Digest = (value) => typeof value === 'string' && SHA256_DIGEST.test(value);

/**
 * Validates an envelope given as an in-memory value and returns a frozen copy containing
 * exactly the six fields (spec §4.1). The value is first snapshotted through canonical
 * serialization, which reads each property once and rejects accessors, Proxies' changing
 * answers and anything without a JSON representation (RNCJ_* errors); only that snapshot is
 * validated. A getter can therefore never show one value to validation and another to hashing.
 * @param {unknown} value
 * @returns {Readonly<Record<string, string>>}
 */
export function validateEnvelope(value) {
  return validateParsedEnvelope(parse(canonicalize(value)));
}

/**
 * Validates a value produced by the strict parser: plain data only, no accessors.
 * @param {unknown} value
 * @returns {Readonly<Record<string, string>>}
 */
export function validateParsedEnvelope(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new CommitmentError(E.NOT_OBJECT, 'The envelope must be a JSON object.');
  }

  const unknown = Object.keys(value).filter((key) => !FIELDS.includes(key)).sort();
  if (unknown.length > 0) throw new CommitmentError(E.UNKNOWN_FIELD, 'The envelope has an unknown field.', unknown[0]);

  for (const field of FIELDS) {
    if (!Object.hasOwn(value, field)) throw new CommitmentError(E.MISSING_FIELD, 'A required field is missing.', field);
  }
  for (const field of FIELDS) {
    if (typeof value[field] !== 'string') throw new CommitmentError(E.FIELD_TYPE, 'Every field must be a string.', field);
  }

  if (value.format !== FORMAT) {
    const code = value.format.startsWith(FORMAT_FAMILY) ? E.UNSUPPORTED_VERSION : E.UNSUPPORTED_FORMAT;
    throw new CommitmentError(code, `Expected format ${FORMAT}.`, 'format');
  }
  if (!matches(value.sourceFormat, FORMAT_ID, MAX_IDENTIFIER)) {
    throw new CommitmentError(E.INVALID_SOURCE_FORMAT, 'Invalid source format identifier.', 'sourceFormat');
  }
  if (!matches(value.sourceCanonicalization, CANONICALIZATION_ID, MAX_IDENTIFIER)) {
    throw new CommitmentError(E.INVALID_CANONICALIZATION_ID, 'Invalid canonicalization identifier.', 'sourceCanonicalization');
  }
  for (const field of ['sourceEvidenceDigest', 'sourceFileSha256']) {
    if (!isSha256Digest(value[field])) throw new CommitmentError(E.INVALID_DIGEST, 'Expected sha256:<64 lowercase hex>.', field);
  }
  if (!matches(value.sourceRef, SOURCE_REF, MAX_SOURCE_REF)) {
    throw new CommitmentError(E.INVALID_SOURCE_REF, 'Invalid source reference.', 'sourceRef');
  }

  return Object.freeze(Object.fromEntries(FIELDS.map((field) => [field, value[field]])));
}

const matches = (value, pattern, maxLength) => value.length <= maxLength && pattern.test(value);
