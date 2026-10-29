// rnnet.evidence-commitment.v1 digest construction and verification (spec §5–§6).
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalize, CanonicalError, CanonicalErrorCode, parse, PROFILE } from '../../canonical/src/index.mjs';
import { CommitmentErrorCode as E } from './errors.mjs';
import { FORMAT, isSha256Digest, validateEnvelope, validateParsedEnvelope } from './envelope.mjs';
import { Classification as C, statement } from './taxonomy.mjs';

/** Domain separator: ASCII tag followed by one 0x00 byte (spec §5.1). */
export const DOMAIN_TAG = 'rnnet:evidence-commitment:v1';
export const DOMAIN_SEPARATOR = Uint8Array.from([...Buffer.from(DOMAIN_TAG, 'ascii'), 0x00]);

const sha256 = (...chunks) => {
  const hash = createHash('sha256');
  for (const chunk of chunks) hash.update(chunk);
  return hash.digest();
};

/** sha256:<hex> of arbitrary bytes, the representation used for every digest in v1. */
export const sha256Digest = (bytes) => `sha256:${sha256(bytes).toString('hex')}`;

/** Hashes a validated, frozen envelope; the only place a commitment digest is computed. */
function commit(envelope) {
  const canonical = canonicalize(envelope);
  const digestBytes = sha256(DOMAIN_SEPARATOR, Buffer.from(canonical, 'utf8'));
  return Object.freeze({
    envelope,
    canonical,
    digest: `sha256:${digestBytes.toString('hex')}`,
    digestBytes: new Uint8Array(digestBytes),
  });
}

/**
 * Computes the commitment for an envelope given as an in-memory value. The value is
 * snapshotted once (see validateEnvelope); the digest covers exactly the validated snapshot.
 * @returns {Readonly<{ envelope: Readonly<Record<string,string>>, canonical: string, digest: string, digestBytes: Uint8Array }>}
 */
export function computeCommitment(envelopeValue) {
  return commit(validateEnvelope(envelopeValue));
}

/**
 * Parses envelope bytes under the strict profile and computes their commitment.
 * Only bytes are accepted: a string may already have lost information (for example, invalid
 * UTF-8 decoded to U+FFFD), so it cannot stand for the bytes that were committed.
 * @param {Uint8Array} bytes
 */
export function commitmentFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new CanonicalError(CanonicalErrorCode.UNSUPPORTED_VALUE, 'Envelope input must be bytes (Uint8Array).');
  }
  return commit(validateParsedEnvelope(parse(bytes)));
}

/**
 * Verifies a presented commitment digest against envelope bytes, and optionally recomputes
 * the source file digest. Every defect in the envelope bytes or the presented digest is
 * returned as a code. It throws a TypeError only for invalid options, a programming error.
 * @param {Uint8Array} envelopeBytes
 * @param {string} presentedDigest
 * @param {{ sourceFile?: Uint8Array }} [options]
 */
export function verifyCommitment(envelopeBytes, presentedDigest, options = {}) {
  if (options === null || typeof options !== 'object') throw new TypeError('options must be an object.');
  const sourceFile = options.sourceFile; // read once
  if (sourceFile !== undefined && !(sourceFile instanceof Uint8Array)) {
    throw new TypeError('options.sourceFile must be a Uint8Array.');
  }
  if (!isSha256Digest(presentedDigest)) {
    return failure(E.INVALID_COMMITMENT_DIGEST, 'The presented commitment is not sha256:<64 lowercase hex>.');
  }
  let commitment;
  try {
    commitment = commitmentFromBytes(envelopeBytes);
  } catch (error) {
    if (typeof error?.code === 'string' && /^RN(CJ|EC)_/.test(error.code)) {
      return failure(error.code, error.message, error.field);
    }
    throw error;
  }
  if (commitment.digest !== presentedDigest) {
    return failure(E.DIGEST_MISMATCH, 'The recomputed commitment differs from the presented one.', undefined, commitment);
  }

  const statements = [
    statement('commitment', C.VERIFIED, `Recomputed from the envelope under ${PROFILE} with domain separator ${DOMAIN_TAG}.`),
    statement('sourceFormat', C.CLAIMED, 'Bound by the commitment; not checked against the source.'),
    statement('sourceCanonicalization', C.CLAIMED, 'Bound by the commitment; the source was not canonicalized.'),
    statement('sourceEvidenceDigest', C.CLAIMED, 'Bound by the commitment; not recomputed from the source evidence.'),
    statement('sourceFileSha256', C.CLAIMED, 'Bound by the commitment; no source file was supplied.'),
    statement('sourceRef', C.UNRESOLVED, 'An identifier only; it was not dereferenced and does not show authenticity.'),
  ];

  if (sourceFile !== undefined) {
    if (sha256Digest(sourceFile) !== commitment.envelope.sourceFileSha256) {
      return failure(E.SOURCE_FILE_MISMATCH, 'The supplied source file does not match sourceFileSha256.', 'sourceFileSha256', commitment);
    }
    statements[4] = statement('sourceFileSha256', C.VERIFIED, 'Recomputed from the supplied source file bytes.');
  }

  return { valid: true, format: FORMAT, commitment, statements };
}

function failure(code, message, field, commitment) {
  const result = { valid: false, code, message };
  if (field !== undefined) result.field = field;
  if (commitment !== undefined) result.commitment = commitment;
  return result;
}

