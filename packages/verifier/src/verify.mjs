// The independent evidence verifier: rnnet.synthetic-evidence.v1 in, an
// rnnet.verification-report.v1 report out (spec/rnnet.verification-report.v1.md).
// Offline and deterministic: it reads only the bytes it is given, holds no keys and consults
// no trust source.
import { Buffer } from 'node:buffer';
import { canonicalBytes, PROFILE } from '../../canonical/src/index.mjs';
import { Classification as C, CommitmentErrorCode, sha256Digest, statement, TAXONOMY, verifyCommitment } from '../../commitment/src/index.mjs';
import { verifyEd25519, SignatureResult } from './ed25519.mjs';
import { EvidenceError, EvidenceErrorCode as E, UNSUPPORTED_CODES } from './errors.mjs';
import { evidenceDigestBytes, FORMAT, LIMITS, parseEvidence, signingMessage } from './evidence.mjs';

export const REPORT_FORMAT = 'rnnet.verification-report.v1';

export const Outcome = Object.freeze({
  PASS: 'PASS',
  FAIL: 'FAIL',
  UNSUPPORTED: 'UNSUPPORTED',
  /** Reserved; not produced in v1. */
  INDETERMINATE: 'INDETERMINATE',
});

// Fixed bases (report spec §6): a report never carries free text from its input.
const BASIS = Object.freeze({
  digest: 'Recomputed from the supplied body under rnnet.synthetic-evidence.v1.',
  claim: 'Stated in the evidence and bound by its digest; not checked against anything else.',
  event: 'Nothing in the evidence can show that the described event happened.',
  noSignatures: 'No signatures were supplied; nothing is known about who produced the evidence.',
  embeddedKey: 'The signature verifies under a public key carried by the evidence itself.',
  signer: 'No trust source binds this public key to an identity.',
  commitment: 'Recomputed from the supplied envelope and equal to the presented commitment.',
  member: 'Equal to the value the verifier established from the supplied evidence.',
  sourceRef: 'An identifier only; it was not dereferenced.',
});
const CLAIMS = ['issuer', 'subject', 'action', 'outcome', 'payload'];
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;

const finding = (code, subject) =>
  Object.freeze({ code, severity: UNSUPPORTED_CODES.has(code) ? 'unsupported' : 'error', subject });

/** Reads and checks the options once (a TypeError is a programming error, not a finding). */
function readOptions(options) {
  if (options === null || typeof options !== 'object') throw new TypeError('options must be an object.');
  const commitment = options.commitment;
  if (commitment === undefined) return { commitment: undefined };
  if (commitment === null || typeof commitment !== 'object') throw new TypeError('options.commitment must be an object.');
  const envelope = commitment.envelope;
  const digest = commitment.digest;
  if (typeof digest !== 'string') throw new TypeError('options.commitment.digest must be a string.');
  return { commitment: { envelope: snapshotBytes(envelope, 'options.commitment.envelope'), digest } };
}

/**
 * One copy of the caller's bytes, taken through the typed-array internals: a Proxy around a
 * Uint8Array passes instanceof but is refused here, so every later step reads the same bytes.
 */
function snapshotBytes(value, name) {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${name} must be a Uint8Array.`);
  try {
    return new Uint8Array(Uint8Array.prototype.slice.call(value));
  } catch {
    throw new TypeError(`${name} must be a Uint8Array.`);
  }
}

/**
 * Verifies an rnnet.synthetic-evidence.v1 document.
 * @param {Uint8Array} evidenceBytes the exact bytes of the evidence file
 * @param {{ commitment?: { envelope: Uint8Array, digest: string } }} [options] an
 *   rnnet.evidence-commitment.v1 envelope's bytes and the commitment presented for it
 * @returns {Readonly<object>} an rnnet.verification-report.v1 report
 */
export function verifyEvidence(evidenceBytes, options = {}) {
  const { commitment } = readOptions(options);
  const bytes = snapshotBytes(evidenceBytes, 'evidenceBytes');
  const report = {
    format: REPORT_FORMAT,
    profile: FORMAT,
    taxonomy: TAXONOMY,
    outcome: Outcome.PASS,
    input: { sha256: sha256Digest(bytes) },
    findings: [],
    statements: [],
  };

  let document;
  try {
    if (bytes.length > LIMITS.maxEvidenceBytes) throw new EvidenceError(E.EVIDENCE_TOO_LARGE, 'Evidence too large.', '');
    document = parseEvidence(bytes);
  } catch (error) {
    if (typeof error?.code !== 'string' || !/^RN(SE|CJ)_/.test(error.code)) throw error;
    report.findings.push(finding(error.code, error.subject ?? ''));
    report.outcome = UNSUPPORTED_CODES.has(error.code) ? Outcome.UNSUPPORTED : Outcome.FAIL;
    return freeze(report);
  }

  const { body } = document;
  const digestBytes = evidenceDigestBytes(body);
  const computedDigest = `sha256:${Buffer.from(digestBytes).toString('hex')}`;
  const digestMatches = computedDigest === document.digest;
  report.evidence = { evidenceId: body.evidenceId, declaredDigest: document.digest, computedDigest };
  if (digestMatches) {
    report.statements.push(statement('evidenceDigest', C.VERIFIED, BASIS.digest));
    for (const claim of CLAIMS) report.statements.push(statement(`body.${claim}`, C.CLAIMED, BASIS.claim));
  } else {
    report.findings.push(finding(E.DIGEST_MISMATCH, 'digest'));
  }
  report.statements.push(statement('eventOccurrence', C.UNRESOLVED, BASIS.event));

  // Every record is verified against the recomputed digest, whatever happened before.
  const message = signingMessage(digestBytes);
  report.signatures = document.signatures.map((record, i) => {
    const result = verifyEd25519(Buffer.from(record.publicKey, 'hex'), Buffer.from(record.signature, 'hex'), message);
    if (result === SignatureResult.KEY_REJECTED) report.findings.push(finding(E.PUBLIC_KEY_REJECTED, `signatures[${i}]`));
    if (result === SignatureResult.INVALID) report.findings.push(finding(E.SIGNATURE_INVALID, `signatures[${i}]`));
    return { keyId: record.keyId, publicKey: record.publicKey, result };
  });
  if (document.signatures.length === 0) report.statements.push(statement('signatures', C.UNRESOLVED, BASIS.noSignatures));
  report.signatures.forEach(({ result }, i) => {
    if (result === SignatureResult.VALID) report.statements.push(statement(`signatures[${i}]`, C.CONSISTENT_UNDER_EMBEDDED_KEYS, BASIS.embeddedKey));
  });
  report.signatures.forEach((_, i) => report.statements.push(statement(`signerIdentity[${i}]`, C.UNRESOLVED, BASIS.signer)));

  if (commitment !== undefined) {
    report.commitment = checkCommitment(commitment, { bytes, computedDigest }, report);
  }
  if (report.findings.length > 0) report.outcome = Outcome.FAIL;
  return freeze(report);
}

/** Commitment comparison (evidence spec §7 step 3); each envelope member is compared separately. */
function checkCommitment({ envelope, digest }, established, report) {
  const section = { result: 'MATCH' };
  if (SHA256_DIGEST.test(digest)) section.presentedDigest = digest;
  const verified = verifyCommitment(envelope, digest);
  const valid = verified.valid === true;
  if (!valid) {
    const subject = verified.code === CommitmentErrorCode.INVALID_COMMITMENT_DIGEST || verified.code === CommitmentErrorCode.DIGEST_MISMATCH
      ? 'commitment.presentedDigest'
      : 'commitment';
    report.findings.push(finding(verified.code, subject));
    section.result = 'MISMATCH';
  }
  const value = verified.commitment?.envelope; // present whenever the envelope itself is valid
  if (value === undefined) return section;
  if (valid) report.statements.push(statement('commitment', C.VERIFIED, BASIS.commitment));
  const expected = [
    ['sourceFormat', FORMAT, E.COMMITMENT_SOURCE_FORMAT_MISMATCH],
    ['sourceCanonicalization', PROFILE, E.COMMITMENT_CANONICALIZATION_MISMATCH],
    ['sourceEvidenceDigest', established.computedDigest, E.COMMITMENT_EVIDENCE_DIGEST_MISMATCH],
    ['sourceFileSha256', report.input.sha256, E.COMMITMENT_SOURCE_FILE_MISMATCH],
  ];
  for (const [member, wanted, code] of expected) {
    if (value[member] === wanted) {
      if (valid) report.statements.push(statement(`commitment.${member}`, C.VERIFIED, BASIS.member));
    } else {
      report.findings.push(finding(code, `commitment.${member}`));
      section.result = 'MISMATCH';
    }
  }
  section.sourceRef = value.sourceRef;
  report.statements.push(statement('commitment.sourceRef', C.UNRESOLVED, BASIS.sourceRef));
  return section;
}

function freeze(report) {
  // Round-trip through canonical JSON: the report is plain data, and its bytes are fixed.
  return deepFreeze(JSON.parse(new TextDecoder().decode(canonicalBytes(report))));
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/** The report's exact bytes under rnnet.canonical-json.v1. */
export function encodeReport(report) {
  return canonicalBytes(report);
}
