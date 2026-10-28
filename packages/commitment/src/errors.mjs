// Error codes of rnnet.evidence-commitment.v1 (spec/rnnet.evidence-commitment.v1.md §7).
// Canonicalization failures keep their RNCJ_* code from the canonical package.

export const CommitmentErrorCode = Object.freeze({
  NOT_OBJECT: 'RNEC_NOT_OBJECT',
  UNKNOWN_FIELD: 'RNEC_UNKNOWN_FIELD',
  MISSING_FIELD: 'RNEC_MISSING_FIELD',
  FIELD_TYPE: 'RNEC_FIELD_TYPE',
  UNSUPPORTED_FORMAT: 'RNEC_UNSUPPORTED_FORMAT',
  UNSUPPORTED_VERSION: 'RNEC_UNSUPPORTED_VERSION',
  INVALID_SOURCE_FORMAT: 'RNEC_INVALID_SOURCE_FORMAT',
  INVALID_CANONICALIZATION_ID: 'RNEC_INVALID_CANONICALIZATION_ID',
  INVALID_DIGEST: 'RNEC_INVALID_DIGEST',
  INVALID_SOURCE_REF: 'RNEC_INVALID_SOURCE_REF',
  INVALID_COMMITMENT_DIGEST: 'RNEC_INVALID_COMMITMENT_DIGEST',
  DIGEST_MISMATCH: 'RNEC_DIGEST_MISMATCH',
  SOURCE_FILE_MISMATCH: 'RNEC_SOURCE_FILE_MISMATCH',
});

export class CommitmentError extends Error {
  /**
   * @param {string} code one of CommitmentErrorCode
   * @param {string} message
   * @param {string} [field] the envelope field concerned, when there is one
   */
  constructor(code, message, field) {
    super(message);
    this.name = 'CommitmentError';
    this.code = code;
    if (field !== undefined) this.field = field;
  }
}
