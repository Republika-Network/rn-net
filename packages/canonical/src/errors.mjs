// Error codes of the rnnet.canonical-json.v1 profile. The codes are part of the
// specification (spec/rnnet.canonical-json.v1.md §6); messages are not.

export const CanonicalErrorCode = Object.freeze({
  INVALID_UTF8: 'RNCJ_INVALID_UTF8',
  BOM: 'RNCJ_BOM',
  SIZE_EXCEEDED: 'RNCJ_SIZE_EXCEEDED',
  SYNTAX: 'RNCJ_SYNTAX',
  TRAILING_CONTENT: 'RNCJ_TRAILING_CONTENT',
  DUPLICATE_KEY: 'RNCJ_DUPLICATE_KEY',
  LONE_SURROGATE: 'RNCJ_LONE_SURROGATE',
  NUMBER_NOT_INTEGER: 'RNCJ_NUMBER_NOT_INTEGER',
  NUMBER_OUT_OF_RANGE: 'RNCJ_NUMBER_OUT_OF_RANGE',
  NEGATIVE_ZERO: 'RNCJ_NEGATIVE_ZERO',
  DEPTH_EXCEEDED: 'RNCJ_DEPTH_EXCEEDED',
  UNSUPPORTED_VALUE: 'RNCJ_UNSUPPORTED_VALUE',
});

export class CanonicalError extends Error {
  /**
   * @param {string} code one of CanonicalErrorCode
   * @param {string} message
   * @param {{ offset?: number, path?: string }} [where]
   */
  constructor(code, message, where = {}) {
    super(message);
    this.name = 'CanonicalError';
    this.code = code;
    if (where.offset !== undefined) this.offset = where.offset;
    if (where.path !== undefined) this.path = where.path;
  }
}
