// Error codes of read-only transaction preparation (RN-NET-03B2-B2, ADR-RN-018). Every refusal
// carries exactly one stable code, so tests and the independent Python reference can assert the
// reason, not only that preparation failed. Preparation fails closed: any refusal means no intent.

export const PrepErrorCode = Object.freeze({
  INPUT_INVALID: 'RNTP_INPUT_INVALID',
  PROVIDER_UNAVAILABLE: 'RNTP_PROVIDER_UNAVAILABLE',
  PROVIDER_ERROR: 'RNTP_PROVIDER_ERROR',
  MALFORMED: 'RNTP_MALFORMED',
  WRONG_NETWORK: 'RNTP_WRONG_NETWORK',
  NOT_SYNCED: 'RNTP_NOT_SYNCED',
  STALE: 'RNTP_STALE',
  INCONSISTENT: 'RNTP_INCONSISTENT',
  ACCOUNT_NOT_FOUND: 'RNTP_ACCOUNT_NOT_FOUND',
  ACCOUNT_UNSUITABLE: 'RNTP_ACCOUNT_UNSUITABLE',
  FEE_TOO_HIGH: 'RNTP_FEE_TOO_HIGH',
  GAS_TOO_HIGH: 'RNTP_GAS_TOO_HIGH',
  NONCE_PENDING: 'RNTP_NONCE_PENDING',
  INSUFFICIENT_BALANCE: 'RNTP_INSUFFICIENT_BALANCE',
  INTENT_INVALID: 'RNTP_INTENT_INVALID',
});

/** A refusal with one stable code, the provider it concerns (or null) and a short detail. */
export class PrepError extends Error {
  constructor(code, providerId = null, detail = undefined) {
    super([code, providerId, detail].filter((part) => part !== null && part !== undefined).join(': '));
    this.name = 'PrepError';
    this.code = code;
    this.providerId = providerId;
    if (detail !== undefined) this.detail = detail;
  }
}
