// Error codes of the offline signing toolchain (RN-NET-03B2-B1, ADR-RN-017). Every refusal
// carries exactly one stable code, so tests and the independent Python reference can assert the
// reason, not only that something failed.

export const TxErrorCode = Object.freeze({
  // Intent and approval
  INTENT_INVALID: 'RNTX_INTENT_INVALID',
  INTENT_DIGEST_MISMATCH: 'RNTX_INTENT_DIGEST_MISMATCH',
  // Keys and the signer
  KEY_INVALID: 'RNTX_KEY_INVALID',
  KEY_NETWORK_MISMATCH: 'RNTX_KEY_NETWORK_MISMATCH',
  KEY_PURPOSE_MISMATCH: 'RNTX_KEY_PURPOSE_MISMATCH',
  ALREADY_SIGNED: 'RNTX_ALREADY_SIGNED',
  SEQUENCE_UNRESOLVED: 'RNTX_SEQUENCE_UNRESOLVED',
  // Decoding signed bytes
  DECODE: 'RNTX_DECODE',
  TRAILING_BYTES: 'RNTX_TRAILING_BYTES',
  NONCANONICAL_ENCODING: 'RNTX_NONCANONICAL_ENCODING',
  UNKNOWN_FIELD: 'RNTX_UNKNOWN_FIELD',
  WRONG_TX_TYPE: 'RNTX_WRONG_TX_TYPE',
  // Comparing signed bytes with the approved intent
  WRONG_CHAIN: 'RNTX_WRONG_CHAIN',
  NONCE_MISMATCH: 'RNTX_NONCE_MISMATCH',
  FEE_MISMATCH: 'RNTX_FEE_MISMATCH',
  PAYLOAD_MISMATCH: 'RNTX_PAYLOAD_MISMATCH',
  FIELD_MISMATCH: 'RNTX_FIELD_MISMATCH',
  // Signatures
  HIGH_S: 'RNTX_HIGH_S',
  BAD_Y_PARITY: 'RNTX_BAD_Y_PARITY',
  SIGNATURE_INVALID: 'RNTX_SIGNATURE_INVALID',
  SENDER_MISMATCH: 'RNTX_SENDER_MISMATCH',
  // Key files (in memory only in B1)
  KEYFILE_INVALID: 'RNTX_KEYFILE_INVALID',
  KEYFILE_DECRYPT: 'RNTX_KEYFILE_DECRYPT',
  // Broadcaster hand-off (interface only in B1)
  HANDOFF_INVALID: 'RNTX_HANDOFF_INVALID',
  HANDOFF_BLOB_MISMATCH: 'RNTX_HANDOFF_BLOB_MISMATCH',
  HANDOFF_NOT_PASS: 'RNTX_HANDOFF_NOT_PASS',
});

/** A refusal with one stable code and an optional human-readable detail. */
export class TxError extends Error {
  constructor(code, detail) {
    super(detail === undefined ? code : `${code}: ${detail}`);
    this.name = 'TxError';
    this.code = code;
    if (detail !== undefined) this.detail = detail;
  }
}

/** Throws a TxError unless `condition` holds. */
export function ensure(condition, code, detail) {
  if (!condition) throw new TxError(code, detail);
}
