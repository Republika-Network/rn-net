// Verification and trust taxonomy (spec/rnnet.verification-taxonomy.v1.md).

export const TAXONOMY = 'rnnet.verification-taxonomy.v1';

export const Classification = Object.freeze({
  /** Recomputed by RN-NET from the bytes it was given; no trust in the producer is needed. */
  VERIFIED: 'VERIFIED',
  /** Signatures verify, but only under keys carried by the evidence itself. */
  CONSISTENT_UNDER_EMBEDDED_KEYS: 'CONSISTENT_UNDER_EMBEDDED_KEYS',
  /** Asserted by an identified third party whose own record can be checked separately. */
  THIRD_PARTY_ATTESTED: 'THIRD_PARTY_ATTESTED',
  /** Stated in the input and bound by a digest, but not checked against its subject. */
  CLAIMED: 'CLAIMED',
  /** Not checkable from the material given, for example an identifier that was not dereferenced. */
  UNRESOLVED: 'UNRESOLVED',
});

/**
 * @param {string} subject
 * @param {string} classification one of Classification
 * @param {string} basis why this classification applies
 */
export const statement = (subject, classification, basis) => Object.freeze({ subject, classification, basis });
