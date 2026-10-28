export { CanonicalError, CanonicalErrorCode } from './errors.mjs';
export { LIMITS, PROFILE } from './limits.mjs';
export { parse } from './parse.mjs';
export { canonicalBytes, canonicalize } from './serialize.mjs';

import { parse } from './parse.mjs';
import { canonicalize } from './serialize.mjs';

/** Parses strict JSON text and returns its canonical form. */
export function canonicalizeText(input) {
  return canonicalize(parse(input));
}
