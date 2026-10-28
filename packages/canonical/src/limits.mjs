export const PROFILE = 'rnnet.canonical-json.v1';

export const LIMITS = Object.freeze({
  /** Maximum input size in bytes (UTF-8). */
  maxBytes: 1_048_576,
  /** Maximum nesting depth; a top-level object or array has depth 1. */
  maxDepth: 64,
});

/** Inclusive integer range representable exactly by IEEE 754 binary64. */
export const MAX_INTEGER = Number.MAX_SAFE_INTEGER;
export const MIN_INTEGER = Number.MIN_SAFE_INTEGER;
