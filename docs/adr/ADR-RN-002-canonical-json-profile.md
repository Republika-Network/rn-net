# ADR-RN-002: Canonical JSON profile

- Status: Accepted
- Date: 2026-10-28
- Specification: [rnnet.canonical-json.v1](../../spec/rnnet.canonical-json.v1.md)

## Context

A commitment is a hash, so every implementation must turn the same document into the same
bytes. Generic JSON does not guarantee that: parsers disagree on duplicate keys (first or
last wins), lone surrogates, number precision, `-0`, and byte order marks. Each of those
disagreements lets two parties hash "the same" document to different values, or two
different documents to the same value.

Existing profiles were considered:

- **RFC 8785 (JCS)** fixes serialization but accepts every I-JSON number, including
  fractions and exponents, whose canonical form depends on binary64 formatting.
- **Soberanía Protocol `aoc-canonical-json/1`** (Apache-2.0) serializes like JCS for common
  inputs but defines no parser. A consumer parsing with `JSON.parse` silently keeps the last
  duplicate key, turns `-0` into `0`, and accepts lone surrogates and unsafe integers.

## Decision

1. RN-NET defines its own profile, `rnnet.canonical-json.v1`: a strict parser plus a
   deterministic serializer, both specified byte for byte, with stable error codes.
2. Accepted inputs: one JSON value in well-formed UTF-8 with no byte order mark; integers in
   ±(2^53 − 1) only; no `-0`; no duplicate keys after unescaping; no lone surrogates; depth
   at most 64; at most 1 MiB.
3. Output: no whitespace; keys sorted by UTF-16 code unit; strings escaped exactly as
   ECMAScript `JSON.stringify` escapes well-formed strings; UTF-8 without a byte order mark.
4. No Unicode normalization. Strings are hashed exactly as given.
5. RN-NET does not claim RFC 8785 conformance, and never treats two profile identifiers as
   equivalent, even when their outputs coincide.
6. Two independent implementations are maintained: JavaScript (`packages/canonical/`) and
   Python (`tools/reference/`). CI requires both to agree with hand-written vectors.

## Validation performed

- 22 valid and 51 invalid canonicalization vectors pass in both implementations.
- Mutation testing: 21 deliberate defects were introduced one at a time, among them a
  missing domain separator, code point key order, accepted duplicates, accepted `-0`,
  unpaired surrogates, lenient UTF-8, and an off-by-one depth limit. Every one made at
  least one test fail.
- A local, non-CI comparison against Soberanía `@aoc/protocol` 0.2.0-rc.3 (Apache-2.0
  tarball, SHA-256 `3d17beff…58f4`, not committed to this repository) showed:
  - identical output on all 22 valid vectors;
  - 22 of the 51 inputs this profile rejects were accepted by `JSON.parse` followed by
    rc.3 serialization: fractions, exponents, `-0` (which becomes `0`), unsafe integers,
    duplicate keys (last wins), unpaired surrogates and nesting deeper than 64. Five
    malformed UTF-8 inputs were also accepted, but only because the comparison harness
    decoded bytes leniently; they say nothing about rc.3.

These observations hold for the vectors only. They do not prove general equivalence.

## Consequences

- Integers outside the safe range and fractional values cannot be represented. Formats
  that need them must carry them as strings with their own documented rules.
- Evidence produced under another profile keeps that profile. RN-NET binds the source's
  profile identifier into a commitment instead of re-canonicalizing the source.
- Any change to accepted inputs, output, limits or error codes needs `rnnet.canonical-json.v2`.
