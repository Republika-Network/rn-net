# JavaScript API compatibility

This page records the intentional behaviour changes to the JavaScript API made in RN-NET-01H
(PR #2, merged as `afc1688`) and what future consumers can rely on. None of them changes
`rnnet.canonical-json.v1` or `rnnet.evidence-commitment.v1`: every conformance vector and
every commitment digest computed before RN-NET-01H is unchanged.

These restrictions are security fixes. They will not be relaxed to restore the earlier
behaviour.

## Changes in RN-NET-01H

### Verification and `commitmentFromBytes` take bytes only

| Call | Before (`a1a61c4`) | Since RN-NET-01H |
|---|---|---|
| `verifyCommitment(string, digest)` | Parsed the string and could return `valid: true` | Returns `valid: false`, code `RNCJ_UNSUPPORTED_VALUE` |
| `commitmentFromBytes(string)` | Parsed the string | Throws `CanonicalError`, code `RNCJ_UNSUPPORTED_VALUE` |

A string may already have lost information (for example, invalid UTF-8 decoded to U+FFFD), so
it cannot stand for the bytes that were committed (commitment spec §6). Pass a `Uint8Array`.
`parse()` in the canonical package still accepts a string as a convenience (canonical spec
§3.1).

### Invalid `verifyCommitment` options throw a `TypeError`

`verifyCommitment` returns every defect in the envelope bytes or the presented digest as a
result code. Invalid options are a programming error and throw before any other check:

- `options` that is not an object (`null`, a string, a number): `TypeError: options must be an object.`
  Before, `null` failed with an incidental property-read `TypeError` and a string was ignored.
- `options.sourceFile` that is neither `undefined` nor a `Uint8Array`: `TypeError`, now before
  the digest and envelope checks rather than after them.

`options.sourceFile` is read exactly once.

### In-memory envelopes report canonical errors first

`validateEnvelope(value)` and `computeCommitment(value)` first serialize the value under
canonical spec §5, reading every property once, then parse and validate that snapshot
(commitment spec §4.1). For in-memory values, `RNCJ_*` errors therefore come before `RNEC_*`
errors, and some inputs now report a different first error:

| Input to `validateEnvelope` | Before | Since RN-NET-01H |
|---|---|---|
| A class instance with the six fields | `RNEC_NOT_OBJECT` | `RNCJ_UNSUPPORTED_VALUE` |
| `undefined` | `RNEC_NOT_OBJECT` | `RNCJ_UNSUPPORTED_VALUE` |
| `1.5` | `RNEC_NOT_OBJECT` | `RNCJ_NUMBER_NOT_INTEGER` |
| `'str'` | `RNEC_NOT_OBJECT` | `RNEC_NOT_OBJECT` (unchanged) |
| A field set to `1.5` | `RNEC_FIELD_TYPE` | `RNCJ_NUMBER_NOT_INTEGER` |
| An extra field set to `undefined` | `RNEC_UNKNOWN_FIELD` | `RNCJ_UNSUPPORTED_VALUE` |

Envelopes given as bytes follow commitment spec §4 exactly as before: the conformance vectors
fix their error codes.

### Restrictions on constructed values

`canonicalize()` and the commitment functions reject, with `RNCJ_UNSUPPORTED_VALUE`, any
constructed value with no JSON representation under canonical spec §5. This includes accessor
(getter) properties, non-enumerable properties, symbol keys, class instances, sparse arrays,
arrays with properties other than their indices and `length`, and (since RN-NET-01J) arrays
whose `length` is not an integer from 0 to 2^32 - 1. A Proxy is read through one snapshot of
its own property descriptors: the bytes always match that snapshot, whatever its traps answer
on later reads.

### Results are frozen

`validateEnvelope()` returns a frozen envelope, and `computeCommitment()` and
`commitmentFromBytes()` return frozen results. Copy a result before changing it.

### String input to `parse()` follows the byte check order

For string input, `parse()` now checks size, then a leading byte order mark, then unpaired
surrogates, the same order as for bytes. An oversized string that also has a byte order mark
or an unpaired surrogate now reports `RNCJ_SIZE_EXCEEDED`.

## What consumers can rely on

- **Stable:**
  - the canonical bytes and commitment digests for every valid input, and the error codes for
    byte input, as fixed by the specifications and `vectors/`;
  - the exported names in each package's `src/index.mjs`.
- **Not part of the contract:**
  - error messages;
  - the `path` or `offset` details on errors;
  - which first error is reported for an in-memory value that has several defects;
  - anything not exported from an `index.mjs`.
- **Before a stable release:** the packages are pre-release (no published versions). Further
  restrictions that close a security gap may be added without a format version change. They
  will be recorded here.
