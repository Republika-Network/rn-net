# rnnet.canonical-json.v1

- Status: Draft (RN-NET-01)
- Decision record: [ADR-RN-002](../docs/adr/ADR-RN-002-canonical-json-profile.md)
- Reference implementations: `packages/canonical/` (JavaScript), `tools/reference/rnnet_reference.py` (Python)
- Conformance vectors: `vectors/canonical/`

## 1. Purpose

This profile turns a JSON document into one exact byte sequence, so that a hash of
those bytes is reproducible by any implementation. It accepts only inputs with a
single unambiguous meaning and rejects everything else with a defined error code.

It is used for documents that RN-NET itself defines, starting with
`rnnet.evidence-commitment.v1`. It is **not** used to re-canonicalize evidence that
was produced under a different profile.

## 2. Conventions

The key words MUST, MUST NOT and MAY are used as in RFC 2119. "Code unit" means a
UTF-16 code unit. Byte values are written in hexadecimal.

## 3. Input

### 3.1 Bytes

1. Input is a sequence of bytes, at most 1,048,576 bytes long; otherwise `RNCJ_SIZE_EXCEEDED`.
2. Input MUST NOT begin with the byte order mark `EF BB BF`; otherwise `RNCJ_BOM`.
3. Input MUST be well-formed UTF-8 (RFC 3629): no overlong forms, no encoded surrogates
   (`ED A0 80`–`ED BF BF`), no truncated sequences, no bytes `C0`, `C1`, `F5`–`FF`; otherwise `RNCJ_INVALID_UTF8`.

These three checks run in this order, before any JSON is read.

### 3.2 Grammar

The decoded text MUST be exactly one JSON value (RFC 8259 §2) surrounded by optional
whitespace (U+0020, U+0009, U+000A, U+000D). Anything else is `RNCJ_SYNTAX`, except
that non-whitespace after a complete value is `RNCJ_TRAILING_CONTENT`. Comments,
single quotes, unquoted keys, trailing commas, `NaN`, `Infinity`, a leading `+`, and
leading zeros are all `RNCJ_SYNTAX`.

### 3.3 Numbers

A number token is read completely according to the RFC 8259 grammar (§6) and then classified:

1. If it has a fraction or an exponent: `RNCJ_NUMBER_NOT_INTEGER`. This includes `1.0`, `1e2` and `-0.0`.
2. If it is `-0`: `RNCJ_NEGATIVE_ZERO`.
3. If its value is outside −(2^53 − 1) … 2^53 − 1: `RNCJ_NUMBER_OUT_OF_RANGE`.

Only integers in the safe range are therefore representable, and each has exactly one input spelling.

### 3.4 Strings

1. Unescaped characters below U+0020 are `RNCJ_SYNTAX`.
2. Valid escapes are `\" \\ \/ \b \f \n \r \t` and `\uXXXX` with four hex digits of either
   case. Any other escape is `RNCJ_SYNTAX`.
3. A `\uXXXX` escape for a high surrogate (D800–DBFF) MUST be immediately followed by a
   `\uXXXX` escape for a low surrogate (DC00–DFFF); the pair denotes one supplementary
   character. A low surrogate escape on its own, or a high surrogate not followed by one,
   is `RNCJ_LONE_SURROGATE`.
4. No Unicode normalization is applied. `"é"` (U+00E9) and `"é"` (U+0065 U+0301) are
   different strings.
5. Noncharacters (for example U+FFFF) are allowed.

### 3.5 Objects and arrays

1. Object keys are compared **after** unescaping. A key that occurs twice in the same
   object is `RNCJ_DUPLICATE_KEY`, so `{"a":1,"a":2}` is rejected.
2. Every key is ordinary data. `__proto__` has no special meaning.
3. Nesting depth MUST NOT exceed 64. The top-level object or array has depth 1; opening a
   container at depth 65 is `RNCJ_DEPTH_EXCEEDED`.

### 3.6 Error precedence

Errors are reported for the first violation encountered: the byte checks of §3.1 first,
then the text is read from left to right. Within one number token, §3.3 applies its
classification order. Conforming implementations therefore report the same code for the
same input.

## 4. Output

The canonical form of a value is:

1. `null`, `true`, `false` as those literals.
2. An integer as its shortest decimal form: optional `-`, no leading zeros, no `+`, no fraction or exponent.
3. A string as `"` + escaped characters + `"`, where escaping (§4.1) is applied to the
   string's characters.
4. An array as `[` + the canonical forms of its elements, in their original order, joined
   by `,` + `]`.
5. An object as `{` + its members sorted by key (§4.2), each written as the canonical key
   string + `:` + the canonical value, joined by `,` + `}`.

No whitespace is emitted anywhere. The output is encoded as UTF-8 with no byte order mark.

### 4.1 String escaping

| Character | Output |
|---|---|
| U+0022 `"` | `\"` |
| U+005C `\` | `\\` |
| U+0008, U+0009, U+000A, U+000C, U+000D | `\b`, `\t`, `\n`, `\f`, `\r` |
| Other U+0000–U+001F | `\u00XX` with lowercase hex |
| Everything else | The character itself, UTF-8 encoded |

`/`, U+007F, U+2028 and U+2029 are not escaped. This matches the string output of
ECMAScript `JSON.stringify` for well-formed strings.

### 4.2 Key order

Keys are sorted by comparing their UTF-16 code unit sequences lexicographically. A key that
is a prefix of another sorts first. This differs from code point order for supplementary
characters: U+1F600 (code units D83D DE00) sorts **before** U+FFFD.

## 5. Values constructed in code

An implementation that canonicalizes values built in a program, rather than parsed from
bytes, MUST apply the same restrictions: integers in the safe range only, no negative zero,
well-formed strings and keys only, and depth at most 64. It MUST reject, not coerce, any
value that has no JSON representation under this profile: undefined, functions, symbols,
big integers, dates, maps, typed arrays, class instances, sparse arrays, accessor or
non-enumerable properties, and symbol keys (`RNCJ_UNSUPPORTED_VALUE`). Non-finite numbers
are `RNCJ_UNSUPPORTED_VALUE`; finite non-integers are `RNCJ_NUMBER_NOT_INTEGER`.

## 6. Error codes

| Code | Meaning |
|---|---|
| `RNCJ_SIZE_EXCEEDED` | Input larger than 1,048,576 bytes |
| `RNCJ_BOM` | Input starts with a byte order mark |
| `RNCJ_INVALID_UTF8` | Input is not well-formed UTF-8 |
| `RNCJ_SYNTAX` | Not a single valid JSON value under this profile |
| `RNCJ_TRAILING_CONTENT` | Non-whitespace after the value |
| `RNCJ_DUPLICATE_KEY` | A key repeated in one object, after unescaping |
| `RNCJ_LONE_SURROGATE` | An unpaired surrogate escape or code unit |
| `RNCJ_NUMBER_NOT_INTEGER` | A fraction or exponent, or a non-integer value |
| `RNCJ_NEGATIVE_ZERO` | `-0`, or negative zero in a constructed value |
| `RNCJ_NUMBER_OUT_OF_RANGE` | An integer outside ±(2^53 − 1) |
| `RNCJ_DEPTH_EXCEEDED` | Nesting deeper than 64 |
| `RNCJ_UNSUPPORTED_VALUE` | A constructed value with no representation (§5) |

## 7. Relationship to other profiles

This profile does **not** claim conformance with RFC 8785 (JCS). For the inputs it accepts,
its output is intended to be identical to JCS and to Soberanía Protocol's
`aoc-canonical-json/1`; that identity has been observed on this repository's vectors only,
not proven. It accepts strictly fewer inputs than either.

A document's canonicalization profile is identified by its exact identifier string. Two
different identifiers are never treated as equivalent by RN-NET, whatever their observed
behaviour.

## 8. Versioning

Any change to the accepted inputs, the output, the limits or the error codes requires a
new identifier (`rnnet.canonical-json.v2`). A conforming v1 implementation never changes
behaviour.
