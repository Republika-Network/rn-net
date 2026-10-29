# rnnet.evidence-commitment.v1

- Status: Draft (RN-NET-01)
- Decision record: [ADR-RN-003](../docs/adr/ADR-RN-003-evidence-commitment-format.md)
- Depends on: [rnnet.canonical-json.v1](rnnet.canonical-json.v1.md), [rnnet.verification-taxonomy.v1](rnnet.verification-taxonomy.v1.md)
- Reference implementations: `packages/commitment/` (JavaScript), `tools/reference/rnnet_reference.py` (Python)
- Conformance vectors: `vectors/commitment/`, `vectors/tamper/`

## 1. Purpose

An evidence commitment is a 32-byte SHA-256 digest that binds a small, closed envelope
describing one piece of source evidence: what format it claims to be, how it was
canonicalized, its evidence digest, the digest of the file that carried it, and an
identifier for where it came from.

The commitment is what later work packages anchor on public test networks (RN-NET-03)
and attest to (RN-NET-04). It is independent of any blockchain.

A commitment proves only that a specific envelope existed in exactly this form. It does
not prove that any value in the envelope is true (§8).

## 2. Envelope

The envelope is a JSON object with exactly these six members, all strings:

| Field | Meaning |
|---|---|
| `format` | Always `rnnet.evidence-commitment.v1` |
| `sourceFormat` | The format identifier the source evidence declares |
| `sourceCanonicalization` | The identifier of the canonicalization profile the source evidence digest was computed under |
| `sourceEvidenceDigest` | The source evidence digest, as stated by the source |
| `sourceFileSha256` | SHA-256 of the exact bytes of the file that carried the evidence |
| `sourceRef` | An identifier for the source, for example a run or artifact locator |

The envelope is **closed**: no other member is allowed, now or as an optional extension.
Mutable provenance, such as descriptions, timestamps or operator notes, stays outside the
envelope. If such information must be bound, a future format version must bind it
through a digest.

## 3. Field rules

All lengths are counted in characters; every valid value is ASCII.

| Field | Rule |
|---|---|
| `format` | Exactly `rnnet.evidence-commitment.v1` |
| `sourceFormat` | 1–128 characters matching `^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)+$`: lowercase dot-separated labels, at least two |
| `sourceCanonicalization` | 1–128 characters matching `^[a-z0-9]+([._/-][a-z0-9]+)*$` |
| `sourceEvidenceDigest` | `sha256:` followed by exactly 64 lowercase hex digits |
| `sourceFileSha256` | `sha256:` followed by exactly 64 lowercase hex digits |
| `sourceRef` | 1–512 characters matching `^[a-z][a-z0-9+.-]*:[\x21-\x7E]+$`: a lowercase scheme, a colon, then visible ASCII with no spaces |

Identifiers are compared byte for byte. Case, Unicode normalization and percent-encoding
are never applied, so `sourceRef` cannot contain look-alike non-ASCII characters.

`sourceRef` is an **identifier, not a claim of authenticity**. RN-NET-01 never
dereferences it.

## 4. Validation order

An implementation MUST validate a candidate envelope in this order and report the first
failure:

1. Parse the bytes under `rnnet.canonical-json.v1` (errors `RNCJ_*`).
2. The value is a JSON object (`RNEC_NOT_OBJECT`).
3. No member outside §2 (`RNEC_UNKNOWN_FIELD`; the reported field is the first unknown key in UTF-16 code unit order).
4. Every member of §2 is present, checked in table order (`RNEC_MISSING_FIELD`).
5. Every member is a string, in table order (`RNEC_FIELD_TYPE`).
6. `format`: a value starting with `rnnet.evidence-commitment.` but not equal to the v1
   identifier is `RNEC_UNSUPPORTED_VERSION`; any other mismatch is `RNEC_UNSUPPORTED_FORMAT`.
7. `sourceFormat` (`RNEC_INVALID_SOURCE_FORMAT`).
8. `sourceCanonicalization` (`RNEC_INVALID_CANONICALIZATION_ID`).
9. `sourceEvidenceDigest`, then `sourceFileSha256` (`RNEC_INVALID_DIGEST`).
10. `sourceRef` (`RNEC_INVALID_SOURCE_REF`).

### 4.1 Envelopes given as in-memory values

An implementation that also accepts an envelope as a value built in a program MUST first
serialize it under `rnnet.canonical-json.v1` §5, which reads every property exactly once,
then parse and validate that serialization as in steps 2–10, and compute the commitment
(§5) over the validated result. `RNCJ_*` errors therefore precede `RNEC_*` errors for such
values. The digest always covers exactly the envelope that was validated, even if the
original value would answer differently when read again.

## 5. Commitment construction

### 5.1 Domain separator

The domain separator is the 28 ASCII bytes of `rnnet:evidence-commitment:v1` followed by
one byte `00`, 29 bytes in total:

```
72 6e 6e 65 74 3a 65 76 69 64 65 6e 63 65 2d 63
6f 6d 6d 69 74 6d 65 6e 74 3a 76 31 00
```

The separator makes an RN-NET commitment different from a plain SHA-256 of the same
envelope, and from a hash computed for any other purpose or format version. The `00`
terminator cannot occur in canonical JSON, so the boundary between separator and envelope
is unambiguous.

### 5.2 Digest

```
canonical  = rnnet.canonical-json.v1(envelope)          (UTF-8 bytes)
commitment = SHA-256(domain_separator || canonical)       (32 bytes)
```

The commitment is written as `sha256:` followed by 64 lowercase hex digits. Where raw bytes
are needed, for example as an anchor payload, the 32 digest bytes are used directly.

Because the commitment is computed over the canonical form, envelopes that differ only in
key order, whitespace or escaping have the same commitment. The commitment binds the
envelope's content, not one particular serialization of it.

## 6. Verification

Given envelope **bytes** and a presented commitment, a verifier performs the steps below.
Verification input is bytes, never decoded text, because decoding can already have replaced
invalid bytes and so hide what was committed.

1. Rejects a presented commitment that is not `sha256:` + 64 lowercase hex (`RNEC_INVALID_COMMITMENT_DIGEST`).
2. Validates the envelope (§4).
3. Recomputes the commitment (§5) and compares it with the presented value (`RNEC_DIGEST_MISMATCH`).
4. Optionally, given the source file bytes, recomputes their SHA-256 and compares it with
   `sourceFileSha256` (`RNEC_SOURCE_FILE_MISMATCH`).

A verifier reports each conclusion with a classification from
[rnnet.verification-taxonomy.v1](rnnet.verification-taxonomy.v1.md):

| Subject | Classification after a successful verification |
|---|---|
| `commitment` | `VERIFIED` |
| `sourceFileSha256` | `VERIFIED` only if the source file was supplied and matched; otherwise `CLAIMED` |
| `sourceFormat`, `sourceCanonicalization`, `sourceEvidenceDigest` | `CLAIMED` |
| `sourceRef` | `UNRESOLVED` |

## 7. Error codes

| Code | Meaning |
|---|---|
| `RNCJ_*` | The envelope bytes violate `rnnet.canonical-json.v1` |
| `RNEC_NOT_OBJECT` | The envelope is not a JSON object |
| `RNEC_UNKNOWN_FIELD` | A member outside §2 |
| `RNEC_MISSING_FIELD` | A §2 member is absent |
| `RNEC_FIELD_TYPE` | A member is not a string |
| `RNEC_UNSUPPORTED_VERSION` | Another version of this format |
| `RNEC_UNSUPPORTED_FORMAT` | Not this format |
| `RNEC_INVALID_SOURCE_FORMAT` | `sourceFormat` violates §3 |
| `RNEC_INVALID_CANONICALIZATION_ID` | `sourceCanonicalization` violates §3 |
| `RNEC_INVALID_DIGEST` | A source digest violates §3 |
| `RNEC_INVALID_SOURCE_REF` | `sourceRef` violates §3 |
| `RNEC_INVALID_COMMITMENT_DIGEST` | The presented commitment is malformed |
| `RNEC_DIGEST_MISMATCH` | The recomputed commitment differs from the presented one |
| `RNEC_SOURCE_FILE_MISMATCH` | The supplied source file does not match `sourceFileSha256` |

## 8. What a commitment does not prove

A recomputed commitment shows only that the verifier holds an envelope that hashes to the
presented value. It does **not** prove:

- that the source evidence exists, or that its digest really is `sourceEvidenceDigest`;
- the identity of the organization or system that produced the evidence;
- the identity of any signer, or who held any key;
- that any policy was evaluated or enforced;
- that any external action or transaction took place;
- that the commitment has been anchored on any blockchain;
- that the source evidence is truthful.

## 9. Compatibility and versioning

1. A v1 implementation MUST reject any envelope whose `format` is not exactly the v1
   identifier, including later versions.
2. Adding, removing, renaming or re-typing a field, changing a field rule, the domain
   separator, the hash function or the canonicalization profile requires a new format
   identifier (`rnnet.evidence-commitment.v2`) and a new domain separator tag.
3. Unknown fields are never ignored, in any version.
4. A v1 commitment, once published, keeps its meaning permanently.
