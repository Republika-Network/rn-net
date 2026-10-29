# rnnet.synthetic-evidence.v1

- Status: Draft (RN-NET-02)
- Decision records: [ADR-RN-006](../docs/adr/ADR-RN-006-evidence-verification-profile.md), [ADR-RN-007](../docs/adr/ADR-RN-007-ed25519-signer-trust.md)
- Depends on: [rnnet.canonical-json.v1](rnnet.canonical-json.v1.md), [rnnet.verification-taxonomy.v1](rnnet.verification-taxonomy.v1.md)
- Reports: [rnnet.verification-report.v1](rnnet.verification-report.v1.md)
- Implementations: `packages/verifier/` (JavaScript), `tools/reference/rnnet_evidence_reference.py` (Python)
- Conformance vectors: `vectors/evidence/`

## 1. Purpose

This is a small, original evidence format for exercising RN-NET's independent verifier. It
carries a claimed record of one operation, a digest that binds it, and optional Ed25519
signatures over that digest.

The format is **synthetic**: a test and interoperability profile. It is not the format of
any other system, and evidence in it describes nothing that happened unless someone
independently shows otherwise. Verifying a document in this format establishes only the
properties in §8.

## 2. Document

An evidence document is a JSON object, encoded as UTF-8 and parsed under
`rnnet.canonical-json.v1`. It is **closed**: it has exactly these members.

| Member | Type | Meaning |
|---|---|---|
| `format` | string | Always `rnnet.synthetic-evidence.v1` |
| `canonicalization` | string | Always `rnnet.canonical-json.v1` |
| `body` | object | The claims; everything the digest binds (§3) |
| `digest` | string | The evidence digest of `body` (§4) |
| `signatures` | array | Zero to 16 signature records (§5) |

The signed content (`body`) is separate from its digest and its signatures. Adding,
removing or reordering a signature never changes the digest, and the digest never covers
itself.

## 3. Body

`body` is a closed object with exactly these members:

| Member | Rule | Meaning |
|---|---|---|
| `evidenceId` | identifier (§3.1) | An identifier the producer chose for this evidence |
| `issuer` | identifier | Who the producer claims issued it |
| `subject` | identifier | What the evidence is about, for example an operation identifier |
| `action` | action name (§3.1) | The claimed action, for example `synthetic.transfer.simulated` |
| `outcome` | one of `succeeded`, `failed`, `rejected`, `unknown` | The claimed outcome |
| `payload` | object | Further claimed detail: any value under `rnnet.canonical-json.v1`; its canonical form at most 65,536 bytes |

Every member is required. `null` is not allowed for any member of the document or body; it
may occur inside `payload`, where it is ordinary data.

Every value in `body`, including all of `payload`, is a claim. The digest makes it
tamper-evident; nothing makes it true.

### 3.1 Value rules

- **Identifier:** 1–128 characters matching `^[A-Za-z0-9][A-Za-z0-9._:-]*$`.
- **Action name:** 1–128 characters matching `^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)*$`.
- **Comparison:**
  - Identifiers and action names are ASCII and compared byte for byte.
  - No case folding, Unicode normalization or trimming is ever applied.
  - A look-alike non-ASCII character therefore cannot pass as an identifier.
- **Payload:**
  - Payload strings may contain any Unicode text the canonical profile accepts.
  - They are bound exactly as given. Text in NFC and NFD forms are different values with
    different digests.
  - Array order in the payload is significant and preserved.
- **Numbers:** numbers anywhere are integers in the safe range, as the canonical profile
  requires.
- **Time:** there are no timestamps. A time value placed in `payload` is an unverified claim
  like any other.

## 4. Evidence digest

**Domain separator.** It is the 34 ASCII bytes of `rnnet:synthetic-evidence:digest:v1`
followed by one byte `00`, 35 bytes in total.

**Computation:**

```
digest = SHA-256(domain_separator || rnnet.canonical-json.v1(body))
```

**Representation.** The digest is written as `sha256:` followed by 64 lowercase hex digits,
and that string is the value of `digest`.

**What it covers.** The digest covers `body` and nothing else. The `format` and
`canonicalization` values are fixed by this version, so the domain separator stands for
them. The separator also makes the evidence digest different from:

- a plain SHA-256 of the same bytes;
- an `rnnet.evidence-commitment.v1` commitment, whose separator is
  `rnnet:evidence-commitment:v1`;
- any digest of another format or version.

**Digest algorithms.** Only `sha256` is supported. A `digest` value that has the shape of
another algorithm's digest (§6, step 10) is unsupported. Any other value that is not a
well-formed `sha256:` digest is invalid.

## 5. Signatures

### 5.1 Signature records

Each element of `signatures` is a closed object:

| Member | Rule | Meaning |
|---|---|---|
| `keyId` | identifier (§3.1) | A label for the key, chosen by the producer. It is a claim, not an identity. |
| `algorithm` | `ed25519` | The only algorithm in v1 |
| `publicKey` | 64 lowercase hex digits | The 32-byte Ed25519 public key (RFC 8032 §5.1.5 encoding) |
| `signature` | 128 lowercase hex digits | The 64-byte Ed25519 signature (RFC 8032 §5.1.6 encoding) |

- **Count and order.**
  - At most 16 records are allowed. An empty array is allowed.
  - Records are sorted by `keyId` in strictly ascending UTF-16 code unit order. Because
    `keyId` is ASCII, this is byte order.
  - A repeated `keyId` is an error, and so is an unsorted array. There is therefore exactly
    one valid order, and reordering a valid list makes it invalid.
- **Unique keys.** No two records may carry the same `publicKey`.

### 5.2 Signed message

**Domain separator.** It is the 37 ASCII bytes of `rnnet:synthetic-evidence:signature:v1`
followed by one byte `00`, 38 bytes in total.

**Message:**

```
message = signature_domain_separator || D
```

Here `D` is the 32 bytes of the evidence digest **recomputed by the verifier** from `body`
(§4), not the declared `digest` string.

**Binding.**

- A signature therefore binds exactly the canonical body under this version.
- It cannot be replayed onto a different body.
- It cannot be replayed onto a document of another format whose separators differ.
- A signature made for any other purpose or domain does not verify.

**Signing domain versions.** There is no field naming the signing domain. The domain is fixed
by `format`, so a different signing-domain version means a different format, which is
reported as unsupported.

### 5.3 Verification of one record

A record's result is exactly one of:

- **`KEY_REJECTED`** when the public key, decoded as in RFC 8032 §5.1.3, is any of the
  following:
  - non-canonical (its y coordinate is not below p);
  - not a point on the curve;
  - encoded with x = 0 and the sign bit set;
  - of small order, that is, multiplying it by 8 gives the neutral element.
- **`INVALID`** when the key is accepted but any of the following holds:
  - S, the second half of the signature as a little-endian integer, is not below L, the
    group order;
  - R does not decode as a canonical point on the curve;
  - the equation `[S]B = R + [k]A` fails, with `k = SHA-512(R || A || message) mod L`. This
    is the cofactorless check of RFC 8032 §5.1.7, with no multiplication by 8.
- **`VALID`** otherwise.

**Same result everywhere.** These rules make the result the same in every implementation of
this profile, including on the edge cases where Ed25519 libraries are known to differ.

## 6. Validation order

A verifier validates the document in this order and stops at the first failure.

**Field names in errors.** They use dotted paths, for example `body.issuer` or
`signatures[2].keyId`. An unknown member is reported by the object that contains it, never by
its name, because member names are input text:

- `""` for the document;
- `body`;
- `signatures[i]`.

| Step | Check | Error |
|---|---|---|
| 1 | Input size: more than 262,144 bytes | `RNSE_EVIDENCE_TOO_LARGE` |
| 2 | Parse under `rnnet.canonical-json.v1` | `RNCJ_*` |
| 3 | The value is a JSON object | `RNSE_NOT_OBJECT` |
| 4 | `format` is present | `RNSE_MISSING_FIELD` |
| 4 | `format` is a string | `RNSE_FIELD_TYPE` |
| 5 | `format` starts with `rnnet.synthetic-evidence.` but is not the v1 identifier | `RNSE_UNSUPPORTED_VERSION` |
| 5 | `format` is any other value other than the v1 identifier | `RNSE_UNSUPPORTED_FORMAT` |
| 6 | No member outside §2 | `RNSE_UNKNOWN_FIELD` |
| 7 | Every member of §2 present, in table order | `RNSE_MISSING_FIELD` |
| 8 | Types, in table order | `RNSE_FIELD_TYPE` |
| 9 | `canonicalization` is exactly `rnnet.canonical-json.v1` | `RNSE_UNSUPPORTED_CANONICALIZATION` |
| 10 | `digest` matches `^[a-z0-9]+(-[a-z0-9]+)*:` with a prefix other than `sha256` | `RNSE_UNSUPPORTED_DIGEST_ALGORITHM` |
| 10 | Otherwise, `digest` does not match `^sha256:[0-9a-f]{64}$` | `RNSE_INVALID_DIGEST` |
| 11 | `body`: unknown members, then missing members, then types (strings, and `payload` an object) | `RNSE_UNKNOWN_FIELD`, `RNSE_MISSING_FIELD`, `RNSE_FIELD_TYPE` |
| 11 | `body`: values, in table order | `RNSE_INVALID_FIELD_VALUE` |
| 11 | `body`: payload size | `RNSE_PAYLOAD_TOO_LARGE` |
| 12 | `signatures`: more than 16 records | `RNSE_TOO_MANY_SIGNATURES` |
| 13 | Each record in array order: an object | `RNSE_FIELD_TYPE` |
| 13 | Each record: unknown, missing, then types | `RNSE_UNKNOWN_FIELD`, `RNSE_MISSING_FIELD`, `RNSE_FIELD_TYPE` |
| 13 | Each record: `algorithm` is not `ed25519` | `RNSE_UNSUPPORTED_SIGNATURE_ALGORITHM` |
| 13 | Each record: `keyId` is not an identifier | `RNSE_INVALID_FIELD_VALUE` |
| 13 | Each record: `publicKey` is not 64 lowercase hex digits | `RNSE_INVALID_PUBLIC_KEY_ENCODING` |
| 13 | Each record: `signature` is not 128 lowercase hex digits | `RNSE_INVALID_SIGNATURE_ENCODING` |
| 14 | Order of records: the first adjacent pair, from the start, that is not strictly ascending by `keyId`: if the two are equal | `RNSE_DUPLICATE_KEY_ID` |
| 14 | … otherwise (they descend) | `RNSE_SIGNATURES_NOT_SORTED` |
| 15 | The first record whose `publicKey` repeats an earlier one | `RNSE_DUPLICATE_PUBLIC_KEY` |

**Why `format` comes first.** It is checked before the closed-member rule, so a document of a
later version is reported as unsupported rather than as having unknown members.

**Outcome of a validation failure.** A failure at step 5, 9, 10 or 13 that names something
unsupported (`RNSE_UNSUPPORTED_*`) makes the document **unsupported**. Any other validation
failure makes it **invalid**.

## 7. Verification

**Precondition.** These checks run only for a document that passed §6.

1. Recompute the evidence digest (§4) and compare it with `digest`. A difference is
   `RNSE_DIGEST_MISMATCH`.
2. Verify every signature record (§5.3) against the recomputed digest. Records are processed
   in array order, which is `keyId` order.
   - Every record is verified even if an earlier one failed.
   - `KEY_REJECTED` is reported as `RNSE_PUBLIC_KEY_REJECTED`.
   - `INVALID` is reported as `RNSE_SIGNATURE_INVALID`.
3. **Optionally, check against a commitment.** This step runs when the caller supplies an
   `rnnet.evidence-commitment.v1` envelope and a presented commitment. It checks:
   - the envelope (the commitment specification §4);
   - the presented commitment (§6 there).

   It then compares each envelope member separately with what the verifier established:

   | Envelope member | Must equal | Error |
   |---|---|---|
   | `sourceFormat` | `rnnet.synthetic-evidence.v1` | `RNSE_COMMITMENT_SOURCE_FORMAT_MISMATCH` |
   | `sourceCanonicalization` | `rnnet.canonical-json.v1` | `RNSE_COMMITMENT_CANONICALIZATION_MISMATCH` |
   | `sourceEvidenceDigest` | the recomputed evidence digest | `RNSE_COMMITMENT_EVIDENCE_DIGEST_MISMATCH` |
   | `sourceFileSha256` | the SHA-256 of the exact evidence bytes supplied | `RNSE_COMMITMENT_SOURCE_FILE_MISMATCH` |

   An envelope or presented commitment that fails its own verification is reported with that
   specification's `RNEC_*` code. It is never treated as a match.

   `sourceRef` is reported as given and never dereferenced.

**Independent results.** The three values compared in step 3 are distinct:

- the SHA-256 of the evidence file;
- the evidence digest of its body;
- the commitment over the envelope.

A matching commitment never makes a failed digest or signature acceptable. A failed
commitment never hides a valid signature.

## 8. What verification establishes

| Claim | Basis after a successful check | Classification |
|---|---|---|
| The body matches `digest` | Recomputed by the verifier | `VERIFIED` |
| A signature record | Verified under a public key that the document itself carries | `CONSISTENT_UNDER_EMBEDDED_KEYS` |
| Who holds a signing key; who the signer is | No trust source binds the key to anyone | `UNRESOLVED` |
| `issuer`, `subject`, `action`, `outcome`, `payload` | Bound by the verified digest, not checked against anything | `CLAIMED` |
| That the described event happened | Nothing in the document can show it | `UNRESOLVED` |
| Commitment, `sourceFileSha256`, `sourceEvidenceDigest`, `sourceFormat`, `sourceCanonicalization` | Recomputed or compared by the verifier | `VERIFIED` |
| `sourceRef` | Not dereferenced | `UNRESOLVED` |

**What a valid signature proves.** It proves that someone holding the private key for that
public key signed this digest. It does not prove:

- who that is;
- that they were authorized;
- that the event happened;
- that any policy was enforced;
- that any payment occurred.

**Multiple signatures.** Several valid signatures are several such facts. They are not proof
of an organization's identity.

**Reserved classification.** `THIRD_PARTY_ATTESTED` is not produced under this profile.

## 9. Error codes

| Code | Meaning |
|---|---|
| `RNSE_EVIDENCE_TOO_LARGE` | Input larger than 262,144 bytes |
| `RNSE_NOT_OBJECT` | The document is not a JSON object |
| `RNSE_UNSUPPORTED_FORMAT` | `format` is not a synthetic-evidence identifier |
| `RNSE_UNSUPPORTED_VERSION` | `format` is a synthetic-evidence identifier of another version |
| `RNSE_UNKNOWN_FIELD` | A member outside the closed schema |
| `RNSE_MISSING_FIELD` | A required member is absent |
| `RNSE_FIELD_TYPE` | A member has the wrong JSON type |
| `RNSE_UNSUPPORTED_CANONICALIZATION` | A canonicalization profile other than `rnnet.canonical-json.v1` |
| `RNSE_UNSUPPORTED_DIGEST_ALGORITHM` | A digest algorithm other than `sha256` |
| `RNSE_INVALID_DIGEST` | `digest` is not a well-formed digest |
| `RNSE_INVALID_FIELD_VALUE` | A value breaks its rule (§3.1, §5.1) |
| `RNSE_PAYLOAD_TOO_LARGE` | Canonical `payload` larger than 65,536 bytes |
| `RNSE_TOO_MANY_SIGNATURES` | More than 16 signature records |
| `RNSE_UNSUPPORTED_SIGNATURE_ALGORITHM` | A signature algorithm other than `ed25519` |
| `RNSE_INVALID_PUBLIC_KEY_ENCODING` | `publicKey` is not 64 lowercase hex digits |
| `RNSE_INVALID_SIGNATURE_ENCODING` | `signature` is not 128 lowercase hex digits |
| `RNSE_DUPLICATE_KEY_ID` | Two records share a `keyId` |
| `RNSE_SIGNATURES_NOT_SORTED` | Records are not in ascending `keyId` order |
| `RNSE_DUPLICATE_PUBLIC_KEY` | Two records share a `publicKey` |
| `RNSE_DIGEST_MISMATCH` | The recomputed digest differs from `digest` |
| `RNSE_PUBLIC_KEY_REJECTED` | A public key is rejected by §5.3 |
| `RNSE_SIGNATURE_INVALID` | A signature does not verify (§5.3) |
| `RNSE_COMMITMENT_SOURCE_FORMAT_MISMATCH` | See §7 |
| `RNSE_COMMITMENT_CANONICALIZATION_MISMATCH` | See §7 |
| `RNSE_COMMITMENT_EVIDENCE_DIGEST_MISMATCH` | See §7 |
| `RNSE_COMMITMENT_SOURCE_FILE_MISMATCH` | See §7 |

## 10. Versioning

- **Within v1.** Every value above is fixed for v1.
- **What needs a new version.** Any change to these needs a new format identifier, and with
  it new domain separators:
  - the members;
  - the value rules;
  - the digest or signature construction;
  - the algorithms;
  - the limits;
  - the validation order.
