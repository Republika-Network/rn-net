# rnnet.verification-report.v1

- Status: Draft (RN-NET-02)
- Decision record: [ADR-RN-008](../docs/adr/ADR-RN-008-deterministic-verification-report.md)
- Depends on: [rnnet.canonical-json.v1](rnnet.canonical-json.v1.md), [rnnet.verification-taxonomy.v1](rnnet.verification-taxonomy.v1.md), [rnnet.synthetic-evidence.v1](rnnet.synthetic-evidence.v1.md)
- Implementation: `packages/verifier/`

## 1. Purpose

A verification report records what RN-NET's verifier checked for one evidence document, what
it found, and the basis of every conclusion. It is a deterministic function of its inputs:

- the evidence bytes;
- optionally, a commitment envelope's bytes and a presented commitment.

The same inputs always give a byte-identical report under `rnnet.canonical-json.v1`.

The report holds no time, host, node identity or other runtime metadata. If such data is
needed later, it belongs in a separate attestation envelope that refers to the report. This
report does not provide one.

## 2. Outcome

`outcome` is exactly one of:

| Outcome | Meaning |
|---|---|
| `PASS` | The document is a valid `rnnet.synthetic-evidence.v1` document; its body matches its digest; every signature record verifies; and, if a commitment was supplied, the commitment verifies and every compared member matches. |
| `FAIL` | The input is malformed, or any check above failed. |
| `UNSUPPORTED` | The input declares a format, version, canonicalization profile or algorithm this verifier does not implement, so nothing further was checked. |
| `INDETERMINATE` | Reserved. Not produced in v1. |

**`PASS` is a statement about bytes and keys only.** It does not mean any of the following:

- the claims in the body are true;
- the described event happened;
- any policy was enforced;
- a signer is who they claim to be.

A `PASS` with zero signature records says nothing about who produced the evidence.

**Failures never combine into a pass.** A correct digest with an invalid signature is `FAIL`,
and so is a matching commitment with an invalid signature. Every failed check is listed in
`findings`.

## 3. Report

The report is a JSON object with these members, in canonical form:

| Member | Present | Value |
|---|---|---|
| `format` | always | `rnnet.verification-report.v1` |
| `profile` | always | `rnnet.synthetic-evidence.v1`, the profile the verifier applied |
| `taxonomy` | always | `rnnet.verification-taxonomy.v1` |
| `outcome` | always | §2 |
| `input` | always | `{ "sha256": "sha256:<hex>" }`, the SHA-256 of the exact evidence bytes supplied |
| `findings` | always | §4; empty for `PASS` |
| `evidence` | when validation passed | `{ "evidenceId", "declaredDigest", "computedDigest" }` |
| `signatures` | when validation passed | One entry per signature record, in record order: `{ "keyId", "publicKey", "result" }`, with `result` `VALID`, `INVALID` or `KEY_REJECTED` |
| `commitment` | when a commitment was supplied | §5 |
| `statements` | always | §6 |

Every string in the report is one of the following, so the report is bounded and contains no
free text from the input:

- a value fixed by this specification;
- a digest;
- a public key;
- an identifier, a `keyId` or a `sourceRef` that passed its format's ASCII pattern.

## 4. Findings

`findings` is an array of `{ "code", "severity", "subject" }`:

- `code` is an `RNSE_*`, `RNEC_*` or `RNCJ_*` code.
- `severity` is `error`, or `unsupported` for the `RNSE_UNSUPPORTED_*` codes.
- `subject` names what the finding concerns:
  - a dotted field path;
  - `digest`;
  - `signatures[<i>]`;
  - `commitment`, `commitment.presentedDigest` or `commitment.<envelope member>`.

**Order.** Findings appear in the order the checks run:

1. at most one validation failure (synthetic-evidence §6), which ends verification;
2. otherwise the digest finding;
3. then signature findings in record order;
4. then commitment findings, in this order:
   - envelope or presented-commitment failure;
   - `sourceFormat`;
   - `sourceCanonicalization`;
   - `sourceEvidenceDigest`;
   - `sourceFileSha256`.

## 5. Commitment section

When the caller supplied a commitment:

| Member | Value |
|---|---|
| `presentedDigest` | The presented commitment, if it is a well-formed `sha256:` digest; otherwise absent |
| `result` | `MATCH` when the commitment verified and every compared member matched; otherwise `MISMATCH` |
| `sourceRef` | The envelope's `sourceRef` when the envelope is valid. It is untrusted text and is never dereferenced. |

If the evidence failed validation, no commitment comparison is made, and there is no
`commitment` member.

## 6. Statements

`statements` is an array of `{ "subject", "classification", "basis" }` from
`rnnet.verification-taxonomy.v1`. Each `basis` is a fixed sentence from this section.

**When there are no statements.** A statement is made only about a subject the verifier
examined. A failed check produces a finding, not a statement. If validation failed, there are
no statements.

**Statements, in order:**

| Subject | When | Classification | Basis |
|---|---|---|---|
| `evidenceDigest` | the digest matched | `VERIFIED` | `Recomputed from the supplied body under rnnet.synthetic-evidence.v1.` |
| `body.issuer`, `body.subject`, `body.action`, `body.outcome`, `body.payload` (each) | the digest matched | `CLAIMED` | `Stated in the evidence and bound by its digest; not checked against anything else.` |
| `eventOccurrence` | always | `UNRESOLVED` | `Nothing in the evidence can show that the described event happened.` |
| `signatures` | no signature records | `UNRESOLVED` | `No signatures were supplied; nothing is known about who produced the evidence.` |
| `signatures[<i>]` | the record is `VALID` | `CONSISTENT_UNDER_EMBEDDED_KEYS` | `The signature verifies under a public key carried by the evidence itself.` |
| `signerIdentity[<i>]` | for every record | `UNRESOLVED` | `No trust source binds this public key to an identity.` |
| `commitment` | it verified | `VERIFIED` | `Recomputed from the supplied envelope and equal to the presented commitment.` |
| `commitment.sourceFormat`, `commitment.sourceCanonicalization`, `commitment.sourceEvidenceDigest`, `commitment.sourceFileSha256` (each) | the commitment verified and that member matched | `VERIFIED` | `Equal to the value the verifier established from the supplied evidence.` |
| `commitment.sourceRef` | the envelope is valid | `UNRESOLVED` | `An identifier only; it was not dereferenced.` |

`THIRD_PARTY_ATTESTED` is never produced in v1.

## 7. Size

The report's size is bounded by its inputs' limits:

- at most 16 signature records and their statements;
- at most one validation finding, or one digest finding, 16 signature findings and five
  commitment findings;
- identifiers of at most 128 characters, and a `sourceRef` of at most 512.
