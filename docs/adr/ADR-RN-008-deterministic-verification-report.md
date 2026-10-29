# ADR-RN-008: Deterministic verification report

- Status: Proposed (RN-NET-02)
- Date: 2026-10-29
- Specification: [rnnet.verification-report.v1](../../spec/rnnet.verification-report.v1.md)

## Context

A verification result is only useful if others can reproduce it and cannot misread it. A
single "verified: true", or a report mixing runtime details with conclusions, invites both
problems: different reports for the same input, and passes that sound like more than they
are.

## Decision

1. **Determinism.** The report `rnnet.verification-report.v1` is a deterministic function of:
   - the evidence bytes;
   - optionally, a commitment envelope and a presented commitment.

   It is serialized under `rnnet.canonical-json.v1`, so the same inputs give the same bytes.
   It contains no time, host, node identity or other runtime metadata. Such data, if ever
   needed, goes in a separate attestation envelope.
2. **Outcomes.**
   - `PASS`, `FAIL` and `UNSUPPORTED` are produced.
   - `INDETERMINATE` is reserved.
   - `PASS` requires every check to pass: the digest, every signature, and the commitment and
     each of its compared members when one is supplied.
   - Any failure makes the outcome `FAIL`.
   - `PASS` is defined as a statement about bytes and keys, never about real-world truth.
3. **Findings.**
   - They carry stable codes (`RNSE_*`, `RNEC_*`, `RNCJ_*`), a severity and a subject.
   - Their order is the order of the checks.
   - A failed check is a finding, never a statement.
4. **Statements.**
   - They carry the taxonomy classification of each examined subject, with fixed basis
     sentences.
   - No statement is made about a subject that was not examined, or whose binding failed. For
     example, claims of a body whose digest does not match are not reported as `CLAIMED`.
5. **No free text from the input.** The report holds only:
   - fixed strings;
   - digests;
   - public keys;
   - ASCII identifiers that passed their pattern.

   `sourceRef` is echoed as untrusted text and never dereferenced. Payloads are never echoed.
   With at most 16 signatures, the report stays small.

## Consequences

- **Machine use.** Reports can be compared, stored or signed later, for example by RN-NET-04
  attestations, without any normalization step.
- **Changes need a new version.** A change to the members, codes, bases or ordering is a new
  report version.
