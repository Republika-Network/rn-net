# ADR-RN-006: Evidence verification profile

- Status: Proposed (RN-NET-02)
- Date: 2026-10-29
- Specification: [rnnet.synthetic-evidence.v1](../../spec/rnnet.synthetic-evidence.v1.md)

## Context

RN-NET-01 can commit to evidence and verify a commitment. It cannot yet look inside the evidence:
recompute its digest, check its signatures, or say which of its claims are bound and by what.
An independent verifier needs a concrete, versioned evidence format to do that.

ADR-RN-001 rule 6 rules out other systems' unpublished formats until a written authorization
covers them. The first format must therefore be original. It is a test and interoperability
profile, not a production one.

## Decision

1. **The format.** The first supported format is `rnnet.synthetic-evidence.v1`. It is
   original, synthetic and deliberately small:
   - a closed document whose claims sit in a closed `body`;
   - an evidence digest of the body;
   - zero to 16 Ed25519 signature records.

   It reuses `rnnet.canonical-json.v1` and has no timestamps.
2. **The digest and what it covers.**
   - **Coverage.** The digest covers only `body`. Signatures sign the recomputed digest,
     never the declared one, and they live outside the body. Adding a signature therefore
     never changes what is signed, and no value covers itself.
   - **Domain separation.** The digest and the signatures use their own domain separators:
     - `rnnet:synthetic-evidence:digest:v1`;
     - `rnnet:synthetic-evidence:signature:v1`.

     These differ from the commitment's `rnnet:evidence-commitment:v1` and from each other.
     The source evidence digest, the source file hash and the commitment stay three distinct
     values.
3. **Validation.**
   - Validation is strict and closed, with a fixed order and a fixed first error, as in
     RN-NET-01.
   - `format` is checked before the closed-member rule, so a later version is reported as
     unsupported rather than as having unknown members.
   - Unsupported inputs (`RNSE_UNSUPPORTED_*`) are kept apart from malformed ones.
4. **Identifiers, ordering and limits.**
   - Identifiers are ASCII and compared byte for byte, with no normalization.
   - Signature records are strictly sorted by `keyId` and carry unique public keys, so a
     valid list has exactly one order.
   - Limits: 262,144 bytes per document, 65,536 bytes of canonical payload, 16 signatures,
     and the canonical profile's depth of 64.
5. **The verifier package.**
   - The verifier is a new package, `packages/verifier/`. It takes bytes only, holds no keys,
     makes no network calls and consults no trust source.
   - It depends only on `canonical`, `commitment` and Node.js built-ins:
     - `createHash`;
     - `createPublicKey` and `verify`, which check signatures and cannot sign;
     - `Buffer`.

     The dependency-boundary guard allows signing exports only in test code.
6. **Conformance.**
   - The vectors in `vectors/evidence/` are generated reproducibly by
     `tools/vectors/evidence-vectors.mjs`, from test keys derived at run time from public
     labels.
   - Each case states its expected outcome and finding codes by hand.
   - A second implementation, `tools/reference/rnnet_evidence_reference.py`, rebuilds every
     expected report byte for byte. It uses its own RFC 8032 Ed25519 code.

## Consequences

- **Integration with other systems.** Verifying another system's evidence needs a new profile
  with its own specification and, for an unpublished format, written authorization.
  `rnnet.synthetic-evidence.v1` does not stand in for any such format.
- **What a passing verification means.** It is a statement about bytes and keys. What it
  establishes and what it does not is set out in ADR-RN-007 and the report specification.
- **Independence of the second implementation.** The two implementations share an author and a
  specification, so their agreement is evidence of correctness, not proof. The Python side
  shares no cryptographic code with Node.js.
