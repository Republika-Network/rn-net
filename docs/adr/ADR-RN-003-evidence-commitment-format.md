# ADR-RN-003: Evidence commitment format and the `rnnet.*` namespace

- Status: Accepted
- Date: 2026-10-28
- Specification: [rnnet.evidence-commitment.v1](../../spec/rnnet.evidence-commitment.v1.md)

## Context

Later work packages anchor a value on public test networks and attest to it. That value
must be small, fixed-size, independent of any chain, and must bind what the evidence
claims to be without RN-NET reinterpreting the evidence itself.

The shorter `rn.` prefix is already used for an unrelated identifier elsewhere in the
ecosystem.

## Decision

1. **Namespace.** Every RN-NET format identifier starts with `rnnet.`. The
   `format-namespace` guard enforces this.
2. **Envelope.** `rnnet.evidence-commitment.v1` is a closed object with six string fields:
   `format`, `sourceFormat`, `sourceCanonicalization`, `sourceEvidenceDigest`,
   `sourceFileSha256`, `sourceRef`. Unknown fields are rejected, never ignored.
3. **Two source digests.** The commitment binds both the source's own evidence digest (as
   the source states it, under its own canonicalization profile) and the SHA-256 of the
   exact file bytes. The first ties the commitment to the evidence's meaning, the second
   to one concrete artifact. Either can later be checked without the other.
4. **Profile identity.** The source canonicalization identifier is bound as an opaque
   string. A different identifier gives a different commitment, even for a related
   profile.
5. **Provenance outside.** Descriptions, timestamps and run metadata are not in the
   envelope. `sourceRef` is an identifier only, restricted to visible ASCII with a scheme so
   that look-alike characters cannot produce two references that read the same.
6. **Construction.** `commitment = SHA-256("rnnet:evidence-commitment:v1" || 0x00 ||
   canonical envelope)`, written `sha256:<64 lowercase hex>`. The domain separator
   distinguishes RN-NET commitments from any other hash of the same bytes, and v1 from
   future versions.
7. **Content binding.** The commitment is over the canonical form, so equivalent encodings
   of one envelope commit to the same value. Byte-level tricks that would change the
   meaning (duplicate keys, trailing content, a byte order mark) are rejected by the
   canonical parser.
8. **Verification results** use the taxonomy of ADR-RN-004 and never claim more than was
   recomputed.

## Alternatives considered

- **Hash the source file only.** Rejected: it binds bytes but not what the evidence claims
  to be, and gives no place for the source's own digest.
- **Open envelope with optional fields.** Rejected: optional fields let two parties hold
  different "valid" envelopes for one commitment.
- **Length-prefixed or binary encoding.** Rejected for v1: canonical JSON is readable,
  already specified (ADR-RN-002), and its domain separator boundary is unambiguous.

## Consequences

- Changing any field, rule, the separator, the hash or the profile requires
  `rnnet.evidence-commitment.v2`.
- RN-NET-02 must recompute `sourceEvidenceDigest` under the source's own profile before it
  can report it as `VERIFIED`.
- RN-NET-03 anchors the 32 raw digest bytes, not the envelope.
