# ADR-RN-004: Verification and trust taxonomy

- Status: Accepted
- Date: 2026-10-28
- Specification: [rnnet.verification-taxonomy.v1](../../spec/rnnet.verification-taxonomy.v1.md)

## Context

Verification output is easy to over-read. A matching hash is often presented as "verified
evidence", although it only shows that two byte sequences agree. Evidence that carries its
own public keys can be internally consistent without identifying anyone. A ledger or CI
record is a third party's statement, not a cryptographic fact about the evidence.

ADR-RN-001 requires RN-NET to separate what it verified from what it could not.

## Decision

1. Every statement RN-NET reports has exactly one of five classifications: `VERIFIED`,
   `CONSISTENT_UNDER_EMBEDDED_KEYS`, `THIRD_PARTY_ATTESTED`, `CLAIMED`, `UNRESOLVED`.
2. `VERIFIED` means recomputed by RN-NET in the same run from bytes it was given. Recorded
   verification flags are at most `CLAIMED`.
3. Agreement between sources never upgrades a classification. Where several bases apply,
   the weakest is reported.
4. Documentation and user-facing output must not describe a commitment, digest or
   signature check as proving organizational identity, signer identity, policy
   enforcement, an external transaction, an anchor, or truthfulness.
5. RN-NET-01 emits only `VERIFIED`, `CLAIMED` and `UNRESOLVED`. The other two
   classifications are defined now for RN-NET-02 and RN-NET-03.

## Consequences

- Reports are longer, and stay honest when quoted out of context.
- Each new verification capability must state which subjects it can move to `VERIFIED`, and
  must be tested so that it cannot classify anything it did not examine.
