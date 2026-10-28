# rnnet.verification-taxonomy.v1

- Status: Draft (RN-NET-01)
- Decision record: [ADR-RN-004](../docs/adr/ADR-RN-004-verification-trust-taxonomy.md)
- Implementation: `packages/commitment/src/taxonomy.mjs`

## 1. Purpose

Every conclusion RN-NET reports carries exactly one classification, so that a reader can
tell what was checked, by whom, and what remains an assertion. A classification describes
the **basis** of a statement, never its likelihood.

## 2. Classifications

| Classification | Meaning | What it does not establish |
|---|---|---|
| `VERIFIED` | RN-NET recomputed the value itself from bytes it was given and it matched, needing no trust in the producer. | That the bytes it was given are the right ones, or that what they describe is true. |
| `CONSISTENT_UNDER_EMBEDDED_KEYS` | Signatures verify, but only under public keys carried by the evidence itself. | Who held the private keys. A key travelling with the data it signs is not a root of trust. |
| `THIRD_PARTY_ATTESTED` | An identified third party (for example a CI provider or a ledger) asserts the fact, and its own record can be checked separately. | That the third party is honest or correct; only that it said so. |
| `CLAIMED` | The value is stated in the input and may be bound by a digest, but RN-NET did not check it against its subject. | Anything about the subject. Binding a claim into a digest makes it tamper-evident, not true. |
| `UNRESOLVED` | The statement cannot be checked from the material given, for example an identifier that was not dereferenced. | Anything; the question is open. |

## 3. Rules

1. A statement is `VERIFIED` only when the verifier performed the recomputation in the same
   run. Reading a recorded "verified: true" flag is at most `CLAIMED`.
2. A classification is never upgraded by agreement: two `CLAIMED` sources that agree are
   still `CLAIMED`.
3. If several bases apply, the weakest one is reported.
4. A verifier never reports a classification for a subject it did not examine.

## 4. What no RN-NET-01 result proves

A successfully recomputed hash or commitment does not prove:

- the identity of the source organization;
- the identity of a signer;
- that a policy was enforced;
- that an external transaction occurred;
- that a blockchain anchor exists;
- that the source evidence is truthful.

## 5. Use in RN-NET-01

RN-NET-01 can produce only `VERIFIED` (for the commitment, and for `sourceFileSha256` when
the source file is supplied), `CLAIMED` and `UNRESOLVED`. It never produces
`CONSISTENT_UNDER_EMBEDDED_KEYS` or `THIRD_PARTY_ATTESTED`, because it verifies no
signatures and consults no third party. Those classifications are defined now so that
RN-NET-02 and RN-NET-03 can use them without changing this taxonomy.
