# ADR-RN-007: Ed25519 signatures and signer trust semantics

- Status: Proposed (RN-NET-02)
- Date: 2026-10-29
- Specifications: [rnnet.synthetic-evidence.v1](../../spec/rnnet.synthetic-evidence.v1.md) §5 and §8, [rnnet.verification-taxonomy.v1](../../spec/rnnet.verification-taxonomy.v1.md)

## Context

A signature that verifies is easily read as "signed by the issuer". Evidence that carries its
own public keys can be entirely self-consistent and still say nothing about who produced it:
anyone can generate a key, sign, and attach both.

Ed25519 implementations also disagree on edge cases:

- non-canonical encodings;
- small-order keys;
- S not reduced modulo L;
- cofactored versus cofactorless verification.

A verifier whose result depends on its library is not reproducible.

## Decision

1. **Algorithm and encodings.**
   - Ed25519 only, in v1.
   - Public keys are 32 bytes and signatures 64 bytes, as lowercase hex.
   - The signed message is the signature domain separator followed by the 32 recomputed
     digest bytes.
2. **A strict profile, fixed by the specification, not by a library.**
   - A public key is rejected if it is non-canonical, not on the curve, or of small order.
   - A signature is invalid if S is at least L, or if R is not a canonical point.
   - The equation is the cofactorless one.
   - The JavaScript verifier applies these rules itself, from RFC 8032, before calling
     Node.js's built-in Ed25519.
   - The Python reference implements all of Ed25519 from RFC 8032.
3. **Every record is verified.** No invalid signature is ignored, and an invalid signature
   always makes the outcome `FAIL`, whatever else matched.
4. **Classifications.** Applied per claim, from `rnnet.verification-taxonomy.v1`:

   | Claim | Classification |
   |---|---|
   | Evidence digest recomputed and matched | `VERIFIED` |
   | A signature that verifies under its embedded key | `CONSISTENT_UNDER_EMBEDDED_KEYS` |
   | Signer identity, for every record | `UNRESOLVED` |
   | Issuer, subject, action, outcome, payload | `CLAIMED`, bound by the verified digest |
   | The event's occurrence | `UNRESOLVED` |
   | Governance or policy enforcement | Not reported: the format carries no such proof, and the verifier does not examine one |

5. **Classifications never emitted.**
   - **`THIRD_PARTY_ATTESTED`.** It is not emitted in RN-NET-02. It would need an
     independently authenticated trust source and a defined verification procedure, and
     neither exists yet. A third party's name or key inside the evidence does not qualify.
   - **Agreement does not upgrade.** Several valid signatures are several facts of the same
     kind, never an identity. No synthetic root of trust is created or presented as an
     external authority.
6. **Private keys.**
   - The verifier never handles a private key.
   - Test signing happens only in test code and in the vector generator, with keys derived
     from public labels. Their derivation is public, so they can never pass as credentials.
   - No private key, seed or mnemonic is committed.

## Consequences

- **What a `PASS` with signatures means.** It means: these bytes were signed by whoever holds
  these keys. Binding a key to a person or an organization is future work, for example
  RN-NET-04 attestations or a separately specified trust source. It is not implied here.
- **Key substitution.** An attacker who re-signs evidence under its own key, and reuses a
  `keyId`, gets a consistent signature and an `UNRESOLVED` signer identity. Readers must not
  treat `keyId` as an identity.
- **Library-independent results.** Results on the Ed25519 edge cases do not depend on the
  library: they are pinned by the vectors and reproduced by the independent Python code.
