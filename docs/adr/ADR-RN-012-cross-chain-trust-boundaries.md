# ADR-RN-012: Cross-chain verification and trust boundaries

- Status: Proposed (RN-NET-03A)
- Date: 2026-10-29
- Specification: [rnnet.anchor-record.v1](../../spec/rnnet.anchor-record.v1.md) §1, §5, §6

## Context

"Anchored on two blockchains" is easily read as more than it is. An anchor record can be any
of these:

- a bare claim;
- consistent with data supplied alongside it;
- consistent with data the verifier fetched itself;
- backed by an authenticated proof of inclusion and finality.

Only the last makes the ledgers witnesses. Even then, an anchor shows only that a commitment
existed by a certain time. It never shows that the evidence behind the commitment is true.

## Decision

1. **Four assurance levels.** These are 1 claim, 2 consistent with supplied data, 3 consistent
   with fetched data, and 4 authenticated inclusion. RN-NET-03A implements level 2 only, and a
   `PASS` record says `CONSISTENT_WITH_SUPPLIED_DATA`. Levels 3 and 4 are future work.
2. **Each observation is checked only for its own network.** Each is checked in its own slot
   (XRPL or Sepolia) by its own adapter, so records cannot be swapped between networks. The
   dual-chain report states separately:
   - `PAYLOAD_MATCH`: the same expected payload is in both;
   - `RECORDS_CONSISTENT`: both records pass;
   - `CHAIN_INCLUSION_UNVERIFIED`: always, in RN-NET-03A.
3. **`CHAIN_PROVEN` is reserved.** It is never emitted until authenticated proof verification
   (level 4) exists for both networks. No combination of supplied records can produce it.
4. **What records say.**
   - **Statements:** every record and report carries taxonomy statements:
     - the payload is `VERIFIED` against the supplied bytes;
     - network, status, inclusion and submitter are `CLAIMED`;
     - finality is `CLAIMED` on XRPL, from the supplied `validated` flag, and `UNRESOLVED` on
       Sepolia;
     - the transaction hash and chain inclusion are `UNRESOLVED`;
     - the anchored evidence's truth is `UNRESOLVED`.
   - **No input text:** records copy no input text. They contain fixed strings and values that
     passed their patterns.
5. **What this milestone does not do.** It adds no network access, keys, signing, transactions,
   wallets, funding, federation or consensus. Testnet records carry no production finality
   guarantee: Sepolia's validators are permissioned, and both networks can be reset.

## Consequences

- **The dual-chain `PASS`.** It is useful, but bounded: it shows the two supplied records agree
  with each other and with the expected commitment. It does not show that either transaction
  exists, that it is final, or that the evidence is true.
- **Later milestones.**
  - **RN-NET-03B:** real testnet transactions, under separate authorization.
  - **RN-NET-03C:** a publicly reproducible proof run.
  - **Later still:** levels 3–4 and RN-NET-04 attestations can raise the assurance. Each
    requires its own specification.
