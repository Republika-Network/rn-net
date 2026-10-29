# ADR-RN-015: Live finality and trust semantics

- Status: Proposed (RN-NET-03B1)
- Date: 2026-10-29
- Specification:
  - [rnnet.live-observation-report.v1](../../spec/rnnet.live-observation-report.v1.md) §5, §6, §7.4
  - [rnnet.anchor-record.v1](../../spec/rnnet.anchor-record.v1.md) §1

## Context

**XRPL.** XRPL marks transactions in validated ledgers with `validated: true`.

**Ethereum.** Ethereum providers expose `safe` and `finalized` blocks. A provider can claim any of
these.

**What this milestone has.** RN-NET-03B1 has no light client and no proof of inclusion, so it cannot
check them cryptographically.

## Decision

1. **Network identity comes from the server.**
   - **XRPL:** `server_info` `network_id` must be 1. If it is missing, the network is unknown and
     the report fails.
   - **Sepolia:** `eth_chainId` must be `0xaa36a7`.

   A provider's name or URL is never evidence of its network.
2. **XRPL validation.** A transaction is "provider-reported validated" only when two things hold:
   - `tx` says it is validated;
   - a separate `ledger` read of the same index is validated and has the same hash.

   The RN-NET-03A adapter still checks the result code, the CTIDs and the anchor.
3. **Sepolia inclusion and finality.**
   - **Inclusion:** the transaction's block must exist, match its hash and number, and list the
     transaction at its index.
   - **Finality:** "provider-reported finalized" requires that the provider's `finalized` block
     reaches the transaction's block through parent hashes. The walk is at most 256 steps, and each
     link is checked.
   - **What counts as conflict or unresolved:**
     - another block at that height is a conflict, and fails the report;
     - a finalized head below the transaction's height is "not reached";
     - a missing tag or too long a walk is unresolved.

   A lower block number alone is never treated as finality.
4. **Classifications.**
   - The provider observation, agreement, validation and finality are `CLAIMED`.
   - Finality that was not established is `UNRESOLVED`.
   - `chainInclusionProof` is always `UNRESOLVED`.
   - No RPC observation, however many providers agree, produces `CHAIN_PROVEN` or assurance above
     `CONSISTENT_WITH_SUPPLIED_DATA`.
5. **What an authenticated proof would require (future work):**
   - **XRPL:** a validated ledger header with a quorum of validator signatures from a trusted UNL,
     plus a SHAMap inclusion proof.
   - **Sepolia:** a consensus light client following sync-committee signatures from a trusted
     checkpoint, plus Merkle-Patricia proofs of the transaction and receipt.

## Consequences

- **What the result can say.** A live `PASS` with `PROVIDER_REPORTED_FINALIZED` and
  `MULTI_PROVIDER_AGREEMENT` is a statement about what those providers said. It is not about what
  the chain's consensus decided.
- **Testnet finality.** Testnets can be reset, and Sepolia's validators are permissioned, so
  provider-reported finality on a testnet is not a production guarantee.
- **What an anchor shows.** Nothing here says anything about whether the anchored evidence is true.
