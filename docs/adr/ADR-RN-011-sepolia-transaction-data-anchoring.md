# ADR-RN-011: Ethereum Sepolia transaction-data anchoring

- Status: Proposed (RN-NET-03A)
- Date: 2026-10-29
- Specification: [rnnet.anchor-record.v1](../../spec/rnnet.anchor-record.v1.md) §4

## Context

Sepolia is Ethereum's recommended testnet for application development
([networks](https://ethereum.org/en/developers/docs/networks/)). It runs on a permissioned
validator set. Its chain ID is 11155111 (`0xaa36a7`), per the
[chain registry](https://github.com/ethereum-lists/chains/blob/master/_data/chains/eip155-11155111.json).

Ethereum's [JSON-RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/) API behaves as
follows:

- `eth_getTransactionByHash` returns `input`, with `null` block fields while the transaction is
  pending.
- `eth_getTransactionReceipt` returns `null` until inclusion, and `status` `1` (success) or `0`
  (failure).

There are two ways to anchor: (A) put the payload in a transaction's input data, or (B) emit it
from a contract.

## Decision

1. **Option A.** The anchor is an ordinary transaction (type `0x0`, `0x1` or `0x2`) to an
   address. Its `input` is exactly the 42-byte payload.
   - No contract is deployed or needed.
   - Data sent to an account without code is not executed, so the transaction succeeds
     whatever its data.
   - A contract would add deployment, code review and a new trust surface (its own logic) for
     no verification benefit: the input bytes are already part of the signed transaction.
2. **Offline checks only.** RN-NET-03A checks a supplied transaction and receipt offline:
   - **Formats:** lowercase hex hashes, addresses and data; canonical quantities.
   - **Network and transaction type:** `chainId` is `0xaa36a7`; the type is `0x0`, `0x1` or
     `0x2`.
   - **No contract creation.**
   - **Agreement between transaction and receipt** on hash, sender, recipient, block hash,
     block number and index.
   - **The input is exactly the payload.**
   - **The claimed status:** not pending, and receipt status `0x1`. A reverted transaction is a
     failure even though it was included.
3. **Kept apart.** These are distinct facts and are never merged:
   - submitted;
   - included: block fields and a receipt;
   - executed successfully: receipt status;
   - consistent: transaction and receipt agree;
   - final: not determinable from a receipt;
   - anchor equality: payload bytes.

## Consequences

- **What the record states.** The record states inclusion and status as `CLAIMED`, and finality
  as `UNRESOLVED`. The transaction hash is not recomputed (that would need RLP and Keccak-256),
  so it is `UNRESOLVED`.
- **What a supplied receipt is.** A supplied receipt is not an authenticated proof. That would
  need block headers and a light client or consensus verification, which is future work.
- **Types the adapter rejects as unsupported transports:**
  - blob transactions (type 3);
  - set-code transactions (type 4);
  - legacy transactions without a `chainId`.
