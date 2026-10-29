# ADR-RN-010: XRPL Testnet memo anchoring

- Status: Proposed (RN-NET-03A)
- Date: 2026-10-29
- Specification: [rnnet.anchor-record.v1](../../spec/rnnet.anchor-record.v1.md) §3

## Context

An XRPL transaction can carry memos. The XRPL documentation
([common fields](https://xrpl.org/docs/references/protocol/transactions/common-fields)) sets
these rules:

- `MemoData`, `MemoType` and `MemoFormat` are hex.
- `MemoType` and `MemoFormat` may contain only URL characters.
- The `Memos` field is limited to 1 KB serialized.
- `NetworkID` must be omitted on networks with an ID of 1024 or less. XRPL Testnet's ID is 1.

The [`tx` method](https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/transaction-methods/tx)
reports data from a validated, final ledger only when `validated` is `true`. Hashes are 64 hex
digits, written in upper case
([basic data types](https://xrpl.org/docs/references/protocol/data-types/basic-data-types)).

[`AccountSet`](https://xrpl.org/docs/references/protocol/transactions/types/accountset) with
no options changes nothing beyond destroying the transaction cost.

This repository must not reuse or modify any other project's XRPL code; RN-NET's adapter is
its own.

## Decision

1. **The transaction.** The anchor is an `AccountSet` with no settings, carrying exactly one
   memo:
   - `MemoType` = hex(`rnnet.anchor-payload.v1`);
   - `MemoData` = the 42 payload bytes;
   - no `MemoFormat`.

   Other memos are ignored. Two anchor memos are ambiguous and rejected, even if identical.
2. **Offline checks only.** RN-NET-03A checks a supplied API v2 `tx` result offline:
   - **Formats:** hashes, ledger index, account and memo hex.
   - **Network signals:** no `NetworkID`, and network ID 1 in the CTID when one is present.
   - **Internal agreement** between `hash`/`tx_json.hash`, `ledger_index`/`tx_json.ledger_index`
     and the CTID ledger and transaction index.
   - **The anchor memo.**
   - **The claimed status:** `validated: true` and `tesSUCCESS`.
3. **Rejected data.**
   - Lowercase hex is rejected: rippled writes binary fields in upper case.
   - A non-boolean `validated` is a type error, never a pass.
   - A transaction hash on its own counts for nothing.
4. **What the result means.** The result is "consistent with supplied data", never "on the
   ledger". The adapter has no network access, and nothing in a supplied record is
   authenticated:
   - the transaction hash is not recomputed from the signed transaction blob;
   - there is no ledger proof.

## Consequences

- **Fabricated records.** A fabricated `tx` result that is internally consistent passes the
  adapter. Its record is still labelled as such: inclusion, status, finality and network are
  `CLAIMED`, and the transaction hash is `UNRESOLVED`.
- **Mainnet and Testnet.** Both have network IDs below 1025 and so omit `NetworkID`. Offline
  data can therefore only show that a transaction is *not* for another identified network. The
  network name is the supplier's claim.
- **Out of scope here:**
  - recomputing the hash from the transaction blob;
  - checking the account address checksum;
  - verifying ledger inclusion against validated ledger headers.

  These are future work (assurance levels 3–4). RN-NET-03B will submit the first real
  transaction under separate authorization.
