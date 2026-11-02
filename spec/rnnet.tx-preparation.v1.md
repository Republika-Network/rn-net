# rnnet.tx-preparation.v1

- Status: Draft (RN-NET-03B2-B2; amended in RN-NET-03B2-C3 for ADR-RN-016 Amendment C1 and ADR-RN-018 Amendment C1, both still Proposed)
- Decision record: [ADR-RN-018](../docs/adr/ADR-RN-018-transaction-preparation-reads.md), Amendment C1 (P1 to P6); [ADR-RN-016](../docs/adr/ADR-RN-016-genesis-anchoring-transactions.md) Amendment C1 (the `+ 80` offset)
- Depends on: [rnnet.unsigned-tx-intent.v1](rnnet.unsigned-tx-intent.v1.md), [rnnet.live-observation-report.v1](rnnet.live-observation-report.v1.md) §3 and §4 (requests, transport, strict JSON)
- Implementations:
  - `packages/chain-readonly/src/preparation.mjs` (readers);
  - `packages/tx-prepare` (checks and binding);
  - `tools/reference/rnnet_prep_reference.py` (independent).
- Vectors: `fixtures/preparation-b2/cases.json` (synthetic, `rnnet.preparation-b2-fixtures.v2`)
- Live entry point: `tools/prepare/prepare-live.mjs` ([rnnet.preparation-authorization.v1](rnnet.preparation-authorization.v1.md)), disabled for live network access

## 1. Purpose

Preparation binds the `null` fields of a Genesis template (ADR-RN-016) from read-only provider
observations, and returns an `rnnet.unsigned-tx-intent.v1` intent and its digest for approval.
It refuses data it cannot check, and it never relaxes a bound that ADR-RN-016 fixes.

## 2. Inputs

| Network | Inputs |
|---|---|
| both | `commitment` (`sha256:<64 lowercase hex>`); `now` (a positive safe integer of Unix seconds); 2 to 4 `providers`, each `{id, network, url, operator}`, distinct by `id`, by `url` and by `operator`, all on the network; an injected transport |
| `xrpl:testnet` | `signingPubKey` (`ED` + 64 upper-case hex) and `account`, which must be its classic address |
| `evm:11155111` | `from`, a lower-case address |

Anything else is `RNTP_INPUT_INVALID`, and nothing is sent.

## 3. Requests

Each request has **one attempt** and no retry. The request bytes are built as in
`rnnet.live-observation-report.v1` §3: canonical JSON; XRPL `{method, params: [params]}`;
Ethereum `{jsonrpc: "2.0", id: 1, method, params}`.

**XRPL**, 2 requests per provider. Providers are read one after another, in the order given, and
each is read and checked (§4.1, §4.2) before the next is contacted:
1. `server_info` `{api_version: 2}`;
2. `account_info` `{account, ledger_index: "validated", signer_lists: true, api_version: 2}`.

**Sepolia**, 8 requests per provider, in three passes over the providers in the order given
(ADR-RN-018 Amendment C1, P1 and P3). A pass ends on every provider before the next pass starts:
1. **Head pass**, on each provider: `eth_chainId` `[]`, then `eth_getBlockByNumber`
   `["latest", false]`. Each head is checked (§4.2) when it arrives; then the heads are checked
   across providers (§4.3).
2. **The pin.** `P` = the lowest head number − 2, as a quantity. On each provider:
   `eth_getBlockByNumber` `[P, false]`. Every provider must return the same hash `H`.
3. **Pinned pass**, on each provider, where `A` = `{"blockHash": H, "requireCanonical": true}`:
   1. `eth_getTransactionCount` `[from, A]`;
   2. `eth_getTransactionCount` `[from, "pending"]` (a pending state has no hash);
   3. `eth_getBalance` `[from, A]`;
   4. `eth_getCode` `[from, A]`;
   5. `eth_estimateGas` `[{from, to: from, value: "0x0", data: <payload>}, A]`, where the payload
      is the `0x`-prefixed lower-case hex of the 42-byte anchor payload.

**No fallback.** A pinned read is always sent with `A`. It is never sent again with `latest`,
`pending`, a block number or no block parameter, and never to another provider. `eth_estimateGas`
is not listed by EIP-1898; it is still sent only with `A` (P4), and a provider that refuses it
refuses preparation.

**Totals per run, two providers:** XRPL 4, Sepolia 16.

## 4. Checks and refusal codes

The first failing check gives the only code. A code that names a provider carries its id.

### 4.1 While reading, in request order

Each response is checked when it arrives:
- **Transport.** A transport error, a body over 256 KiB, or an HTTP status other than 200 is
  `RNTP_PROVIDER_UNAVAILABLE`.
- **JSON.** The body must be strict JSON (live-observation-report §4), else `RNTP_MALFORMED`.
  A number is an integer only when it is a safe integer other than `-0`; any other number,
  however long, is kept as its text and fails every integer check.
- **Envelope.**
  - XRPL: `result` must be an object. `status: "error"` is `RNTP_ACCOUNT_NOT_FOUND` when
    `error` is `actNotFound`, and `RNTP_PROVIDER_ERROR` otherwise. Any `status` other than
    `"success"` is `RNTP_MALFORMED`. (`txnNotFound` is `RNTP_PROVIDER_ERROR` too.)
  - Ethereum: `jsonrpc` must be `"2.0"` and `id` the integer 1, else `RNTP_MALFORMED`. An
    `error` member is `RNTP_PROVIDER_ERROR`. A missing `result` is `RNTP_MALFORMED`.
- **Values**, in the order listed. A value of the wrong form is `RNTP_MALFORMED`.

  **`server_info`** (`result.info`, an object):
  1. `network_id`:
     - absent: `RNTP_WRONG_NETWORK`;
     - not a safe integer: `RNTP_MALFORMED`;
     - not 1: `RNTP_WRONG_NETWORK`.
  2. `server_state`: a string.
  3. `validated_ledger`, an object:
     - `seq`: an integer from 1 to 2^32−1;
     - `hash`: 64 upper-case hex digits;
     - `age`: a non-negative safe integer;
     - `base_fee_xrp`, `reserve_base_xrp` and `reserve_inc_xrp`: amounts in XRP (below). The base
       fee must not be zero.
  4. `load_factor`: an exact decimal (below), at least 1.

  **`account_info`** (`result`):
  1. `validated`: a boolean.
  2. `ledger_index`: an integer from 1 to 2^32−1.
  3. `ledger_hash`: 64 upper-case hex digits.
  4. `account_data`, an object:
     - `Account`: a classic address;
     - `Balance`: a decimal string of drops, `0|[1-9][0-9]{0,17}`;
     - `Sequence`: an integer from 1 to 2^32−1;
     - `OwnerCount` and `Flags`: integers from 0 to 2^32−1;
     - `RegularKey`, if present: a classic address.
  5. `signer_lists`: an array. API v2 places it at the top level of the result.

  **Sepolia:**
  1. The chain ID must be a quantity (`0x0` or `0x` + lower-case hex with no leading zero), and
     must be `0xaa36a7`, else `RNTP_WRONG_NETWORK`.
  2. The block is an object:
     - `number`, `timestamp` and `baseFeePerGas`: quantities;
     - `hash`: `0x` + 64 lower-case hex digits.
  3. Both nonces are quantities below 2^64.
  4. The balance is a quantity.
  5. The code is `0x` followed by lower-case hex byte pairs.
  6. The estimate is a quantity.

  **XRP amounts and decimals.**
  - **Form.** A safe non-negative integer, or a JSON number written as
    `(0|[1-9][0-9]{0,29})(\.[0-9]{1,30})?([eE][+-]?[0-9]{1,2})?` (for example `1e-05` or `0.2`).
  - **Exact value.** It is read as an exact fraction, never as a binary float.
  - **Amounts.** An amount must be a whole number of drops (XRP × 10^6), at most 10^17.

### 4.2 Per provider, on what it reported

**XRPL**, in order:

| Check | Code |
|---|---|
| `server_state` is `full`, `proposing` or `validating` | `RNTP_NOT_SYNCED` |
| `validated_ledger.age` ≤ 30 | `RNTP_STALE` |
| `account_info.validated` is true | `RNTP_INCONSISTENT` |
| 0 ≤ `account_info.ledger_index` − `validated_ledger.seq` ≤ 2 | `RNTP_INCONSISTENT` |
| if that difference is 0, the two ledger hashes are equal | `RNTP_INCONSISTENT` |
| `account_data.Account` is the input `account` | `RNTP_INCONSISTENT` |
| no `RegularKey`; `Flags` without `lsfDisableMaster` (`0x00100000`); `signer_lists` empty | `RNTP_ACCOUNT_UNSUITABLE` (each, in this order) |
| `base_fee_drops × load_factor` ≤ 12 | `RNTP_FEE_TOO_HIGH` |
| `Balance` ≥ `reserve_base` + `OwnerCount` × `reserve_inc` + 12 (drops) | `RNTP_INSUFFICIENT_BALANCE` |

**Sepolia**, with `ts` a block's timestamp.

The head, on each provider, in the head pass:

| Check | Code |
|---|---|
| `now` − `ts` ≤ 60 | `RNTP_STALE` |
| `ts` − `now` < 15 | `RNTP_STALE` |
| `baseFeePerGas` ≤ 19 gwei | `RNTP_FEE_TOO_HIGH` |

The pin, on each provider, in order:

| Check | Code |
|---|---|
| its `number` is `P` | `RNTP_INCONSISTENT` |
| its hash is not this provider's head hash, and its `ts` is not after the head's | `RNTP_INCONSISTENT` |
| `now` − `ts` ≤ 90 | `RNTP_STALE` |
| `ts` − `now` < 15 | `RNTP_STALE` |
| `baseFeePerGas` ≤ 19 gwei | `RNTP_FEE_TOO_HIGH` |

The pinned reads, on each provider, in order:

| Check | Code |
|---|---|
| pending nonce = pinned nonce | `RNTP_NONCE_PENDING` |
| code = `0x` | `RNTP_ACCOUNT_UNSUITABLE` |
| estimate ≤ 30,000 | `RNTP_GAS_TOO_HIGH` |
| estimate ≥ the intrinsic gas of the payload (22,680 for Genesis Proof 01) | `RNTP_INCONSISTENT` |

### 4.3 Across providers

These checks carry no provider id, except the balance check.

**XRPL:**
1. max − min of `validated_ledger.seq` ≤ 4, else `RNTP_INCONSISTENT`.
2. No ledger index appears, among all `validated_ledger` and `account_info` ledgers, with two
   different hashes, else `RNTP_INCONSISTENT`.
3. Every `Sequence` is equal, else `RNTP_INCONSISTENT`.

**Sepolia:**
1. After the head pass: max − min of the head numbers ≤ 4, and no number with two hashes, else
   `RNTP_INCONSISTENT`. `P` < 0 is `RNTP_INCONSISTENT`.
2. After the pin: every provider's pin has the same hash, else `RNTP_INCONSISTENT`; and the same
   timestamp and base fee, else `RNTP_INCONSISTENT`.
3. After the pinned pass: every pinned nonce is equal, else `RNTP_INCONSISTENT`.
4. `maxFeePerGas` = min(2 × the pin's base fee + 1 gwei, 20 gwei) (ADR-RN-018 Amendment C1, P6).
   Each provider's balance, in provider order, must be ≥ 30,000 × `maxFeePerGas`, else
   `RNTP_INSUFFICIENT_BALANCE` for that provider.

### 4.4 Blocked: a refused pinned read

A JSON-RPC `error` answer to a pinned read (§3, Sepolia pass 3) is `RNTP_PROVIDER_ERROR` for that
provider, like any RPC error, with no new code (P2). It is also marked **blocked**, because the
reviewed strategy has no fallback to try:
- `GAS_ESTIMATION_UNAVAILABLE` when the refused read is `eth_estimateGas`;
- `BLOCK_HASH_READ_REFUSED` for any other pinned read (an unsupported block-hash form, an unknown
  hash, or a hash that is no longer canonical).

A transport failure or a malformed answer on a pinned read is not blocked: its code is as in §4.1.
Nothing is retried in either case. The entry point reports a blocked refusal as `BLOCKED`.

## 5. Binding and the record

**XRPL.** `xrplAnchorTemplate(commitment, {Account, Sequence, LastLedgerSequence, SigningPubKey})`:
- `Sequence` is the agreed `Sequence`;
- `LastLedgerSequence` = min(`validated_ledger.seq`) + 80 (ADR-RN-016 Amendment C1; was + 20). The
  broadcaster still refuses before any write once a validated ledger it reads is
  `LastLedgerSequence` − 4 or later, so at least 5 ledgers must remain (ADR-RN-019 §5).

**Sepolia.** `sepoliaAnchorTemplate(commitment, {nonce, from, maxFeePerGas})`:
- `nonce` is the agreed latest nonce;
- `maxFeePerGas` is as computed in §4.3.

**The record.** The intent's `preparation` member is:

```
{ "format": "rnnet.tx-preparation.v1", "source": "rpc-read", "rules": "ADR-RN-018",
  "observedAt": <now>, "providers": [ <entry>, ... ] }
```

Each entry, in provider order, holds `id` and `operator`, then:
- **XRPL:** `validatedLedger` `{index, hash}`, from `server_info`, and `accountLedger`
  `{index, hash}`, from `account_info`;
- **Sepolia:** `block` `{number, hash, timestamp, baseFeePerGas}` of the **pinned** block `P` (the
  same on every provider), and `estimateGas`, as received. The head blocks are covered by their
  exchange digests.

It also holds `exchanges`: one `{method, requestSha256, responseSha256}` per request of that
provider, in its order (8 on Sepolia, across the three passes).
The digests are `sha256:<hex>` of the exact request bytes and of the exact response body.

**The intent** is `{format, network, purpose: "genesis-proof-01", commitment, transaction,
preparation}`. It must pass `makeIntent`; a failure is `RNTP_INTENT_INVALID`. One reachable case is a
validated ledger within 80 of 2^32−1, which would make `LastLedgerSequence` overflow. Its digest is the `rnnet.unsigned-tx-intent.v1` §3 digest, so it
covers the record.

## 6. What a prepared intent shows

A prepared intent shows two things:
- the named providers returned these bytes;
- the bytes passed these checks.

It does not show that the providers told the truth (ADR-RN-015). Agreement between providers is
not a consensus proof.

Every bound on fees, gas, the network and the transaction's form is fixed independently of the
providers and re-checked by `makeIntent`. So a false answer can make the transaction fail, but
cannot make it move value or leave the network.
