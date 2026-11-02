# rnnet.tx-preparation.v1

- Status: Draft (RN-NET-03B2-B2)
- Decision record: [ADR-RN-018](../docs/adr/ADR-RN-018-transaction-preparation-reads.md)
- Depends on: [rnnet.unsigned-tx-intent.v1](rnnet.unsigned-tx-intent.v1.md), [rnnet.live-observation-report.v1](rnnet.live-observation-report.v1.md) §3 and §4 (requests, transport, strict JSON)
- Implementations:
  - `packages/chain-readonly/src/preparation.mjs` (readers);
  - `packages/tx-prepare` (checks and binding);
  - `tools/reference/rnnet_prep_reference.py` (independent).
- Vectors: `fixtures/preparation-b2/cases.json` (synthetic)

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

Providers are read one after another, in the order given. Each provider is read and checked
(§4.1, §4.2) before the next is contacted. Each request has **one attempt** and no retry. The
request bytes are built as in `rnnet.live-observation-report.v1` §3: canonical JSON; XRPL
`{method, params: [params]}`; Ethereum `{jsonrpc: "2.0", id: 1, method, params}`.

**XRPL**, 2 requests:
1. `server_info` `{api_version: 2}`;
2. `account_info` `{account, ledger_index: "validated", signer_lists: true, api_version: 2}`.

**Sepolia**, 7 requests, where `B` is the `number` of the block read in step 2:
1. `eth_chainId` `[]`;
2. `eth_getBlockByNumber` `["latest", false]`;
3. `eth_getTransactionCount` `[from, B]`;
4. `eth_getTransactionCount` `[from, "pending"]`;
5. `eth_getBalance` `[from, B]`;
6. `eth_getCode` `[from, B]`;
7. `eth_estimateGas` `[{from, to: from, value: "0x0", data: <payload>}, B]`, where the payload is the
   `0x`-prefixed lower-case hex of the 42-byte anchor payload.

**Pinning.** In this version `B` is a block **number**, which is enough for offline fixtures.
Before an intent prepared from live Sepolia reads may be signed, ADR-RN-018 requires an amended
version. In it, steps 3, 5, 6 and 7 name one agreed block **hash**, as
`{blockHash, requireCanonical: true}` (EIP-1898), and every provider reads at that same hash.

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

**Sepolia**, in order, with `ts` the block timestamp:

| Check | Code |
|---|---|
| `now` − `ts` ≤ 60 | `RNTP_STALE` |
| `ts` − `now` < 15 | `RNTP_STALE` |
| `baseFeePerGas` ≤ 19 gwei | `RNTP_FEE_TOO_HIGH` |
| pending nonce = latest nonce | `RNTP_NONCE_PENDING` |
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
1. max − min of the block numbers ≤ 4, else `RNTP_INCONSISTENT`.
2. No block number appears with two different hashes, else `RNTP_INCONSISTENT`.
3. Every latest nonce is equal, else `RNTP_INCONSISTENT`.
4. `maxFeePerGas` = min(2 × the highest base fee + 1 gwei, 20 gwei). Each provider's balance,
   in provider order, must be ≥ 30,000 × `maxFeePerGas`, else `RNTP_INSUFFICIENT_BALANCE` for
   that provider.

## 5. Binding and the record

**XRPL.** `xrplAnchorTemplate(commitment, {Account, Sequence, LastLedgerSequence, SigningPubKey})`:
- `Sequence` is the agreed `Sequence`;
- `LastLedgerSequence` = min(`validated_ledger.seq`) + 20.

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
- **Sepolia:** `block` `{number, hash, timestamp, baseFeePerGas}` and `estimateGas`, as received.

It also holds `exchanges`: one `{method, requestSha256, responseSha256}` per request, in order.
The digests are `sha256:<hex>` of the exact request bytes and of the exact response body.

**The intent** is `{format, network, purpose: "genesis-proof-01", commitment, transaction,
preparation}`. It must pass `makeIntent`; a failure is `RNTP_INTENT_INVALID`. One reachable case is a
validated ledger within 20 of 2^32−1, which would make `LastLedgerSequence` overflow. Its digest is the `rnnet.unsigned-tx-intent.v1` §3 digest, so it
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
