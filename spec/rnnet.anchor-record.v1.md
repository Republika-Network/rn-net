# rnnet.anchor-record.v1

- Status: Draft (RN-NET-03A)
- Decision records:
  - [ADR-RN-010](../docs/adr/ADR-RN-010-xrpl-testnet-memo-anchoring.md) (XRPL)
  - [ADR-RN-011](../docs/adr/ADR-RN-011-sepolia-transaction-data-anchoring.md) (Sepolia)
  - [ADR-RN-012](../docs/adr/ADR-RN-012-cross-chain-trust-boundaries.md) (trust boundaries)
- Depends on: [rnnet.anchor-payload.v1](rnnet.anchor-payload.v1.md), [rnnet.canonical-json.v1](rnnet.canonical-json.v1.md), [rnnet.verification-taxonomy.v1](rnnet.verification-taxonomy.v1.md)
- Implementations:
  - `packages/anchor/` (JavaScript)
  - `tools/reference/rnnet_anchor_reference.py` (Python)
- Conformance vectors: `vectors/anchor/`

## 1. Purpose and verification boundary

This specification defines four things:

- **Observation:** what a party supplies about one anchoring transaction on one network.
- **Record:** how a verifier checks one observation against an expected commitment, and the
  per-network result it produces.
- **Report:** how two records, one on XRPL Testnet and one on Ethereum Sepolia, are compared.
- **Trust:** what each result does and does not establish.

### Levels of assurance

| Level | Meaning | In RN-NET-03A |
|---|---|---|
| 1 | A party claims an anchor exists | The input to this specification |
| 2 | The claim is consistent with transaction and ledger data **supplied with it** | Implemented: `CONSISTENT_WITH_SUPPLIED_DATA` |
| 3 | Consistent with chain data the verifier fetched itself | Future work; not produced |
| 4 | Supported by an authenticated proof of inclusion and finality (light client, consensus proof) | Future work; not produced |

**What supplied data proves.** Supplied transaction and ledger data is whatever the supplier
sent. RN-NET-03A checks it carefully but cannot authenticate it. A fabricated record can reach
level 2 if it is internally consistent. Nothing here is proof that a transaction exists on any
network.

## 2. Observation

An observation is a JSON object of at most 65,536 bytes, parsed under
`rnnet.canonical-json.v1`.

| Member | Value |
|---|---|
| `format` | `rnnet.anchor-observation.v1` |
| `network` | `xrpl:testnet` or `evm:11155111` (Ethereum Sepolia) |
| `tx` | For `xrpl:testnet` only: the `result` object of the rippled `tx` method, API version 2 (§3) |
| `transaction`, `receipt` | For `evm:11155111` only: the results of `eth_getTransactionByHash` and `eth_getTransactionReceipt` (§4). `receipt` may be `null`. |

**What the network member means.** The `network` member is the supplier's claim about which
network the data came from. It is checked against what the transaction data itself says about
its network, which is all that offline data allows.

**Upstream objects.** These are passed through as the node returned them. Members this
specification does not use are ignored. They are never copied into a record.

### 2.1 Observation checks

The checks run in order, and the first failure ends verification:

| Step | Check | Error |
|---|---|---|
| 1 | At most 65,536 bytes | `RNAO_TOO_LARGE` |
| 2 | Parses under `rnnet.canonical-json.v1` | `RNCJ_*` |
| 3 | A JSON object | `RNAO_NOT_OBJECT` |
| 4 | `format` is present and is a string | `RNAO_MISSING_FIELD`, `RNAO_FIELD_TYPE` |
| 4 | `format` value | `RNAO_UNSUPPORTED_VERSION` (`rnnet.anchor-observation.` + other), `RNAO_UNSUPPORTED_FORMAT` (anything else) |
| 5 | `network` is present and is a string | `RNAO_MISSING_FIELD`, `RNAO_FIELD_TYPE` |
| 5 | `network` is the network this check was asked for | `RNAO_WRONG_NETWORK` |
| 6 | Exactly the members of the table above for that network; no other member | `RNAO_UNKNOWN_FIELD`, `RNAO_MISSING_FIELD` |

**Reporting unknown members.** An unknown member is reported by its containing object (the
observation itself), never by its name.

**Which network is asked for.** The verifier is always told which network an observation is
for, through the XRPL slot or the Sepolia slot (§6). An observation for the other network in
that slot is `RNAO_WRONG_NETWORK`.

## 3. XRPL Testnet

### 3.1 Transport

**The transaction.** An anchoring transaction is an `AccountSet` with no settings changed, a
no-op apart from its fee. It carries exactly one anchor memo:

| Memo member | Value |
|---|---|
| `MemoType` | The uppercase hex of the ASCII string `rnnet.anchor-payload.v1`: `726E6E65742E616E63686F722D7061796C6F61642E7631` |
| `MemoData` | The uppercase hex of the 42 payload bytes |
| `MemoFormat` | Absent |

The transaction may carry other memos with other `MemoType` values. They are ignored.

**Network identity.** XRPL Testnet has network ID 1. On networks with ID 1024 or less, the
`NetworkID` field must be omitted, so a Testnet transaction never has one.

**Ledger fields.**

- Hashes are 64 uppercase hex digits.
- Ledger indexes are unsigned 32-bit integers.
- A `tx` result is final only when `validated` is `true`.

### 3.2 Checks

`tx` is checked in three phases.

**Phase A: structure and consistency.** The first failure ends verification.

| Step | Check | Error |
|---|---|---|
| A1 | `tx` is an object with `hash` (string), `ledger_index` (integer), `ledger_hash` (string), `validated` (boolean), `meta` (object) and `tx_json` (object) | `RNAX_MISSING_FIELD`, `RNAX_FIELD_TYPE` |
| A2 | `hash` is 64 uppercase hex digits | `RNAX_INVALID_HASH` |
| A3 | `ledger_hash` is 64 uppercase hex digits | `RNAX_INVALID_LEDGER_HASH` |
| A4 | `ledger_index` is between 1 and 4,294,967,295 | `RNAX_INVALID_LEDGER_INDEX` |
| A5 | `tx_json.NetworkID` is absent | `RNAX_WRONG_NETWORK` |
| A6 | Each CTID present (`ctid`, then `tx_json.ctid`): it is `C` followed by 15 uppercase hex digits, and its low 16 bits (the network ID) are 1 | `RNAX_INVALID_CTID`, `RNAX_WRONG_NETWORK` |
| A7 | Each duplicate reference agrees with its counterpart (see below) | `RNAX_CONTRADICTORY_REFERENCE` (and `RNAX_MISSING_FIELD` or `RNAX_FIELD_TYPE` for `meta.TransactionIndex`) |
| A8 | `tx_json.TransactionType` is `AccountSet`, and `tx_json` has none of the settings fields `ClearFlag`, `SetFlag`, `Domain`, `EmailHash`, `MessageKey`, `NFTokenMinter`, `TickSize`, `TransferRate`, `WalletLocator`, `WalletSize` | `RNAX_UNSUPPORTED_TRANSACTION_TYPE` |
| A9 | `tx_json.Account` matches `^r[1-9A-HJ-NP-Za-km-z]{24,34}$` | `RNAX_INVALID_ACCOUNT` |
| A10 | `tx_json.Memos` is absent, or an array of at most 32 elements. Each element is exactly `{"Memo": {...}}`. Its members are a non-empty subset of `MemoType`, `MemoData` and `MemoFormat`, each a string of uppercase hex with an even number of digits, at most 2,048 digits. | `RNAX_MALFORMED_MEMO` |

Step A7 compares each duplicate reference with its counterpart, in this order, where the
duplicate is present:

| Duplicate reference | Must equal |
|---|---|
| `tx_json.hash` | `hash` |
| `tx_json.ledger_index` | `ledger_index` |
| `tx_json.ctid`, when `ctid` is also present | `ctid` |
| Each CTID's ledger index: bits 32–59, with the lead nibble removed | `ledger_index` |
| Each CTID's transaction index: bits 16–31 | `meta.TransactionIndex` |

**When a CTID is present.** `meta.TransactionIndex` is then required (`RNAX_MISSING_FIELD`) and
must be an integer (`RNAX_FIELD_TYPE`). It is checked before the CTID comparisons.

**Network identity offline.** Without a CTID, offline data cannot tell XRPL Testnet from Mainnet
(network ID 0) or Devnet (2). None of them carries a `NetworkID` field. The network is then only
the supplier's claim (ADR-RN-010).

**Phase B: anchor.** At most one finding.

| Step | Check | Error |
|---|---|---|
| B1 | Exactly one memo has the anchor `MemoType`; none means no anchor | `RNAX_MISSING_ANCHOR` |
| B1 | More than one memo has the anchor `MemoType`, even if identical | `RNAX_DUPLICATE_ANCHOR` |
| B2 | The anchor memo has `MemoData` and no `MemoFormat` | `RNAX_MALFORMED_MEMO` |
| B3 | `MemoData` decodes as an anchor payload | `RNAP_*` |
| B4 | The payload's commitment equals the expected commitment | `RNAP_COMMITMENT_MISMATCH` |

**Phase C: claimed status.** At most one finding.

| Step | Check | Error |
|---|---|---|
| C1 | `validated` is `true` | `RNAX_NOT_VALIDATED` |
| C2 | `meta.TransactionResult` is the string `tesSUCCESS` | `RNAX_TRANSACTION_NOT_SUCCESSFUL` |

**Hex rule.** Lowercase and mixed-case hex are malformed, because rippled writes binary fields
and hashes in uppercase hex. This applies to hashes, CTIDs and memo fields.

## 4. Ethereum Sepolia

### 4.1 Transport

**The transaction.**

- An anchoring transaction is an ordinary transaction of type `0x0`, `0x1` or `0x2`.
- It is sent to an address, not a contract creation.
- Its `input` is exactly the 42 payload bytes.
- Sepolia's chain ID is 11155111 (`0xaa36a7`).

No contract is involved: the data needs no execution. A plain value transfer to an account
with no code succeeds whatever its data, and its receipt carries no logs.

**JSON-RPC encodings.**

- Data and hashes are `0x` followed by lowercase hex.
- Quantities are `0x` followed by lowercase hex without leading zeros, and `0x0` for zero.
- A pending transaction has `null` block fields and no receipt.
- Receipt `status` is `0x1` for success and `0x0` for failure.

### 4.2 Checks

**Phase A: structure and consistency.** The first failure ends verification.

| Step | Check | Error |
|---|---|---|
| A1 | `transaction` is an object with `hash`, `chainId`, `type`, `from` and `input` (strings) and `to`, `blockHash`, `blockNumber` and `transactionIndex` (string or `null`). `receipt` is an object or `null`. | `RNAE_MISSING_FIELD`, `RNAE_FIELD_TYPE` |
| A2 | `transaction.hash` is `0x` followed by 64 lowercase hex digits | `RNAE_INVALID_HASH` |
| A3 | `chainId` is a quantity | `RNAE_FIELD_TYPE` |
| A3 | `chainId` equals `0xaa36a7` | `RNAE_WRONG_NETWORK` |
| A4 | `type` is `0x0`, `0x1` or `0x2` | `RNAE_UNSUPPORTED_TRANSACTION_TYPE` |
| A5 | `to` is not `null` | `RNAE_CONTRACT_CREATION` |
| A5 | `from` and `to` are `0x` followed by 40 lowercase hex digits | `RNAE_INVALID_ADDRESS` |
| A6 | `input` is `0x` followed by lowercase hex with an even number of digits | `RNAE_INVALID_INPUT` |
| A7 | Block fields are either all `null` or all present. `blockHash` is `0x` plus 64 lowercase hex digits; `blockNumber` and `transactionIndex` are quantities. | `RNAE_INVALID_BLOCK_REFERENCE` |
| A8 | If `receipt` is not `null`: it has `transactionHash`, `blockHash`, `blockNumber`, `transactionIndex`, `from` and `status` (strings), and `to` and `contractAddress` (string or `null`) | `RNAE_MISSING_FIELD`, `RNAE_FIELD_TYPE` |
| A9 | If `receipt` is not `null`: `transactionHash`, `from` and `to` equal the transaction's | `RNAE_RECEIPT_MISMATCH` |
| A10 | If `receipt` is not `null`: `blockHash`, `blockNumber` and `transactionIndex` equal the transaction's, which must not be `null` | `RNAE_CONFLICTING_BLOCK_REFERENCE` |

**Phase B: anchor.** At most one finding.

| Step | Check | Error |
|---|---|---|
| B1 | `input` is not empty (`0x`) | `RNAE_MISSING_ANCHOR` |
| B2 | The input bytes decode as an anchor payload, with nothing before or after it | `RNAP_*` |
| B3 | The payload's commitment equals the expected commitment | `RNAP_COMMITMENT_MISMATCH` |

**Phase C: claimed status.** At most one finding.

| Step | Check | Error |
|---|---|---|
| C1 | `receipt` is not `null` and the block fields are not `null` | `RNAE_PENDING` |
| C2 | `receipt.contractAddress` is `null` | `RNAE_CONTRACT_CREATION` |
| C3 | `receipt.status` is `0x1`; `0x0` means reverted | `RNAE_TRANSACTION_REVERTED` |
| C3 | `receipt.status` is any other value | `RNAE_INVALID_STATUS` |

**Duplicate anchors.** The payload must be the whole input, so one transaction cannot carry two
anchors. Input that contains the payload twice is `RNAP_INVALID_LENGTH`.

## 5. Anchor record

The anchor record is the result of checking one observation. It is a deterministic JSON object
in canonical form.

### 5.1 Members

| Member | Present | Value |
|---|---|---|
| `format` | always | `rnnet.anchor-record.v1` |
| `network` | always | The network that was checked (`xrpl:testnet` or `evm:11155111`) |
| `expectedCommitment` | always | The commitment the check was against |
| `input` | always | `{ "sha256": "sha256:<hex>" }`, the hash of the observation bytes |
| `outcome` | always | `PASS`, `FAIL` or `UNSUPPORTED`, defined below |
| `assurance` | for `PASS` | `CONSISTENT_WITH_SUPPLIED_DATA` (level 2) |
| `transaction` | when phase A passed | XRPL: `{ "hash", "ledgerIndex", "ledgerHash", "account" }`. Sepolia: `{ "hash", "blockHash", "blockNumber", "transactionIndex", "from", "to" }`, with `null` block fields when pending. |
| `payload` | when phase B decoded a v1 payload | `{ "hex": <the 42 bytes, lowercase hex>, "commitment": <decoded>, "matchesExpected": <boolean> }` |
| `findings` | always | `{ "code", "severity", "subject" }`, in check order; `severity` is `error` or `unsupported` |
| `statements` | always | Taxonomy statements (§5.2); empty unless the outcome is `PASS` |

### 5.2 Outcome

| Outcome | When |
|---|---|
| `PASS` | No findings |
| `UNSUPPORTED` | Every finding is one of `RNAO_UNSUPPORTED_FORMAT`, `RNAO_UNSUPPORTED_VERSION`, `RNAX_UNSUPPORTED_TRANSACTION_TYPE`, `RNAE_UNSUPPORTED_TRANSACTION_TYPE`, `RNAP_UNSUPPORTED_VERSION` or `RNAP_UNSUPPORTED_COMMITMENT_FORMAT` |
| `FAIL` | Otherwise: any other finding makes the record `FAIL`, even alongside an unsupported one |

### 5.3 Statements for `PASS`, in order

| Subject | Classification | Basis |
|---|---|---|
| `anchorPayload` | `VERIFIED` | `Decoded from the supplied transaction data and equal to the payload of the expected commitment.` |
| `network` | `CLAIMED` | `Named by the supplier of the record and consistent with the transaction's own network fields; not authenticated.` |
| `transactionStatus` | `CLAIMED` | `Stated by the supplied transaction data; not authenticated.` |
| `inclusion` | `CLAIMED` | `The supplied data names the ledger or block that includes the transaction; no inclusion proof was checked.` |
| `finality` | `CLAIMED` on XRPL, `UNRESOLVED` on Sepolia | XRPL: `The supplied data states the transaction is in a validated ledger; not authenticated.` Sepolia: `The supplied data shows inclusion in a block, not finality.` |
| `transactionHash` | `UNRESOLVED` | `Not recomputed from the signed transaction, so not bound to the data that was checked.` |
| `submitter` | `CLAIMED` | `The sending account as stated by the supplied data.` |

### 5.4 No input text

Every string in a record is one of:

- a value fixed by this specification;
- a hash, digest, quantity or address that passed its pattern;
- the payload hex.

Upstream fields, error messages and unknown member names are never copied into a record.

## 6. Dual-chain verification report

The report `rnnet.anchor-verification-report.v1` compares one XRPL Testnet observation with one
Ethereum Sepolia observation for one expected commitment. Each observation is checked in its own
slot, as in §3 and §4.

### 6.1 Members

| Member | Value |
|---|---|
| `format` | `rnnet.anchor-verification-report.v1` |
| `expectedCommitment` | The commitment |
| `outcome` | `PASS`, `FAIL` or `UNSUPPORTED` (§6.2) |
| `conclusions` | The conclusions that hold, in this order: `PAYLOAD_MATCH`, `RECORDS_CONSISTENT`, `CHAIN_INCLUSION_UNVERIFIED` |
| `records` | `{ "xrpl": <anchor record>, "evm": <anchor record> }`; a slot with no observation is absent |
| `findings` | Report-level findings: `RNAD_MISSING_RECORD`, `RNAD_RECORD_NOT_PASSED`, `RNAD_PAYLOAD_DIFFERS` (subject `xrpl`, `evm` or `pair`) |
| `statements` | §6.3 |

### 6.2 Conclusions and outcome

| Conclusion | Holds when |
|---|---|
| `PAYLOAD_MATCH` | Both records have a `payload`; both `matchesExpected`; their `hex` values are equal |
| `RECORDS_CONSISTENT` | Both records are `PASS` |
| `CHAIN_INCLUSION_UNVERIFIED` | Always in RN-NET-03A: no authenticated inclusion proof is checked on either network |
| `CHAIN_PROVEN` | Reserved. **Never produced** until an authenticated proof-verification mechanism exists (assurance level 4 on both networks). |

**Findings, in order:**

- `RNAD_MISSING_RECORD`, for each slot with no observation (`xrpl`, then `evm`);
- `RNAD_RECORD_NOT_PASSED`, for each record that is not `PASS`;
- `RNAD_PAYLOAD_DIFFERS` (subject `pair`), when both records have a payload but their `hex`
  values differ.

**Outcome:**

- `PASS` when `PAYLOAD_MATCH` and `RECORDS_CONSISTENT` both hold;
- `UNSUPPORTED` when both records are present, at least one is `UNSUPPORTED`, and none is
  `FAIL`;
- `FAIL` otherwise, including whenever a record is missing.

**What `PASS` means.** A `PASS` means that the same commitment payload is found, consistently,
in the data supplied for both networks. It does **not** mean either of these:

- that the transactions exist on either network;
- that the anchored evidence is true.

### 6.3 Statements

| Subject | Classification | Basis |
|---|---|---|
| `chainInclusion` | `UNRESOLVED` | `No authenticated proof of inclusion was verified on either network.` |
| `anchoredEvidence` | `UNRESOLVED` | `An anchor binds a commitment; it says nothing about whether the evidence is true or the event happened.` |

## 7. Error codes

**Observation:**

| Code | Meaning |
|---|---|
| `RNAO_TOO_LARGE`, `RNAO_NOT_OBJECT`, `RNAO_UNKNOWN_FIELD`, `RNAO_MISSING_FIELD`, `RNAO_FIELD_TYPE` | Observation structure |
| `RNAO_UNSUPPORTED_FORMAT`, `RNAO_UNSUPPORTED_VERSION` | Observation format |
| `RNAO_WRONG_NETWORK` | The observation is for the other network |

**XRPL:**

| Code | Meaning |
|---|---|
| `RNAX_MISSING_FIELD`, `RNAX_FIELD_TYPE` | `tx` structure |
| `RNAX_INVALID_HASH`, `RNAX_INVALID_LEDGER_HASH`, `RNAX_INVALID_LEDGER_INDEX`, `RNAX_INVALID_CTID`, `RNAX_INVALID_ACCOUNT` | Malformed references |
| `RNAX_WRONG_NETWORK` | The transaction's own fields name another network |
| `RNAX_CONTRADICTORY_REFERENCE` | Two references to the same thing disagree |
| `RNAX_UNSUPPORTED_TRANSACTION_TYPE` | Not `AccountSet` |
| `RNAX_MALFORMED_MEMO` | A memo breaks §3.2 step A10 or B2 |
| `RNAX_MISSING_ANCHOR`, `RNAX_DUPLICATE_ANCHOR` | No anchor memo, or more than one |
| `RNAX_NOT_VALIDATED` | `validated` is not `true` |
| `RNAX_TRANSACTION_NOT_SUCCESSFUL` | `meta.TransactionResult` is not `tesSUCCESS` |

**Ethereum Sepolia:**

| Code | Meaning |
|---|---|
| `RNAE_MISSING_FIELD`, `RNAE_FIELD_TYPE` | Transaction or receipt structure |
| `RNAE_INVALID_HASH`, `RNAE_INVALID_ADDRESS`, `RNAE_INVALID_INPUT`, `RNAE_INVALID_BLOCK_REFERENCE` | Malformed values |
| `RNAE_WRONG_NETWORK` | `chainId` is not Sepolia's |
| `RNAE_UNSUPPORTED_TRANSACTION_TYPE` | A type other than `0x0`, `0x1` or `0x2` |
| `RNAE_CONTRACT_CREATION` | No `to`, or a contract was created |
| `RNAE_RECEIPT_MISMATCH` | Receipt and transaction disagree on hash or parties |
| `RNAE_CONFLICTING_BLOCK_REFERENCE` | Receipt and transaction disagree on block or position |
| `RNAE_MISSING_ANCHOR` | Empty input |
| `RNAE_PENDING` | Not included in a block |
| `RNAE_TRANSACTION_REVERTED` | Receipt status `0x0` |
| `RNAE_INVALID_STATUS` | A receipt status other than `0x0` or `0x1` |

**Dual-chain report:**

| Code | Meaning |
|---|---|
| `RNAD_MISSING_RECORD` | No observation for a network |
| `RNAD_RECORD_NOT_PASSED` | A record is not `PASS` |
| `RNAD_PAYLOAD_DIFFERS` | The two payloads differ |

Payload errors (`RNAP_*`) are defined in `rnnet.anchor-payload.v1`.
