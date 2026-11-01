# Genesis Proof 01: anchoring preflight

- Status: **Preflight only (RN-NET-03B2-A).** Nothing has been signed, submitted or anchored. No
  wallet, key or account exists.
- Decision record: [ADR-RN-016](../adr/ADR-RN-016-genesis-anchoring-transactions.md) (Accepted)
- Authorization gates: [genesis-proof-01-authorization.md](genesis-proof-01-authorization.md)
- Fixture and golden values: [`fixtures/genesis-proof-01/`](../../fixtures/genesis-proof-01/)
- Code:
  - [`tools/genesis/prepare.mjs`](../../tools/genesis/prepare.mjs) (preparation and checks);
  - [`tools/genesis/build-genesis-01.mjs`](../../tools/genesis/build-genesis-01.mjs) (generator);
  - [`tools/genesis.test.mjs`](../../tools/genesis.test.mjs) (tests);
  - [`tools/reference/rnnet_genesis_reference.py`](../../tools/reference/rnnet_genesis_reference.py)
    (independent check).

Genesis Proof 01 will anchor one commitment to one original, synthetic RN-NET evidence document,
on both XRPL Testnet and Ethereum Sepolia. Anyone will then be able to rebuild the commitment from
the fixture and find the same 42 bytes on both networks. This document fixes everything that can
be fixed offline.

## 1. Genesis evidence

The evidence file is
[`fixtures/genesis-proof-01/evidence.json`](../../fixtures/genesis-proof-01/evidence.json), in the
format `rnnet.synthetic-evidence.v1`. It is original and synthetic, and describes no real
operation, person or organization. It contains no Frontera or other proprietary material.

**Body:**

| Member | Value |
|---|---|
| `evidenceId` | `genesis-proof-01` |
| `issuer` | `synthetic-issuer.rnnet.example` |
| `subject` | `demonstration:genesis-proof-01` |
| `action` | `synthetic.anchoring.demonstration` |
| `outcome` | `succeeded` |

**Signature.** One Ed25519 signature, `genesis-fixture-key-1`, made with a **fixture key**:

- The seed is SHA-256(`rnnet:synthetic-test-key:v1:genesis-proof-01`), derived the same way as
  the RN-NET-02 test keys.
- The key is public by construction: anyone can rebuild it. It therefore shows only signature
  consistency (`CONSISTENT_UNDER_EMBEDDED_KEYS`), never an identity.
- It is not an operational key, and it is never stored.

### 1.1 Golden values (immutable)

| Value | |
|---|---|
| Evidence file SHA-256 | `sha256:4a94ce939193dce631b1c0059c46dbfcbd7249885fe2e4ca330c87730ba6532f` |
| Evidence digest (`body`) | `sha256:1551cf374a3abcdbd849663cc0b85033afc5b9a7e045ca211b6e724595f412f8` |
| Fixture public key | `golden.json` → `evidence.fixtureKey.publicKey` |
| RN-NET-02 report | `PASS`, no findings; canonical report SHA-256 `sha256:f70ad0e745dbcb1c81bc425d24dc613c36ea9fa46e7946d64f1e372bf925b37c` |
| Envelope file SHA-256 | `sha256:38c9ffcb39056e8177ec64ef88a389f1853e00410d4ffd1a2b8801ddd5c8323f` |
| **RN-NET-01 commitment** | **`sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7`** |
| **Anchor payload (42 bytes)** | **`524e4e4554414e43 01 01 a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7`** |

The envelope's `sourceRef` is `synthetic:fixtures/genesis-proof-01/evidence.json`. Like every
`sourceRef`, it is an identifier, never dereferenced.

**Reproduce:**

```sh
node tools/verify-evidence.mjs fixtures/genesis-proof-01/evidence.json \
  --commitment fixtures/genesis-proof-01/envelope.json \
  --commitment-digest sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7
node tools/genesis/build-genesis-01.mjs              # the committed fixture is what the generator builds
python3 -I -B tools/reference/rnnet_genesis_reference.py
```

**Immutability.**

- `build-genesis-01.mjs --write` refuses to overwrite existing files.
- A test fails if a fixture byte changes.
- The values in the table above are pinned in the tests.
- `.gitattributes` keeps `fixtures/**` byte-exact.

## 2. XRPL Testnet transaction

### 2.1 Construction (unsigned)

```json
{
  "TransactionType": "AccountSet",
  "Account": "<gate B: new Ed25519 test account>",
  "Fee": "12",
  "Sequence": "<gate D: account_info>",
  "LastLedgerSequence": "<gate D: latest validated ledger + 20>",
  "SigningPubKey": "<gate D: ED + 64 hex>",
  "Memos": [{ "Memo": {
    "MemoType": "726E6E65742E616E63686F722D7061796C6F61642E7631",
    "MemoData": "524E4E4554414E430101A20C2311EC1B1084409446FD3E78A49004328EE0521237647BB9E909B6A06EE7"
  }}]
}
```

### 2.2 Offline validation (`checkXrplAnchorTx`)

| Property | Rule | Basis |
|---|---|---|
| Transaction type | `AccountSet`. No `SetFlag`, `ClearFlag`, `Domain` or other settings field. `Flags` absent or 0. | rnnet.anchor-record.v1 §3.2 A8; a no-op apart from the fee |
| Fields | Exactly those above. Any other field is refused. | ADR-RN-016 |
| Network identity | No `NetworkID`: Testnet's ID is 1, and IDs ≤ 1024 must omit it | §3.1, ADR-RN-010 |
| Memo encoding | Exactly one memo. `MemoType` is upper-case hex of `rnnet.anchor-payload.v1`. `MemoData` is the payload in upper-case hex. No `MemoFormat`. | §3.1 |
| Commitment bytes | `MemoData` bytes 10–41 are the commitment digest. Any other commitment is refused. | rnnet.anchor-payload.v1 §2 |
| Memo size | The serialized `Memos` field is 73 bytes; the limit is 1,024 | XRPL common fields |
| Fee | Decimal string of drops: 12, cap 1,000 | ADR-RN-016 |
| Replay and expiry | `Sequence` (one use per account) and a required `LastLedgerSequence` | XRPL reliable submission |
| Key | `SigningPubKey` is an Ed25519 key (`ED…`) | ADR-RN-016 |

### 2.3 After submission: what verification must show

The read-only tool reads the transaction:

```sh
node tools/verify-live-anchor.mjs --network xrpl-testnet --tx <hash> --commitment sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7 \
  --compare-providers --capture <file>
```

Then:

- **`tx` result:** `validated: true` and `meta.TransactionResult` = `tesSUCCESS`.
- **Expiry:** `ledger_index` ≤ the `LastLedgerSequence` that was signed.
- **CTID:** when present, its network ID is 1 and its ledger and transaction index match `ledger_index` and
  `meta.TransactionIndex`.
- **Providers:** both reviewed providers (Ripple and XRPL Labs) report the same ledger and hash.
  The record states finality as `CLAIMED`, never proven.

### 2.4 Fees, reserve and funding

| Item | Value | Assumption to confirm (read-only `server_info` at gate B) |
|---|---|---|
| Transaction cost | 12 drops (0.000012 XRP), cap 1,000 drops | Reference cost of 10 drops; no load escalation |
| Base reserve | 1 XRP, locked while the account exists | `validated_ledger.reserve_base_xrp` on Testnet |
| Owner reserve | None: `AccountSet` creates no ledger object | `reserve_inc_xrp` does not apply |
| Funding need | Base reserve + fees: under 1.001 XRP. The Testnet faucet's grant covers it. | Faucet grant amount recorded at gate C |

Testnet XRP has no value, and **Testnet can be reset**. Records and captures must therefore be
kept as soon as the transaction validates (gate F).

## 3. Ethereum Sepolia transaction

### 3.1 Construction (unsigned)

```json
{
  "type": "0x2",
  "chainId": "0xaa36a7",
  "nonce": "<gate D: eth_getTransactionCount; 0x0 for a new account>",
  "from": "<gate B: new test address>",
  "to": "<same as from: self-send>",
  "value": "0x0",
  "input": "0x524e4e4554414e430101a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7",
  "gas": "0x7530",
  "maxFeePerGas": "<gate D: min(2 × baseFeePerGas + tip, 20 gwei)>",
  "maxPriorityFeePerGas": "0x3b9aca00",
  "accessList": []
}
```

### 3.2 Offline validation (`checkSepoliaAnchorTx`)

| Property | Rule | Basis |
|---|---|---|
| Chain ID | `0xaa36a7` (11155111). It is signed into the type-2 envelope, so the transaction cannot be replayed on another chain. | rnnet.anchor-record.v1 §4.2 A3; EIP-1559/EIP-2718 |
| Type | `0x2`. Types 3 and 4 are refused (they are not anchor transports). | §4.2 A4 |
| Input | Exactly the 42-byte payload, nothing before or after | §4.2 B2 |
| Recipient | `to` = `from`: a self-send, never `null` (no contract creation), never a third party | ADR-RN-016 |
| Value and access list | `0x0` and `[]` | ADR-RN-016 |
| Gas | 30,000 limit. It must cover the intrinsic gas and must not exceed 30,000. | Below |
| Fee cap | `maxFeePerGas` ≤ 20 gwei; `maxPriorityFeePerGas` (1 gwei) ≤ `maxFeePerGas` | ADR-RN-016 |
| Nonce | A canonical quantity, bound at gate D. Prevents replay on Sepolia itself. | Ethereum transaction rules |
| Encoding | Lower-case addresses, canonical quantities, no unknown fields | §4.1 |

### 3.3 Gas estimation method

The recipient has no code, so gas used is exactly the intrinsic cost. All 42 payload bytes are
non-zero, so the calldata counts as 168 tokens (each non-zero byte is 4 tokens). Two costs apply:

- **Standard (EIP-2028):** 21,000 + 4 × 168 = 21,672.
- **Floor (EIP-7623):** 21,000 + 10 × 168 = 22,680.

**Gas used = 22,680.** The 30,000 limit leaves 7,320 of margin, and unused gas is not charged.

The SMOKE-02 finalized block carried post-Prague header fields (`blockAccessListHash`,
`slotNumber`). A later fork may have repriced calldata, so gas use **must be confirmed with
`eth_estimateGas` at gate D**, and the limit re-checked, before signing.

### 3.4 Fees and funding

| Item | Value |
|---|---|
| Observed base fee | 17 wei, in the SMOKE-02 finalized block 12042415 (`0x11`); this varies |
| Expected cost | 22,680 × (base fee + 1 gwei tip) ≈ **0.0000227 ETH** |
| Worst case | 30,000 × 20 gwei = **0.0006 ETH** (cannot be exceeded) |
| Proposed funding | **0.01 Sepolia ETH**, over 16 × the worst case. Sepolia ETH has no value; the faucet is chosen at gate C. |

### 3.5 After submission: what verification must show

```sh
node tools/verify-live-anchor.mjs --network sepolia --tx <hash> --commitment sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7 \
  --compare-providers --capture <file>
```

Then:

- **Receipt:** `status` `0x1` and `contractAddress` `null`. The transaction and the receipt agree
  on hash, `from`, `to`, block hash, number and index.
- **Payload:** `input` equals the payload.
- **Finality:** the block must be at or below the **finalized** block reported by *both* reviewed
  providers (PublicNode and Automata 1RPC). A provider's view is still a claim (ADR-RN-015), and
  the anchor record states Sepolia finality as `UNRESOLVED`.
- **Provider agreement:** the two providers must report the same block hash. If they disagree,
  the result is not a pass.
- **Open issue:** the 1RPC finalized-block lag of about 67 minutes seen in SMOKE-02 is unresolved
  ([smoke summary](../operations/rn-net-03b1-smoke-tests.md#observation-1rpc-finalized-block-lag)).
  Until it is understood, finality is judged by the **lower (older)** of the two providers'
  finalized block numbers, never by a single provider.

## 4. Rehearsal

`fixtures/genesis-proof-01/golden.json` → `rehearsal` holds two observations:

- the completed transactions, with **synthetic** accounts, hashes, ledgers and blocks derived from
  `rnnet:synthetic-genesis-rehearsal:` labels;
- shaped as `tx`, `eth_getTransactionByHash` and `eth_getTransactionReceipt` would return them.

The existing dual-chain check reports `PASS` for them, with the conclusions `PAYLOAD_MATCH`,
`RECORDS_CONSISTENT` and `CHAIN_INCLUSION_UNVERIFIED`. Both implementations rebuild that report
byte for byte, and both report `FAIL` against any other commitment.

This shows that the intended transactions are ones the RN-NET-03A/03B1 verifiers accept. It says
nothing about any network.

## 5. Remaining blockers to Genesis Proof 01

| # | Blocker | Needed |
|---|---|---|
| 1 | No signer exists. **XRPL:** a binary serializer for this one `AccountSet` shape, plus Ed25519 signing; Node built-ins provide Ed25519, SHA-512 and RIPEMD-160. **Sepolia:** RLP, Keccak-256 and recoverable secp256k1 ECDSA, none of which Node's built-ins provide (no Keccak-256; `crypto.sign` always hashes its input). | RN-NET-03B2-B. **Open decision, recorded in ADR-RN-016:** Sepolia needs an ADR: an audited dependency or an original implementation with published test vectors. |
| 2 | No write path. `packages/chain-readonly` is read-only by design. | A separate broadcaster with no key access, and its own ADR (XRPL `submit`, Ethereum `eth_sendRawTransaction`) |
| 3 | Read-only methods missing from the allowlist: XRPL `account_info`; Ethereum `eth_getTransactionCount`, `eth_estimateGas`, `eth_getBalance`, `eth_getCode` | A reviewed allowlist change |
| 4 | No keys or accounts; no funding | Gates B and C |
| 5 | ADR-RN-009 to ADR-RN-012 (payload and transports) are still **Proposed** on `main`. ADR-RN-016 is Accepted. | Founder acceptance of ADR-RN-009 to 012 before gate D |
| 6 | SMOKE-01 raw captures and their hashes could not be recovered, so SMOKE-01 has not been independently re-verified | Founder locates them, or accepts the recorded summary |
| 7 | 1RPC finalized-block lag unresolved | A separately authorized read-only comparison of the finalized block on both providers |
| 8 | The calldata gas rules of Sepolia's current fork are unconfirmed | `eth_estimateGas` at gate D |
