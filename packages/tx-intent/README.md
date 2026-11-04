# packages/tx-intent

The approved unsigned transaction of RN-NET-03B2-B1 (ADR-RN-017, `spec/rnnet.unsigned-tx-intent.v1.md`).

- **`rnnet.unsigned-tx-intent.v1`:** the intent, checked and frozen by `makeIntent`, and its digest from `intentDigest`.
- **The ADR-RN-016 checks:** `checkXrplAnchorTx` and `checkSepoliaAnchorTx`, moved here unchanged from `tools/genesis/prepare.mjs`, which re-exports them.
- **XRPL:** binary encoding and decoding of the Genesis `AccountSet` only, in canonical field order, with base58check addresses and the signing preimage and transaction hash.
- **Sepolia:** strict RLP, and EIP-1559 type-2 encoding and decoding.
- **Comparison:** decoded signed bytes against the intent, in a fixed order, so both verifiers report the same error code.

This package has no keys, does no signing or hashing with Keccak, and never touches the network. Signing and signature checks live in `signer/`.

## Fork-aware gas rules (`src/gas-rules.mjs`; RN-NET-03B2-WP2, offline only)

This implements [ADR-RN-018 Amendment C2](../../docs/adr/ADR-RN-018-transaction-preparation-reads.md) G1–G7 and founder decisions Q1–Q2.

**It is not wired into anything yet.** Preparation, signing, broadcasting, C6 and gate F do not use it; WP3 integrates it. The production `intrinsicGas` and `checkSepoliaAnchorTx` are unchanged.

**Rule sets.**
- `prague` covers Prague, Osaka, BPO1 and BPO2: standard `21000 + 4z + 16n`, floor `21000 + 10(z + 4n)`.
- `amsterdam`: standard `12000 + 4z + 16n`, floor `12000 + 16·4(z + n)`.
- The need is the larger of the two. For the Genesis payload it is 22,680 under `prague` and 14,688 under `amsterdam`, computed from the bytes.

**Selection.** `selectSepoliaGasRules(timestamp)` uses only the reviewed `SEPOLIA_ACTIVATIONS` table. It never uses a provider field. A pre-Prague time refuses.

**Review horizon (Q1).** `validateReviewedRulesHorizon(review, { pinTimestamp, now })` requires:
- the record lists exactly `REVIEWED_GAS_RULE_SOURCES`;
- `reviewedAt < horizon ≤ reviewedAt + 2,592,000`;
- the horizon is no later than any known unreviewed activation;
- `pinTimestamp` and `now` are before the horizon. It is inclusive: exactly at the horizon refuses.
- `reviewedAt ≤ now`: a future-dated review never extends the trusted window.

It limits how long one review is trusted. It does **not** detect unannounced forks.

`SEPOLIA_GAS_RULES_REVIEW` ships as `null`, because no review is recorded, so evaluation refuses until a reviewed change records one.

**Boundary (Q2).** `checkForkBoundary(pin, now, extra)` refuses any known activation `A` with `pin − 3600 ≤ A ≤ now + 86400` (inclusive), and refuses `rules(pin) ≠ rules(now)`.

**Preconditions (G4).** `validateGenesisGasPreconditions(tx, { commitment, providerIds, codeEvidence })` requires:
- the exact Genesis self-send: type 2, Sepolia, `to == from`, value 0, an empty access list, no authorization list or blob fields, the 42-byte payload of `commitment`, gas `0x7530`;
- at least two providers, each reporting code `0x`. A delegation, a disagreement, or missing or malformed evidence refuses.

It reads nothing itself.

**Evaluator.** `evaluateGenesisGas({ transaction, commitment, providerIds, codeEvidence, pinTimestamp, now, review })` first requires `pinTimestamp ≤ now` (`RNTX_GAS_INPUT_INVALID`), because a pinned block cannot be later than the evaluation. It then composes these steps in order: review, rule set at the pin, boundary, preconditions, arithmetic, then the limit check (`need ≤ 30000`, never clamped). Any other input field is refused.

Its result is frozen and module-local, **not** a protocol format: `ruleSetId`, `fork`, `reviewDigest`, `zeroBytes`, `nonzeroBytes`, `standard`, `floor`, `need`, `gasLimit`, `margin`. The `rnnet.tx-preparation.v2` schema is reviewed in WP3.

`calldataGas` and `calldataGasForInput` are arithmetic only. They are not evidence that a transaction is safe.

**Refusals** are `TxError` codes `RNTX_GAS_INPUT_INVALID`, `RNTX_GAS_RULES_UNSUPPORTED`, `RNTX_GAS_RULES_UNREVIEWED`, `RNTX_GAS_FORK_BOUNDARY`, `RNTX_GAS_PRECONDITION`, `RNTX_GAS_LIMIT_EXCEEDED` and `RNTX_GAS_OVERFLOW`. Timestamps are integers in `[0, 2^40)`.

**Independent reference.** `tools/reference/rnnet_gas_rules_reference.py` recomputes every case of `fixtures/gas-rules-wp2/vectors.json`, which `tools/gas-rules/build-gas-rules-vectors.mjs` builds and `tools/gas-rules.test.mjs` keeps current.

- **Dependencies:** `packages/canonical`, `packages/anchor`, and the Node.js built-ins `Buffer`, `createHash` and `types` (from `node:util`).
