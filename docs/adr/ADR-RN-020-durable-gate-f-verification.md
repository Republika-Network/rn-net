# ADR-RN-020: Durable gate-F verification for Genesis Proof 01 (Sepolia)

- Status: **Proposed** (RN-NET-03B2-WP4-A). Documentation only.
  - It authorizes no implementation of a live path, no RPC request, no H10 run, no signing,
    submission or publication, and no Stage B.
  - It changes no accepted ADR. Where it relies on a Proposed text (ADR-RN-018 C2, ADR-RN-019
    C1), that text stays Proposed.
- Date: 2026-11-04
- Specification: [rnnet.gate-f-sepolia-verification.v1](../../spec/rnnet.gate-f-sepolia-verification.v1.md)
  (Proposed).
- Builds on:
  - [ADR-RN-015](ADR-RN-015-live-finality-trust-semantics.md) (finality; **unchanged**);
  - [ADR-RN-014](ADR-RN-014-multi-provider-provenance.md);
  - [ADR-RN-016](ADR-RN-016-genesis-anchoring-transactions.md), [ADR-RN-017](ADR-RN-017-offline-signing-toolchain.md);
  - [ADR-RN-018](ADR-RN-018-transaction-preparation-reads.md) C2 G4, G9, G10, Q4 and Q5;
  - [ADR-RN-019](ADR-RN-019-controlled-testnet-broadcasting.md) §7 and §8;
  - [readiness analysis](../genesis/rn-net-03b2c-operational-readiness.md) §4, "durable,
    reproducible verification", and §6 (C5).
- Fulfils: the "durable-verification ADR" that ADR-RN-018 C2 G10 (Q5) names as the home of the
  authoritative receipt check, and the strategy that readiness §4 requires before gate F.

## Context: what exists today (factual baseline)

| Capability | State | Where |
|---|---|---|
| Sepolia inclusion and finality, as provider claims | **Implemented**: `eth_getTransactionByHash`, the receipt, and `eth_getBlockByHash`, with the block listing the transaction at its index; `finalized` (then `safe`) walked by parent hashes, at most 256 steps, giving `IN_ANCESTRY` / `CONFLICT` / `NOT_REACHED` / `UNRESOLVED` | `tools/verify-live-anchor.mjs`, `packages/chain-readonly`, spec `rnnet.live-observation-report.v1` §6 |
| Capture and offline replay | **Implemented**: `rnnet.rpc-capture.v1` stores the exact request and response bytes, and `--offline-replay` reproduces the report byte for byte with no connection | live-observation-report §8 |
| Anchor checks | **Implemented**: type, chain, `to`, input = payload, commitment, receipt consistency, status `0x1` | spec `rnnet.anchor-record.v1` §4.2 |
| Signed-transaction verification | **Implemented**: decode, signature, sender, comparison with the intent, transaction hash | `txverify/` (`rnnet.signed-tx-verification.v1`) |
| Submission and status records | **Implemented**, offline and simulated only: `rnnet.submission-record.v1`, `rnnet.submission-status.v1` (`INCLUDED`, `PENDING`, `EXPIRED`), the append-only submission log | `packages/chain-submit`, `tools/submit/` (live access disabled) |
| Fork-aware gas rules | **Implemented**, offline | `packages/tx-intent/src/gas-rules.mjs` (WP2) |
| v2 preparation record | **Stage A candidate only** (`rnnet.tx-preparation-v2-candidate.v1`), never an intent | WP3, spec `rnnet.tx-preparation.v2` §5 |
| Strict intent preparation formats | **Implemented**: v1 and synthetic only | S1, `packages/tx-intent/src/intent.mjs` |
| **A durable gate-F verifier** | **Not implemented, not specified** before this ADR | — |
| **C5, the publication bundle** | **Not implemented**; planned in readiness §6 | — |

### What the existing evidence does not carry
- **The inclusion block's timestamp.** It is in the captured `eth_getBlockByHash` response
  bytes, but not in the observation or the report.
- **`receipt.gasUsed` across providers.** It is in each unchanged receipt, but not in the
  compared "material" (live-observation-report §7.2). It is never compared across providers.
- **A binding to the approved intent and the signed bytes.** The live report binds the
  commitment only.
- **The sender's code state at inclusion.** Preparation reads `eth_getCode` at its pin. The
  pre-submit reads (ADR-RN-019 §6) re-read nonces, base fee, the transaction and the balance,
  **not** the code.

## Decision

### V1. Durable strategy: offline reproduction from captured exchanges
Readiness §4 lists three candidates. This ADR proposes the first: **the gate-F verdict is a pure,
deterministic function of captured bytes and approved artifacts. Anyone holding the inputs can
recompute it offline, indefinitely, with no connection.**
- **Acquisition** is separate and **not authorized here**. It is one founder-authorized
  read-only run (H10, with its exact request budget), using the existing reader in its existing
  mode with `--capture`, inside the existing walk window (about 15 to 60 minutes after inclusion,
  ADR-RN-019 C1 E5).
- **The 256-step walk limit applies only at acquisition.** Replay reproduces the result later
  without any network.
- **Not adopted:**
  - "a bounded check by height" is a weaker provider claim, and would change ADR-RN-015 §3;
  - "a larger ancestry limit" changes an accepted bound.

  Either would need its own amendment.

### V2. Finality is exactly ADR-RN-015 §3 and ADR-RN-019 §8
- No new confirmation count, trusted provider or shortcut.
- Inclusion: the block exists, matches the transaction's hash and number, and lists the
  transaction at its index.
- Finality: `finalized` reaches the block by verified parent hashes (`IN_ANCESTRY`). Another
  block at that height is `CONFLICT` and fails.
- **Both reviewed providers are read.** Because the 1RPC finality lag is unresolved, the
  PublicNode walk **must** be `IN_ANCESTRY`, and a 1RPC result that differs is reported, not
  averaged.
- **Classifications** stay `CLAIMED` / `UNRESOLVED`. `chainInclusionProof` is always
  `UNRESOLVED`, and nothing is ever `CHAIN_PROVEN`.
- **Whether a PublicNode-only finalized result may go to founder review** is a founder decision
  (U1), as ADR-RN-019 §8 and C6 branch D foresee. This ADR only labels it.

### V3. The authoritative inclusion timestamp
`t_i` is the `timestamp` of the inclusion block, parsed from the **captured
`eth_getBlockByHash` response** whose `hash` is the receipt's `blockHash`. That block is the one
the finalized walk reached (`IN_ANCESTRY`).
- The same block hash must give the same timestamp on every provider; a difference is
  contradictory evidence.
- `t_i` is never taken from:
  - the candidate or the intent;
  - an estimate;
  - a receipt field without verified block linkage;
  - a provider label;
  - the verifier's clock.

### V4. Subject eligibility and the candidate boundary
- **The authoritative Sepolia subject** is an approved intent (`rnnet.unsigned-tx-intent.v1`)
  whose preparation is a v2 record **accepted under a separately reviewed Stage B policy**
  (ADR-RN-018 C2 Q4).
- **Stage B does not exist today**, so authoritative Sepolia gate F is **BLOCKED** on it (D1).
- **Refused as subjects:**
  - a Stage A candidate, or a candidate digest presented as an intent digest (S1 and the format
    refuse them);
  - a v1 or synthetic Sepolia preparation. **A Proposed choice**; the alternative is U2.
- **Synthetic hypothetical Stage B records** may exist only in offline tests, labelled, through
  an unexported test seam, as WP3's `…WithAuthority`.

### V5. Transaction binding
**The authoritative bytes** are the signed transaction (`signedTransaction`) with:
- `blobSha256` equal in the txverify record, the submission record and the sign-log entry;
- a txverify record of `PASS`, which covers signature, sender, and every field against the
  approved intent;
- `transactionHash` = keccak-256 of the bytes, computed by txverify.

**Every provider observation must agree:**
- `transaction.hash` equals that `transactionHash`;
- `type`, `chainId`, `nonce`, `from`, `to`, `value`, `input`, `gas`, `maxFeePerGas`,
  `maxPriorityFeePerGas` and `accessList`, where the provider returns them, equal the decoded
  signed transaction. A required field that is missing is invalid evidence.

**The submission record** of the attempt must name the same `intentDigest`, `blobSha256` and
`expectedTransactionHash`.

**No user-supplied hash is used in place of these checks.**

### V6. Gas: ADR-RN-018 C2 G10, exactly
1. **Integrity first.** Recompute `standard`, `floor` and `need` from the recorded rule set and
   the verifier's own reviewed constants, and compare each, plus `gasLimit` and the source
   digests. Any difference is **`GAS_RECORD_INVALID`**, a hard failure: no later gas step runs,
   and a matching receipt never repairs it.
2. **`R_i = rules(t_i)`** under the **verifier's own** reviewed table and horizon. It is never
   selected from the recorded rule-set id.
3. **Same rule set:** compare `receipt.gasUsed` with the recorded `need`, giving
   `GAS_ACCOUNTED` or `GAS_ACCOUNTING_MISMATCH` (with the observed value).
4. **A different, reviewed rule set:** `GAS_RULES_CROSSED`. Compute `need_Ri` from reviewed rules
   only, compare, and **keep both values**.
5. **Unknown or unreviewed `R_i`:** `GAS_RULES_UNRESOLVED`. Record the observed value, with **no
   expected value**, and never guess one.

**Gas evidence:** `gasUsed` must be the same quantity on every observed provider, under the same
block hash. Otherwise the evidence is contradictory: that is an evidence failure, not
`GAS_RULES_UNRESOLVED`.

### V7. Code state at inclusion is not established; it is stated
- The zero runtime, state and refund terms rest on the G4 shape (verified from the signed bytes)
  and on the sender having no code. The code at inclusion is **not observed**.
- **The basis is G4.3:** the signer produces only EIP-1559 signatures, and no EIP-7702
  authorization path exists. That is a key-custody argument, not evidence.
- **Detective controls** in the record:
  - `gasUsed == need`;
  - `receipt.status == 0x1`;
  - `receipt.logs == []`;
  - `contractAddress == null`.
- A delegation would most likely change `gasUsed` or emit logs, giving
  `GAS_ACCOUNTING_MISMATCH` or `RNGF_EXECUTION_OBSERVED`. Both are `UNRESOLVED`, and inclusion is
  unaffected. **That is not proof of its absence.**
- The record states `codeStateAtInclusion: "NOT_ESTABLISHED"`. Whether a later acquisition adds a
  block-hash-pinned `eth_getCode` read is a separate decision (U3). It is a new read, needs EIP-1898
  support (1RPC is unresolved) and its own budget.

### V8. Separate findings, never one Boolean
These are recorded separately, and they may coexist:
- evidence integrity;
- transaction binding;
- inclusion;
- finality;
- gas-record integrity;
- fork crossing;
- gas accounting;
- review eligibility.

**Gas never proves finality, and finality never proves gas.** The overall disposition is one of:
- **`FAIL`:** an integrity, binding or evidence failure, `CONFLICT`, or `GAS_RECORD_INVALID`;
- **`UNRESOLVED`:** anything not established;
- **`ELIGIBLE_FOR_FOUNDER_REVIEW`:** everything required is established, under `CLAIMED`
  semantics.

There is no `VERIFIED` and no `CHAIN_PROVEN`. Publication stays H10 and C5.

### V9. A new, append-only record
- **Format:** `rnnet.gate-f-sepolia-verification.v1`, digest domain
  `rnnet:gate-f-sepolia-verification:v1\0`. No accepted format binds intent, signed bytes,
  finality and gas together.
- **It references the accepted artifacts by digest:** intent, txverify record, submission record,
  capture, live report, the optional preliminary status record. It never embeds raw bodies.
- **Append-only.** Later evidence, or a later reviewed rule set, is a **new** record whose
  `supersedes` names the digest of the earlier one, with a reason. Earlier records are never
  edited or deleted. A set of records with a fork in the chain, a dangling reference or a cycle is
  invalid.

### V10. Status is preliminary
`rnnet.submission-status.v1` (status) may be **referenced** in the gate-F record as preliminary
(Q5). It is never evidence: gate F re-derives everything from the captures.
- A status `INCLUDED` is never promoted to a gate-F disposition.
- Status never overwrites a gate-F record, never repairs a gas record, and never triggers signing
  or broadcasting.

## Threat model

| # | Threat | Control (stage) | Expected result | Residual |
|---|---|---|---|---|
| T1 | A provider fabricates receipt fields | Both providers read. Cross-provider agreement on material and `gasUsed`. Receipt-to-transaction and block consistency (anchor A9, A10). Field binding to the signed bytes (V5) | `RNLO_PROVIDER_DISAGREEMENT`, `RNAE_RECEIPT_MISMATCH`, or binding / evidence `FAIL` | Two colluding providers can agree on a fabrication. ADR-RN-015: `CLAIMED`, not proof |
| T2 | The providers disagree on inclusion | Disagreement is never averaged (ADR-RN-019 §8). The spec's provider comparison table (§3.3.1) separates material, missing-observation, finality-only, `CONFLICT` and unresolved-walk cases | `FAIL` (material or contradicted), `FAIL` (any `CONFLICT`), or `UNRESOLVED` (finality-only, unresolved, uncontradicted missing) | — |
| T3 | An orphaned or replaced block | Walk from `finalized` with every link checked (V2) | `CONFLICT`, so `FAIL`; or `NOT_REACHED`, so `UNRESOLVED` | Reorganization after finality on a permissioned testnet (ADR-RN-015) |
| T4 | A receipt belongs to another transaction | `receipt.transactionHash` = the hash = keccak of the signed bytes (A9, V5) | binding `FAIL` | — |
| T5 | `gasUsed` disagrees with the reviewed calculation | G10 | `GAS_ACCOUNTING_MISMATCH` (recorded; inclusion unaffected) | Cause not determined (rule, code state, provider) |
| T6 | A fork boundary is crossed | `R_i` from `t_i` | `GAS_RULES_CROSSED` with both needs | — |
| T7 | An unknown fork activates before inclusion | The verifier's own table and horizon | `GAS_RULES_UNRESOLVED`, no expected value | Detected only as a mismatch if the review is still in horizon (ADR-RN-018 G5 R2) |
| T8 | The review horizon expires | Horizon checked at `t_i` (and at verification) | `GAS_RULES_UNRESOLVED` (rules unknown at `t_i`) | A later review supersedes by a new record |
| T9 | A gas member is changed and re-digested | Intent digest = the approved digest; integrity recomputation (V6.1) | `RNTX_INTENT_DIGEST_MISMATCH` or `GAS_RECORD_INVALID` | — |
| T10 | A candidate is passed off as an intent | S1; format; candidate domain (V4) | subject refused | — |
| T11 | An estimate is numerically right while the block hash was ignored | No reliance on estimates; ADR-RN-018 G8/G9 | n/a (gate F does not use the estimate) | `blockHashSemantics` stays `UNRESOLVED` (D4) |
| T12 | Preparation-time code is taken as inclusion-time code | V7: stated as `NOT_ESTABLISHED` | recorded, with the detective controls | U3 |
| T13 | Conflicting evidence is removed afterwards | Record references capture digests; append-only `supersedes` (V9) | a missing or changed capture fails replay (`RNLO_REPLAY_MISMATCH`) | Private storage custody (ADR-RN-019 §7) |
| T14 | Status is promoted to a gate-F verdict | V10 | refused; status is referenced as preliminary only | — |
| T15 | Publication without founder review | The disposition is at most `ELIGIBLE_FOR_FOUNDER_REVIEW`; H10 and C5 are separate | no publication path in gate F | — |

## Unresolved decisions (each needs the founder or its own review)
- **U1.** Whether a result where PublicNode is `IN_ANCESTRY` and 1RPC differs may reach founder
  review, labelled as a single-provider claim (ADR-RN-019 §8, C6 branch D).
- **U2.** Whether a Sepolia subject with a v1 (C1) preparation is eligible, with gas accounting
  `NOT_APPLICABLE`, or is refused (proposed: refused, V4).
- **U3.** Whether acquisition adds a block-hash-pinned `eth_getCode` read at the inclusion block,
  and its budget.
- **U4.** The H10 acquisition run's exact request budget and walk timing (ADR-RN-019 C1 E2/E5 are
  Proposed).
- **U5.** Whether XRPL gate-F records share this format family. This ADR covers Sepolia; XRPL
  keeps ADR-RN-019 §8.
- **U6.** Which receipt field is authoritative under EIP-7778 if `gasUsed` and the per-transaction
  difference of `cumulativeGasUsed` ever diverge. Proposed: `receipt.gasUsed` only. For this
  transaction they are equal (ADR-RN-018 G10).

## Independent dependencies and blockers
- **D1. Stage B** (a v2 intent): not implemented. Authoritative Sepolia gate F is blocked on it.
- **D2.** The real `SEPOLIA_GAS_RULES_REVIEW` is `null`. Until a reviewed record exists, every gas
  step is `NOT_EVALUATED` (`RNGF_RULES_AUTHORITY_ABSENT`), and the disposition is at most
  `UNRESOLVED`.
- **D3. 1RPC:** the pinned-read and finality-lag issues are unresolved, and gas work does not
  touch them.
- **D4. Block-hash semantics** stay `UNRESOLVED` (ADR-RN-018 G9).
- **D5. Live authorizations:** every read run (H10) and every gate keeps its own founder
  authorization. Nothing here grants one.
- **D6.** The durable verifier is **not implemented**. Status is not a substitute (V10).
- **D7. C5** (the publication bundle) and the legal confirmation (readiness §6) are
  unchanged and still required.

## WP4-B implementation sequence (offline; each step reviewed with its tests)
| # | Step | Inputs → outputs | Spec | Depends on | Acceptance tests | Fail-closed |
|---|---|---|---|---|---|---|
| 1 | Record schema and canonical builder | findings → canonical record and digest | §6 | — | strict members, digest domain, null versus absent | unknown member refused |
| 2 | Subject eligibility | intent, approved digest → subject | §3.1 | S1, D1 | candidate, v1, synthetic, unknown preparation refused | refuse |
| 3 | Transaction binding | intent, txverify record, signed bytes, submission record → binding finding | §3.2 | txverify | every field, hash, blob digest | `FAIL` |
| 4 | Capture replay and evidence integrity | capture, live report → per-provider observations | §3.3 | the existing reader and replay | replay mismatch, leftover exchanges | `FAIL` |
| 5 | Inclusion and finality | observations → finality finding | §3.4 | ADR-RN-015 | `IN_ANCESTRY`, `CONFLICT`, `NOT_REACHED`, `UNRESOLVED`, PublicNode required | `FAIL` / `UNRESOLVED` |
| 6 | `t_i` extraction | captured block response → `t_i` | §3.5 | step 4 | provider mismatch, malformed, unlinked | evidence `FAIL` |
| 7 | Gas-record integrity | Stage B record, reviewed constants → integrity finding | §4.1 | WP2, D1, D2 | each field changed; unknown rule set; source digest | `GAS_RECORD_INVALID` |
| 8 | Inclusion rule selection | `t_i`, the verifier's reviewed table and horizon → `R_i` or unknown | §4.2 | WP2 | activation and horizon boundaries | `GAS_RULES_UNRESOLVED` |
| 9 | Gas accounting | `gasUsed`, need(s) → accounting finding | §4.3 | 7, 8 | ±1, crossed, unresolved | no guessed value |
| 10 | Finding aggregation | all findings → disposition | §5 | 3–9 | the precedence table | `FAIL` first |
| 11 | Append-only chain | records → chain validity | §6.3 | 1 | fork, cycle, dangling reference, silent rewrite | invalid |
| 12 | Independent Python reference | the same inputs → the same record bytes | §7 | 1–11 | JS = Python on every vector; no Node call | disagreement fails CI |
| 13 | Synthetic vectors and mutation/property tests | §7 matrix | §7 | 12 | all §7 vectors; negative controls | — |
| 14 | CI and guard wiring | — | — | 13 | runs in `offline-checks.sh`; no joiner; no transport | guard refusal |

WP4-B adds **no** live path, transport joiner, RPC request, Stage B acceptance, signing or
broadcasting.

## Consequences
- **Gate F gains a precise, reproducible contract.** Its conclusions are still provider claims
  under ADR-RN-015.
- **Authoritative Sepolia gate F stays blocked** on D1–D3 and D5–D7, even after WP4-B.
- **The two independence properties hold:** a gas finding never changes inclusion or finality,
  and finality never validates gas.
