# rnnet.gate-f-sepolia-verification.v1: the durable gate-F verification of a Sepolia Genesis transaction

- Status: **Proposed** ([ADR-RN-020](../docs/adr/ADR-RN-020-durable-gate-f-verification.md),
  RN-NET-03B2-WP4-A). **Not implemented.**
  - This specification authorizes no RPC request, no H10 run, no Stage B, no signing,
    submission or publication.
  - Authoritative use is **BLOCKED** on Stage B (ADR-RN-020 D1) and on a recorded rules review
    (D2).
- Finality semantics: [ADR-RN-015](../docs/adr/ADR-RN-015-live-finality-trust-semantics.md) and
  [ADR-RN-019](../docs/adr/ADR-RN-019-controlled-testnet-broadcasting.md) §8, **unchanged**.
- Gas semantics: [ADR-RN-018](../docs/adr/ADR-RN-018-transaction-preparation-reads.md) C2 G4,
  G10 and Q4/Q5, **unchanged** (Proposed there).

## 1. What this verification is

A **pure, deterministic** function. It reads no clock and no environment, and makes no network
request. Its inputs (§2) produce one canonical record (§6). Anyone holding the same inputs
reproduces the same record bytes, indefinitely (ADR-RN-020 V1).

Its conclusions about the chain are **provider claims** (ADR-RN-015):
- finality is `CLAIMED` or `UNRESOLVED`;
- `chainInclusionProof` is always `UNRESOLVED`;
- nothing is `CHAIN_PROVEN` or `VERIFIED` inclusion.

What it computes itself from bytes is the transaction hash, the binding and the gas need. Those
are recomputations (`VERIFIED` in the taxonomy sense), and the record says so.

## 2. Inputs

Every input is an artifact of an accepted or Proposed format, given whole. The record names each
by its digest.

| # | Input | Format | Role | Required |
|---|---|---|---|---|
| I1 | The approved intent | `rnnet.unsigned-tx-intent.v1` (canonical JSON text) | the subject (§3.1) | yes |
| I2 | The approved digest | `sha256:<hex>` | intent approval | yes |
| I3 | The signed transaction | `0x` hex (the sign-log output) | the authoritative bytes (§3.2) | yes |
| I4 | The txverify record | `rnnet.signed-tx-verification.v1` | signature, sender, fields, hash | yes |
| I5 | The submission record of the attempt | `rnnet.submission-record.v1` | submission provenance | yes |
| I6 | The capture | `rnnet.rpc-capture.v1` | the provider bytes, replayed (§3.3) | yes |
| I7 | The live report | `rnnet.live-observation-report.v1` | must equal the replayed report | yes |
| I8 | The verifier's reviewed rules | the reviewed table, the sources and the **review history** (`SEPOLIA_GAS_RULES_REVIEW` and its recorded successors) | integrity (§4.1) and `R_i` (§4.2) | yes; empty refuses every gas step |
| I9 | A preliminary status record | `rnnet.submission-status.v1` | referenced only, never evidence (§3.7) | no |
| I10 | The superseded record | `rnnet.gate-f-sepolia-verification.v1` | append-only chain (§6.3) | only for a successor record |

**Never inputs:**
- a Stage A candidate or its digest;
- a provider estimate;
- a user-supplied transaction hash or timestamp;
- the verifier's clock;
- private RPC bodies outside the capture.

## 3. Procedure, in order

Steps 1–4 end verification at their first failure (`FAIL`, §5). Steps 5 onwards record findings
that may coexist.

### 3.1 Subject eligibility
1. `approvedIntent(I1, I2)`: the intent is valid under S1 and its digest is the approved one.
   Otherwise the RNTX code (`RNTX_INTENT_INVALID`, `RNTX_INTENT_DIGEST_MISMATCH`).
2. `network` is `evm:11155111`, and `purpose` is `genesis-proof-01`.
3. The preparation is a **v2 record accepted under the Stage B policy**, by format and full
   verification. Anything else is `RNGF_SUBJECT_NOT_ELIGIBLE`:
   - a v1 or synthetic preparation (ADR-RN-020 V4; alternative U2);
   - any candidate (`rnnet.tx-preparation-v2-candidate.v1`): S1 already refuses it at step 1;
   - a candidate digest offered as I2: it fails step 1, because the domains differ.

   **Until Stage B exists, every real subject stops here.**

### 3.2 Transaction binding (`RNGF_BINDING_MISMATCH` unless a more specific code is named)
1. I4 is `PASS` for (I1, I2, I3). Otherwise its RNTX code.
2. `I4.transactionHash` is keccak-256 of the I3 bytes. `I4.blobSha256` is SHA-256 of the I3
   bytes. `I4.intentDigest` is I2.
3. I5: `intentDigest` = I2, `blobSha256` = `I4.blobSha256`, `expectedTransactionHash` =
   `I4.transactionHash`, and `network` is Sepolia. `outcome` is any submitted outcome; a dry run
   is refused.
4. For every observed provider (§3.3), the transaction object:
   - `hash` = `I4.transactionHash`;
   - `type`, `chainId`, `nonce`, `from`, `to`, `value`, `input`, `gas`, `maxFeePerGas`,
     `maxPriorityFeePerGas` and `accessList` equal the decoded I3. A field **absent** from the
     provider's object is `RNGF_EVIDENCE_INVALID`, never skipped.
   - The receipt: `transactionHash` = the hash; `from` and `to` as the transaction
     (`RNAE_RECEIPT_MISMATCH`); `contractAddress` is `null`.
   - `logs` other than `[]` is **not** a binding failure. It is a code-state symptom (§4.3),
     recorded as `RNGF_EXECUTION_OBSERVED`. Inclusion is unaffected (ADR-RN-020 V8).

### 3.3 Evidence integrity
1. Replay I6 with the existing reader (live-observation-report §8). Any mismatch or unused
   exchange is `RNLO_REPLAY_MISMATCH`. The canonical replayed report must equal I7 byte for byte
   (`RNGF_EVIDENCE_INVALID`).
2. The capture names the two reviewed Sepolia providers (`sepolia-publicnode`, `sepolia-1rpc`)
   and the transaction hash of §3.2.
3. The I7 outcome and agreement:
   - `RNLO_PROVIDER_DISAGREEMENT` or an `INCONSISTENT` provider is `FAIL`, here;
   - `RNLO_FINALITY_CONFLICT` is **not** cut off here. §3.4 records each provider's `CONFLICT`
     before the `FAIL`, so the record preserves it;
   - `INDETERMINATE` is `UNRESOLVED`.

### 3.4 Inclusion and finality (ADR-RN-015 §3; ADR-RN-019 §8)
- **Inclusion,** per provider: the block exists, matches the transaction's `blockHash` and
  `blockNumber`, and lists the hash at `transactionIndex` (reader §6 step 4). Not found or pending
  means inclusion is `NOT_ESTABLISHED`; the gas steps are then `NOT_EVALUATED`.
- **Finality,** per provider: the `finalized` walk result (`IN_ANCESTRY`, `CONFLICT`,
  `NOT_REACHED`, `UNRESOLVED`), taken from the replay. Block numbers are never used on their own.
- **The finality disposition:**

  | PublicNode | 1RPC | Disposition |
  |---|---|---|
  | `IN_ANCESTRY` | `IN_ANCESTRY` | `PROVIDER_REPORTED_FINALIZED` (both) |
  | `IN_ANCESTRY` | other than `CONFLICT` | `PROVIDER_REPORTED_FINALIZED_SINGLE` (labelled single-provider claim; review eligibility is U1) |
  | `CONFLICT` | any | `CONFLICT`. Overall **`FAIL`** (`RNLO_FINALITY_CONFLICT`) |
  | any | `CONFLICT` | `CONFLICT`. Overall **`FAIL`**, even when PublicNode is `IN_ANCESTRY` |
  | not `IN_ANCESTRY` | any non-conflict | `NOT_ESTABLISHED` (`UNRESOLVED`) |

  The rows are checked in order, and **any `CONFLICT` takes precedence**. It is recorded per
  provider in `perProvider`. A `CONFLICT` is **never** mapped to `UNRESOLVED`,
  `NOT_ESTABLISHED` or `PROVIDER_REPORTED_FINALIZED_SINGLE`. Like any failure in steps 1–4,
  verification then ends. `inclusion` and `finality` are recorded as observed, and every gas
  state is `NOT_EVALUATED`.

### 3.5 The inclusion timestamp `t_i`
- **The source:** the captured response to `eth_getBlockByHash(receipt.blockHash, false)`, whose
  `hash` and `number` equal the receipt's.
- **Linkage:** the block must be the one the PublicNode finalized walk reached at that height.
- **Parsing:** `t_i` is that block's `timestamp`, parsed as a canonical quantity into an integer in
  `[0, 2^40)`.
- **Agreement:** every provider's block of that hash must give the same `timestamp`. Otherwise
  `RNGF_EVIDENCE_CONTRADICTORY`, a `FAIL`.
- **Refusals:** a missing, malformed or unlinked block is `RNGF_INCLUSION_TIMESTAMP_INVALID`, a
  `FAIL`. That is **evidence**, never `GAS_RULES_UNRESOLVED`.

### 3.6 The receipt for gas
- `receipt.status` must be `0x1` (`RNAE_TRANSACTION_REVERTED` / `RNAE_INVALID_STATUS`, `FAIL`).
- `receipt.gasUsed` must be a canonical quantity on every observed provider
  (`RNGF_EVIDENCE_INVALID`), and the same on every provider (`RNGF_EVIDENCE_CONTRADICTORY`). That
  value is `gasUsed`. Its classification is `CLAIMED`.

### 3.7 Preliminary status (Q5)
When I9 is given, its digest and `finding` are copied under `preliminaryStatus`.
- It is never evidence and never changes any finding.
- A status `INCLUDED` with a gate-F `UNRESOLVED` stays `UNRESOLVED`.

## 4. Gas (ADR-RN-018 C2 G10)

Steps 4.1 to 4.3 run only when inclusion is established (§3.4) and §3.5–§3.6 passed.

### 4.1 Integrity of the recorded gas member (first, always)
**No authority:** if the verifier's review history (I8) is empty, as today (D2), no gas step can
be checked.
- The finding is `RNGF_RULES_AUTHORITY_ABSENT`; `gasRecord`, `gasRules` and `gasAccounting` are
  `NOT_EVALUATED`; the disposition is at most `UNRESOLVED`.
- The record is not blamed for the verifier's missing authority.

**Recompute from:**
- the recorded `ruleSetId`;
- the verifier's own constants for it (I8);
- the I3 payload, by zero and non-zero byte counts.

**Then require:**
1. `ruleSetId` is a rule set the verifier knows;
2. `review` is in the verifier's (non-empty) review history, and `reviewDigest` = the digest of
   `review`. A recorded review the verifier does not recognize was never authoritative, so it is
   `GAS_RECORD_INVALID`;
3. `review.sources` = the verifier's pinned sources for that review;
4. `standard`, `floor` and `need` each equal the recomputation, **checked separately**;
5. `gasLimit` = 30,000 = `tx.gas`;
6. `ruleSetId` and `fork` = `rules(pin.timestamp)` under that review;
7. the review covered the preparation (`reviewedAt ≤ observedAt < horizon`, and `pin ≤ observedAt`).

**Any difference is `GAS_RECORD_INVALID`,** a **hard failure** (§5).
- §4.2–§4.3 do not run.
- A matching receipt never repairs it.
- A valid intent digest is no evidence that the gas values are correct.

### 4.2 The inclusion rule set
`R_i = rules(t_i)` under the verifier's **current** reviewed table, and a review in its history
whose horizon is **after** `t_i` and which lists no known unreviewed activation at or before
`t_i`.
- `R_i` is never taken from the recorded `ruleSetId`, a provider label or a header field.
- If no such review exists, or the table does not cover `t_i`, `R_i` is **unknown**.

### 4.3 Accounting
| Case | Findings | Expected value | Recorded |
|---|---|---|---|
| `R_i` = recorded `ruleSetId` | `GAS_ACCOUNTED` if `gasUsed` = recorded `need`, else `GAS_ACCOUNTING_MISMATCH` | the recorded `need` (checked in 4.1) | `gasUsed`, the recorded values |
| `R_i` reviewed, ≠ recorded | **`GAS_RULES_CROSSED`**, plus `GAS_ACCOUNTED` / `GAS_ACCOUNTING_MISMATCH` against `need_Ri` | `need_Ri` = G3 under `R_i`, with the G4 preconditions of the I3 shape | **both** the recorded values and `{ruleSetId: R_i, standard, floor, need}` at inclusion |
| `R_i` unknown | **`GAS_RULES_UNRESOLVED`**; accounting `UNRESOLVED` | **none**: never the recorded set, the nearest set, an estimate, a hard-coded fork, or assumed runtime, state or refund terms | `gasUsed`, the recorded values, `expected: null` |

**Code state.** The record states `codeStateAtInclusion: "NOT_ESTABLISHED"`, with basis
`"G4.3"` (ADR-RN-020 V7). Its detective controls are `gasUsed` = need, status `0x1`, no logs
and no `contractAddress`. A `GAS_ACCOUNTED` result is "consistent with no execution", not proof of
it. Non-empty `logs` add `RNGF_EXECUTION_OBSERVED`, giving `UNRESOLVED`, for founder review.

### 4.4 Evidence problems are not rule problems
- **Evidence failures (`FAIL`):** a missing receipt, a missing or malformed `gasUsed`, receipts
  that contradict each other, a receipt for another transaction, a missing inclusion block, an
  invalid ancestry, or a malformed or unlinked timestamp.
- **Not established (`UNRESOLVED`, gas `NOT_EVALUATED`):** finality not established or
  inclusion not established.
- **`GAS_RULES_UNRESOLVED`** is used **only** for §4.2 unknown rules. That covers an expired
  horizon at `t_i`, an unsupported fork, and a missing review for `t_i`.
- **`GAS_RECORD_INVALID`** is used **only** for §4.1, which covers an unknown original rule set
  and a missing original review.

## 5. Findings and disposition

The finding groups are recorded separately and can coexist:
- `subject`;
- `binding`;
- `evidence`;
- `inclusion`;
- `finality`;
- `gasRecord` (`VALID` / `GAS_RECORD_INVALID` / `NOT_EVALUATED`);
- `gasRules` (`SAME` / `GAS_RULES_CROSSED` / `GAS_RULES_UNRESOLVED` / `NOT_EVALUATED`);
- `gasAccounting` (`GAS_ACCOUNTED` / `GAS_ACCOUNTING_MISMATCH` / `UNRESOLVED` /
  `NOT_EVALUATED`);
- `review`;
- `chain` (the append-only chain of §6.3).

`findings[].group` is exactly one of these eleven names.

**Precedence of the overall `disposition`** (first match wins):

| # | Condition | disposition |
|---|---|---|
| 1 | §3.1–§3.3 failed, a finality `CONFLICT`, §3.5–§3.6 evidence failed, or `GAS_RECORD_INVALID` | `FAIL` |
| 2 | Inclusion or finality not established; `PROVIDER_REPORTED_FINALIZED_SINGLE` (until U1); `RNGF_RULES_AUTHORITY_ABSENT`; `GAS_RULES_UNRESOLVED`; `GAS_ACCOUNTING_MISMATCH`; or `RNGF_EXECUTION_OBSERVED` | `UNRESOLVED` |
| 3 | Otherwise: subject, binding and evidence valid; `PROVIDER_REPORTED_FINALIZED`; `gasRecord` `VALID`; `GAS_ACCOUNTED`, with or without `GAS_RULES_CROSSED` | `ELIGIBLE_FOR_FOUNDER_REVIEW` |

- **A mismatch is `UNRESOLVED`, not `FAIL`:** inclusion stands (I2). It must be explained in
  founder review before any publication.
- **Never produced:** `VERIFIED`, `PASS`, `CHAIN_PROVEN`, `published`.
- **Review eligibility is not publication.** H10, the legal confirmation and C5 remain separate.

**Examples of coexistence:**
- `GAS_RULES_CROSSED` + `GAS_ACCOUNTED` + `PROVIDER_REPORTED_FINALIZED` →
  `ELIGIBLE_FOR_FOUNDER_REVIEW`;
- `GAS_ACCOUNTED` + finality `NOT_ESTABLISHED` → `UNRESOLVED`;
- `GAS_RULES_UNRESOLVED` + `PROVIDER_REPORTED_FINALIZED` → `UNRESOLVED`;
- `GAS_RECORD_INVALID` + a valid receipt → `FAIL`.

## 6. The record

### 6.1 Members (rnnet.canonical-json.v1; every member required; no other member at any level)
```
{ "format": "rnnet.gate-f-sepolia-verification.v1",
  "rules": "ADR-RN-020",
  "network": "evm:11155111",
  "subject": { "intentDigest": <digest>, "commitment": <digest|null>, "transactionHash": <hash|null>,
               "blobSha256": <digest|null>, "txverifyRecordSha256": <digest>, "submissionRecordDigest": <digest> },
  "evidence": { "captureSha256", "liveReportSha256", "providers": [ "sepolia-publicnode", "sepolia-1rpc" ] },
  "inclusion": { "status": "ESTABLISHED" | "NOT_ESTABLISHED" | "NOT_EVALUATED",
                 "blockHash": <hash|null>, "blockNumber": <quantity|null>, "transactionIndex": <quantity|null>,
                 "timestamp": <integer|null> },
  "finality": { "disposition": "PROVIDER_REPORTED_FINALIZED" | "PROVIDER_REPORTED_FINALIZED_SINGLE" | "CONFLICT" | "NOT_ESTABLISHED" | "NOT_EVALUATED",
                "perProvider": [ { "id", "result": "IN_ANCESTRY" | "CONFLICT" | "NOT_REACHED" | "UNRESOLVED" | "NOT_OBSERVED" } ],
                "classification": "CLAIMED" | "UNRESOLVED", "chainInclusionProof": "UNRESOLVED" },
  "gas": { "record": "VALID" | "GAS_RECORD_INVALID" | "NOT_EVALUATED",
           "recorded": { "ruleSetId", "fork", "reviewDigest", "standard", "floor", "need", "gasLimit" } | null,
           "rules": "SAME" | "GAS_RULES_CROSSED" | "GAS_RULES_UNRESOLVED" | "NOT_EVALUATED",
           "atInclusion": { "ruleSetId", "standard", "floor", "need" } | null,
           "expected": <integer|null>, "gasUsed": <integer|null>,
           "accounting": "GAS_ACCOUNTED" | "GAS_ACCOUNTING_MISMATCH" | "UNRESOLVED" | "NOT_EVALUATED",
           "codeStateAtInclusion": "NOT_ESTABLISHED", "codeStateBasis": "G4.3" },
  "findings": [ { "code", "group": <one of the §5 groups>, "subject": <provider id | member name | null> } ],
  "disposition": "FAIL" | "UNRESOLVED" | "ELIGIBLE_FOR_FOUNDER_REVIEW",
  "preliminaryStatus": { "statusRecordDigest", "finding" } | null,
  "supersedes": { "recordDigest", "reason" } | null }
```

**Encoding rules:**
- **`null` versus absent.** Every member is present. `null` means "not established, or not
  applicable at this stage", and never "unknown but assumed". Absence is invalid.
- **Integers.** Gas values and `timestamp` are JSON integers (safe range). Block fields keep the
  JSON-RPC quantity and hash strings exactly as captured. There are no floats.
- **Order.** `providers` and `perProvider` are in the reviewed order (PublicNode, then 1RPC).
  `findings` are in procedure order (§3–§4), and within a step by provider order.
- **States.** Every documented outcome has exactly one representation, and no invented value:
  - **verification ended at §3.1–§3.3:** `inclusion.status` and `finality.disposition` are
    `NOT_EVALUATED`; `perProvider` is `[]`; every gas state is `NOT_EVALUATED`; the disposition
    is `FAIL` or `UNRESOLVED` per §5;
  - **`subject`:** `intentDigest`, `txverifyRecordSha256` and `submissionRecordDigest` are always
    the digests of the given inputs. `commitment`, `transactionHash` and `blobSha256` are `null`
    only when the input that carries them is invalid (§3.1–§3.2);
  - **verification ended at a §3.4 `CONFLICT`:** `inclusion` as observed;
    `finality.disposition` `CONFLICT`; every gas state `NOT_EVALUATED`; the disposition is
    `FAIL`;
  - **`finality.disposition` is `CONFLICT` if and only if** some `perProvider[].result` is
    `CONFLICT`, and then `disposition` is `FAIL`;
  - **`perProvider[].result`:** `NOT_OBSERVED` for a provider the replay did not read; otherwise
    the walk result, unchanged;
  - **`finality.classification`:** `CLAIMED` when at least one walk result was observed;
    otherwise `UNRESOLVED`.
- **Consistency of duplicated data:**
  - `subject.transactionHash` = the hash of every observation;
  - `gas.recorded.gasLimit` = 30,000;
  - `gas.expected` = `gas.recorded.need` when `rules` is `SAME`, `gas.atInclusion.need` when
    `GAS_RULES_CROSSED`, and `null` otherwise;
  - `gas.atInclusion` is non-null **only** when `GAS_RULES_CROSSED`.
- **No clock and no verifier identity.** Time appears only in the capture
  (`retrieval`), so JavaScript and Python produce identical bytes.
- **Nothing private:** no raw response bodies, URLs, local paths or authorization contents. All of
  those are referenced by digest.

### 6.2 Digest
`"sha256:" + hex(SHA-256("rnnet:gate-f-sepolia-verification:v1\0" ‖ canonical bytes))`.

### 6.3 Append-only chain
- **A record is never edited or deleted.** New evidence, a new acquisition run or a later
  reviewed rule set is a new record. `supersedes.recordDigest` names the record it follows, and
  `reason` is one of `NEW_EVIDENCE`, `NEW_RULES_REVIEW` or `CORRECTION`.
- **The chain is invalid** (`RNGF_CHAIN_INVALID`) if:
  - two records supersede the same record (a fork);
  - a cycle exists;
  - a `supersedes` names an unknown record;
  - a successor changes `subject` (same `intentDigest` and `transactionHash` are required).
- **An earlier `UNRESOLVED` record stays as it was.** A later record may resolve it, as with U3
  or a review in D2, but it is never rewritten.

## 7. Conformance test plan (for WP4-B; synthetic and offline only)

All Stage B subjects below are **hypothetical synthetic** fixtures, labelled `TEST ONLY` and made
through an unexported test seam, until Stage B is authorized. The expected values are computed
independently: Prague 22,680 (21,672 / 22,680) and Amsterdam 14,688 (12,672 / 14,688) for the
Genesis payload, with gas 30,000.

### 7.1 Positive
| ID | Vector | Expected |
|---|---|---|
| P1 | Valid subject; both providers `IN_ANCESTRY`; recorded `amsterdam`; `t_i` under `amsterdam`; `gasUsed` 14,688 | `SAME`, `GAS_ACCOUNTED`, `ELIGIBLE_FOR_FOUNDER_REVIEW` |
| P2 | As P1, with the binding checked on every field, and the receipt matching the transaction | binding valid |
| P3 | Recorded `prague`, `t_i` under `prague`, `gasUsed` 22,680 | `SAME`, `GAS_ACCOUNTED` |
| P4 | Recorded `prague` (22,680), `t_i` after `amsterdamTime` with a reviewed `amsterdam`, `gasUsed` 14,688 | `GAS_RULES_CROSSED`, `GAS_ACCOUNTED`, both values kept, `ELIGIBLE…` |
| P5 | P4 recorded and recomputed byte for byte by Python | JS = Python |
| P6 | A full ancestry walk replayed from the capture | finality `PROVIDER_REPORTED_FINALIZED` |
| P7 | Record digest and canonical bytes; a valid successor with `NEW_RULES_REVIEW` | digest stable; the chain valid |

### 7.2 Negative
| ID | Vector | Expected |
|---|---|---|
| N1 | A Stage A candidate as I1 | `RNTX_INTENT_INVALID` (§3.1), `FAIL` |
| N2 | Unsupported preparation (v9) | `RNTX_INTENT_INVALID`, `FAIL` |
| N3 | A candidate digest as I2 for a relabelled intent | `RNTX_INTENT_INVALID` (S1), `FAIL` |
| N4 | `need` changed (re-digested, re-approved) | `GAS_RECORD_INVALID`, `FAIL` |
| N5 | `standard` changed | `GAS_RECORD_INVALID` |
| N6 | `floor` changed | `GAS_RECORD_INVALID` |
| N7 | A review source digest changed | `GAS_RECORD_INVALID` |
| N8 | Unknown recorded `ruleSetId` | `GAS_RECORD_INVALID` |
| N9 | `t_i` beyond the verifier's table (unknown inclusion rule set) | `GAS_RULES_UNRESOLVED`, `expected: null`, `UNRESOLVED` |
| N10 | Empty review history (I8, as today) | `RNGF_RULES_AUTHORITY_ABSENT`, gas `NOT_EVALUATED`, `UNRESOLVED` |
| N10b | The recorded review is not in a non-empty verifier history | `GAS_RECORD_INVALID`, `FAIL` |
| N11 | `t_i` ≥ the covering review's horizon | `GAS_RULES_UNRESOLVED` |
| N12 | The inclusion block response missing from the capture | `RNGF_INCLUSION_TIMESTAMP_INVALID`, `FAIL` |
| N13 | The timestamp taken from an unlinked block, or a supplied value | `RNGF_INCLUSION_TIMESTAMP_INVALID` |
| N14 | finalized `NOT_REACHED` on PublicNode | finality `NOT_ESTABLISHED`, `UNRESOLVED` |
| N15 | `receipt.transactionHash` of another transaction | `RNAE_RECEIPT_MISMATCH` / `RNGF_BINDING_MISMATCH`, `FAIL` |
| N16 | The two providers give two block hashes | `RNLO_PROVIDER_DISAGREEMENT`, `FAIL` |
| N17 | A walk link with the wrong parent or number | `RNLO_BLOCK_MISMATCH` (§3.3, an `INCONSISTENT` provider), `FAIL`; finality `NOT_EVALUATED` |
| N17b | PublicNode walk reaches **another block** at the transaction's height | `perProvider[0].result: CONFLICT`, `finality.disposition: CONFLICT`, `RNLO_FINALITY_CONFLICT`, gas `NOT_EVALUATED`, **`FAIL`**; never `UNRESOLVED` |
| N17c | PublicNode `IN_ANCESTRY`, 1RPC `CONFLICT` | `perProvider[1].result: CONFLICT`, `finality.disposition: CONFLICT`, gas `NOT_EVALUATED`, **`FAIL`**; never `PROVIDER_REPORTED_FINALIZED_SINGLE` |
| N18 | `gasUsed` = expected − 1 | `GAS_ACCOUNTING_MISMATCH`, `UNRESOLVED` |
| N19 | `gasUsed` = expected + 1 | `GAS_ACCOUNTING_MISMATCH`, `UNRESOLVED` |
| N20 | `gasUsed` correct, finality `NOT_ESTABLISHED` | `GAS_ACCOUNTED` + `UNRESOLVED` |
| N21 | Crossed, `gasUsed` = recorded `need` (22,680), not `need_Ri` | `GAS_RULES_CROSSED` + `GAS_ACCOUNTING_MISMATCH` |
| N22 | `receipt.logs` not empty (a code-state symptom) | `RNGF_EXECUTION_OBSERVED`; inclusion kept; `UNRESOLVED` |
| N23 | A successor that rewrites `subject`, or two successors of one record | `RNGF_CHAIN_INVALID` |
| N24 | A status `INCLUDED` (I9) with finality `NOT_ESTABLISHED` | stays `UNRESOLVED`; status only under `preliminaryStatus` |
| N25 | Any output with `published`, `VERIFIED` or `CHAIN_PROVEN` | refused by the schema; the disposition caps at `ELIGIBLE_FOR_FOUNDER_REVIEW` |
| N26 | `gasUsed` differs between providers under one block hash | `RNGF_EVIDENCE_CONTRADICTORY`, `FAIL` |
| N27 | A provider transaction object missing `maxFeePerGas` | `RNGF_EVIDENCE_INVALID`, `FAIL` |
| N28 | A dry-run submission record | `RNGF_BINDING_MISMATCH`, `FAIL` |
| N29 | N1 (candidate as I1): the whole record | `inclusion.status` and `finality.disposition` `NOT_EVALUATED`, `perProvider: []`, every gas state `NOT_EVALUATED`, `subject.transactionHash: null`, `FAIL` |
| N30 | A record with `finality.disposition: CONFLICT` and `disposition: UNRESOLVED`, or `CONFLICT` in neither `perProvider` | refused by the §6.1 state rules (schema-invalid) |

### 7.3 Boundaries (recorded `prague`; reviewed `amsterdam` at A = 1791294816; covering-review horizon H)
| ID | `t_i` | Expected |
|---|---|---|
| B1 | A − 1 | `SAME` (`prague`); `gasUsed` 22,680 gives `GAS_ACCOUNTED` |
| B2 | A | `GAS_RULES_CROSSED` (`amsterdam`, 14,688) |
| B3 | A + 1 | `GAS_RULES_CROSSED` |
| B4 | H − 1 | reviewed: crossed or same, per the rule set |
| B5 | H | `GAS_RULES_UNRESOLVED` (inclusive) |
| B6 | H + 1 | `GAS_RULES_UNRESOLVED` |

### 7.4 The reference and controls
- **The JavaScript verifier and an independently written Python reference** agree on every
  vector's record bytes. Python never calls Node.
- **Fixtures:** synthetic captures from the existing simulated providers. No private evidence,
  and fixture response bytes must not coincide with any recorded provider response.
- **Mutation tests:** each field of each input changed in turn, with the expected group and
  code.
- **Property tests:** random digests and `t_i` across the table, under a fixed seed.
- **Negative controls:** each verifier check removed in turn must make vectors disagree.

### 7.5 Traceability
| Requirement | Source | Spec § | Vectors |
|---|---|---|---|
| Finality = the provider-reported walk, both providers, no shortcut | ADR-RN-015 §3; ADR-RN-019 §8 | 3.4 | P6, N14, N16, N17 |
| `CONFLICT` preserved per provider; always `FAIL`; never `UNRESOLVED` | ADR-RN-015 §3 ("a conflict … fails"); ADR-RN-020 V2 | 3.3, 3.4, 6.1 | N17b, N17c, N30 |
| Every documented outcome is representable, without invented values | ADR-RN-020 V8, V9 | 6.1 | N1, N29, N30 |
| The authoritative `t_i` from the linked block | ADR-RN-018 G10; ADR-RN-020 V3 | 3.5 | N12, N13, B1–B6 |
| Integrity of the recorded gas, first and hard | G10 step 1; V6 | 4.1 | N4–N8, N10b |
| No authority means not evaluated (fail-closed, not blamed on the record) | D2; V6 | 4.1 | N10 |
| Inclusion rules from the verifier's own reviewed table | G10 step 2; Q1 | 4.2 | N9, N11, B5, B6 |
| Same rules, accounted or mismatched | G10 step 3 | 4.3 | P1, P3, N18, N19 |
| A crossed fork keeps both values | G10 step 4 | 4.3 | P4, P5, N21, B2, B3 |
| An unknown rule set gives no expected value | G10 step 5 | 4.3 | N9, N11 |
| Gas and finality are independent | ADR-RN-020 V8 | 5 | N20, P4 |
| Candidate is not an intent | S1; Q4 Stage A | 3.1 | N1–N3 |
| Transaction binding to the signed bytes | ADR-RN-016/017/019 §3; V5 | 3.2 | P2, N15, N22, N27, N28 |
| Code state stated, not assumed | G4.3; V7 | 4.3 | N22 |
| Status is preliminary | Q5; V10 | 3.7 | N24 |
| Append-only | ADR-RN-020 V9 | 6.3 | P7, N23 |
| No proof wording; no self-publication | ADR-RN-015 §4; H10 | 5 | N25 |
| Evidence contradiction is not a rule problem | V6; §4.4 | 3.5, 3.6 | N26 |

## 8. Codes

- **Reused, unchanged:**
  - `RNTX_INTENT_INVALID`, `RNTX_INTENT_DIGEST_MISMATCH` and txverify's RNTX codes;
  - `RNLO_*` (reader and replay);
  - `RNAE_*` (anchor);
  - `GAS_RECORD_INVALID`, `GAS_ACCOUNTED`, `GAS_ACCOUNTING_MISMATCH`, `GAS_RULES_CROSSED` and
    `GAS_RULES_UNRESOLVED` (ADR-RN-018 G10).
- **New, Proposed:**
  - `RNGF_SUBJECT_NOT_ELIGIBLE`;
  - `RNGF_BINDING_MISMATCH`;
  - `RNGF_EVIDENCE_INVALID`;
  - `RNGF_EVIDENCE_CONTRADICTORY`;
  - `RNGF_INCLUSION_TIMESTAMP_INVALID`;
  - `RNGF_CHAIN_INVALID`;
  - `RNGF_RULES_AUTHORITY_ABSENT`;
  - `RNGF_EXECUTION_OBSERVED`.

## 9. Non-goals

This specification does not cover:
- acquisition (the H10 read run and its budget, U4);
- Stage B acceptance;
- XRPL gate F (U5);
- C5 publication;
- any change to ADR-RN-015 finality, to the reader, or to the request policies.
