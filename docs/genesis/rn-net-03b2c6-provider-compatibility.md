# RN-NET-03B2-C6: read-only provider compatibility check (preparation)

- Status: **prepared offline, not run.** This document, the manifest and the offline run code
  (`tools/compat/`) authorize **no live RPC request**. The run needs its own written founder read
  authorization (H3, §8) and a separately reviewed live entry point (§8).
- Basis: [ADR-RN-018](../adr/ADR-RN-018-transaction-preparation-reads.md) Amendment C1, P4, P5
  and P7; [readiness analysis](rn-net-03b2c-operational-readiness.md) §4 "C6" and "Sepolia
  finality constraints"; [ADR-RN-013](../adr/ADR-RN-013-read-only-rpc-architecture.md) limits.
- Manifest: [`fixtures/compat-c6/manifest.json`](../../fixtures/compat-c6/manifest.json),
  SHA-256 `871140d88fc79881c2dddc3659db5ee80058b7f9a36152f39c1009e84515a4a2`.
- Code: `tools/compat/manifest.mjs` (the manifest), `tools/compat/run.mjs` (one run over an
  injected transport), `tools/compat/classify.mjs` (the classification),
  `tools/compat/simulated.mjs` (simulated providers). Python reference:
  `tools/reference/rnnet_compat_reference.py`.

## 1. What C6 must establish

| Network | Question | Why it matters |
|---|---|---|
| XRPL Testnet | Both reviewed providers report `network_id` 1 | network identity comes from the server, never from the URL (ADR-RN-013) |
| | `build_version` of each | the `fail_hard` reading was done at rippled 3.4.1 only (C2); another release must be read before gate E |
| | The validated ledger: seq, hash and age ≤ 30 s, and agreement (≤ 4 ledgers apart, one hash per seq) | the freshness and agreement rules of preparation (ADR-RN-018 §4, P8) |
| | `complete_ledgers` covers the last 1,000 validated ledgers | the ranged `tx` lookup of a status check needs that history |
| | A ranged `tx` lookup of an absent hash returns `txnNotFound` with `searched_all: true` | only that answer supports an `EXPIRED` finding (ADR-RN-019 §8) |
| Ethereum Sepolia | Both reviewed providers report chain id `0xaa36a7` (11155111) | network identity |
| | Head freshness and agreement; one hash at the pin P = lowest head − 2 | P1, and the C branch below |
| | `eth_getTransactionCount`, `eth_getBalance`, `eth_getCode` accept `{blockHash, requireCanonical: true}` | EIP-1898 account reads (P1, P2) |
| | `eth_estimateGas` accepts the same object | not in EIP-1898's list; **assumed on neither provider** (P4) |
| | The error each provider returns for an unknown hash, and that it refuses rather than answers | a provider that answers for a hash it cannot know makes `requireCanonical` meaningless |
| | Finalized heads of the two providers, and how far apart they are | the 1RPC lag of about 67 min in SMOKE-02, and the gate-F walk window (§7) |

**Provider identity, stated precisely.** C6 confirms the *network* identity each endpoint reports,
at the *reviewed URL* (host name checked by the transport's TLS). It cannot confirm who operates
the infrastructure behind it; the operators stay "as published" (ADR-RN-014).

## 2. Providers: the reviewed configuration only

| Provider id | Network | URL (config/rpc-endpoints.json) | Operator, as published |
|---|---|---|---|
| `xrpl-testnet-ripple` | `xrpl:testnet` | `https://s.altnet.rippletest.net:51234/` | Ripple |
| `xrpl-testnet-xrpl-labs` | `xrpl:testnet` | `https://testnet.xrpl-labs.com/` | XRPL Labs |
| `sepolia-publicnode` | `evm:11155111` | `https://ethereum-sepolia-rpc.publicnode.com/` | PublicNode |
| `sepolia-1rpc` | `evm:11155111` | `https://public.1rpc.io/sepolia` | Automata 1RPC |

- **No substitution.** The run refuses, before any request, unless the endpoint file holds
  exactly these four, at these URLs and networks. These are also the providers preparation reviews
  (`REVIEWED_PREPARATION_PROVIDERS`); a test pins the equality.
- **No fallback.** A request planned for one provider is never sent to another.

## 3. The manifest: 22 read-only requests

Each request is sent **at most once**, in this order. Bodies are canonical JSON as
`packages/chain-readonly` builds them (`requestBytes`). `<…>` marks a value only the run observes.

| # | Id | Provider | Method | Params | Sent only if | Expected response |
|---|---|---|---|---|---|---|
| 1 | X01 | ripple | `server_info` | `{api_version: 2}` | | `network_id` 1, `build_version`, `complete_ledgers`, `validated_ledger {seq, hash, age}` |
| 2 | X02 | xrpl-labs | `server_info` | as X01 | | as X01 |
| 3 | X03 | ripple | `tx` | `{transaction: A, binary: false, min_ledger: <V−999>, max_ledger: <V>, api_version: 2}` | X01 showed network 1 and a validated seq V | error `txnNotFound`, `searched_all: true` |
| 4 | X04 | xrpl-labs | `tx` | as X03, with X02's V | as X03 | as X03 |
| 5 | S01 | publicnode | `eth_chainId` | `[]` | | `"0xaa36a7"` |
| 6 | S02 | 1rpc | `eth_chainId` | `[]` | | as S01 |
| 7 | S03 | publicnode | `eth_getBlockByNumber` | `["latest", false]` | chain confirmed | block `{number, hash, timestamp, baseFeePerGas}` |
| 8 | S04 | 1rpc | `eth_getBlockByNumber` | `["latest", false]` | chain confirmed | as S03 |
| 9 | S05 | publicnode | `eth_getBlockByNumber` | `[<P>, false]` | both heads read; P = lowest − 2 | block at P |
| 10 | S06 | 1rpc | `eth_getBlockByNumber` | `[<P>, false]` | as S05 | block at P, the same hash as S05 |
| 11 | S07 | publicnode | `eth_getTransactionCount` | `[T, {blockHash: <H_pn>, requireCanonical: true}]` | S05 returned block P | QUANTITY |
| 12 | S08 | publicnode | `eth_getBalance` | as S07 | as S07 | QUANTITY |
| 13 | S09 | publicnode | `eth_getCode` | as S07 | as S07 | DATA, `"0x"` |
| 14 | S10 | publicnode | `eth_estimateGas` | `[{from: T, to: T, value: "0x0", data: D}, {blockHash: <H_pn>, requireCanonical: true}]` | as S07 | QUANTITY, from the intrinsic gas (21,672) to 30,000 |
| 15 | S11 | 1rpc | `eth_getTransactionCount` | as S07, at `<H_1rpc>` | S06 returned block P | QUANTITY |
| 16 | S12 | 1rpc | `eth_getBalance` | as S11 | as S11 | QUANTITY |
| 17 | S13 | 1rpc | `eth_getCode` | as S11 | as S11 | DATA |
| 18 | S14 | 1rpc | `eth_estimateGas` | as S10, at `<H_1rpc>` | as S11 | QUANTITY, 21,672 to 30,000 |
| 19 | S15 | publicnode | `eth_getBalance` | `[T, {blockHash: U, requireCanonical: true}]` | chain confirmed | **a JSON-RPC error** |
| 20 | S16 | 1rpc | `eth_getBalance` | as S15 | chain confirmed | a JSON-RPC error |
| 21 | S17 | publicnode | `eth_getBlockByNumber` | `["finalized", false]` | chain confirmed | block `{number, hash}` |
| 22 | S18 | 1rpc | `eth_getBlockByNumber` | `["finalized", false]` | chain confirmed | as S17 |

Constants, all public and derived from labels:
- **T**: `0x57db031993583fe0cbbf42dbfcf6489e0fb70b86`, the B1 test address (label
  `rn-net-03b2b1-sepolia-1`). It is never funded, and no Genesis key exists.
- **D**: the 42-byte Genesis Proof 01 payload, the same calldata preparation estimates.
- **A**: `B552D9334994C821546FDD06DEAA50BE3C8F1BAB2B81B001FAF4789C2995DD45`, SHA-256 of
  `rnnet:c6:absent-xrpl-transaction:v1`.
- **U**: `0x469f97ee2e9af87fc41e1d328ae1eca78d4cbad0f36c70df267a1b6c05e15251`, SHA-256 of
  `rnnet:c6:unknown-sepolia-block:v1`.

### Differences from the 22-request plan in the readiness analysis

The count, the providers and the methods are the same (2 + 2 + 9 + 9). Four details are made
precise, so that one failure cannot hide another:
1. **Each provider's pinned reads use the hash that provider returned for P**, not one agreed
   hash. EIP-1898 support is then measured on each provider even when the two disagree (branch C).
   Preparation itself still requires one agreed hash (P1); that is the `pin_agreement` check.
2. **Each XRPL range ends at that provider's own validated ledger**, so the lookup tests that
   provider's history.
3. **The pin needs both heads.** P is the lowest head − 2, as in preparation, so if one head
   is missing, both pins and all 8 pinned reads are `NOT_SENT`.
4. **Fees and reserves are not classified.** `server_info` carries `base_fee`, `load_factor`
   and the reserves, and they are kept in the private raw bodies. The fee bound is checked by
   preparation at gate D, not here. The pending nonce is not tested: it uses a tag, not EIP-1898.

## 4. Request rules, budget and limits

| Rule | Value |
|---|---|
| Total | at most **22** requests; exactly 22 when every dependency is met |
| Per provider | `xrpl-testnet-ripple` 2, `xrpl-testnet-xrpl-labs` 2, `sepolia-publicnode` 9, `sepolia-1rpc` 9 |
| Attempts | **1** per request. No retry of any kind, including on timeout, 429 or 5xx |
| Deadline | 10 s per request (ADR-RN-013); a whole run is at most 22 × 10 s ≈ 3.7 min |
| Response limit | 256 KiB; a larger body is `TOO_LARGE` |
| Methods | only methods already in `READ_ONLY_METHODS`; no write method exists in that list (tested) |
| Missing dependency | the request is `NOT_SENT`, never sent in another form (no `latest` for a hash, no number for a pin, no other provider) |
| Wrong network | once a provider reports another network, nothing more is sent to it |
| Repeat | a second run is a new founder authorization, never a retry inside a run |

## 5. Provider test matrix

**PASS**: the provider showed the behaviour the reviewed code needs.
**BLOCKED**: the reviewed code would refuse on what the provider returned. This is a finding about
this one observation; it does not show the behaviour persists.
**UNRESOLVED**: no conclusion, because of no answer, a transient state, a request not sent, or a
fact one run cannot settle.

| Check | Ripple | XRPL Labs | PASS | BLOCKED | UNRESOLVED |
|---|---|---|---|---|---|
| `xrpl.identity` | X01 | X02 | `network_id` 1 | another network id | no usable answer |
| `xrpl.build_version` | X01 | X02 | `3.4.1` | — | another release (fail_hard must be read at it), or missing |
| `xrpl.validated` | X01 | X02 | seq, hash, age ≤ 30 s | a field missing | age > 30 s |
| `xrpl.history` | X01 | X02 | `complete_ledgers` covers V−999..V | not covered, `empty` or unparseable | — |
| `xrpl.tx_lookup` | X03 | X04 | `txnNotFound`, `searched_all: true` | `searched_all` false or absent; any other error | reported found; no answer; not sent |
| `xrpl.agreement` | X01+X02 | | ≤ 4 apart, one hash per seq | one seq, two hashes | > 4 apart; one missing |

| Check | PublicNode | 1RPC | PASS | BLOCKED | UNRESOLVED |
|---|---|---|---|---|---|
| `sepolia.identity` | S01 | S02 | `0xaa36a7` | another chain | no usable answer |
| `sepolia.head` | S03 | S04 | well-formed, 60 s old at most, < 15 s ahead | a field missing | stale or ahead |
| `sepolia.head_agreement` | S03+S04 | | ≤ 4 apart, one hash per number | one number, two hashes | > 4 apart; one missing |
| `sepolia.pin_agreement` | S05+S06 | | the same block P, one hash, ≤ 90 s old | another number, two hashes, a field missing | older; one missing |
| `sepolia.eip1898.{nonce,balance,code}` | S07–S09 | S11–S13 | a result of the right type | a JSON-RPC error (any HTTP status), or a wrong type | no answer, 429, HTTP error without a JSON-RPC error, not sent |
| `sepolia.estimate_gas` | S10 | S14 | QUANTITY from 21,672 to 30,000 | a JSON-RPC error, or out of range | as above |
| `sepolia.unknown_hash` | S15 | S16 | a JSON-RPC error (code and sanitized message recorded) | **a result** | as above |
| `sepolia.finalized` | S17 | S18 | well-formed, not ahead of its own head | a field missing, or ahead of its head | no answer |
| `sepolia.finality_window` | S17+S18 | | finalized heads ≤ 64 blocks apart | > 192 apart | 65 to 192 apart; one missing |

A network's verdict is BLOCKED if any of its checks is, PASS if all are, and otherwise UNRESOLVED.
The run also gives a **compatibility candidate** per Sepolia provider,
`{eip1898AccountReads, estimateGasBlockHash}`: `true` when every check behind it passes, `false`
when one is BLOCKED, and `null` otherwise. That is the form of `SEPOLIA_COMPATIBILITY` in
`tools/prepare/entry.mjs`. Writing it there is a separately reviewed change, made from the
evidence, never by the run.

## 6. Sepolia decision branches

The classifier names every branch the evidence supports; more than one can hold. None is acted on
automatically, and no branch weakens the consensus or finality semantics: no unpinned state, no
`safe` tag for `finalized`, no finality inferred from time.

| Branch | Evidence | Next action (each separately reviewed and approved) |
|---|---|---|
| **A** | every Sepolia check PASS | 1. A PR records `SEPOLIA_COMPATIBILITY` = `true`/`true` for both providers, citing the evidence digest. 2. The P9 enabling PR for `prepare-live.mjs` (`LIVE_NETWORK_ACCESS`, one `PREPARE_TRANSPORT_JOINERS` member, `AGREED_EVIDENCE_DIR`), with its review. 3. D-SEP then needs B-SEP, C-SEP, H2 and H6/H7 as in readiness §9 |
| **B** | the account reads PASS on both providers; `eth_estimateGas` BLOCKED on one or both | **Smallest corrective:** an ADR-RN-018 amendment (C2) proposing **one** estimation strategy without the provider estimate, with simulated refusal cases, a Python reference and an independent review (P4). Recommended candidate: **compute the gas offline** and keep the pinned `eth_getCode` = `"0x"` read as its precondition. The target is the sender's own code-less account and the value is zero, so execution adds nothing to the intrinsic cost. It must include the EIP-7623 calldata floor (Prague, active on Sepolia): for the 42-byte payload the floor is 22,680 against a standard cost of 21,672, so gas used is 22,680, within the fixed 30,000 limit. Not acceptable: an unpinned or block-number estimate, or `eth_estimateGas` with no block parameter. Until that is accepted, `SEPOLIA_COMPATIBILITY` records `estimateGasBlockHash: false` and Sepolia preparation stays `BLOCKED` |
| **C** | head or pin hash agreement BLOCKED | **Smallest corrective:** one repeat C6 run under a **new** authorization, at another time. Agreement failures can be transient: a reorganization near the head, or a lagging node. If the disagreement repeats, the provider is not usable for pinned preparation. The corrective is then a reviewed provider addition (an ADR-RN-013/014 provider review and a config PR), not a looser agreement rule |
| **D** | finalized heads more than 192 blocks apart: under 64 blocks (about 13 min) of joint walk window | **Smallest corrective:** settle it in the **durable verification strategy** that gate F already needs (readiness §4), reviewed before gate F. Its candidates are offline reproduction from the captured exchanges, a bounded check by height, or a larger, budgeted ancestry limit. Separately, the founder may decide to accept a gate-F record whose Sepolia finality comes from PublicNode alone, labelled as one provider's claim, with the disagreement reported. ADR-RN-019 §8 already allows that. Adding a reviewed provider is the third option |
| **E** | outside A–D: an account read refused, an unknown hash answered, a wrong chain, or a malformed block | **The provider cannot serve pinned preparation.** Corrective: a reviewed replacement or additional provider. An answered unknown hash is the most serious case, because it would let a non-canonical pin pass |
| **UNRESOLVED** | no BLOCKED check, and not all PASS | one repeat run under a new authorization; the reason is recorded per check |

## 7. Can the current finality verifier provide the evidence gate F needs?

- **The walk.** `readEvm` walks parent hashes from each provider's `finalized` block down to the
  transaction's block, at most 256 steps (`ANCESTRY_LIMIT`). Gate F needs `IN_ANCESTRY` on both
  providers.
- **The joint window.** If the two finalized heads are Δ blocks apart, both can walk to the same
  transaction only while it is at most 256 − Δ blocks below the lower one. C6 measures Δ once and
  reports `jointWindowBlocks` and `jointWindowSeconds` (12 s per block).
- **What the thresholds mean.** Δ ≤ 64 leaves at least 192 blocks, about 38 minutes, for one
  authorized verification run. Δ > 192 leaves under 64 blocks, less than one finality period.
  The 67-minute lag seen in SMOKE-02 (about 335 blocks) would leave none.
- **What one run cannot settle.** Whether a lag persists. A PASS means the lag was not observed
  this time, not that it never occurs.
- **Even with A,** gate F stays blocked until the durable verification strategy is reviewed and
  accepted (readiness §4). The record must stay checkable after the walk window closes, and C6
  does not change that.

## 8. Evidence, and what the actual run requires

**Evidence format** `rnnet.provider-compat-evidence.v1` (`runCompatibility` returns it):
- per request:
  - the request text and its SHA-256;
  - the outcome (`OK`, `RPC_ERROR`, `HTTP_STATUS`, `RATE_LIMITED`, `TIMEOUT`, `TRANSPORT_ERROR`,
    `TOO_LARGE`, `INVALID_RESPONSE`, `NOT_SENT` with its reason);
  - the HTTP status, the response SHA-256 and its length;
  - the JSON-RPC error: code or name, `searched_all`, and the message, sanitized;
  - a small typed observation;
- then the checks, both verdicts, the branches, the candidate and the finality numbers.

**Sanitized:**
- no request or response headers and no address of the machine;
- error messages reduced to printable ASCII, URLs replaced by `<url>`, IPv4 addresses by `<ip>`,
  and cut to 160 characters.

The raw response bodies are returned separately. They are kept private, in the agreed evidence
directory outside every repository (H11), and are never published. Publishing any of it is gate F
(H10), a separate decision.

**Before the actual C6 run, each of these needs its own founder approval:**
1. **This preparation PR**, reviewed and merged. Its executable code is new: the manifest, run,
   classifier, simulator, guard rule and Python reference. It needs a focused review first.
2. **A live C6 entry point**, in its own PR with a focused review. It is the one file that may
   join `runCompatibility` to `tools/live/https-transport.mjs`, as a named exception to
   `compat-reaches-network`. It would:
   - refuse without the authorization below;
   - take no provider, budget or retry argument;
   - check the manifest digest;
   - read `now` after the founder's approval;
   - write the evidence privately (`0700`/`0600`, `wx`).
   It is not built here.
3. **The H3 read authorization**, written by the founder for one run. It names:
   - exactly 22 requests;
   - the four provider ids and URLs;
   - the manifest SHA-256 above;
   - one `authorizationId`;
   - a `notAfter` at most 60 minutes ahead;
   - the evidence directory;
   - "no publication".
4. **After the run:** the founder's review of the sanitized evidence. Only then may a separate PR
   record `SEPOLIA_COMPATIBILITY`, or open a corrective review (§6).

This authorizes no key generation, funding, signing, broadcasting or publication (gates B to F).

## 9. Offline validation

- **Simulated scenarios.** `fixtures/compat-c6/cases.json` holds 28 scenarios, each a transcript
  of simulated responses and the evidence the run produced. They cover:
  - A;
  - B: one provider, both providers, HTTP 400 with a JSON-RPC error, an estimate out of range,
    and a sanitized message;
  - C at the pin and at the head;
  - D, with B+D;
  - E: an account read refused, an unknown hash served, a wrong chain;
  - UNRESOLVED: a timeout, a stale head, skew, 429, invalid JSON, an oversized body, and a lag
    between the thresholds;
  - eight XRPL cases.

  No response there is a real provider answer.
- **`tools/compat.test.mjs`**:
  - the manifest's count, budget, methods and providers, and that a substituted, extra or missing
    provider is refused;
  - exact bytes, order and limits, with one send per request;
  - `NOT_SENT` on missing dependencies, and nothing more after a wrong network;
  - sanitization, the threshold edges (64/65/192/193), and fixture currency and replay.
- **`rnnet_compat_reference.py`** rebuilds every request byte for byte and every outcome,
  observation, status, verdict, branch, candidate and finality number from the transcripts alone.
  It checks the manifest against the configuration independently.
- **The guard.** `compat-reaches-network` and `compat-reaches-write-or-key` keep `tools/compat/`
  away from the transport, network modules, the write path, the signer and the key tool.

## 10. Path to C5 and Genesis Proof 01

1. **Founder:** merge the acceptance PR for ADR-RN-016/018 Amendments C1 (offline scope). Have
   this preparation PR reviewed.
2. **C6-LIVE**, then the run (§8): the entry point PR, then H3, then one run of 22 requests,
   then the evidence review.
3. **By result** (§6): A, record compatibility; B, C, D or E, the smallest corrective review.
   XRPL: a `build_version` other than 3.4.1 means reading `fail_hard` at that release before
   gate E.
4. **In parallel, offline: the durable verification strategy.** An ADR and its review, which gate
   F needs in every branch. Then **C5**, the gate-F record builder, implementing that strategy
   offline against simulated and recorded evidence.
5. **Enabling PRs, each reviewed:**
   - the P9 enabling of live preparation (after A, or after an accepted B amendment);
   - ADR-RN-019 Amendment C1 acceptance;
   - the submit and status entry points.
6. **Gates.** B and C per network (H2 for Sepolia). Then **Sepolia: D-SEP, then E-SEP**, first,
   because it has no expiry and the slowest finality. Then **XRPL: C-XRPL, then D-XRPL and E-XRPL
   in one sitting**. Then **F**, inside the window the accepted verification strategy allows,
   the same day, because XRPL Testnet can be reset.

The critical path is now **C6-LIVE → C6 run → (A or B amendment) → P9 enabling → D-SEP**. In
parallel: **durable verification → C5 → F**.
