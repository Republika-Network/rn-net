# ADR-RN-018: Read-only transaction preparation

- Status: Accepted for the offline read-only preparation architecture only (founder approval of PR #16 as implemented, RN-NET-03B2-B2 governance closure)
- Date: 2026-11-01
- Amendment C1: **Accepted for the reviewed offline two-pass Sepolia preparation architecture only** (recorded when the founder merges this documentation change; the implementation is RN-NET-03B2-C3, PR #26, squash-merged as main `1723439`, whose tree `a91fc55` equals the reviewed head `578a4db`). It authorizes no live RPC: the C6 compatibility check (P5) and every preparation run need their own read authorization. Live Sepolia preparation stays `BLOCKED` until C6 records block-hash support on both providers, and its live provisions (P5, P9 enabled) are not accepted.
- Amendment C2: **Proposed** (RN-NET Genesis Proof 01 WP1), not accepted: a fork-aware Sepolia gas policy (see *Amendment C2* below). Until it is accepted, Amendment C1 applies unchanged; C2 authorizes no implementation, no live RPC request and no change to the C6 manifest, evidence or report.
- Amends: [ADR-RN-013](ADR-RN-013-read-only-rpc-architecture.md). It adds read-only methods to the allowlist and changes nothing else in that ADR.
- Builds on: [ADR-RN-016](ADR-RN-016-genesis-anchoring-transactions.md), [ADR-RN-017](ADR-RN-017-offline-signing-toolchain.md), [ADR-RN-014](ADR-RN-014-multi-provider-provenance.md)
- Specification: [rnnet.tx-preparation.v1](../../spec/rnnet.tx-preparation.v1.md)
- Design: [RN-NET-03B2-B signing design](../genesis/rn-net-03b2b-signing-design.md) §6 to §8

## Context

The Genesis templates (ADR-RN-016) leave some fields `null`, to be bound at gate D from
read-only observations:
- **XRPL:** `Account`, `Sequence`, `LastLedgerSequence`, `SigningPubKey`;
- **Sepolia:** `from`/`to`, `nonce`, `maxFeePerGas`.

The founder then approves the resulting `rnnet.unsigned-tx-intent.v1` intent by digest
(ADR-RN-017 §4).

Those values come from public providers, which can be stale, disagree, lag or answer falsely.
Preparation must therefore refuse anything it cannot check, and must not weaken the fee, nonce,
sequence and network controls that ADR-RN-016 fixes.

RN-NET-03B2-B2 implements preparation **offline only**. It runs against injected,
synthetic fixtures. No live provider is contacted, and nothing is signed, funded or broadcast.

## Decision

### 1. Five read-only methods are added to the ADR-RN-013 allowlist

| Network | Added | Request (exact) |
|---|---|---|
| XRPL | `account_info` | `{account, ledger_index: "validated", signer_lists: true, api_version: 2}` |
| Sepolia | `eth_getTransactionCount` | `[from, <latest block number>]`, then `[from, "pending"]` |
| Sepolia | `eth_getBalance` | `[from, <latest block number>]` |
| Sepolia | `eth_getCode` | `[from, <latest block number>]` |
| Sepolia | `eth_estimateGas` | `[{from, to: from, value: "0x0", data: <payload>}, <latest block number>]` |

- **No other method is added.** `server_info`, `eth_chainId` and `eth_getBlockByNumber` were
  already allowed.
- **Methods that stay refused.** `fee`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`,
  `eth_feeHistory` and `eth_call` are not needed, because the fee rules are fixed. Every
  signing, submitting and wallet method stays unexpressible, as before.
- **The allowlist is still one list.** Like the ADR-RN-013 methods, the added methods can be
  built by any caller of `chain-readonly`. `PREPARATION_METHODS` names them so that tests pin the
  addition exactly.
- **`eth_estimateGas` executes a call simulation.** It changes no state. It sends the unsigned
  call to the provider, which is the same public data the transaction will carry.
- **Pinned block number.** Sepolia account reads name the latest block's number, not the
  `latest` tag, so a new block arriving during the run does not change what they describe. This
  is stricter than design §6. It is pinned by number, not hash: after a reorganization at that
  height, the reads could describe a different block from the recorded hash. The pending nonce is
  necessarily read with `pending`.
- **Requirement before live signing: one agreed block hash.** Number pinning is accepted for the
  offline fixtures only. Before any intent prepared from live Sepolia reads may be signed
  (gate D), the following must be reviewed and accepted, as an amendment to this ADR:
  - **Pinning by hash.** Preparation must pin the account reads (`eth_getTransactionCount` latest,
    `eth_getBalance`, `eth_getCode`, `eth_estimateGas`) to a block **hash**, using the EIP-1898
    form `{blockHash, requireCanonical: true}`.
  - **One agreed block.** Every provider's reads must be made at that **same** hash, and every
    provider must return that hash for the block.
  - **Refusal.** A provider that cannot serve the agreed hash is refused; it is never replaced by
    a number or a tag.
  - **Provider support.** Support for this form must be confirmed for each reviewed provider,
    with a separately authorized read-only check.

### 2. Where the code lives

- **`packages/chain-readonly/src/preparation.mjs`: the readers.**
  - They send each provider its exact request list (§3) through the injected transport.
  - They check the shape of every value they keep and refuse anything malformed.
  - They decide nothing about freshness or agreement.
- **`packages/tx-prepare`: everything else.** This new package:
  - checks freshness, consistency, fees, nonce, sequence and balance;
  - binds the template;
  - returns the intent and its digest, via `makeIntent`, which re-runs the ADR-RN-016 checks.
- **Guard rules for `tx-prepare`.**
  - It may import only `chain-readonly`, `tx-intent`, `Buffer` and `createHash`.
  - No package depends on it, and nor does `signer/`.
  - Outside `packages/`, only the B2 fixture generator and its test import it. A test asserts
    that none of them reaches a transport or a network module.
- **No live entry point.** No CLI, and nothing in `tools/live/`, can run preparation.

### 3. Exact requests, one attempt each

- **Request list per provider:**
  - XRPL, 2 requests: `server_info`, then `account_info`;
  - Sepolia, 7 requests: `eth_chainId`, `eth_getBlockByNumber`, `eth_getTransactionCount` ×2,
    `eth_getBalance`, `eth_getCode`, `eth_estimateGas`.
- **Budget.** The budget equals the list, with one attempt per request and no retry. Providers
  are read one after another.
- **Shared limits.** `rpc.call` gained an optional `maxAttempts` that can only lower
  `LIMITS.maxAttempts`. The 256 KiB response limit and the 10 s deadline of ADR-RN-013 apply
  unchanged.
- **Wrong network.** A provider on the wrong network is refused before any account read.

### 4. Refusals

Preparation **fails closed**: any refusal means no intent. Each refusal has one code, checked
in a fixed order (spec §4):

- **Inputs** (`RNTP_INPUT_INVALID`):
  - 2 to 4 providers, distinct by id, URL and operator, all on the requested network. Before
    any live use, providers must also come from `loadEndpointConfig`, which normalizes URLs;
  - XRPL: `account` is the classic address of `signingPubKey`;
  - `now` is integer Unix seconds.
- **Per provider, first while reading.** Each response is checked as it arrives, in request
  order (spec §3), and the first failure stops the run:
  - transport and HTTP failures (`RNTP_PROVIDER_UNAVAILABLE`);
  - RPC errors, `txnNotFound` included (`RNTP_PROVIDER_ERROR`; an unfunded XRPL account is
    `RNTP_ACCOUNT_NOT_FOUND`);
  - strict JSON and shape (`RNTP_MALFORMED`). This includes:
    - duplicate keys;
    - non-canonical hex quantities;
    - XRP amounts that are not whole drops;
    - a fractional or non-integer value where an integer is required;
    - a nonce of 2^64 or more;
  - network identity (`RNTP_WRONG_NETWORK`): XRPL `network_id` must be the integer 1, and the
    Sepolia chain ID must be `0xaa36a7`.
- **Per provider, then on what it reported**, in this order:
  - **XRPL:**
    - `server_state` is `full`, `proposing` or `validating` (`RNTP_NOT_SYNCED`);
    - the validated ledger's `age`, as the provider reports it, is at most 30 s (`RNTP_STALE`).
      This is the provider's claim: `now` is not compared with a ledger close time;
    - `account_info` is from a validated ledger 0 to 2 ledgers after `server_info`'s, with
      the same hash when it is the same ledger, and is for the requested account
      (`RNTP_INCONSISTENT`);
    - no `RegularKey`, no disabled master key, no signer list (`RNTP_ACCOUNT_UNSUITABLE`);
    - the load-scaled fee (`base_fee × load_factor`, exact) is at most the fixed 12 drops
      (`RNTP_FEE_TOO_HIGH`). The run stops; it never raises the fee;
    - the balance is at least reserve + `OwnerCount` × increment + 12 drops
      (`RNTP_INSUFFICIENT_BALANCE`).
  - **Sepolia:**
    - the latest block is at most 60 s before `now`, and less than 15 s after it
      (`RNTP_STALE`);
    - the base fee is at most 19 gwei (`RNTP_FEE_TOO_HIGH`);
    - the pending nonce equals the latest nonce (`RNTP_NONCE_PENDING`);
    - the code is `0x`: no contract and no EIP-7702 delegation (`RNTP_ACCOUNT_UNSUITABLE`);
    - the estimate is at most the 30,000 gas limit (`RNTP_GAS_TOO_HIGH`), and not below the
      intrinsic gas (`RNTP_INCONSISTENT`).
- **Across providers:**
  - XRPL: validated ledgers at most 4 apart, no ledger index reported with two different hashes,
    and equal `Sequence` (`RNTP_INCONSISTENT`);
  - Sepolia: latest blocks at most 4 apart, no block number reported with two different hashes,
    and equal nonce (`RNTP_INCONSISTENT`). Every
    provider's balance must cover 30,000 × `maxFeePerGas` (`RNTP_INSUFFICIENT_BALANCE`).

### 5. Binding

- **XRPL:**
  - `Sequence` is the agreed account `Sequence`;
  - `LastLedgerSequence` is the **lowest** reported validated ledger + 20. A lagging provider
    can shorten the validity window but never lengthen it;
  - `Fee` stays 12 drops;
  - `NetworkID` stays omitted.
- **Sepolia:**
  - `nonce` is the agreed nonce;
  - `maxFeePerGas` is `min(2 × the highest reported base fee + 1 gwei, 20 gwei)`;
  - the tip, gas limit, value, input and chain ID stay as ADR-RN-016 fixes them.
- **The preparation record.** The intent's `preparation` member is an
  `rnnet.tx-preparation.v1` record, covered by the intent digest. It holds:
  - the run's `now`;
  - for each provider: its id and operator, the ledger or block it described, and the SHA-256
    of every request and response.

  So an approval by digest also binds the observations the transaction was built from.

### 6. Evidence

- **Corpus.** `fixtures/preparation-b2/cases.json` holds 78 synthetic cases: 11 accepted and 67
  refused, covering all 15 codes. The expected codes are stated by hand in the generator.
- **What a case holds.** Each case records:
  - the exact request and response text of every exchange;
  - the expected intent and digest, or the refusal code and provider.
- **Two independent reproductions:**
  - `packages/tx-prepare`, run on the recorded exchanges alone;
  - `tools/reference/rnnet_prep_reference.py`, which rebuilds every request, parses every
    response, and reproduces every result without the JavaScript code. It is run in
    `offline-checks.sh`.

## Consequences

- **What this acceptance covers.** It accepts the offline, read-only preparation architecture
  as implemented in PR #16 (`9801b36`). It explicitly preserves the following:
  - **No live RPC.** It authorizes no live RPC call. A live preparation run still needs a
    reviewed live entry point, an exact per-run request budget, and the founder's authorization
    at gate D.
  - **No keys or wallets.** It authorizes no operational wallet, key, key file or account.
  - **Block-hash pinning is mandatory.** Before any intent prepared from live Sepolia data is
    signed, the account reads must be pinned to one agreed block hash on every provider (§1).
    That requires a reviewed amendment to this ADR.
  - **Independent verification is preserved.** Account state and provider agreement are
    checked by the preparation rules (§4) and reproduced independently by
    `tools/reference/rnnet_prep_reference.py`. A prepared intent is approved by digest only after
    that review.
  - **The 1RPC finality lag stays unresolved.** It is carried below.
  - **Agreement is not proof.** Provider agreement is not a consensus proof (ADR-RN-015).
  - **Nothing else is accepted.** It authorizes none of gates B to F, and it does not accept
    ADR-RN-019.

- **What B2 adds:**
  - five allowlisted read-only methods and their readers;
  - `packages/tx-prepare`;
  - the B2 fixtures and Python reference.

  No key, no wallet, no signing, no write method, no transport and no live entry point.
- **Unchanged:**
  - ADR-RN-016's construction and bounds, which `makeIntent` re-checks after binding;
  - the intent format;
  - the signer and the hand-off;
  - every existing vector and fixture.
- **Live use needs separate approvals.** A live preparation run belongs to gate D. It needs:
  - this ADR accepted;
  - a reviewed live entry point;
  - an exact request list and budget per run;
  - the founder's authorization.

  Nothing here authorizes gates B to F.
- **Provider truth is still a claim (ADR-RN-015).** Agreement between two providers is not a
  consensus proof. A colluding or compromised pair could still report a wrong `Sequence` or
  nonce. The consequence is a transaction that fails, not one that moves value, because every
  bound is fixed independently of the providers.
- **Carried, unresolved: the 1RPC finalized-block lag.** SMOKE-02 saw Automata 1RPC's
  `finalized` block lag by about 67 minutes (preflight blocker 7; design §11). This ADR does not
  resolve it, and preparation does not depend on `finalized`. It remains open until a separately
  authorized read-only comparison of both Sepolia providers explains it. Until then, 1RPC's
  finality answers must not be relied on.
- **Thresholds are judgment calls.** The 30 s / 60 s freshness limits and the 4-ledger or
  4-block skew are proposals for the founder's acceptance. A slow provider makes preparation
  refuse, never accept.

## Amendment C1 (Accepted, offline architecture only): EIP-1898 block-hash pinning and Sepolia provider freshness

- Status: **Accepted for the reviewed offline two-pass Sepolia preparation architecture only**
  (RN-NET-03B2-C6-PREP governance closure; the implementation is RN-NET-03B2-C3, PR #26,
  squash-merged as main `1723439`, whose tree `a91fc55` equals the reviewed head `578a4db`;
  independent review PASS WITH NON-BLOCKING FOLLOW-UPS, all fixed and re-checked closed). As
  originally proposed, acceptance covers the preparation entry point **implemented and tested offline**
  (milestone C3). It authorizes no live RPC call: the provider check in P5 and every preparation
  run need their own read-only authorization, with an exact budget. See *What this acceptance
  covers* at the end of this amendment.
- Readiness analysis: [RN-NET-03B2-C operational readiness](../genesis/rn-net-03b2c-operational-readiness.md) §4.

### P1. One agreed block, chosen before any account read

Sepolia preparation runs in two passes over the same two providers, in a fixed order:

1. **Head pass.** On each provider: `eth_chainId`, then `eth_getBlockByNumber(["latest", false])`.
   The §4 freshness and skew rules apply to these blocks unchanged:
   - at most 60 s before `now`, less than 15 s after it;
   - at most 4 blocks apart;
   - no number reported with two hashes.
2. **The pin.** P = (the **lowest** reported latest number) − 2. Two blocks of depth make it
   less likely that P is reorganized away during the run, at a cost of about 24 s of freshness.
3. **Pin pass.** On each provider, `eth_getBlockByNumber([P, false])`. Every provider must return
   the **same** hash H for P (otherwise `RNTP_INCONSISTENT`), and a timestamp at most 90 s
   before `now` (otherwise `RNTP_STALE`).
4. **Pinned reads.** Each provider is read at
   `{"blockHash": H, "requireCanonical": true}`:
   - `eth_getTransactionCount` (latest);
   - `eth_getBalance`;
   - `eth_getCode`;
   - `eth_estimateGas` (see P4).

   The pending nonce stays `[from, "pending"]`: a pending state has no hash. It must still equal
   the pinned nonce on every provider (`RNTP_NONCE_PENDING`). A transaction from the sender that
   is mined after P makes the two differ, so the run refuses rather than binding a stale nonce.

### P2. Refusal, never fallback

- **A provider that cannot serve H is refused.** Any JSON-RPC error on a pinned read is
  `RNTP_PROVIDER_ERROR`. That includes an unsupported block-hash parameter, an unknown block,
  and a block that is no longer canonical.
- **Never replaced.** A pinned read is never retried by number or by tag, and never sent to
  another provider.
- **No new codes.** These refusals use the existing codes (`RNTP_PROVIDER_ERROR`,
  `RNTP_INCONSISTENT`, `RNTP_STALE`), so the refusal list of `rnnet.tx-preparation.v1` does not
  change.

### P3. Request list and budget per provider

| Network | Requests, in order | Count |
|---|---|---|
| XRPL | `server_info`, `account_info` (unchanged) | 2 |
| Sepolia | `eth_chainId`, `eth_getBlockByNumber` (latest), `eth_getBlockByNumber` (P), `eth_getTransactionCount` (H), `eth_getTransactionCount` (pending), `eth_getBalance` (H), `eth_getCode` (H), `eth_estimateGas` (H) | 8 |

- **Totals per run, two providers:** 4 requests on XRPL, 16 on Sepolia.
- **One attempt each, no retry**, with the 10 s deadline and 256 KiB response limit of ADR-RN-013.
- **The head pass completes on both providers before the pin pass starts.**

### P4. `eth_estimateGas` and EIP-1898

- **EIP-1898 does not list `eth_estimateGas`.** It names `eth_getBalance`, `eth_getStorageAt`,
  `eth_getTransactionCount`, `eth_getCode`, `eth_call` and `eth_getProof`. Whether
  `eth_estimateGas` accepts the block-hash object depends on the client behind each provider.
- **Support is not assumed on either provider.** Neither `sepolia-publicnode` nor
  `sepolia-1rpc` is assumed to accept `{blockHash, requireCanonical: true}` for
  `eth_estimateGas`.
  - Support must be verified **separately for each provider**, by the P5 read-only check, and the
    result recorded.
  - Until it is recorded for both providers, C3 must treat the method as possibly unsupported. Its
    tests must show that a refusal ends preparation on that provider (P2).
- **No silent fallback.** The request always carries the block-hash object. Preparation never
  sends `eth_estimateGas`:
  - with `latest` or `pending`;
  - with no block parameter (clients then pick their own default);
  - by number, unless a reviewed amendment allows it.

  An error is a refusal, not a cue to retry another way.
- **If a provider refuses it,** P2 applies and that provider refuses preparation. RN-NET then has
  no working Sepolia pair.
- **Any alternative estimation strategy needs its own focused review.** It is not part of this
  amendment, and it is not a founder decision alone. Examples:
  - by the number P;
  - an `eth_call` at the pinned hash;
  - estimating offline from the intrinsic cost.

  Each needs a written amendment, its own simulated refusal cases and Python reference, and an
  independent review, before the founder can accept it. One fact is relevant to that review: the
  estimate binds no field, because it is only checked against the fixed 30,000 limit and the
  intrinsic cost. That fact does not by itself justify an alternative.

### P5. Provider compatibility check, before C3 is used live

One separately authorized, read-only run (milestone C6), with an exact budget, on
`sepolia-publicnode` and `sepolia-1rpc`. On each provider it checks:

- each pinned method with `{blockHash, requireCanonical: true}` at a recent hash;
- the error each provider returns for an unknown hash;
- whether `eth_estimateGas` accepts the object form;
- the 1RPC `finalized` lag (below).

The run reads **public, synthetic addresses only**. It reads no Genesis key's address, because
none exists before gate B.

### P6. The record format does not change

- **`block` holds the pinned block P.** In the `rnnet.tx-preparation.v1` record, the provider's
  `block` member `{number, hash, timestamp, baseFeePerGas}` now describes P, not the head.
- **The head blocks are still covered.** Their request and response digests stay in `exchanges`,
  like every other request.
- **The fee rule is unchanged** and uses P's `baseFeePerGas`: `maxFeePerGas` = min(2 × the
  highest base fee + 1 gwei, 20 gwei). The newest head can be up to 6 blocks past P (4 of skew
  and 2 of depth). Over 6 full blocks the base fee can rise by up to 1.125^6 ≈ 2.03 times, just
  past the factor of 2. In that extreme case the broadcaster's pre-submit base-fee check
  (ADR-RN-019 §6) refuses before any write (`NOT_SENT`), and a new gate D follows. Nothing is
  sent when the latest base fee is already too high. A rise after the submission can still leave
  the transaction pending (ADR-RN-019 §8).
- **No version bump.** No field or type changes, and every record that exists today is a
  synthetic fixture, so the format identifier stays `rnnet.tx-preparation.v1`.
- **What C3 changes.** The specification text (request list, meaning of `block`) and the B2
  fixtures and Python reference are changed in C3 and reviewed there. This PR changes no code.

### P7. Finality, which preparation does not use

- **Preparation never reads `finalized`.** A reorganization after the run cannot change any
  bound value without being caught: the broadcaster's pre-submit reads (ADR-RN-019 §6) re-check
  the latest and pending nonce, the balance and the base fee.
- **Inclusion is checked at gate F.** It is `PROVIDER_REPORTED_FINALIZED` by the parent-hash
  walk. On Sepolia that is normally two epochs, about 13 minutes or more after inclusion.
- **The 1RPC `finalized` lag stays unresolved** (§ Consequences above). Until P5 explains it, a
  1RPC finality answer alone is not relied on.

### P8. XRPL freshness, unchanged

The XRPL rules stay as in §4:
- the validated ledger `age`, as the provider reports it, is at most 30 s;
- providers are at most 4 ledgers apart;
- the reported ledger hashes agree.

XRPL has no block-hash pinning issue: `account_info` names `validated`, and §4 already requires
it to be 0 to 2 ledgers after `server_info`'s, with the same hash when it is the same ledger. The
only XRPL change is the ADR-RN-016 Amendment C1 offset (+ 80 in place of + 20 in §5).

### P9. The live entry point

- **One named file.** `tools/prepare/prepare-live.mjs` (C3) would be the only file allowed to
  join `packages/tx-prepare` to the network transport. Once this amendment is accepted and that
  file is reviewed, it replaces §2's "no live entry point".
- **What it does:**
  - it takes the providers by id from `config/rpc-endpoints.json`, through `loadEndpointConfig`;
  - its budget is fixed in code as in P3, never set by an argument;
  - it refuses to run without a founder-written read authorization for that one run;
  - it writes the intent and its captures to a new private directory (`0700`, files `0600`,
    `wx`) outside every repository.
- **It cannot sign or submit.** It has no access to a key, `signer/` or `chain-submit`.

### Consequences

- Sepolia preparation costs one more request per provider (8 in place of 7), and binds every
  account read to one block that both providers agree on.
- If a provider cannot serve the block-hash form, preparation refuses on that provider. P4 is
  the likeliest case, and P5 finds out before any key exists.
- The commitment, the payload, the intent format, the record format and the fee, nonce and gas
  bounds are unchanged.

### C3 implementation record (RN-NET-03B2-C3)

At C3 this amendment stayed **Proposed**. RN-NET-03B2-C3 implemented it offline, with live network
access disabled; that record accepted nothing and authorized nothing.
- **P1 to P3.** `packages/tx-prepare` reads Sepolia in three passes (head, pin, pinned) over one
  request budget of 8 per provider.
  - Every pinned read carries `{blockHash, requireCanonical: true}`, and the pending nonce `"pending"`.
  - A pinned read is never sent another way.
  - `tools/prepare/policy.mjs` also refuses, before the transport, any request not in the plan or
    not in its planned form.
- **P2 and P4.** A JSON-RPC error on a pinned read is `RNTP_PROVIDER_ERROR`, with no new code,
  marked `blocked` (`BLOCK_HASH_READ_REFUSED`, or `GAS_ESTIMATION_UNAVAILABLE` for
  `eth_estimateGas`). The entry point reports it as `BLOCKED`.
  - Support is not assumed: `SEPOLIA_COMPATIBILITY` is unrecorded for both providers.
  - While it is unrecorded, Sepolia preparation is `BLOCKED` before any read, until C6 (P5)
    records support.
  - No alternative estimation strategy was built.
- **P6.** The record's `block` is the pin, and the fee is set from its base fee; the format is
  unchanged. Heads are still held to the 19 gwei cap, as before.
- **The entry point.** `tools/prepare/prepare-live.mjs` is specified in
  `spec/rnnet.preparation-authorization.v1.md`, the read-only authorization this amendment's status
  line requires. As a command it refuses with `RNPL_LIVE_DISABLED`.
- **Found by the offline rehearsal.** The time preparation checks freshness against is read after
  the founder's approval, not before it. Otherwise blocks made while the founder reads the prompt
  would be refused as "in the future".

### What this acceptance covers, and what it does not

| Decision | Status | What it allows |
|---|---|---|
| **Acceptance of the offline architecture** (this amendment) | **Accepted**, for the code reviewed in PR #26 as merged | P1 to P4 and P6 to P8 as implemented in `packages/tx-prepare` and `packages/chain-readonly`: the head pass, the pin at the lowest head − 2, the agreed hash, the pinned reads at `{blockHash, requireCanonical: true}`, the pending-nonce equality, refusal never fallback (`BLOCK_HASH_READ_REFUSED`, `GAS_ESTIMATION_UNAVAILABLE`), 8 requests per Sepolia provider, the unchanged record format; the request policy `tools/prepare/policy.mjs`; the disabled entry point and `rnnet.preparation-authorization.v1` as offline code; the B2 v2 fixtures and the Python reference |
| **P5, the C6 provider compatibility run** | **Not authorized** | One read-only run with its own founder read authorization and exact budget (H3) |
| **Recording C6 results in `SEPOLIA_COMPATIBILITY`** | **Not authorized** | A separately reviewed change, after C6, from its evidence |
| **P9 enabled: live preparation** | **Not authorized** | Setting `LIVE_NETWORK_ACCESS`, adding a `PREPARE_TRANSPORT_JOINERS` member and agreeing `AGREED_EVIDENCE_DIR`, each a reviewed change; then each run by its own read authorization (H6) |

- **`eth_estimateGas` support is not accepted as a fact.** P4 stands: it is not assumed on
  either provider, there is no fallback, and any alternative estimation strategy needs its own
  amendment and focused review.
- **Finality trust semantics are unchanged.** Preparation never reads `finalized` (P7); gate F
  keeps the parent-hash walk and stays blocked until a durable verification strategy is
  reviewed and accepted (readiness §4).
- **Still separately authorized, and not authorized by this acceptance.** Each needs its own
  written founder decision, as the readiness analysis §8 and §9 list:
  - **live RPC**: any request to a provider, including the C6 compatibility run (H3) and every
    preparation run (H6), each with its own read authorization and exact budget;
  - **operational key generation** (gate B, H4);
  - **funding** (gate C, H5);
  - **operational signing** (gate D, H7);
  - **broadcasting** (gate E, H8 and H9);
  - **public evidence publication** (gate F, H10).
- **Not covered:** ADR-RN-019 Amendment C1 (live entry points) stays **Proposed**.

## Amendment C2 (Proposed): fork-aware Sepolia gas policy

- Status: **Proposed** (RN-NET Genesis Proof 01 WP1). **Not accepted.** While it is Proposed:
  - Amendment C1 applies unchanged, and so does P4's bar on any alternative estimation strategy;
  - it authorizes no implementation, no live RPC request, no new read authorization (H3 or H6),
    and no change to `LIVE_NETWORK_ACCESS`, `AGREED_EVIDENCE_DIR` or `SEPOLIA_COMPATIBILITY`;
  - it makes no change to the C6 manifest, evidence or report.
- Acceptance needs three things, in order (P4):
  - an independent review of this text;
  - an implementation PR with simulated refusal cases and an independent Python reference;
  - the founder's acceptance.
- Basis:
  - the C6-H3 run, authorization `c6-h3-20261104-032110-0aa58aaa`, report SHA-256
    `036542204dc7beefd08b9a2ced888c72ee778d90c143b104fc1e61907dedc701`, replayed by the Python
    reference with 16/16 agreeing;
  - the founder's private WP0 research memo, whose sources are pinned in G2. The raw C6 evidence
    stays private, and nothing from it is reproduced here beyond the sanitized facts in G9.

### G0. Why an amendment is needed

C6-H3 ended **BLOCKED, branch B**: PublicNode's pinned `eth_estimateGas` (S10) was classified
BLOCKED. The provider did not refuse the request. It answered with a QUANTITY of **14,847**. The
reviewed classifier requires at least **22,680**, which is the EIP-7623 floor for the 42-byte
payload **under Prague rules**.

Every block C6 captured is after Sepolia's Amsterdam (Glamsterdam) activation (G1). Under the
Amsterdam rules the same transaction needs **14,688** (G4). The standard estimator reports a
limit at most 1.5 % above the need, and its exact search reproduces **14,847** from 14,688
(G8).

The 22,680 minimum was therefore **outdated for the observed blocks**. RN-NET's preparation code
has the same Prague-only bound in two places:
- `packages/tx-prepare/src/prepare.mjs`: `estimate < intrinsic`;
- `packages/tx-intent/src/genesis.mjs`: `intrinsicGas`.

So preparation would refuse a correct estimate too.

This amendment replaces the single, fork-blind bound with a reviewed, fork-aware policy. It keeps
every protection of Amendment C1:
- pinned block-hash reads, `requireCanonical: true` and one agreed pin;
- chain identity and provider agreement;
- refusal without fallback;
- the fixed 30,000 gas limit;
- the live estimate, as a cross-check.

### G1. Supported Sepolia forks and activation timestamps

Activation is by **block timestamp** (execution layer), from the Sepolia chain configuration in G2.

| Rule set | Sepolia activation (`…Time`, unix s, UTC) | CL epoch | Gas rules for this transaction |
|---|---|---|---|
| — (pre-Prague) | before 1741159776 | — | **unsupported: refused** |
| `prague` | `pragueTime` 1741159776 (2025-03-05 07:29:36) | Electra 222464 | EIP-2028 calldata, EIP-7623 floor |
| `prague` (unchanged) | `osakaTime` 1760427360 (2025-10-14 07:36:00); `bpo1Time` 1761017184; `bpo2Time` 1761607008 | Fulu 272640; 274176; 275712 | Osaka and the two blob-parameter-only forks change nothing for this transaction. EIP-7825's 2^24 cap does not bind at 30,000 |
| `amsterdam` | `amsterdamTime` **1791294816** (2026-10-06 13:53:36) | Gloas 353024 | EIP-2780 base, EIP-7976 floor (G3) |
| — (later) | any activation after `amsterdamTime`, or any time at or after `REVIEWED_RULES_HORIZON` | — | **unreviewed: refused** |

- The selector is `rules(t)`: the last rule set whose activation is ≤ `t`. It is a pure function
  of a reviewed table and a timestamp.
- **A JSON-RPC response never selects a rule set.** Header fields (for example
  `blockAccessListHash`, `slotNumber`) may only *refuse*, as a secondary consistency check (G5,
  R7). They never prove a fork.
- **Scheduled is not the same as activated.** EIP-7773 lists Glamsterdam's EIPs as "Scheduled for
  Inclusion". EIP-2780, EIP-7976, EIP-8037 and EIP-7778 are still Last Call. The rules in force
  are those **implemented by the client releases at the activation**. G2 pins two independent
  implementations, which agree.

### G2. Reviewed, version-pinned primary sources

| Source | Pinned at | Used for | SHA-256 of the file as fetched |
|---|---|---|---|
| `eth-clients/sepolia` `metadata/genesis.json` | commit `7b1b9d9549787b6bbf538f943304c4cf84f7e39e` | `pragueTime` … `amsterdamTime`; no later fork configured | `d558a75ef48e6fdb224b063c84c309de8a55995e263db63515b79ad4432a37df` |
| `ethereum/execution-specs` `src/ethereum/forks/amsterdam/vm/gas.py` | commit `16898000911c1e3caa57be08509536c10ae92d3e` (branch `forks/amsterdam`) | `TX_BASE` 12000, `TX_VALUE_COST` 6000, `COLD_ACCOUNT_ACCESS` 3000, `TX_DATA_TOKEN_STANDARD` 4, `TX_DATA_TOKEN_FLOOR` 16 | `67973191c49234387186ad17316c556adab73723f782e95104dd3a949132367c` |
| `ethereum/execution-specs` `src/ethereum/forks/amsterdam/transactions.py` | same commit | `calculate_intrinsic_cost`: self-transfer skips the recipient and value charges; `floor_tokens_in_calldata = len(data) × 4`; floor base = `TX_BASE` + recipient charge | `846e1b579e133ab2e282ca19e85903b2b7a969d47b0b8511cf70c938e38d7188` |
| go-ethereum `params/protocol_params.go` | tag `v1.17.7` = commit `3d858f858a458effb2a563788aedf1fe65e1f0d3` (release notes: "ready for the Amsterdam fork on Sepolia") | `TxBaseCost2780` 12000, `TxValueCost2780` 6000, `TxCostFloorPerToken7976` 16, `TxTokenPerNonZeroByte` 4, `TxDataNonZeroGasEIP2028` 16, `TxDataZeroGas` 4, `TxCostFloorPerToken` 10 | `94657cdf80d2f0b136ff6d89003326f496d3b1ba1abcb1a855b7b98c941e9e28` |
| go-ethereum `core/state_transition.go` | same commit | `intrinsicBaseGasEIP2780`, `FloorDataGas` (Amsterdam floor base = the EIP-2780 base), `settleGas` | `72e7a68d1f180069920dd5db624fe8fbc7f4cb96f4491d3478239a91ae3d170d` |
| go-ethereum `eth/gasestimator/gasestimator.go` and `internal/ethapi/api.go` | same commit | estimator search; `estimateGasErrorRatio = 0.015` | `5b2949f6c16abf05cf5ad5a1ecd985c0adc693530c11b9b6e0221aefa70fcf68`, `df5d20455fe37005d4b953a448a019f5ba0ec7aaee258060c7ed28d142743990` |
| EIPs 2028, 7623, 2780, 7976, 8037, 8038, 7981, 7778, 7708, 7773 (eips.ethereum.org) | text read 2026-11-03 | the rationale and the mapping of each rule to its EIP | not pinned: these are living documents. The implementations above are normative for RN-NET |

**The implementation must fail closed on its sources.** The reviewed constants are written into
the code and into the Python reference **independently**. A test checks both against the values
in this table. Any later change to the sources needs a new review: a new client release, a Last
Call edit, or a new fork in the chain configuration.

### G3. Deterministic gas computation

Let `d` be the transaction data. `z` is its count of zero bytes and `n = len(d) − z`.

**`prague`** (EIP-2028, EIP-7623):
- `standard = 21000 + 4·z + 16·n`
- `floor = 21000 + 10·(z + 4·n)`
- `intrinsic = standard`

**`amsterdam`** (EIP-2780, EIP-7976; EIP-7623 mechanism):
- `base = TX_BASE (12000) + recipient + value`
  - `recipient`: 0 for a self-transfer, otherwise 3000 (12000 for a creation, refused anyway);
  - `value`: 6000 only if the value is non-zero and the transaction is not a self-transfer.
  - For the Genesis transaction, `base = 12000`.
- `standard = base + 4·z + 16·n` (calldata metering unchanged)
- `floor = base + 16·(4·len(d))` (EIP-7976: every byte is 4 floor tokens)
- `intrinsic = standard` (access-list and authorization terms are 0 by precondition)

**Applicable runtime and state gas** (all rule sets):
- `runtime = 0`, `state = 0` and `refund = 0` **only under the preconditions of G4**:
  - no code runs;
  - no account or storage is created;
  - EIP-8037 state gas is not triggered;
  - EIP-8038 has no runtime access;
  - EIP-7708 emits no log, because the value is zero and it is a self-transfer.
- The calculation **never estimates a non-zero runtime, state or refund term**. If the
  preconditions do not hold, it refuses (G5). It never computes a larger number instead.

**Need:** `need_R = max(intrinsic + runtime + state − refund, floor)`, which reduces to
`max(standard, floor)` under G4.

### G4. Transaction shape and state preconditions

The calculation is valid only when **all** of the following hold. Each is already enforced or
read today:
1. **Shape** (`checkSepoliaAnchorTx`, ADR-RN-016):
   - type `0x2`; chain id `0xaa36a7`;
   - `to == from` (self-send; never `null`); `value == 0x0`;
   - `accessList == []`; no `authorizationList`, no blob fields;
   - `input` exactly the 42-byte payload of the Genesis commitment;
   - `gas == 30000`.
2. **No code at the sender:** `eth_getCode(from, {blockHash: H, requireCanonical: true})` returns
   `"0x"` on **every** provider. Any other value refuses (`RNTP_ACCOUNT_UNSUITABLE`), including
   an EIP-7702 delegation `0xef0100…`.
3. **No delegation before inclusion.** The signer produces only EIP-1559 type-2 signatures, and
   no EIP-7702 authorization path exists. The sender's code cannot change between H and
   inclusion without the key.

**Values for the Genesis Proof 01 payload:** `RNNETANC` ‖ `01` ‖ `01` ‖ 32-byte digest, with 0
zero bytes and 42 non-zero bytes.

| Rule set | standard | floor | need_R | Margin to 30,000 |
|---|---|---|---|---|
| `prague` (Prague, Osaka, BPO1–2) | 21,000 + 672 = 21,672 | 21,000 + 10·168 = 22,680 | **22,680** | 7,320 |
| `amsterdam` | 12,000 + 672 = 12,672 | 12,000 + 16·168 = 14,688 | **14,688** | 15,312 |

**A naive combination is wrong.** Using EIP-7976's own text with a 21,000 base would give
23,688. Both implementations, and EIP-2780's text, use the EIP-2780 base for the floor.

**Over all v1 payloads:** the Amsterdam floor is 14,688 for any digest. The Prague value ranges
from 21,720 to 22,680. The value is always computed from the bytes, never hard-coded.

### G5. Refusals (fail closed)

Each is a refusal before any intent is written. It uses an existing code unless review adds one
(P2, "no new codes"):
- **R1. Unsupported fork.** `rules(P.timestamp)` is pre-Prague → `RNTP_INCONSISTENT`.
- **R2. Unreviewed horizon.** `P.timestamp` or `now` is at or after `REVIEWED_RULES_HORIZON` →
  refused. The horizon is a reviewed constant, set at implementation review no later than the
  earliest of:
  - any next Sepolia activation in the pinned chain configuration;
  - the start of any client release that changes a G2 constant;
  - a fixed date that the review chooses (open question Q1).
- **R3. Fork boundary.** Any activation `A` in the table with
  `P.timestamp − BOUNDARY_BEFORE ≤ A ≤ now + BOUNDARY_AFTER` is refused.
  - The point: the pin, the run and the expected inclusion must all fall under one rule set.
  - Proposed values: `BOUNDARY_BEFORE` = 3,600 s, `BOUNDARY_AFTER` = 86,400 s (Q2).
  - **One rule set per run:** `rules(P.timestamp)` must equal `rules(now)`.
- **R4. Shape.** Any G4.1 violation → the existing `checkSepoliaAnchorTx` problems.
- **R5. Ambiguous execution state.**
  - Code ≠ `"0x"` on any provider, or a disagreement between providers → `RNTP_ACCOUNT_UNSUITABLE`
    or `RNTP_INCONSISTENT`.
  - A missing code read → that provider is refused (P2).
- **R6. Limit.** `need_R > 30000` → `RNTP_GAS_TOO_HIGH`.
- **R7. Header consistency** (secondary; refuse-only). The pinned header's field set is not the
  set reviewed for `rules(P.timestamp)` → `RNTP_INCONSISTENT`. It never selects or proves a rule
  set.
- **R8. Estimate inconsistency** (G8).

### G6. At and near a fork boundary

- **Inside the boundary window (R3), preparation refuses.** The founder waits and runs a new
  gate D with a new read authorization. There is no retry inside a run.
- **If a broadcast is pending across a boundary** (Sepolia has no expiry):
  - The **gas limit is fixed and not derived from need_R**. A later rule set with a lower need
    changes nothing but the gas charged.
  - A later rule set whose need exceeds 30,000 would make the transaction **invalid**: it is not
    included and no fee is charged. That is fail-safe.
  - The receipt check (G10) evaluates the rule set **at the inclusion block's timestamp**.
- **Pre-submit.** The broadcaster's pre-submit reads (ADR-RN-019 §6) must also refuse when
  `rules(head.timestamp) ≠` the intent's recorded rule set. This needs ADR-RN-019 Amendment C1 or
  a later amendment; it is a requirement, not a change made here.

### G7. The gas limit

- `gas` stays **30,000**, bound in the intent and signed. The balance rule stays
  `balance ≥ 30,000 × maxFeePerGas` (P6).
- need_R and the estimate are **checks only**. Neither sets a field.
- `checkSepoliaAnchorTx`'s lower bound becomes `need_R` for the recorded rule set, in place of
  the Prague value.

### G8. Comparison with the pinned `eth_estimateGas`

The live estimate is **retained** as a runtime cross-check. It is not replaced: removing it would
remove the only live signal that the provider's rules differ from RN-NET's reviewed model.

- **Request:** unchanged (P1, P4): `[{from, to: from, value: "0x0", data}, {blockHash: H,
  requireCanonical: true}]`, on every provider, one attempt, never with `latest`, `pending`, a
  number or no block parameter.
- **Accept** iff `need_R(P.timestamp) ≤ est ≤ 30000`.
- **Refuse:**
  - `est < need_R`: the provider's rules or answer differ from the reviewed model →
    `RNTP_INCONSISTENT`;
  - `est > 30000` → `RNTP_GAS_TOO_HIGH`;
  - a JSON-RPC error → P2.
- **No upper tolerance relative to need_R.** An estimate is an upper bound by design. The standard
  estimators stop within 1.5 % (`estimateGasErrorRatio = 0.015`), and the search differs between
  clients. Equality with need_R is never required.
  - Worked reproduction, go-ethereum v1.17.7 search with need 14,688:
    - optimistic limit `(14,688 + 2,300)·64/63 = 17,257`;
    - midpoints 15,972 → 15,329 → 15,008 → 14,847;
    - stop at `(14,847 − 14,687)/14,847 = 1.08 % < 1.5 %`;
    - **14,847**.
  - Under Prague the same search gives 23,016.
- **What an estimate does not prove.** A numerically correct estimate **does not show that the
  provider honored the block-hash parameter**. For a code-less, history-less account, the
  estimate is the same at H, at `latest`, or with the parameter ignored. Block-hash compliance is
  a separate requirement (G9).

### G9. Block-hash semantics, provider agreement, and C6 classification

**Unchanged from C1:**
- one agreed pin H across providers;
- every pinned read at `{blockHash: H, requireCanonical: true}`;
- the pending-nonce equality;
- refusal without fallback;
- both reviewed providers required.

**Six separate questions.** They are recorded separately, and none implies another:

| Question | Evidence that answers it | Recorded as |
|---|---|---|
| **Gas value correct** | `need_R(pin) ≤ est ≤ 30000` under G1–G4 | PASS / BLOCKED (out of range under the *correct* rule set) / UNRESOLVED (no answer, busy, not sent) |
| **Block-hash form accepted** | the pinned request answered with a result of the right type, no JSON-RPC refusal | as `eip1898AccountReads` today, and for the estimate as `estimateGasBlockHash` (meaning narrowed to the form plus G8) |
| **Pinned-block compliance** (state served at H; `requireCanonical` enforced) | only a reviewed test whose expected answer differs between H and other blocks; an unknown-hash refusal is supporting evidence only | a new field, `blockHashSemantics`: **`null` (UNRESOLVED) unless demonstrated**. No C6 result so far demonstrates it |
| **Provider agreement** | head and pin agreement, one hash per number (C1) | PASS / BLOCKED / UNRESOLVED, unchanged |
| **Unknown or unavailable** | no answer, HTTP error without JSON-RPC error, busy codes, not sent | UNRESOLVED, never PASS and never BLOCKED |
| **Provider incompatibility** | a JSON-RPC refusal of a pinned form, an answered unknown hash, a wrong chain, a malformed block, or an estimate out of range under the correct rule set | BLOCKED (branch E for account reads, as today) |

**Prospective, fork-aware C6 classification.** A future C6 run's `estimate_gas` range is
`[need_R(rules(pin.timestamp)), 30000]`.
- The classifier and its Python reference are **versioned**. The version that produced C6-H3
  stays frozen, so that the historical report is still rebuilt byte for byte (16/16 AGREES).
- The new version names its rule set in the check detail.
- The manifest is unchanged: S10/S14 expect "QUANTITY from the intrinsic gas to 30,000", which
  carries no number.

**The C6-H3 report stays BLOCKED B.**
- It is the immutable output of the reviewed classifier over the recorded exchanges, and it
  correctly reports what that classifier decided.
- This amendment does not re-classify it.
- The reading recorded here is that the BLOCKED estimate check was caused by a **stale
  pre-Amsterdam lower bound in RN-NET's classifier**. It is not evidence of provider
  incompatibility.
- It is also not a PASS of pinned-block compliance, which stays UNRESOLVED.
- Any future `SEPOLIA_COMPATIBILITY` record is a separate reviewed change. It must not record
  PublicNode `estimateGasBlockHash: false` from C6-H3.

**Whether preparation must require `blockHashSemantics: true` is open (Q3).** Requiring it
blocks Sepolia until a test design exists that can demonstrate it. Without it, account-read
correctness rests on the C1 controls:
- agreement on H across two providers;
- unknown-hash refusal;
- the broadcaster's pre-submit re-reads (ADR-RN-019 §6).

### G10. Receipt `gasUsed` verification after inclusion

At the status check or gate F (ADR-RN-019 Amendment C1, or the durable-verification ADR, which
is to be specified there):
- Let `R_i = rules(inclusion block timestamp)`. If `R_i` ≠ the intent's recorded rule set, report
  `GAS_RULES_CROSSED`. This is an anomaly in the record, not a failure of inclusion.
- **Expected:** `gasUsed = max(intrinsic_Ri + runtime + state − refund, floor_Ri)`, with
  `runtime`, `state` and `refund` each **0** under G4.
  - Under Amsterdam, EIP-7778 changes only block-level accounting: with no refund, transaction
    and block gas are equal.
  - EIP-8037 state gas is part of the transaction's gas used, and is 0 here.
- **Check:** `receipt.gasUsed == need_Ri` (14,688 under `amsterdam`; 22,680 under `prague`).
  - A mismatch is reported as `GAS_ACCOUNTING_MISMATCH`, together with the observed value.
  - It is **never** silently accepted, and it is never "explained" by assuming a non-zero runtime,
    state or refund term.
  - Funds at risk are already bounded by `30,000 × maxFeePerGas`.
- The receipt is read under the existing finality rules (P7, ADR-RN-015). This adds no new trust
  in a provider.

### G11. 1RPC remains an independent blocker

**Observed in C6-H3:**
- S06 (`eth_getBlockByNumber [P, false]` on `sepolia-1rpc`) received **HTTP 404** with an HTML
  body and no JSON-RPC envelope.
- Under the C6 matrix, an HTTP error without a JSON-RPC error is UNRESOLVED, so
  `sepolia.pin_agreement` is **UNRESOLVED**.
- S11–S14 (1RPC's nonce, balance, code and estimate at its own pin hash) each depend on that
  hash, so they were **not sent** (`NOT_SENT`, "no pinned block on this provider").
- 1RPC answered its other request forms in the same run.

**Consequences:**
- 1RPC's `eip1898AccountReads`, its estimate form and its `blockHashSemantics` are **UNRESOLVED**.
- Preparation requires both reviewed providers, and runs the same numbered pin read.
- **Accepting this amendment does not unblock Sepolia.**

**Options**, each a separate, reviewed decision; WP1 performs no live investigation:
- **O1. Repeat the reviewed manifest.** Run the same immutable 22-request manifest once, under a
  **new** H3. It needs a new activation and deactivation cycle, and the fork-aware classifier
  version first, so that PublicNode's estimate is not BLOCKED again.
- **O2. A narrower diagnostic manifest** for 1RPC only: the pin, then the four pinned reads. It
  is a new reviewed manifest, digest and budget, with its own H3.
- **O3. Replace or add a provider**, through an ADR-RN-013/014 provider review and a config PR.
  The two-provider agreement rule is never relaxed to one provider.
- **O4. A desk review** of 1RPC's published documentation and limits, without any request. It is
  evidence for choosing among O1–O3, not a substitute for them.

### G12. Traceability

| Requirement | Section | Future implementation component | Test (simulated, with Python reference) | Security invariant |
|---|---|---|---|---|
| Fork selected from reviewed timestamps only | G1, G2 | `packages/tx-intent` gas-rules table; `rnnet_prep_reference.py` twin | activation −1 / 0 / +1 s; pre-Prague refused; constants equal the G2 table | No RPC field selects a rule set |
| Deterministic need_R | G3, G4 | `intrinsicGas(data, ruleSet)` | vectors 22,680 / 14,688; random digests: JS = Python; the Amsterdam floor is independent of the digest | Same bytes, same rule set, same need |
| Preconditions | G4 | `checkSepoliaAnchorTx`, `prepareSepoliaIntent` | 7702 prefix, code disagreement, access list, value, `to ≠ from`, wrong input | No execution, so no runtime gas |
| Unreviewed fork refused | G5 R2, R7 | horizon constant; header check | horizon −1 / 0; added or removed header field | Fail closed on the unknown |
| Boundary | G5 R3, G6 | window check; pre-submit rule check (ADR-RN-019) | activation inside and outside the window; `rules(pin) ≠ rules(now)` | One rule set from pin to inclusion |
| Gas limit | G7 | `SEPOLIA.gasLimit` unchanged | need_R > 30,000 with a synthetic rule set | The signed limit never comes from a provider |
| Estimate cross-check | G8 | `prepare.mjs` estimate check | est = need_R − 1, need_R, 30,000, 30,001; reproduction of 14,847 | Live disagreement with the model refuses |
| Separate block-hash semantics | G9 | `SEPOLIA_COMPATIBILITY` field; classifier | estimate in range with semantics `null` stays UNRESOLVED | A number never proves pinning |
| Classifier versioning | G9 | `tools/compat/classify.mjs` v2; frozen v1; `rnnet_compat_reference.py` | C6-H3 replay with v1 rebuilds the report (16/16); v2 gives PublicNode's estimate in range | History is immutable |
| Receipt check | G10 | status / gate-F verifier | gasUsed = need, ≠ need, rules crossed | Mismatch reported, never explained away |
| 1RPC independent | G11 | none in C2 | compatibility with 1RPC `null` stays BLOCKED | Two providers, no relaxation |

### G13. Assumptions and open questions

- **A1.** The rules in force on Sepolia are those of the pinned client releases. If an EIP still
  in Last Call changes before mainnet, Sepolia only follows through new releases and a chain
  configuration change. That is caught by R2 and needs a new review.
- **A2.** PublicNode's client is not identified. Nothing here depends on it.
- **A3.** The G4 preconditions hold at inclusion by G4.3, and are re-read by the pre-submit check.
- **Q1.** The value and governance of `REVIEWED_RULES_HORIZON`.
- **Q2.** `BOUNDARY_BEFORE` and `BOUNDARY_AFTER`.
- **Q3.** Whether preparation requires `blockHashSemantics: true`, and whether any reviewed C6
  design can show it.
- **Q4.** Whether the preparation record carries the rule set and need_R in
  `rnnet.tx-preparation.v1` (P6 reasoning: only synthetic records exist) or in a v2.
- **Q5.** Where the receipt check lives: ADR-RN-019 Amendment C1, or the durable-verification ADR.

### What this amendment would change, once accepted, and what it does not

- **Would allow** (implementation PRs, each reviewed):
  - the fork-aware gas module and its Python twin;
  - the fork-aware bounds in preparation, in `checkSepoliaAnchorTx` and in a versioned C6
    classifier;
  - the record of the rule set and need_R;
  - the receipt check.
- **Does not change:**
  - the C6 manifest (`2a45e37c…088037`), its evidence or its report;
  - `config/rpc-endpoints.json` and the reviewed providers;
  - the request forms and P4's no-fallback rules;
  - the 30,000 limit, the fee caps and the balance rule;
  - finality (P7);
  - any live switch.
- **Still separately authorized:** every live RPC request (H3, H6) and gates B–F, as in the
  acceptance of Amendment C1.
