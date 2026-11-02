# ADR-RN-018: Read-only transaction preparation

- Status: Accepted for the offline read-only preparation architecture only (founder approval of PR #16 as implemented, RN-NET-03B2-B2 governance closure)
- Date: 2026-11-01
- Amendment C1: **Proposed** (RN-NET-03B2-C1), not accepted. It is the amendment §1 requires before live Sepolia signing; until it is accepted, the Decision below applies unchanged.
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

## Amendment C1 (Proposed): EIP-1898 block-hash pinning and Sepolia provider freshness

- Status: **Proposed** (RN-NET-03B2-C1). It is not accepted. Accepting it would allow the live
  preparation entry point to be **implemented and tested offline** (milestone C3). It would
  authorize no live RPC call: the provider check in P5 and every preparation run need their own
  read-only authorization, with an exact budget.
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
- **So P5 must check it for each provider.** If a provider refuses it, P2 applies and that
  provider refuses preparation. RN-NET then has no working Sepolia pair.
- **The way out is a separate founder decision**, not part of this amendment: allow only
  `eth_estimateGas` by the number P. The estimate binds no field: it is only checked against the
  fixed 30,000 limit and the intrinsic cost.

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
