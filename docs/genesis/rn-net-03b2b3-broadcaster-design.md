# RN-NET-03B2-B3: keyless broadcaster design and implementation plan

- Status: **Proposal** for founder review. The decisions go into
  [ADR-RN-019](../adr/ADR-RN-019-controlled-testnet-broadcasting.md) (Proposed). Nothing here is
  implemented.
- Builds on:
  - [ADR-RN-016](../adr/ADR-RN-016-genesis-anchoring-transactions.md) and the
    [authorization gates](genesis-proof-01-authorization.md);
  - [ADR-RN-017](../adr/ADR-RN-017-offline-signing-toolchain.md) (signing toolchain);
  - [ADR-RN-018](../adr/ADR-RN-018-transaction-preparation-reads.md) (preparation);
  - the [signing design](rn-net-03b2b-signing-design.md) §5 and §8.

**Gate A only.** This document creates no key, wallet or account. It funds, signs and
broadcasts nothing, makes no RPC call, and implements no write method.

## 1. Flow

```
gate D (founder, offline)                gate E (keyless process)                 read-only, later
intent ──approve by digest──► signer ──► signed blob ──► submit-anchor ──► 1 write ──► verify-live-anchor
                                              │            │  ▲                              (both providers)
                                              │            │  └ broadcast authorization (founder, one attempt)
                                              │            ├ re-verify: intent, decode, fields, signature, hashes
                                              │            ├ run JS + Python verifiers itself
                                              │            ├ pre-submit reads (both providers, budgeted)
                                              │            └ append-only log: RUN_STARTED, ATTEMPTING, RESULT (wx)
                                              └ never read by the broadcaster: key, key file, passphrase
```

## 2. The XRPL Testnet submit path

1. **Inputs, verification and authorization.** ADR-RN-019 §2, §3 and §5. The Ed25519 check uses
   Node's built-in `verify`.
2. **Pre-submit reads** from `xrpl-testnet-ripple` and `xrpl-testnet-xrpl-labs`. One attempt each,
   6 requests in all:
   - **`server_info`:** `network_id` = 1; the validated ledger, which must be at most
     `LastLedgerSequence` − 4;
   - **`account_info`** (validated): `Sequence` equals the transaction's;
   - **`tx`** (expected hash): `txnNotFound`.
3. **The write.** One `submit`, `{tx_blob, fail_hard: true}`, to the authorized provider only:
   - 10 s deadline, 256 KiB response limit, one attempt.
4. **Classification** (ADR-RN-019 §6):
   - `ACCEPTED_PROVISIONAL` only when all of these hold:
     - `engine_result` is `tesSUCCESS` or `terQUEUED`;
     - `accepted: true`;
     - `broadcast: true` or `queued: true`, with `queued` exactly when the result is
       `terQUEUED`;
     - `tx_json.hash` is the expected hash;
     - `tx_blob` echoes the sent blob.
   - `tec*` is `UNCERTAIN` under `fail_hard` until the rippled source check (§9 step 1).
   - Anything unexpected is `UNCERTAIN`.
5. **The record.** An `rnnet.submission-record.v1` and the private capture are written. The run
   ends; it does not poll.
6. **Verification.** A separately authorized read-only run of `verify-live-anchor` on both
   providers (§7).

## 3. The Ethereum Sepolia `eth_sendRawTransaction` path

1. **Inputs, verification and authorization.** ADR-RN-019 §2, §3 and §5. Keccak-256 and
   secp256k1 recovery come from `txverify/` (pinned noble, verification only).
2. **Pre-submit reads** from `sepolia-publicnode` and `sepolia-1rpc`. One attempt each, 12
   requests in all:
   - **`eth_chainId`:** `0xaa36a7`;
   - **`eth_getBlockByNumber`** (`latest`): base fee ≤ `maxFeePerGas` − 1 gwei;
   - **`eth_getTransactionCount`**, latest and pending: both equal the transaction's nonce;
   - **`eth_getTransactionByHash`:** `null`;
   - **`eth_getBalance`:** at least 30,000 × `maxFeePerGas`.
3. **The write.** One `eth_sendRawTransaction`, to the authorized provider only, with the same
   limits.
4. **Classification.**
   - `ACCEPTED_PROVISIONAL` only when `result` equals the recomputed Keccak-256 transaction hash.
   - Any JSON-RPC `error` is `UNCERTAIN`. Error text is recorded but never interpreted.
5. **The record**, as for XRPL.
6. **Verification.** Separately authorized read-only verification, by the finality walk on both
   providers (§7).

## 4. Budgets, timeouts and failures

| Step | Requests per run | Attempts | Deadline | On failure |
|---|---|---|---|---|
| XRPL pre-submit reads | 6 (3 per provider) | 1 each | 10 s each | `NOT_SENT`, stop |
| Sepolia pre-submit reads | 12 (6 per provider) | 1 each | 10 s each | `NOT_SENT`, stop |
| Write | **1**, to the authorized provider | **1** | 10 s | `NOT_SENT` only if the harness refused before calling the transport, or the transport returned `RNLO_BLOCKED_ADDRESS`. Every other failure, `RNLO_CONNECTION` included, is `UNCERTAIN`: stop |
| Post-submit verification | Its own authorized run (ADR-RN-013 limits; at most 262 calls per Sepolia provider) | as ADR-RN-013 | 10 s each | Report; never triggers a write |

- **Whole-run limits.** The harness counts every request and refuses one over budget. A run that
  hits a limit ends with that code.
- **No fallbacks.** There is no fallback provider, no retry, and no polling loop.
- **The transport.** The write uses the same transport as the reads
  (`tools/live/https-transport.mjs`):
  - HTTPS only, with verified certificates;
  - no redirects;
  - public-address check at connection time, and a response-size limit.

## 5. Replay protection

| Risk | Control |
|---|---|
| The same authorization is used twice | `RUN_STARTED` (`wx`) is the first action of every run, including a `NOT_SENT` run and a dry run. An authorization therefore works for one run only (ADR-RN-019 §5) |
| A second blob for the same `Sequence` or nonce | The append-only log is keyed on (network, sender, `Sequence` or nonce). A later attempt needs an authorization that links to the latest `RESULT` or `RESOLVED` entry, and is either the same blob or a gate-D replacement named in the authorization. Once a `RESOLVED` entry records inclusion, nothing more is sent. The B1 sign log refuses a second intent at signing |
| A crash after sending | An `ATTEMPTING` entry with no `RESULT` refuses every run for that sequence. The founder runs a read-only status check, which writes a `RESOLVED` entry, then writes a new authorization linking to it |
| A resubmit or replacement after a rejection | Allowed only through the linked chain above, never by deleting or editing log entries |
| Fee bump or replacement by the broadcaster | Impossible: it cannot build or sign. A replacement is a new gate-D intent (same nonce on Sepolia) |
| Cross-chain, Sepolia | The chain ID is in the signed payload, and `0xaa36a7` is re-checked from the bytes and from two providers |
| Cross-network, XRPL | Testnet omits `NetworkID`. Mitigated: a fresh key never funded on Mainnet, a 20-ledger expiry, and only Testnet endpoints. **Residual:** anyone can relay a public blob to Mainnet (signing design §8) |
| A provider not on the list | Selected by id from `config/rpc-endpoints.json` only. The URL is never an input |

## 6. Expected testnet operating costs

| Item | XRPL Testnet | Sepolia |
|---|---|---|
| Transaction fee | 12 drops = 0.000012 XRP (cap 1,000 drops) | Expected 22,680 gas × (base fee + 1 gwei). At a 1 gwei base fee: ≈ 0.000045 ETH |
| Worst case | 12 drops; the fee is fixed in the signed bytes. A load-scaled fee above 12 stops **preparation** (ADR-RN-018). At broadcast, a fee rise shows up as `telINSUF_FEE_P` (`REJECTED`), and the fee is never raised | 30,000 × 20 gwei = **0.0006 ETH**, which cannot be exceeded |
| Locked | 1 XRP base reserve while the account exists (`AccountSet` adds no owner reserve) | none |
| Funding (gate C) | One faucet grant, which covers reserve + fee many times over | 0.01 Sepolia ETH proposed (over 16 × the worst case) |
| Provider cost | None: public keyless endpoints | None: public keyless endpoints |
| Real-money cost | **Zero.** Testnet assets have no value. Testnet can be reset | **Zero.** Sepolia ETH has no value |

A failed or expired XRPL transaction costs nothing (`tel`/`tem`/`tef` claim no fee). Whether a
`tec*` can be applied, claiming 12 drops, under `fail_hard` is checked against the rippled
source in §9 step 1. A Sepolia self-send to an account with no code cannot revert. An included
transaction therefore uses exactly 22,680 gas: the EIP-7623 calldata floor, since all 42
payload bytes are non-zero.

## 7. Finality and independent verification plan

1. **Immediately after the run.** Nothing. The outcome is provisional at best.
2. **XRPL verification run.** At least ~10 s after submission (about 3 ledgers). One run of
   `verify-live-anchor --network xrpl:testnet --compare-providers` with captures:
   - **PASS:** both providers report `PROVIDER_REPORTED_VALIDATED` and `tesSUCCESS`, with the
     anchor memo matching the commitment.
   - **Expired.** Recorded only when both providers show two things (ADR-RN-019 §8):
     - a ledger-ranged `tx` lookup returning `txnNotFound` with `searched_all: true`, up to a
       validated ledger past `LastLedgerSequence`;
     - the account `Sequence` **unchanged** at such a ledger.

     This record, written to the log as `RESOLVED`, is what a new gate-D intent with the
     **same** `Sequence` needs. It needs the `tx` call's `min_ledger`/`max_ledger` parameters,
     which the B3 allowlist review must confirm.
   - **Otherwise:** report and stop. Another run needs another read-only authorization.
3. **Sepolia verification run.** After finalization, about 13 to 20 minutes (2 epochs). One run
   with `--compare-providers`:
   - **PASS:** `PROVIDER_REPORTED_FINALIZED` by the parent-hash walk. PublicNode's walk must
     succeed.
   - **1RPC caveat.** The 1RPC finalized-block lag is unresolved (ADR-RN-018). An `UNRESOLVED`
     or lagging 1RPC answer is reported as it is. It is never treated as agreement or as
     finality.
   - **Not included:** report. A retry is a gate-D same-nonce replacement.
4. **Gate F.** A sanitized public record only after both networks pass, under its own
   authorization. It holds:
   - the commitment, payload and transaction hashes;
   - the dual-chain report and its limits.

   No raw captures, paths or logs. The wording follows ADR-RN-012: agreement is not proof, the
   evidence is synthetic, and `CHAIN_PROVEN` is never produced.

## 8. Negative test scenarios (offline, simulated providers)

Each scenario asserts its specific code, and that **no write request was sent** unless the
scenario is about the write itself.

**Inputs and authorization:**
1. Intent fails `makeIntent`, or its digest is not the approved one.
2. Authorization digest, network, provider, intent digest, blob hash or expected transaction
   hash differs.
3. Authorization expired (XRPL ledger margin, Sepolia time).
4. Authorization already used, or a log entry exists for the same sender and `Sequence` or nonce.
5. Attempt number skips, or the previous-attempt link is wrong.
6. Provider id not in the configuration, or configured for the other network.
7. Unknown or extra inputs, including `secret`, `seed`, `key_type`, a key file path, or a
   passphrase variable.

**Bytes:**
8. Trailing bytes, non-canonical encoding, an unknown field, an XRPL `NetworkID`, an EVM type
   other than 2.
9. Any single field changed after signing: fee, `maxFeePerGas`, tip, gas, nonce or `Sequence`,
   `LastLedgerSequence`, chain ID, `to`, value, memo or input, access list.
10. A flipped signature bit, high s, y-parity 2, a recovered sender ≠ `from`, an XRPL `Account`
    that is not the address of `SigningPubKey`.
11. Supplied PASS records for different bytes. Supplied records that differ from each other. The
    broadcaster's own JS and Python verifier results that differ.

**Pre-submit reads:**
12. Wrong network or chain ID on either provider.
13. XRPL `Sequence` moved. Fewer than 4 ledgers left before `LastLedgerSequence`. The
    transaction is already known.
14. Sepolia pending nonce ≠ latest nonce, or either ≠ the transaction's. The transaction is
    already known. The base fee is too high for `maxFeePerGas`. The balance is too low.
15. Malformed, duplicate-key, oversized or redirected responses. A timeout. The budget is
    exhausted.

**The write:**
16. Timeout or connection loss on the write, including `RNLO_CONNECTION` at DNS or TLS:
    `UNCERTAIN`, exactly one write request, nothing sent afterwards. Only `RNLO_BLOCKED_ADDRESS`,
    or a harness refusal, gives `NOT_SENT`.
17. HTTP 5xx or 429 on the write: `UNCERTAIN`, no retry.
18. The returned hash differs from the expected one: `UNCERTAIN`.
19. XRPL engine results by class, under the real `fail_hard` behaviour confirmed in §9 step 1:
    - `tesSUCCESS`, `terQUEUED`, `tem*`, `tel*` (including `telINSUF_FEE_P` and
      `telCAN_NOT_QUEUE*`), `tefALREADY`, `tefPAST_SEQ`, `tec*`;
    - flags inconsistent with the result (`accepted: false`, or `broadcast: false` with
      `tesSUCCESS`).
20. Any Sepolia JSON-RPC error: `UNCERTAIN`, with the text recorded and not parsed.
21. A second write attempted in the same run is refused by the harness.
22. Log: `RUN_STARTED` is written before any read, and `ATTEMPTING` before the write. A simulated
    crash after sending leaves the next run refused until there is a `RESOLVED` entry. A
    re-run of a `NOT_SENT` or dry-run authorization is refused. A resubmit authorization with a
    wrong previous-attempt link is refused. A correctly linked same-blob resubmit after
    `REJECTED` is allowed. Any attempt after an inclusion `RESOLVED` is refused.
23. A plain `txnNotFound` without `searched_all: true`, or a changed `Sequence`, does not produce
    an expired `RESOLVED`.

**Isolation (guards and tests):**
24. `chain-submit` imports `signer/`, `txverify/`, `node:fs` or a key API.
25. Any package other than the named entry point reaches `chain-submit` with a transport.
26. `txverify/` uses `sign`, `getPublicKey`, `randomSecretKey` or `keygen`.
27. The read and write allowlists intersect.
28. A write method is built by `chain-readonly`.

**Evidence:**
29. Capture and record files are written with `wx`, never overwritten, and never inside a git
    worktree. Their modes are `0700` and `0600`.

## 9. Exact B3 implementation plan

B3 is implemented and tested **offline only**. Each step is one reviewed change, with CI green
and the Python reference agreeing.

1. **Facts to confirm first**, from published rippled sources and documentation, read only:
   - `submit` under `fail_hard`: what happens to `tec` and `ter` results, and whether
     `terQUEUED` can be returned;
   - the meaning of the `accepted`, `applied`, `broadcast`, `kept` and `queued` flags;
   - `tx` with `min_ledger`/`max_ledger` and `searched_all`.

   The classifier and the tests follow what is confirmed. Until then, the conservative classes
   of ADR-RN-019 §6 stand.
2. **The noble decision (founder).** A renewed, explicit approval of `@noble/hashes@2.4.0` and
   `@noble/curves@2.4.0` for **verification only** in `txverify/`. Without it, the Sepolia path
   stops at step 4 and only XRPL proceeds.
3. **`spec/rnnet.broadcast.v1.md`.** It specifies:
   - `rnnet.broadcast-authorization.v1` and its digest;
   - `rnnet.submission-record.v1`;
   - the exact write requests;
   - the response classes and the precedence of refusal codes (`RNBC_*`).
4. **`txverify/`.** A separate npm project, pinned like `signer/`:
   - `verifySepoliaSignature(bytes)`, which returns the recovered sender and the Keccak-256 hash;
   - `signer/src/verify.mjs` and the verification half of `signer/src/crypto.mjs`, moved here
     unchanged in behaviour. `signer/` then imports `txverify/` for its self-check, so the
     broadcaster never imports `signer/`. The B1 tests and golden records must still pass;
   - a guard allowlist of only the verification functions;
   - tests against the B1 golden fixtures and the public known-answer vectors.
5. **`packages/chain-submit`** (no dependencies). It holds:
   - `WRITE_METHODS`, disjoint from `READ_ONLY_METHODS`;
   - `submitRequestBytes(network, signedBytes)`;
   - `classifySubmitResponse(network, response, expectedHash)`;
   - the authorization check and digest;
   - the submission record builder.
   - **Guard:** built-ins `Buffer` and `createHash`, plus `createPublicKey` and `verify` for
     Ed25519. Packages `canonical`, `tx-intent` and `broadcast-handoff`. No `node:fs`.
6. **`tools/submit/submit-anchor.mjs`.** The only file that joins `chain-submit` to
   `https-transport`. It does:
   - argument parsing (the authorization file only; the provider comes from the authorization);
   - the re-verification sequence, including spawning `rnnet_tx_reference.py` with
     `python3 -I -B`;
   - the pre-submit reads;
   - the append-only submission log (`RUN_STARTED`, `ATTEMPTING`, `RESULT`), the single write and
     the private capture;
   - a separate read-only `status` mode, which writes `RESOLVED`. It runs only under its own
     read-only authorization.

   It has a `--dry-run` that stops before the write. Dry runs are tested offline, and a live dry
   run (reads only) is separately authorizable.
7. **Guards.** New `dependency-boundaries` rules for `chain-submit`, `txverify/` and the single
   entry point. A test pins both allowlists.
8. **Tests and fixtures.**
   - `fixtures/broadcast-b3/`: synthetic signed blobs (from B1), authorizations, and simulated
     provider exchanges for every §8 scenario;
   - a deterministic generator with hand-stated codes.
9. **`tools/reference/rnnet_broadcast_reference.py`.** It independently reproduces the
   authorization digest, the request bytes, the classification, the log decisions and the
   record for every fixture.
   It is added to `offline-checks.sh`.
10. **Independent review**, separately instructed, of the write path, guards, classifier and
   replay controls. Findings are addressed before acceptance.
11. **ADR-RN-019 acceptance** is a separate founder decision, documentation only.

**What B3 does not include:** any live write, any live read, keys, funding or signing.

## 10. Authorization matrix, gates B to F

These are the gates of the [authorization document](genesis-proof-01-authorization.md),
unchanged. Each one applies to one network and one attempt, and never carries over.

| Gate | XRPL Testnet: preconditions not yet met | Sepolia: preconditions not yet met | Run by | Status |
|---|---|---|---|---|
| **B: key creation** | `signer keygen` and the key-file writer implemented and reviewed (B1 excluded them); key location agreed; founder approval | The same, plus the **renewed noble approval** for key generation and signing (ADR-RN-017 §6) | Founder at the terminal; no agent session running at the same time | Not authorized |
| **C: funding** | Gate B-XRPL; a faucet the founder names; one read-only `account_info` check | Gate B-SEP; a faucet the founder names; one read-only `eth_getBalance` check | Founder | Not authorized |
| **D: signing** | Gate C-XRPL; a reviewed live preparation entry point and per-run budget (ADR-RN-018); the persistent sign log; intent approved by digest; dual verification PASS | Gate C-SEP; the **block-hash-pinned** preparation amendment (ADR-RN-018); `eth_estimateGas` confirmed; the renewed noble approval; the rest as for XRPL | Founder at the terminal (passphrase) | Not authorized |
| **E: broadcasting** | Gate D-XRPL; ADR-RN-019 accepted; B3 merged and reviewed; one broadcast authorization per attempt | Gate D-SEP; the same, plus the noble approval for `txverify/` | Agent or founder; the process holds no key | Not authorized |
| **F: verification and publication** | Gate E on **both** networks; read-only verification runs authorized; the sanitized record reviewed | The same, with the 1RPC caveat in §7 | Agent, read-only; publication by the founder | Not authorized |

## 11. Remaining prerequisites for Genesis Proof 01

**Decisions and acceptances:**
1. ADR-RN-018 acceptance (PR #17), then ADR-RN-019 acceptance.
2. The renewed noble approval, by use:
   - B-SEP (key generation);
   - D-SEP (signing);
   - E-SEP (verification in `txverify/`).

**Implementation, each reviewed:**

3. Key generation and the encrypted key-file writer and loader (before gate B).
4. The persistent sign log and same-nonce replacement (before gate D).
5. The live preparation entry point, with block-hash pinning for Sepolia (before gate D).
6. B3 (§9): `txverify/`, `chain-submit` and `submit-anchor` (before gate E).

**Read-only checks, each separately authorized:**

7. EIP-1898 block-hash support on both Sepolia providers.
8. The comparison that resolves the **1RPC finalized-block lag**.
9. `eth_estimateGas` for the Genesis calldata on the current fork.

**Carried from the preflight:**

10. SMOKE-01 raw evidence: located by the founder, or the recorded summary accepted.

**Legal (unchanged):**

11. The exact entity name, the licence (Apache-2.0 proposed), the copyright holder, and the
    signed D3 authorization.
12. Until these are settled, no `LICENSE` or `NOTICE`, and no Frontera-derived content.

**Gates B to F**, each separately, per network (§10).
