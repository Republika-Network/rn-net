# RN-NET-03B2-C: Genesis Proof 01 operational readiness

- Status: **Proposed** (RN-NET-03B2-C1). This is a planning record. It authorizes none of gates B
  to F, no live RPC call, no key, no funding, no signing and no broadcast.
- Baseline: `main` at `2481095` (PR #20 merged; tree identical to the reviewed head `6dc96af`).
- Amendments it supports, all **Proposed**:
  - [ADR-RN-016](../adr/ADR-RN-016-genesis-anchoring-transactions.md) Amendment C1: the XRPL
    expiry offset and the submission margin;
  - [ADR-RN-017](../adr/ADR-RN-017-offline-signing-toolchain.md) Amendment C1: keys, the
    terminal and the sign log;
  - [ADR-RN-018](../adr/ADR-RN-018-transaction-preparation-reads.md) Amendment C1: EIP-1898 and
    freshness;
  - [ADR-RN-019](../adr/ADR-RN-019-controlled-testnet-broadcasting.md) Amendment C1: the live
    entry points, the budgets and uncertain outcomes.
- Gates: [authorization document](genesis-proof-01-authorization.md). This record changes none
  of them.

## 1. Scope and what is already accepted

The scope is only what blocks the **first** Genesis Proof 01:
- one XRPL Testnet `AccountSet`;
- one Sepolia self-send;
- both carrying the same 42-byte `rnnet.anchor-payload.v1` payload;
- then the gate-F publication.

Anything not needed for that is out of scope.

| | Accepted (offline) | Proposed here (operational) |
|---|---|---|
| Construction, fees, keys policy | ADR-RN-016 (`+ 20` expiry) | `+ 80` expiry; margin of 4 kept |
| Signing toolchain | ADR-RN-017, gate A only: formats, in-memory sign log, no real key | Key generation, key files on WSL ext4, terminal passphrase and approval, persistent sign log |
| Preparation | ADR-RN-018, offline fixtures, pinned by number | EIP-1898 hash pinning, two-pass agreement, the live entry point |
| Broadcasting | ADR-RN-019, simulated providers, no write joiner | The live entry points, budgets, authorization procedure, uncertain-outcome handling |

**Unchanged:**
- every cryptographic format;
- the commitment and payload values;
- `rnnet.canonical-json.v1`;
- every existing record format.

The only new formats proposed are private operational records: `rnnet.sign-log-entry.v1` (C4),
and the gate-F record (C5).

## 2. The XRPL expiry window

The founder decided to propose 80 validated ledgers, and to keep the refusal when 4 or fewer
remain. The analysis is in ADR-RN-016 Amendment C1.

**At least 72 ledgers are usable:** 80, minus 4 of provider skew, minus the margin of 4. That is
about 3.6 minutes at 3 s per ledger, and 6 minutes at 5 s.

Estimated time per step, typical and worst case, from the preparation read to the write:

| Step | Typical | Worst case (bounded) |
|---|---|---|
| Preparation reads (4 requests) | 2–5 s | 40 s (10 s deadline each) |
| Founder reviews the printed intent, types the 16-character confirmation | 30–60 s | founder-paced |
| Passphrase, scrypt (N=2^17), sign, self-check, JS and Python verification | 3–5 s | ~10 s |
| Founder checks and saves the printed authorization draft | 45–90 s | founder-paced |
| Broadcaster: log, both verifiers, 6 pre-submit reads | 4–8 s | ~70 s |
| `submit` | < 1 s | 10 s |
| **Total** | **≈ 1.5–2.8 min** | |

**Verdict: 80 is valid for a human-gated flow, with conditions.** It fits only if:
- the authorization is drafted by tooling (ADR-RN-019 Amendment C1, E3);
- D-XRPL and E-XRPL run in one sitting;
- the run is rehearsed against simulated providers first.

With `+ 20` the same sequence has 48 to 80 s, which does not fit.

**Missing the window is safe but slow.** The run refuses with nothing sent. Then:
1. wait until `LastLedgerSequence` has passed;
2. run an authorized status check that records `EXPIRED`;
3. start a new gate D with the same `Sequence`.

**Clock.** Preparation compares the Sepolia block time with the local `now`, and Sepolia
authorizations carry a UTC `notAfter`. WSL2's clock can drift after the host sleeps. Before gates
D and E, the founder checks the WSL time against the Windows host. That is a local check, not a
network call.

## 3. C2: live broadcaster, follow-ups N1–N5 and transport isolation

These block **gate E on both networks**.

1. **N1: transport isolation in `tools/submit/`.**
   - An allowlist of built-ins and of relative imports for `tools/submit/`.
   - The graph rule must count hand-written network constructs as network: `fetch`,
     `createRequire`, `process.getBuiltinModule`, `child_process` other than the one named
     verifier spawn, and `_http_*`.

   The reviewer rated this a gate-E prerequisite. A file in `tools/` must not join the transport
   before it is fixed.
2. **N2.** The `txverify/` guard refuses `secp256k1` as a value, not only as a member.
3. **N3.** The Python broadcast reference recomputes the `INCLUDED` live summary. The JS-only
   re-checks (hand-off, own signature) are either modeled or stated as out of the reference's
   scope.
4. **N4: crash durability.** `fsync` the log directory, and write each entry via a temporary file
   and `link()`.
5. **N5.**
   - The 4096-byte blob limit is checked at input, not after `ATTEMPTING`.
   - `NOT_SENT_HARNESS` is decided from the one-shot gate's state, never from the type of error
     the transport throws.
6. **`fail_hard` source check** (ADR-RN-019 Amendment C1, E6).
   - Read the rippled source at the release tag the Testnet providers report as
     `build_version`.
   - Record what `tec*` and `terQUEUED` mean under `fail_hard`.
   - Until then both stay `UNCERTAIN`.

   This is a reading of public source code, not an RPC call. `build_version` comes from the C6
   run, or from the recorded SMOKE evidence if it holds it. If the two providers run different
   versions, both are checked.
7. **The entry points.**
   - `tools/submit/submit-anchor.mjs`: the only `WRITE_TRANSPORT_JOINERS` member.
   - `tools/submit/status-check.mjs`: read-only.
   - Both have budgets fixed in code (ADR-RN-019 Amendment C1, E2), and both refuse without
     their authorization file.
8. **The message fix.** The broadcaster's "fewer than 4 ledgers remain" becomes "4 or fewer
   ledgers remain". The behaviour does not change.
9. **The rehearsal harness.** One offline command runs C3 → C4 → C2 end to end against
   simulated providers and prints the time of each step (§2).
10. **Review.** An independent adversarial review covers all of the above.

**What C2 cannot check before gate E:** whether each provider accepts the write method. The
public XRPL servers are documented as accepting `submit` of signed blobs. Whether PublicNode and
1RPC relay `eth_sendRawTransaction` cannot be tested without sending.

If the authorized provider fails with `NOT_SENT` or `REJECTED`, the other provider is a new
authorization (attempt + 1). After `UNCERTAIN`, a status check comes first.

## 4. C3: live preparation and provider agreement

These block **gate D on both networks**.

1. **The `+ 80` offset in code.** `XRPL.lastLedgerOffset`, the Python preparation reference, the
   specification §5 and the preflight template all change. The B2 fixtures and expected intent
   digests are regenerated, and the regenerated digests are reviewed.
2. **EIP-1898 two-pass preparation** (ADR-RN-018 Amendment C1, P1 to P3):
   - head pass, then the pin at the lowest head − 2, then the agreed hash, then the pinned reads;
   - refusal, never fallback;
   - 8 requests per Sepolia provider.
3. **Simulated cases.** Hash disagreement at P, an unsupported block-hash form, a
   non-canonical-block error, a pending ≠ pinned nonce, a stale pinned block, and a provider that
   refuses the object form for `eth_estimateGas` only. All are reproduced by the Python reference.
4. **The entry point** `tools/prepare/prepare-live.mjs` (P9), with an independent review.

### C6: provider compatibility check (one read-only run, after C3 merges)

The run needs its own founder authorization, with this exact budget: **22 requests**, one
attempt each.

| Provider | Requests | Purpose |
|---|---|---|
| `xrpl-testnet-ripple`, `xrpl-testnet-xrpl-labs` (2 each, 4 in all) | `server_info` | `network_id` 1; `build_version` (for the `fail_hard` check); `complete_ledgers` (history needed by the ranged `tx` lookup in a status check); `base_fee` × `load_factor` ≤ 12 drops; current reserves |
| | `tx` with `min_ledger`/`max_ledger` over a recent range of up to 1,000 ledgers, for a hash that does not exist | that `searched_all: true` is returned, which `EXPIRED` needs |
| `sepolia-publicnode`, `sepolia-1rpc` (9 each, 18 in all) | `eth_chainId`; `eth_getBlockByNumber` `latest`; `eth_getBlockByNumber` at latest − 2 | head freshness, skew, and that both report the same hash at the pin |
| | `eth_getTransactionCount`, `eth_getBalance`, `eth_getCode`, `eth_estimateGas` at `{blockHash, requireCanonical: true}` | EIP-1898 support per method; `eth_estimateGas` is the doubtful one (P4) |
| | `eth_getBalance` at an unknown block hash | the error shape for an unservable hash |
| | `eth_getBlockByNumber` `finalized` | the 1RPC finalized-lag question (about 67 minutes in SMOKE-02); compared with PublicNode |

- **Addresses.** The Sepolia reads use one public, label-derived test address from the B1
  vectors. That address is never funded, and no Genesis key exists yet.
- **Method allowlist.** The run uses only methods that are already allowlisted.
- **What the run cannot settle.** The 1RPC lag needs one comparison. If that does not explain
  it, gate F keeps relying on the PublicNode walk alone, as ADR-RN-019 §8 already says.
- **If either Sepolia provider refuses the block-hash form for `eth_estimateGas`.** RN-NET then
  has no working Sepolia pair, and the founder decides the P4 alternative. There are two
  reviewed Sepolia providers today, and preparation needs 2 to 4.

### Sepolia finality constraints

- **Preparation never reads `finalized`** (P7).
- **Gate F needs `PROVIDER_REPORTED_FINALIZED`** by the parent-hash walk on both providers.
  Finality normally comes two epochs (64 slots × 12 s ≈ 12.8 min) or more after inclusion.
- **The walk.** The verifier walks parent hashes from the provider's `finalized` block **down
  to** the transaction's block, at most 256 steps (`ANCESTRY_LIMIT`, about 51 minutes of 12 s
  blocks):
  - a `finalized` block still below the transaction gives `NOT_REACHED`;
  - one more than 256 blocks above it gives `UNRESOLVED`, which is not inferred.
- **So gate F has a window.** The verification run must fall roughly between 15 and 60 minutes
  after inclusion: after finality, and before the `finalized` head is more than 256 blocks
  past the transaction. It is authorized once inside that window, not polled. A later run
  cannot show finality by the walk.
- **The 1RPC observation is a real blocker for agreement.** If 1RPC's `finalized` lags by about
  67 minutes, as in SMOKE-02, the two providers cannot be inside the window together:
  - while PublicNode can walk, 1RPC reports `NOT_REACHED`;
  - by the time 1RPC reaches the block, PublicNode is past 256 blocks.

  ADR-RN-019 §8 already lets the PublicNode walk alone carry finality and reports the
  disagreement. C6 must find out whether the lag persists. If it does, the founder accepts a
  gate-F record with Sepolia finality from one provider, or adds a reviewed provider.

## 5. C4: encrypted testnet key tooling and founder-controlled signing

These block **gate B** (then C) and **gate D**.

1. **`signer/src/keygen.mjs`** (ADR-RN-017 Amendment C1, K1).
   - Ed25519 comes from Node.
   - secp256k1 uses rejection sampling.
   - The guard exception covers only that file.
2. **Key file I/O on WSL ext4** (K2):
   - the `statfs` ext4 check, and refusal of `/mnt/` and of worktrees;
   - `0700`/`0600`, `wx`, a temporary file + `link()`, `fsync`.
3. **The terminal** (K3):
   - `/dev/tty` with no echo; refused when no terminal is attached;
   - the passphrase twice at gate B, at least 20 characters;
   - the intent printout and the 16-character digest confirmation at gate D.
4. **The persistent sign log** (K4): `rnnet.sign-log-entry.v1` with `SIGNING`, `SIGNED` and
   `RESIGN_BASIS`, and the four rules.
5. **The signer command line under `tools/keys/`** (K5).
   - It refuses to run if any interface other than loopback is present.
   - After signing, it prints the authorization draft (§2).
6. **Tests.** The B1 *(later)* tests that need the file system, and fixtures for every refusal.
   They use temporary directories on the CI filesystem. The ext4 check is injected so that tests
   can exercise both outcomes.
7. **Review.** An independent review takes place before gate B.

**Not settled by C4:**
- the renewed `@noble/*` approval for B-SEP and D-SEP;
- the decision whether to keep or destroy the keys after Genesis Proof 01 (authorization doc
  §2.7).

## 6. C5: the Genesis Proof 01 publication bundle

These block **gate F**.

1. **A record builder.**
   - **Inputs:** the two submission records, the two live verification reports, and the
     dual-chain report.
   - **Output:** one sanitized Genesis Proof 01 record. A new format, specified in C5.
2. **What the record holds:**
   - the commitment;
   - the 42-byte payload;
   - for each network: the network, the sender address (public on chain), the transaction hash,
     and the validated ledger index or finalized block number and hash;
   - the providers that reported it, and the dual-chain outcome;
   - the ADR-RN-012 limits as fixed text: the same commitment is shown in the data reported for
     both networks; finality is a provider claim; the evidence is synthetic, and the anchors say
     nothing about its truth.
3. **What it refuses:**
   - raw captures and base64 bodies;
   - local paths (`/home/`, `/mnt/`, `~`);
   - log entries and authorization files;
   - key-file contents or digests;
   - anything the `secret-shapes` guard flags;
   - any wording claiming proof (`CHAIN_PROVEN`, "proven", "true").
4. **A Python mirror** that rebuilds the record from the same inputs, byte for byte.
5. **Independent verification instructions.** How a third party checks the record:
   - recompute the payload from the commitment with the offline verifier;
   - look up both transaction hashes with any public explorer or node;
   - compare the memo and the `input` with the payload.

   RN-NET's providers are not needed for this.

**Legal, before publication.** The open items (entity name, licence, D3) stand. Before gate F the
founder must confirm that publishing a sanitized record of **synthetic** evidence is allowed:
- with no Frontera-derived content;
- with no LICENSE file;
- in the public repository, or elsewhere.

Otherwise this is the long pole.

## 7. Fees and funding

| | XRPL Testnet | Ethereum Sepolia |
|---|---|---|
| Fee | 12 drops, fixed (cap 1,000) | gas limit 30,000; tip 1 gwei; `maxFeePerGas` = min(2 × base + 1 gwei, 20 gwei) |
| Maximum cost | 12 drops | 30,000 × 20 gwei = 0.0006 Sepolia ETH |
| Balance required | reserve + `OwnerCount` × increment + 12 drops, with the reserves read live | 30,000 × `maxFeePerGas`, on every provider |
| Refused when | `base_fee × load_factor` > 12 drops (`RNTP_FEE_TOO_HIGH`). The fee is never raised: raising it needs an ADR-RN-016 amendment | base fee > 19 gwei (`RNTP_FEE_TOO_HIGH`) |
| Funding (gate C) | one request to a faucet the founder names (for example the xrpl.org Testnet faucet), to the gate-B address only | one request to a faucet the founder names |
| Funding constraint | Testnet can be reset, which removes the account. Fund close to gate D | Many Sepolia faucets require the **recipient** to hold Mainnet ETH, or to link another wallet. Both are excluded (no Mainnet funds, no other project's wallet). The faucet must work for a fresh, empty address, for example a login-based or proof-of-work faucet; the founder checks its current terms |
| Queueing | Under load a 12-drop transaction may be queued (`terQUEUED`). That stays `UNCERTAIN` until the `fail_hard` check (§3.6) | a base-fee rise after submission can leave the transaction pending (ADR-RN-019 Amendment C1, E5) |

Neither network spends real value. No Mainnet funds, bridge or purchase is involved.

## 8. Human authorization artifacts

Each artifact is a separate founder decision. None carries over to another network, gate or
attempt.

| # | Artifact | For | Form |
|---|---|---|---|
| H1 | Acceptance of each C1 amendment, after its implementation PR is reviewed | C2–C4 merge; gates B–E | an acceptance PR, as for PR #15, #17 and #19 |
| H2 | Renewed `@noble/*` approval for key generation and signing | B-SEP, D-SEP | a written founder decision |
| H3 | The C6 read-only run, 22 requests | C3 live use | a written read authorization with the exact budget |
| H4 | Gate B, per network, with the recorded public key, address and key-file SHA-256 | B-XRPL, B-SEP | a gate record; the founder runs it at the terminal |
| H5 | Gate C: the named faucet, one request, and a read-only balance check | C-XRPL, C-SEP | a gate record and a read authorization |
| H6 | Preparation reads (4 XRPL, 16 Sepolia requests) | D | a read authorization per run |
| H7 | The intent approved by digest; the 16-character terminal confirmation; the passphrase | D | the gate-D record; at the terminal |
| H8 | `rnnet.broadcast-authorization.v1`, one per attempt, saved from the checked draft | E-XRPL, E-SEP | a file, mode `0600` |
| H9 | `rnnet.status-authorization.v1`, only after `UNCERTAIN` | E follow-up | a file |
| H10 | The gate-F verification run; review of the sanitized record; publication approval; the legal confirmation (§6) | F | written decisions |
| H11 | One machine, no agent session during gates B and D, and agreed private directories, all outside every repository and on ext4 | B–E | a written procedure |

**Proposed private directories (H11):**
- keys: `~/.local/share/rn-net-keys/genesis-01/`;
- sign log: `~/.local/state/rn-net/genesis-01/sign-log/`;
- submission log: `~/.local/state/rn-net/genesis-01/submission-log/`;
- evidence: `~/.local/state/rn-net/genesis-01/evidence/`.

## 9. Gates B–F, separately per network

| Gate | Network | Needs (beyond the authorization document) | Run by |
|---|---|---|---|
| B-XRPL | XRPL Testnet | C4 merged and reviewed; ADR-RN-017 Amendment C1 accepted; H4 | founder, at the terminal, no agent session |
| B-SEP | Sepolia | as B-XRPL, plus H2 | founder, the same |
| C-XRPL | XRPL Testnet | B-XRPL; H5; close to D-XRPL (Testnet resets) | founder (faucet); read-only check |
| C-SEP | Sepolia | B-SEP; H5; a faucet usable by a fresh address (§7) | founder (faucet); read-only check |
| D-XRPL | XRPL Testnet | C-XRPL; C3 merged and reviewed; ADR-RN-016 and 018 amendments accepted; H6, H7; rehearsal done | founder, at the terminal |
| D-SEP | Sepolia | C-SEP; as D-XRPL, plus C6 passed on EIP-1898 and H2 | founder, at the terminal |
| E-XRPL | XRPL Testnet | D-XRPL **in the same sitting**; C2 merged and reviewed (N1–N5, `fail_hard` recorded); ADR-RN-019 Amendment C1 accepted; H8 | founder |
| E-SEP | Sepolia | D-SEP; as E-XRPL; H8 | founder |
| F | both | E on both networks, each resolved as included; Sepolia finalized on PublicNode; C5 merged; H10 | agent, read-only; publication by the founder |

## 10. Revised shortest path to Genesis Proof 01

1. **Founder.** Review this PR. Decide H2 (noble renewal) and the legal question in §6, the two
   decisions with the longest lead times.
2. **Four implementation PRs, in parallel,** each independently reviewed:
   - **C4**: keys and signing; the long pole, and it unblocks gates B and C;
   - **C2**: N1–N5, `fail_hard`, the submit and status entry points;
   - **C3**: `+ 80`, EIP-1898, the preparation entry point;
   - **C5**: the gate-F record builder.
3. **Accept the C1 amendments (H1),** each after its implementation PR.
4. **Gates B-XRPL and B-SEP** as soon as C4 and ADR-RN-017 Amendment C1 are accepted (with H2
   for B-SEP). Then **C-SEP** early, because faucets add friction.
5. **C6**, the read-only run, after C3 merges. The `fail_hard` source check in C2 uses its
   `build_version`.
6. **An offline end-to-end rehearsal** with timings (§3.9).
7. **Sepolia: D-SEP, then E-SEP.** It has no expiry, and its finality takes the longest, so it
   goes first.
8. **XRPL: C-XRPL, then D-XRPL and E-XRPL in one sitting.**
9. **Gate F** inside the Sepolia walk window (about 15 to 60 minutes after inclusion, §4), with
   XRPL validated: one verification run, the C5 record, the founder's review, publication. Do it the
   same day, because XRPL Testnet can be reset.

**Critical path:** C4 → H1 → B → C, run in parallel with C3 → C6 → D; then C2 → E; then F.

## 11. Deferred, and not needed for the first proof

- **Sepolia same-nonce replacement tooling.** Built only if E-SEP ends `PENDING`, after its own
  founder decision. ADR-RN-017 Amendment C1, K4 rule 4, keeps it refused.
- **More Sepolia providers.** Only needed if C6 shows that one of the two cannot serve the
  block-hash form, and the founder rejects the P4 alternative.
- **The SMOKE-01 raw evidence.** Not recovered. The recorded summary stands, unless the founder
  decides otherwise.
- **Key retirement.** Decided after the proof (authorization doc §2.7).
