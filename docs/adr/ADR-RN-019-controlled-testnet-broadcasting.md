# ADR-RN-019: Controlled testnet broadcasting

- Status: Accepted for the offline architecture and simulated implementation only (founder approval of the PR #18 design, RN-NET-03B2-B3 Gate A). No real broadcast, live RPC call or operational key is authorized
- Date: 2026-11-01
- Builds on: [ADR-RN-013](ADR-RN-013-read-only-rpc-architecture.md), [ADR-RN-016](ADR-RN-016-genesis-anchoring-transactions.md), [ADR-RN-017](ADR-RN-017-offline-signing-toolchain.md), [ADR-RN-018](ADR-RN-018-transaction-preparation-reads.md), [ADR-RN-012](ADR-RN-012-cross-chain-trust-boundaries.md), [ADR-RN-015](ADR-RN-015-live-finality-trust-semantics.md)
- Specification: [rnnet.unsigned-tx-intent.v1](../../spec/rnnet.unsigned-tx-intent.v1.md) §5 and §6. The submission formats in §7 below become a specification when B3 is implemented.
- Design and plan: [RN-NET-03B2-B3 broadcaster design](../genesis/rn-net-03b2b3-broadcaster-design.md)
- Gates: [authorization](../genesis/genesis-proof-01-authorization.md) gate E (E-XRPL, E-SEP)

## Context

Genesis Proof 01 ends with two signed transactions:
- an XRPL Testnet `AccountSet`;
- a Sepolia EIP-1559 self-send.

Each is signed once, offline, from an intent the founder approved by digest (gate D). Something
must then put those exact bytes on the network (gate E).

That step is the first in RN-NET that **writes** to a network. Every earlier ADR keeps
`packages/` read-only, and ADR-RN-013 makes write methods unexpressible.

The B1 hand-off (`packages/broadcast-handoff`) checks a blob against its intent. It does not
trust the verification records for the bytes. But it takes the **signature** checks and the
Sepolia hash from those records, because `packages/` has no Keccak-256 or secp256k1. Its README
says the broadcaster must re-verify them itself.

This ADR decides how broadcasting is done, so that it:
- cannot sign, change or re-price a transaction;
- cannot submit anything but the one approved blob, once per authorization;
- leaves an exact, private record of what was sent and what came back.

## Decision

### 1. The broadcaster is keyless

- **No secrets.** The broadcaster never reads, receives, derives or prompts for a private key,
  key file, seed or passphrase.
- **No signer code.** It never imports `signer/`, and it has no signing API: no `sign`, no
  `createPrivateKey`, no `getPublicKey` from a secret, no key file code.
- **It cannot change the bytes.** It holds no code that builds, edits or re-signs a transaction.
  It can only pass the received bytes through unchanged, or refuse.

### 2. What it accepts

Exactly four inputs. Anything else is refused.

1. **The approved intent.** The exact `rnnet.unsigned-tx-intent.v1` intent, as canonical JSON
   text.
2. **The approved digest.** The intent's digest, which must equal the one recorded in the
   founder's gate-D approval.
3. **The signed bytes.** XRPL: upper-case hex. Sepolia: `0x` + lower-case hex.
4. **A broadcast authorization** (§5), for this network, intent, blob and attempt.

Verification records may be supplied for comparison. They are **never** a reason to accept
(§3).

This **supersedes** signing design §5.1, under which the broadcaster accepted a blob only with
a PASS record. Here a record is optional, and the broadcaster's own two verifications are
required.

### 3. It verifies everything again, itself

Before anything is sent, the broadcaster recomputes every check itself, in a fixed order. The
first failure stops the run:

1. **The intent.**
   - It passes `makeIntent`, which re-runs the ADR-RN-016 checks.
   - Its digest equals the approved digest.
   - Its commitment gives the expected 42-byte payload: the XRPL memo, or the Sepolia `input`.
2. **The bytes.**
   - They decode with `packages/tx-intent`, with no trailing bytes.
   - They are exactly the canonical encoding.
   - Every decoded field equals the intent's field (spec §5 step 4), including:
     - sender, chain or network, nonce or `Sequence`;
     - fee, `maxFeePerGas`, `maxPriorityFeePerGas`, gas, `LastLedgerSequence`;
     - recipient, value, memo or input, access list.
3. **The signature.**
   - **XRPL:** Ed25519 verification over `STX\0` ‖ the serialization without `TxnSignature`,
     using Node's built-in `verify`. `Account` must be the address of `SigningPubKey`.
   - **Sepolia:** the checks run in the spec §5 order: y-parity ≤ 1, r and s in range, low s.
     The sender is recovered and must equal `from`.
4. **The hashes.** It recomputes the blob SHA-256 and the transaction hash:
   - XRPL: SHA-512Half(`TXN\0` ‖ blob);
   - Sepolia: Keccak-256 of the signed envelope.
5. **Two verifiers, run by the broadcaster.** It runs the JavaScript verifier and
   `tools/reference/rnnet_tx_reference.py` itself, on the same inputs.
   - **Where the JavaScript verifier lives.** Today it is in `signer/src/verify.mjs`. B3 moves it,
     with the verification half of `signer/src/crypto.mjs`, into `txverify/`. The signer then
     imports `txverify/` for its self-check, and the broadcaster imports `txverify/`, never
     `signer/`.
   - **The Python reference** is spawned as `python3 -I -B`, with the intent, digest and bytes as
     arguments.
   - Both must produce identical `rnnet.signed-tx-verification.v1` PASS records.
   - Those records must equal its own results from steps 1 to 4.
   - Supplied records are compared with these, and a difference is a refusal. A supplied PASS
     never replaces a check.

**Where the Sepolia cryptography comes from.** Keccak-256 and secp256k1 recovery come from the
same **verification-only** project, `txverify/`, outside `packages/`. It uses the same pinned
`@noble/hashes@2.4.0` and `@noble/curves@2.4.0` as `signer/`. Its guard allows only:
- `keccak_256`;
- `secp256k1.Signature.fromBytes(…, 'recovered')`;
- `recoverPublicKey`;
- `secp256k1.verify`.

It refuses `sign`, `getPublicKey`, `randomSecretKey`, `keygen` and every key-file API.
**This use of the noble packages needs a renewed, explicit founder dependency approval**, for
verification in B3. ADR-RN-017 approved them for B1 only.

**The rejected alternative** is an original Keccak and secp256k1 recovery in JavaScript, which
would be new cryptography. The Python reference already holds an original implementation, and
that remains the independent second check.

### 4. A strict write allowlist, separate from the read allowlist

`packages/chain-submit` (new, dependency-free) builds the only write requests RN-NET can
express. They are kept apart from `READ_ONLY_METHODS`.

| Network | Method | Exact request | Refused |
|---|---|---|---|
| `xrpl:testnet` | `submit` | `{"method":"submit","params":[{"tx_blob":<hex>,"fail_hard":true}]}` | `submit` with `tx_json`, `secret`, `seed`, `seed_hex`, `passphrase`, `key_type` or `offline`; `sign`, `sign_for`, `submit_multisigned`, `wallet_propose`, every admin method |
| `evm:11155111` | `eth_sendRawTransaction` | `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[<0x hex>]}` | `eth_sendTransaction`, `eth_sign*`, `eth_signTransaction`, `personal_*`, `wallet_*`, every other method |

- **One builder.** Requests take only the signed bytes. There is no parameter through which a
  caller could pass a field, a fee or a key.
- **`fail_hard: true`.** A transaction that fails locally on the server is neither retried nor
  relayed by that server.
- **The guard.**
  - Nothing under `packages/` may import `chain-submit`, except a future package that this ADR is
    amended to name.
  - `chain-submit` may not import `signer/`, `txverify/`, `node:fs` or any key API.
  - `chain-readonly` stays read-only and may not import `chain-submit`.
  - The read and write allowlists are disjoint, and a test pins both.
- **One entry point.** `tools/submit/submit-anchor.mjs` is the only file that may join
  `chain-submit` to the network transport (`tools/live/https-transport.mjs`). A guard rule names
  it.
- **Providers.** Only providers in `config/rpc-endpoints.json`, selected by id. The
  authorization names the one provider used.

### 5. One explicit authorization per broadcast

**The authorization record.** `rnnet.broadcast-authorization.v1` is written by the founder for
**one network and one attempt**. It holds:
- network, provider id, attempt number, and the previous attempt's record digest (or `null`);
- intent digest, blob SHA-256 and expected transaction hash;
- validity:
  - XRPL: the authorization is void once a validated ledger reaches `LastLedgerSequence` − 4;
  - Sepolia: void after a stated UTC time;
- the founder's statement of scope.

Its digest is SHA-256(`rnnet:broadcast-authorization:v1\0` ‖ canonical JSON).

**What the broadcaster checks:**
- **Exact match.** Every authorization field equals what it recomputed.
- **The submission log.** A private, **append-only** log outside every repository. Each entry
  is its own file, created with `wx` and never changed or deleted. Entry kinds:
  - **`RUN_STARTED`** (authorization digest). Written **first**, before any read. Every run
    consumes its authorization, including a run that ends `NOT_SENT` and a `--dry-run`. A
    re-run always needs a new authorization.
  - **`ATTEMPTING`** (authorization digest, network, sender, `Sequence` or nonce, blob SHA-256).
    Written **immediately before** the write request.
  - **`RESULT`** (the submission record's digest). Written after the write, whatever its
    outcome, `UNCERTAIN` included.
  - **`RESOLVED`** (the digest of a read-only status-check record). It states one finding:
    - the transaction is in a validated ledger or finalized block;
    - it is absent (XRPL: expired, §8);
    - it is pending (Sepolia).
- **When a run is refused.** A run is refused unless all of these hold:
  1. **Unused authorization.** No `RUN_STARTED` exists for its digest.
  2. **No unfinished attempt.** For the same (network, sender, `Sequence` or nonce), every
     earlier `ATTEMPTING` has a `RESULT`. A crash between them leaves an attempt without a
     result, which refuses every later run for that sequence until a `RESOLVED` entry exists.
  3. **A correct link.** For attempt 2 and later, the authorization's previous-attempt field
     names the digest of the latest `RESULT` or `RESOLVED` entry for that sequence.
  4. **A permitted case.** One of these:
     - the same blob as before, re-sent;
     - a gate-D replacement whose new intent digest the authorization names, and whose
       previous attempt is `RESOLVED` as absent or pending;
     - a same-`Sequence` XRPL re-sign, whose previous attempt is `RESOLVED` as absent.
  5. **Not already included.** No `RESOLVED` for that sequence records inclusion. After
     inclusion, nothing more may be sent for it.
- **No reuse elsewhere.** An authorization never carries over to another network, provider,
  blob or attempt. Deleting log entries is outside the design. The log is a control, so a gate-E
  run starts by checking that its directory is the agreed one, and that it has mode `0700` and is
  not inside a git worktree.

**Resubmitting.** Sending the **same** blob again is a new gate-E authorization:
- it names the next attempt number and the previous attempt's record;
- for XRPL, only before expiry.

This follows the gate-E row of the authorization document, which allows resubmitting the same
blob. "A new attempt is a new gate-D decision" (authorization doc §3) applies to new **bytes**.

**No new bytes.** A different fee, a different nonce or `Sequence`, or a replacement transaction
needs a new gate-D intent and signature, never a broadcaster option.

### 6. One attempt, bounded reads, stop on uncertainty

**Pre-submit reads.** In the same run, read-only, one attempt each, from both reviewed providers
of the network:
- **XRPL:** `server_info`, `account_info` and `tx` (by the expected hash), 6 requests in all.
  - Refused unless `network_id` = 1.
  - The account `Sequence` must equal the transaction's.
  - At least 4 ledgers must remain before `LastLedgerSequence`.
  - The transaction must be unknown (`txnNotFound`) on both providers. This is only a guard
    against an obvious resend: absence is established only as in §8.
- **Sepolia:** `eth_chainId`, `eth_getBlockByNumber` (`latest`), `eth_getTransactionCount`
  (latest and pending), `eth_getTransactionByHash` and `eth_getBalance`, 12 requests in all.
  - Refused unless the chain ID is `0xaa36a7`.
  - Latest and pending nonce must both equal the transaction's.
  - The transaction must be unknown (`null`) on both providers.
  - The base fee must be at most `maxFeePerGas` − the tip. This is a sanity check on the latest
    block only: the next block's base fee can be up to 12.5% higher.
  - The balance must cover gas × `maxFeePerGas`.

  These are reads by tag. They are not used to bind any field, so the block-hash pinning that
  ADR-RN-018 requires for preparation does not apply here.

**The submission.** Exactly **one** write request, to the one authorized provider, with a 10 s
deadline, `maxAttempts: 1`, no retry, no fallback to another provider, and no polling.

**Sent or not sent.** The transport cannot always tell whether a failed request left the
machine. A connection error can come from DNS or TLS, or after the bytes were written. So a
write failure is `NOT_SENT` **only** in two cases:
- the transport refused before opening a connection (`RNLO_BLOCKED_ADDRESS`);
- the harness refused before calling the transport.

**Every other write failure is `UNCERTAIN`.**

**XRPL response checks.** Before any outcome other than `UNCERTAIN`:
- `engine_result`, `engine_result_code`, `tx_blob` and `tx_json.hash` must be present and
  consistent;
- `tx_blob` must be the sent blob;
- `tx_json.hash` must be the expected hash.

`ACCEPTED_PROVISIONAL` also requires:
- `accepted: true`;
- `broadcast: true` or `queued: true`, with `queued: true` exactly when the result is
  `terQUEUED`.

Any other combination is `UNCERTAIN`.

**`fail_hard` semantics** must be confirmed against the rippled source as the first B3 step.
Until then, the classes below are conservative:
- under `fail_hard`, `tec*` is treated as `UNCERTAIN`, not as included;
- `terQUEUED` is accepted only if rippled can return it under `fail_hard`.

**What the run ends with:**

| Outcome | When | What follows |
|---|---|---|
| `ACCEPTED_PROVISIONAL` | XRPL `engine_result` `tesSUCCESS` or `terQUEUED`, with `tx_json.hash` equal to the expected hash; Sepolia `result` equal to the recomputed hash | Read-only verification (§8). Not final |
| `REJECTED` | XRPL `tem*`, `tel*`, `ter*` other than `terQUEUED`, and `tef*` other than `tefALREADY` and `tefPAST_SEQ` | Stop. Recorded. A new attempt needs a new authorization, or a new gate D if the bytes must change |
| `UNCERTAIN` | Any write failure other than the two `NOT_SENT` cases above; any XRPL `tec*` (under `fail_hard`, pending the source check); flags inconsistent with the result; a malformed or unexpected response; a returned hash that differs; XRPL `tefALREADY` or `tefPAST_SEQ` (the transaction, or another one with that `Sequence`, may already be in a ledger); **any** Sepolia JSON-RPC `error`. Error texts are not standardized, and `already known` or `nonce too low` can mean the bytes are already on the network | **Stop.** Never resubmit automatically. The next step is a separately authorized read-only status check. The error text is recorded but never parsed into a decision |

A refusal **before** the write request (§3, §5, pre-submit reads) sends nothing, and is
recorded as `NOT_SENT` with its code.

### 7. Evidence stays private

Every exchange of the run is captured, both the reads and the one write. `recordingTransport`
writes it to a new private directory outside every repository:
- directory mode `0700`, file mode `0600`;
- files written with `wx`, never overwritten.

The run writes an `rnnet.submission-record.v1`. It holds:
- network and provider id;
- the authorization, intent and blob digests;
- the expected and returned transaction hashes;
- the SHA-256 of the exact request and response bytes;
- the HTTP status, the outcome and its code;
- for XRPL: `engine_result`, `engine_result_code`, and the flags `accepted`, `applied`,
  `broadcast`, `kept` and `queued`;
- for Sepolia: the verbatim JSON-RPC `error` `code`, with the SHA-256 of its `message`;
- the submission time.

Raw captures and the submission log are **not** committed or published. Publication is gate F
and needs its own authorization: a sanitized record only, worded as ADR-RN-012 requires.

### 8. Finality is verified separately and read-only

The broadcaster never waits or polls.

**Inclusion.** It is established afterwards by the existing read-only verifier
(`tools/verify-live-anchor.mjs --compare-providers`, with captures). Each verification run is
its own read-only authorization, with its request budget.

**XRPL:**
- `PROVIDER_REPORTED_VALIDATED` from both providers, with `tesSUCCESS`, in a ledger at or before
  `LastLedgerSequence`;
- **Expired.** Recorded only when, on both providers:
  - a ledger-ranged `tx` lookup, from the submission's validated ledger to a validated ledger
    past `LastLedgerSequence`, returns `txnNotFound` with `searched_all: true`;
  - `account_info` at a validated ledger past `LastLedgerSequence` shows the account `Sequence`
    **unchanged**, which is the decisive check.

  That is the recorded observation a new gate-D intent with the **same** `Sequence` requires
  (signing design §8). A plain `txnNotFound`, without `searched_all: true`, proves nothing.

**Sepolia:**
- `PROVIDER_REPORTED_FINALIZED`, by the parent-hash walk, on both providers.
- **The 1RPC finality-lag observation is unresolved** (ADR-RN-018). A 1RPC `finalized` answer
  alone is not relied on. Until it is explained, the PublicNode walk must succeed, and a
  disagreement is reported, not averaged.
- An unincluded transaction stays pending until its nonce is used. A retry is a gate-D
  **same-nonce replacement**, never a new nonce.

**Agreement is not proof.** Agreement between providers is not a consensus proof
(ADR-RN-015). `CHAIN_PROVEN` is never produced.

## Consequences

- **What this acceptance covers.** It accepts the keyless broadcaster architecture of this
  ADR, as designed in PR #18 (`3dfd588`), for **offline implementation and simulated testing
  only** (RN-NET-03B2-B3, gate A). It explicitly preserves the following:
  - **No real broadcasting.** It authorizes no write request to any network. Every submission
    in B3 goes to an injected, simulated transport. Gate E stays unauthorized for both
    networks, and each attempt still needs its own founder-written broadcast authorization.
  - **No live RPC.** It authorizes no live read or write. B3 adds no executable entry point that
    joins the write path to a network transport.
  - **No operational keys.** It authorizes no operational wallet, key, key file, seed, account,
    funding or signing. The broadcaster stays keyless (§1).
  - **The noble approval is verification only.** The founder approved `@noble/hashes@2.4.0` and
    `@noble/curves@2.4.0` for verification-only use in `txverify/`. That does not authorize key
    creation or signing for Sepolia (gates B-SEP and D-SEP).
  - **Agreement is not proof.** Provider agreement is not a consensus proof (ADR-RN-015).
    `CHAIN_PROVEN` is never produced.
  - **Nothing else is accepted.** It authorizes none of gates B to F.

- **What B3 will add:**
  - `packages/chain-submit` (request builder and response classifier);
  - `txverify/` (verification-only, pinned noble);
  - `tools/submit/submit-anchor.mjs`;
  - the authorization and submission record formats;
  - guards;
  - simulated-server tests, and a Python reference for the classifier and record.

  The implementation is tested **offline only**, with simulated providers. Merging it
  authorizes no broadcast.
- **What a live broadcast needs.** Gate E, separately for each network, with:
  - this ADR accepted;
  - B3 merged and independently reviewed;
  - the renewed noble approval for `txverify/` (Sepolia);
  - gates B, C and D done for that network;
  - a founder-written authorization for that one attempt.
- **Residual risks:**
  - **XRPL Mainnet replay.** It is mitigated, not prevented (design §8): an identical XRPL blob
    is valid on Mainnet if a funded account with that `Sequence` exists there.
  - **Lying providers.** A provider can lie about acceptance. That is why every outcome is
    provisional until read-only verification on two providers.
  - **The submission log is local.** If the founder runs from two machines, it cannot prevent
    reuse there. Gate E is run from one machine, by one operator.
- **Cost.** Testnet value only; see the design §6. Nothing here spends real funds.
