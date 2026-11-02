# rnnet.broadcast.v1: controlled testnet broadcasting (offline implementation)

- Status: Draft, implemented offline in RN-NET-03B2-B3 (gate A), with the controlled live
  boundary of RN-NET-03B2-C2 (§12). **Nothing here authorizes a broadcast.** The two entry points
  exist but are **disabled for live network access**: neither imports the network transport, both
  refuse as commands, and every submission in this repository goes to an injected, simulated
  transport.
- Decision: [ADR-RN-019](../docs/adr/ADR-RN-019-controlled-testnet-broadcasting.md); plan:
  [B3 design](../docs/genesis/rn-net-03b2b3-broadcaster-design.md).
- Code: `packages/chain-submit` (formats, write requests, classifier, log rules; no dependencies,
  no file or network access), `txverify/` (verification only), `tools/submit/` (the harness:
  storage, run, status check; a library with no command line).
- Independent reproduction: `tools/reference/rnnet_broadcast_reference.py`, over
  `fixtures/broadcast-b3/cases.json`.

Formats in this document: `rnnet.broadcast-authorization.v1`, `rnnet.status-authorization.v1`,
`rnnet.submission-log-entry.v1`, `rnnet.submission-record.v1`, `rnnet.submission-status.v1`.
Every digest is `sha256:` + hex of SHA-256(domain ‖ the value's rnnet.canonical-json.v1 bytes).

## 1. Inputs

A run takes exactly these inputs; any other name (`secret`, `seed`, `seed_hex`, `passphrase`,
`key_type`, `keyFile`, `privateKey`, `tx_json`, ...) is `RNBC_INPUT_INVALID`:

| Input | Form |
|---|---|
| `intent` | The approved `rnnet.unsigned-tx-intent.v1` as canonical JSON text, exactly (no trailing newline) |
| `approvedDigest` | The digest the founder approved at gate D |
| `signedTransaction` | XRPL: upper-case hex. Sepolia: `0x` + lower-case hex. At most 4096 bytes |
| `authorization` | An `rnnet.broadcast-authorization.v1`, canonical JSON text, optionally followed by one newline |
| `verificationRecords` | Optional: 0 to 2 `rnnet.signed-tx-verification.v1` records, compared and never trusted |

The environment (injected by the caller) is exactly: `endpoints` (an `rnnet.rpc-endpoints.v1`),
`transport`, `referenceVerifier` (the Python reference, §9 step 5), `logDir`, `evidenceDir` and
`now` (seconds since the epoch). Nothing else; in particular no key, key file or passphrase.

## 2. rnnet.broadcast-authorization.v1

Domain: `rnnet:broadcast-authorization:v1\0`. Exactly these fields:

| Field | Value |
|---|---|
| `format` | `rnnet.broadcast-authorization.v1` |
| `authorizationId` | `[A-Za-z0-9][A-Za-z0-9._:-]{0,95}`, chosen by the founder; makes each authorization distinct |
| `network` | `xrpl:testnet` or `evm:11155111` |
| `providerId` | The one configured provider of that network the write goes to |
| `attempt` | 1 to 64 |
| `kind` | `first` (exactly attempt 1), `resend` (the same blob again) or `replacement` (new gate-D bytes, same Sequence or nonce) |
| `previousAttempt` | `null` for attempt 1; otherwise the digest of the latest `RESULT` or `RESOLVED` entry for this sequence |
| `sender`, `sequence` | The XRPL `Account` or Sepolia `from`; the `Sequence` or nonce as a decimal string |
| `intentDigest`, `blobSha256`, `transactionHash` | Of the approved intent and the signed bytes |
| `validity` | XRPL `{ "lastLedgerSequence": n }`, equal to the intent's; void once a validated ledger reaches n − 4. Sepolia `{ "notAfter": "YYYY-MM-DDTHH:MM:SSZ" }`; void after it |
| `dryRun` | `true`: the run stops before the write (`RNBC_DRY_RUN`) and still consumes the authorization |
| `scope` | The founder's statement, 1 to 1000 printable ASCII characters |

Every field is compared with what the broadcaster recomputed (`RNBC_AUTHORIZATION_MISMATCH`).

## 3. rnnet.status-authorization.v1

Domain: `rnnet:status-authorization:v1\0`. Fields: `format`, `authorizationId`, `network`,
`providerIds` (the two providers of the network), `attemptEntry` (the digest of the `ATTEMPTING`
entry to resolve), `sender`, `sequence`, `transactionHash`, `scope`. Its run also takes the
attempt's intent (canonical text), whose digest must be the attempt's.

## 4. The write requests

The only write methods (`WRITE_METHODS`), disjoint from `READ_ONLY_METHODS`:

| Network | Exact request bytes |
|---|---|
| `xrpl:testnet` | `{"method":"submit","params":[{"fail_hard":true,"tx_blob":<blob>}]}` |
| `evm:11155111` | `{"id":1,"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":[<0x blob>]}` |

The builder takes only the signed bytes. One request, 10 s deadline, 256 KiB response limit, one
attempt, no retry, no fallback, no polling.

## 5. The submission log

Private, append-only, outside every repository. A directory is used only if it is absolute, its
own real path, owned by the user, mode `0700`, and not inside a git worktree
(`RNBC_LOG_DIRECTORY`, `RNBC_EVIDENCE_DIRECTORY`). Each entry is a file `NNNNNN.json` (its index,
from 0, without gaps) holding its canonical JSON and a newline, created with `wx` and mode `0600`,
never changed or deleted. An entry is written at index N only after the decision was taken on
entries 0..N−1; if N already exists the run is refused (`RNBC_LOG_CONFLICT`).

`rnnet.submission-log-entry.v1`, domain `rnnet:submission-log-entry:v1\0`. Common fields:
`format`, `index`, `kind`, `authorizationDigest`, `network`, `sender`, `sequence`.

| Kind | Further fields | Written |
|---|---|---|
| `RUN_STARTED` | `mode` (`submit` or `status`) | First, before any read; every run consumes its authorization |
| `ATTEMPTING` | `attempt`, `providerId`, `intentDigest`, `blobSha256`, `transactionHash`, `observedLedger` (XRPL: the highest validated ledger read; Sepolia: `null`) | Immediately before the write |
| `RESULT` | `attemptEntry`, `outcome`, `code`, `record` (the submission record's digest) | After the write, whatever its outcome |
| `RESOLVED` | `attemptEntry`, `finding` (XRPL `INCLUDED` or `EXPIRED`; Sepolia `INCLUDED` or `PENDING`), `record` (the status record's digest) | By a status check (§10) only |

A log that is not consistent (an entry out of place, a `RESULT` without its attempt, two attempts
in one run, a `RESOLVED` not written by a status run) is `RNBC_LOG_INVALID`.

**Decision rules**, for (network, sender, sequence), in this order:
1. The authorization has no `RUN_STARTED` yet (`RNBC_AUTHORIZATION_USED`).
2. No `RESOLVED` records inclusion (`RNBC_LOG_ALREADY_INCLUDED`).
3. Every earlier `ATTEMPTING` has a later `RESULT` or `RESOLVED` naming it
   (`RNBC_LOG_UNRESOLVED_ATTEMPT`: a crash between them refuses every run until a status check).
4. `attempt` is the number of earlier attempts + 1 (`RNBC_LOG_ATTEMPT_NUMBER`).
5. From attempt 2: `previousAttempt` is the digest of the latest `RESULT` or `RESOLVED`
   (`RNBC_LOG_LINK_MISMATCH`).
6. A permitted case (`RNBC_LOG_CASE_NOT_PERMITTED`):
   - `resend`: the same intent and blob as the latest attempt, after a `RESULT` of `REJECTED` or
     `NOT_SENT`, or a `RESOLVED` `PENDING` of the latest attempt;
   - `replacement`: a blob no earlier attempt used, after a `RESOLVED` of the latest attempt:
     `EXPIRED` on XRPL, `PENDING` on Sepolia.

These are **stricter than ADR-RN-019 §5** in one way, deliberately (fail closed): after an
`UNCERTAIN` or `ACCEPTED_PROVISIONAL` result nothing more is sent for the sequence until a status
check has written a `RESOLVED` entry, as ADR-RN-019 §6 makes the status check the next step.

## 6. Classification of the write

| Outcome | Code | When |
|---|---|---|
| `NOT_SENT` | `RNBC_NOT_SENT_HARNESS` | The harness refused before calling the transport (a second write in one run, or the request policy, §12). Decided from the harness's own state, never from what a transport throws: a transport that throws anything after being called is `UNCERTAIN` |
| `NOT_SENT` | `RNBC_NOT_SENT_BLOCKED_ADDRESS` | The transport refused before connecting (`RNLO_BLOCKED_ADDRESS`) |
| `UNCERTAIN` | `RNBC_UNCERTAIN_TRANSPORT` | Any other transport failure: timeout, connection, redirect, oversized response |
| `UNCERTAIN` | `RNBC_UNCERTAIN_HTTP_STATUS` | Any HTTP status other than 200 (429 and 5xx included; no retry) |
| `UNCERTAIN` | `RNBC_UNCERTAIN_RESPONSE` | Invalid or duplicate-key JSON; a malformed envelope; XRPL `engine_result` missing, malformed or inconsistent with `engine_result_code`; Sepolia both or neither of `result` and `error`, or a malformed `result` |
| `UNCERTAIN` | `RNBC_UNCERTAIN_RPC_ERROR` | XRPL `status: error`; **any** Sepolia JSON-RPC `error` (its `code` is recorded, its `message` only by SHA-256, and neither is interpreted) |
| `UNCERTAIN` | `RNBC_UNCERTAIN_BLOB_MISMATCH` | XRPL `tx_blob` is not the sent blob |
| `UNCERTAIN` | `RNBC_UNCERTAIN_HASH_MISMATCH` | The returned hash is not the recomputed one |
| `UNCERTAIN` | `RNBC_UNCERTAIN_FLAGS` | XRPL: any of `accepted`, `applied`, `broadcast`, `kept`, `queued` missing; `tesSUCCESS` without `accepted` and `broadcast`, or with `queued`; a rejected class with any flag true |
| `UNCERTAIN` | `RNBC_UNCERTAIN_ENGINE_RESULT` | XRPL `tec*`, `tefALREADY`, `tefPAST_SEQ`, `tefNO_TICKET`, and `terQUEUED` |
| `REJECTED` | `RNBC_REJECTED` | XRPL `tem*`, `tel*`, other `ter*` and other `tef*`, with every flag false |
| `ACCEPTED_PROVISIONAL` | `RNBC_ACCEPTED` | XRPL `tesSUCCESS` with `accepted` and `broadcast` true and `queued` false; Sepolia `result` equal to the recomputed hash |

Checks run in this order: transport, HTTP status, JSON, envelope, engine result and code,
`tx_blob` and `tx_json.hash` present, `tx_blob` equal, `tx_json.hash` equal, all five flags
present, then the class.

### 6.1 `fail_hard` (ADR-RN-019 Amendment C1, E6)

The rippled source was read at tag `3.4.1` (commit `00e64075`), the `build_version` both Testnet
providers reported. The finding is recorded in
[rn-net-03b2c2-fail-hard-rippled-3.4.1](../docs/genesis/rn-net-03b2c2-fail-hard-rippled-3.4.1.md):
- under `fail_hard`, a tec result is discarded and is neither relayed nor kept when it is answered,
  except a tes that fails an invariant check: that becomes `tecINVARIANT_FAILED`, is applied, and
  is relayed at the next ledger close;
- `terQUEUED` cannot be returned (`TxQ::canBeHeld` gives `telCAN_NOT_QUEUE`);
- `tesSUCCESS` means applied to one server's open ledger, never inclusion.

The classes do not change. tec* stays `UNCERTAIN`: an invariant failure can return a tec for an
applied transaction, the answer is one server's open view, and the blob stays valid until
`LastLedgerSequence`. `terQUEUED` stays `UNCERTAIN` as an inconsistent answer. `tefNO_TICKET` is
added to `UNCERTAIN` (an already-applied Ticket transaction). No answer is proof of inclusion or
finality, and a timeout or disconnect says nothing about whether the transaction was applied and
relayed.

## 7. rnnet.submission-record.v1

Domain `rnnet:submission-record:v1\0`. Fields: `format`, `authorizationDigest`, `network`,
`providerId`, `intentDigest`, `blobSha256`, `expectedTransactionHash`, `returnedTransactionHash`,
`requestSha256`, `responseSha256`, `httpStatus`, `transportError`, `outcome`, `code`, `xrpl`
(`engineResult`, `engineResultCode` and the five flags, or `null`), `sepolia` (`errorCode`,
`errorMessageSha256`, or `null`), `dryRun`, `recordedAt` (UTC, from `now`). A field not reached
is `null`. Before `RUN_STARTED` (invalid inputs, authorization, directories or log) the record
names no authorization and nothing is stored.

The record and the capture of every exchange (`capture.json`, `rnnet.rpc-capture.v1`, reads and
the write) go to a new run directory (`run-NNNNNN`, mode `0700`) under the evidence directory,
mode `0600`. Neither is committed or published; publication is gate F.

**Evidence before the write (C2).** Immediately after `ATTEMPTING` and before the transport is
called, `attempt.json` is written to the run directory: `rnnet.submission-attempt.v1`, with
`authorizationDigest`, `attemptEntry` (the `ATTEMPTING` digest), `providerId`, `url`,
`requestSha256`, `request` (the exact request text), `presubmitExchanges` (their count) and
`presubmitExchangesSha256`.

**Durability (C2, B3 review N4).** Every log entry and evidence file is created the same way:
1. written to `.NAME.tmp` (`O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600`), fsync'ed;
2. `link()`ed to its name, which fails if the name exists;
3. the temporary name removed and the directory fsync'ed.

`ATTEMPTING` is durable before the write. A leftover temporary name in the log refuses every later
run (`RNBC_LOG_CONFLICT`) until the founder has looked at it.

## 8. Refusal precedence

1. `RNBC_INPUT_INVALID`; `RNBC_AUTHORIZATION_INVALID`; `RNBC_INPUT_INVALID` for a signed
   transaction above 4096 bytes in its network's form (C2, B3 review N5); `RNBC_LOG_DIRECTORY`,
   `RNBC_EVIDENCE_DIRECTORY`; `RNBC_LOG_INVALID` or `RNBC_LOG_CONFLICT` (a leftover temporary
   name); `RNBC_AUTHORIZATION_USED`. Nothing is logged.
2. `RUN_STARTED` is written. Then: `RNBC_PROVIDER_NOT_ALLOWED` (the id must be one of the two
   configured providers of the network).
3. Verification (§9): `RNTX_INTENT_INVALID` for non-canonical intent text;
   `RNBC_VERIFIER_DISAGREEMENT`; the verification record's `RNTX_*` code;
   `RNBC_SUPPLIED_RECORD_MISMATCH`.
4. `RNBC_AUTHORIZATION_MISMATCH`; Sepolia `RNBC_AUTHORIZATION_EXPIRED`.
5. The log rules of §5 (`RNBC_LOG_*`).
6. Pre-submit reads, provider by provider in configuration order, each checked as it is read:
   read failures keep their `RNLO_*` code; then `RNBC_PRESUBMIT_ACCOUNT`,
   `RNBC_PRESUBMIT_SEQUENCE`, XRPL `RNBC_AUTHORIZATION_EXPIRED`, `RNBC_PRESUBMIT_ALREADY_KNOWN`;
   Sepolia `RNLO_WRONG_NETWORK`, `RNBC_PRESUBMIT_BASE_FEE`, `RNBC_PRESUBMIT_NONCE` (latest, then
   pending), `RNBC_PRESUBMIT_ALREADY_KNOWN`, `RNBC_PRESUBMIT_BALANCE`.
7. `RNBC_DRY_RUN`; Sepolia `RNBC_AUTHORIZATION_EXPIRED` again; the write request is built
   (`RNBC_INPUT_INVALID` if it cannot be); `RNBC_REQUEST_POLICY` if any request was refused (§12);
   the log rules again on the log as it now stands; `ATTEMPTING`; `attempt.json`; the write (§6).

After the write has started, no failure is ever recorded as `NOT_SENT`. If the run cannot write
`RESULT`, the attempt stays unresolved, which refuses every later run for that sequence until a
status check (§5).

## 9. The run

1. Inputs, authorization, directories, log; `RUN_STARTED`; the provider.
2. Verification, by the broadcaster itself:
   - the intent text is canonical and passes `makeIntent` with the approved digest;
   - the JavaScript verifier (`txverify/`) and the Python reference
     (`tools/reference/rnnet_tx_reference.py verify`, spawned as `python3 -I -B` with an empty
     environment) must give canonically identical records, and PASS;
   - the hand-off check (`packages/broadcast-handoff`) recomputes the intent, the blob SHA-256,
     the decoding without trailing bytes, the canonical encoding, every field and the XRPL hash;
   - the signature is re-checked with `txverify/` (Ed25519 over `STX\0` ‖ the unsigned
     serialization; secp256k1 y-parity, ranges, low s, recovery = `from`) and the Sepolia hash
     recomputed with Keccak-256; these must equal the records' hashes;
   - supplied records must equal the broadcaster's own record.
3. The authorization match and validity; the log rules.
4. Pre-submit reads, one attempt each, from both providers:
   - XRPL (3 per provider): `server_info` (`network_id` 1), `account_info` on the validated ledger
     (`validated`, `Account`, `Sequence` = the transaction's; the highest validated ledger must be
     below `LastLedgerSequence` − 4), `tx` by hash (must be `txnNotFound`);
   - Sepolia (6 per provider): `eth_chainId` (`0xaa36a7`), `eth_getBlockByNumber` `latest`
     (`baseFeePerGas` ≤ `maxFeePerGas` − tip: a sanity check only), `eth_getTransactionCount`
     `latest` and `pending` (both = the nonce), `eth_getTransactionByHash` (`null`),
     `eth_getBalance` `latest` (≥ gas × `maxFeePerGas`).
5. Dry run stops here. Otherwise `ATTEMPTING`, the one write, the classification, the record,
   the capture, `RESULT`.

## 10. The status check and rnnet.submission-status.v1

Read-only, under its own `rnnet.status-authorization.v1` (consumed by `RUN_STARTED`, mode
`status`). It never writes to a network.

1. The attempt is found by digest and must match the authorization; the intent's digest must be
   the attempt's (`RNBC_STATUS_MISMATCH`); both providers must be configured for the network.
2. Inclusion: `verifyLiveAnchor` (RN-NET-03B1) on both providers. `INCLUDED` only when the report
   is PASS, AGREEMENT, both providers OBSERVED, and `PROVIDER_REPORTED_VALIDATED` (XRPL) or
   `PROVIDER_REPORTED_FINALIZED` (Sepolia, by the parent-hash walk) holds.
3. Absence, only when both providers did not find the transaction:
   - XRPL `EXPIRED`, on **each** provider: `server_info` shows a validated ledger V past
     `LastLedgerSequence`; `tx` with `min_ledger` = the attempt's `observedLedger` and
     `max_ledger` = V (at most 1000 ledgers) returns `txnNotFound` with `searched_all: true` (a
     plain `txnNotFound` proves nothing); `account_info` at ledger V shows the `Sequence`
     unchanged;
   - Sepolia `PENDING`, on each provider: `eth_getTransactionCount` `latest` still equals the
     nonce.
4. Anything else is `UNRESOLVED` (`RNBC_STATUS_UNRESOLVED`): nothing is written to the log.

`rnnet.submission-status.v1`, domain `rnnet:submission-status:v1\0`: `format`,
`authorizationDigest`, `network`, `attemptEntry`, `transactionHash`, `finding`, `code`,
`liveReportSha256`, `live` (`outcome`, `agreement`, `statuses`, per-provider `outcomes`),
`providers` (`id`, `observation`, `absence`), `recordedAt`. A finding other than `UNRESOLVED`
is written to the log as `RESOLVED`. The 1RPC finality-lag caveat of ADR-RN-018 applies: a
lagging provider leaves the finding `UNRESOLVED`. Agreement is not a consensus proof
(ADR-RN-015); `CHAIN_PROVEN` is never produced.

## 11. Differences from the design, and why

- **`tools/submit/submit-anchor.mjs` exists from C2, disabled** (§12). In B3, the founder's
  instruction excluded any executable live write entry point. In C2, the entry point's interface
  and checks exist, but it cannot reach the network: it does not import the transport, and
  `WRITE_TRANSPORT_JOINERS` is empty. Enabling it is a gate-E change.
- **`chain-submit` has no Ed25519 built-ins.** Signature checks are in `txverify/`, which the
  harness calls; `chain-submit` imports only `Buffer` and `createHash`.
- **The XRPL validity margin** is applied as "void once a validated ledger reaches
  `LastLedgerSequence` − 4" (ADR-RN-019 §5), the stricter reading of design §2 ("at most").
- **The log rules** are stricter after uncertainty (§5).
- **`authorizationId` and `dryRun`** are authorization fields, so that a re-run needs a new
  authorization and a dry run is the founder's stated intent.

## 12. The controlled live boundary (RN-NET-03B2-C2)

ADR-RN-019 Amendment C1 (E1 to E6) stays **Proposed**. C2 implements it offline, with live network
access **disabled**.

### 12.1 Entry points

| File | Role | Live network access |
|---|---|---|
| `tools/submit/submit-anchor.mjs` | `submitAnchor({ argv, deps })`: one founder-approved submission | **Disabled.** As a command it refuses at once (`RNSA_LIVE_DISABLED`, exit 3) and reads nothing. `LIVE_NETWORK_ACCESS = false` |
| `tools/submit/status-check.mjs` | `statusCheck({ argv, deps })`: one read-only status check | **Disabled**, the same way |

The submission flow, in order:
1. **Flags.** Exactly `--network --authorization --intent --approved-digest --signed-transaction
   --endpoints --log-dir --evidence-dir`, each once (`RNSA_USAGE`). There is no retry, fee, field,
   provider or force option.
2. **Network.** `--network` is `xrpl:testnet` or `evm:11155111` (`RNSA_NETWORK_NOT_ALLOWED`), and
   the authorization names the same one (`RNSA_NETWORK_MISMATCH`).
   **Directories.** `--log-dir` and `--evidence-dir` are exactly the agreed directories,
   `AGREED_DIRECTORIES` (`RNSA_DIRECTORY_NOT_AGREED`). The log is what makes an authorization
   single-use, so a run may never choose another one: the same authorization against a fresh log
   would otherwise be accepted again (C2 review F1). In C2 none are agreed (both `null`), so no run
   can pass this step outside the tests.
3. **Endpoints.** The endpoint file is exactly the reviewed providers, pinned in code as
   `REVIEWED_PROVIDERS` by id, network and URL (`RNSA_ENDPOINTS_NOT_REVIEWED`). A test pins that
   list to `config/rpc-endpoints.json`.
4. **Files.** Each input is a private file: absolute path, regular file, not a symbolic link,
   owned by the user, mode `0600`, at most 64 KiB (`RNSA_FILE`). One final newline is removed from
   the intent and the signed transaction.
5. **Approval.** The founder sees every value the run is bound to, including the log and evidence
   directories, and types
   `<network> <last 16 hex digits of the authorization digest>` (`RNSA_APPROVAL_REFUSED`). Typing
   the network makes the approval separate per network; the digest makes it separate per
   submission. A refusal at steps 1 to 5 consumes nothing.
6. **The run.** `runBroadcast` (§9), under the request policy (§12.2).

**Exit codes:**
- `0`: `ACCEPTED_PROVISIONAL`. Never proof of inclusion.
- `10`: `NOT_SENT`. `11`: `REJECTED`. `12`: `UNCERTAIN`; do not resend, a status check comes next.
- `2`: refused before the run. `3`: live access disabled.

`status-check.mjs` takes `--network --authorization --intent --endpoints --log-dir
--evidence-dir`, with the same file, endpoint and approval checks, and runs `runStatusCheck` (§10).
Its exit codes: `0` for a finding written as `RESOLVED`, `12` for `UNRESOLVED`, `2` refused,
`3` disabled.

### 12.2 The request policy (`tools/submit/policy.mjs`)

Every request of a run is checked before the transport is called; a refused request is never sent.

**Submit runs.** A request is admitted only if:
- it names one of the run's two configured providers, at that provider's URL;
- its body is one JSON-RPC request, and its method is on the exact per-provider plan:
  - XRPL: `server_info` 1, `account_info` 1, `tx` 1;
  - Sepolia: `eth_chainId` 1, `eth_getBlockByNumber` 1, `eth_getTransactionCount` 2,
    `eth_getTransactionByHash` 1, `eth_getBalance` 1.

The write is admitted only:
- as the network's one write method (`submit`, or `eth_sendRawTransaction`);
- to the authorized provider;
- once;
- after **every** planned read.

A run that sends therefore uses exactly 7 requests on XRPL, or 13 on Sepolia. A refused read ends
the run `NOT_SENT` (`RNBC_REQUEST_POLICY`), and a refused write is `NOT_SENT`
(`RNBC_NOT_SENT_HARNESS`).

**Status checks.** Only `READ_ONLY_METHODS`, never a write method, to the two named providers.
The ceiling per provider is XRPL 9 and Sepolia 527: the live verifier's reads with their retries,
plus at most 3 absence reads. A refusal ends the check with `RNBC_REQUEST_POLICY`, and no
`RESOLVED` entry is written.

### 12.3 Guard rules added in C2 (`tools/guards/dependency-boundaries.mjs`)

- **`tools/submit/` allowlists (B3 review N1).**
  - Built-in exports: `SUBMIT_BUILTIN_EXPORTS`, no default or namespace import.
  - `child_process`: `execFileSync` in `python-verifier.mjs` only.
  - `process`: only `getuid` and `pid`; the two entry points also `argv`, `exitCode`, `stdout` and
    `stderr`.
  - Relative imports: only `tools/submit/` and the entry points of the five packages it uses and
    of `txverify/`.
  - `FORBIDDEN_CONSTRUCTS` and the raw-text rules apply.
  - Only the two entry points may have a command line.
- **Network-capable files (B3 review N1 residual).** In the import graph, a file is network if it
  imports any of: a network, subprocess, worker, cluster, inspector, vm, repl or wasi module;
  `node:module`; `node:process`; an underscore-prefixed legacy module. Or if it:
  - names `fetch`, `WebSocket`, `XMLHttpRequest`, `EventSource`, `createRequire`,
    `getBuiltinModule`, `require`, `eval`, `Function`, `WebAssembly`, `globalThis` or `global`;
  - reads `process.binding`, `_linkedBinding`, `dlopen`, `getBuiltinModule` or `execve`, or a
    computed member of `process`;
  - has a computed `import()`;
  - or cannot be parsed.

  The one named verifier spawn is not counted. Every network-capable file under `tools/` must be
  listed in `NETWORK_CAPABLE_FILES`. The write side may not reach a network file, and no other file
  may reach both.
- **Review follow-ups (C2 review F2, F3).** `process` used as a value (an alias, an argument, a
  destructuring), `constructor` other than a class's own constructor method (or as a computed
  member key), and `Reflect` outside `packages/` also make a file network-capable;
  `tools/submit/` refuses `Reflect` outright. The string `constructor` (or a template literal
  without expressions) used as a computed member or property key, or as a call argument, and the
  property-descriptor APIs (`getOwnPropertyDescriptor(s)`, `__lookupGetter__` and similar) outside
  `packages/`, count too. `signer/` and `txverify/` refuse any dynamic import of a non-relative
  specifier and any `export ... from` a library, so a library cannot be handed on whole around
  the named-import rule.
- **The read-only entry point** may not reach `tools/submit/broadcaster.mjs`, however indirectly.
- **`txverify/` (B3 review N2).** `secp256k1` may appear only as its import binding or as the
  object of a non-computed `.Signature` or `.verify`; any other use is
  `txverify-secp256k1-value`.
- `WRITE_TRANSPORT_JOINERS` stays empty.

### 12.4 What enabling live access would take (gate E, per network)

All of these are outside C2, and C2 authorizes none of them:
- **Approvals:** ADR-RN-019 Amendment C1 accepted; this implementation reviewed and merged.
- **The directories:** the agreed log and evidence directories, on one machine, set in
  `AGREED_DIRECTORIES` by a reviewed change.
- **The code change:** a reviewed change that names one entry point in `WRITE_TRANSPORT_JOINERS`,
  imports the transport there, adds the terminal route for the approval prompt, and sets
  `LIVE_NETWORK_ACCESS`.
- **Gates B to D for that network.**
- **The C6 read-only run:** it confirms `build_version`, `complete_ledgers` and each provider's
  answers.
- **The authorization:** a founder-written `rnnet.broadcast-authorization.v1`.

