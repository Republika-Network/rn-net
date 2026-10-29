# rnnet.live-observation-report.v1

- Status: Draft (RN-NET-03B1)
- Decision records:
  - [ADR-RN-013](../docs/adr/ADR-RN-013-read-only-rpc-architecture.md) (read-only RPC)
  - [ADR-RN-014](../docs/adr/ADR-RN-014-multi-provider-provenance.md) (providers and provenance)
  - [ADR-RN-015](../docs/adr/ADR-RN-015-live-finality-trust-semantics.md) (finality and trust)
- Depends on:
  - [rnnet.anchor-record.v1](rnnet.anchor-record.v1.md)
  - [rnnet.anchor-payload.v1](rnnet.anchor-payload.v1.md)
  - [rnnet.canonical-json.v1](rnnet.canonical-json.v1.md)
  - [rnnet.verification-taxonomy.v1](rnnet.verification-taxonomy.v1.md)
- Implementation:
  - `packages/chain-readonly/` (no network code)
  - `tools/live/https-transport.mjs` (the only transport)
  - `tools/verify-live-anchor.mjs` (CLI)

## 1. Purpose and boundary

This specification covers how RN-NET reads one anchoring transaction from public RPC providers of
XRPL Testnet or Ethereum Sepolia. The reading is read-only. Each reading is normalized into an
`rnnet.anchor-observation.v1` and checked by the RN-NET-03A adapter. Readings from several providers
are then compared.

The result is a report of **what providers said**.

- An RPC response is the provider's claim. Neither TLS nor agreement between providers makes it an
  authenticated proof.
- Nothing here reaches `CHAIN_PROVEN` or assurance level 4 (`rnnet.anchor-record.v1` §1).
- An authenticated proof would need:
  - **XRPL:** the validated ledger header and its validators' signatures checked against a trusted
    UNL, plus a SHAMap proof of the transaction.
  - **Sepolia:** a consensus light client (sync-committee signatures from a trusted checkpoint), plus
    a Merkle-Patricia proof of the transaction and receipt against the block's roots.

  Both are future work.

## 2. Endpoint configuration

**Where endpoints come from.** Endpoints come only from `config/rpc-endpoints.json`, format
`rnnet.rpc-endpoints.v1`. This is a reviewed allowlist, changed only by pull request. A provider is
selected by its `id`. No endpoint is ever taken from a command line, an evidence document or an
RPC response.

**Each entry has:**

| Member | Rule |
|---|---|
| `id` | Lowercase words joined by `-` |
| `network` | `xrpl:testnet` or `evm:11155111` |
| `operator` | 1 to 64 letters, digits, spaces or `().&,'-`, starting with a letter or digit |
| `url` | See below |

**URL rules.** The `url` must be all of the following:

- in normalized form;
- `https:`;
- free of user name, password, query and fragment;
- on a DNS host name, not an IP address or a single-label name (the transport refuses address
  literals too, because they would bypass its DNS checks);
- on a path of at most 128 URL-safe characters.

The `id` must be unique, and so must the `url`.

**No secrets.** Credentials have no place in the URL. An endpoint that needs an API key is not
supported in v1.

## 3. Transport and requests

**Who opens connections.** `packages/chain-readonly` opens no connections. A transport is injected:
`(request) => Promise<{ status, body }>`. The request is
`{ providerId, url, body, timeoutMs, maxResponseBytes }`.

**The production transport (`tools/live/https-transport.mjs`).** It sends one HTTPS POST:

- the TLS certificate is verified;
- a 3xx response is refused (`RNLO_REDIRECT`) and never followed;
- the address is resolved by its own DNS lookup, and refused (`RNLO_BLOCKED_ADDRESS`) if any
  resolved address is not public unicast:
  - loopback, private, link-local, shared, documentation, benchmarking, multicast or unspecified;
  - IPv6 ULA or link-local;
  - IPv4-mapped private, NAT64, 6to4, Teredo, IPv6 benchmarking and ORCHID;
- the request has a deadline (`RNLO_TIMEOUT`);
- the response is read up to a size limit (`RNLO_RESPONSE_TOO_LARGE`).

**Read-only methods.** These are the only methods that can be requested, as exact names:

| Network | Methods |
|---|---|
| `xrpl:testnet` | `server_info`, `tx`, `ledger` |
| `evm:11155111` | `eth_chainId`, `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getBlockByHash`, `eth_getBlockByNumber` |

Request bodies are built only by the package, as canonical JSON:

- XRPL: `{"method","params":[{...}]}`;
- Ethereum: JSON-RPC 2.0 with `id` 1.

**Limits:**

| Limit | Value |
|---|---|
| Response size | 262,144 bytes |
| Per-request timeout | 10 s |
| Attempts per provider per verification, retries included | 600 (`RNLO_REQUEST_BUDGET`). A Sepolia reading makes at most 262 calls, each of at most 2 attempts, so the budget is never reached by a reading that is following the rules. |
| Concurrency | One request in flight; providers are read one after another |
| Attempts per request | 2. The second attempt is made only after a timeout, a connection failure, HTTP 429 (`RNLO_RATE_LIMITED`) or HTTP 502–504. |

Other HTTP statuses are `RNLO_HTTP_STATUS` and are not retried. There is no polling and no
pagination.

## 4. Response parsing

**Strict JSON.** Responses are untrusted bytes, parsed as strict JSON:

- UTF-8, no byte order mark;
- RFC 8259 grammar;
- duplicate keys refused;
- depth at most 64;
- objects with a null prototype.

Integers in the safe range become numbers. Any other number is kept as its exact text, and it has
no canonical form. A response value that has no canonical form therefore cannot become an
observation (`RNLO_INVALID_RESPONSE`). Malformed JSON is `RNLO_INVALID_JSON`.

**Envelopes:**

- **XRPL:** `result.status` must be `success`. An error named `txnNotFound` is `RNLO_NOT_FOUND`;
  other errors are `RNLO_RPC_ERROR`.
- **Ethereum:** `jsonrpc` must be `2.0` and `id` 1. An `error` member is `RNLO_RPC_ERROR`.

## 5. XRPL Testnet reader

The hash is 64 uppercase hex digits.

1. **`server_info`.** `result.info.network_id` must be the integer `1` (XRPL Testnet).
   - Absent: `RNLO_NETWORK_UNKNOWN`.
   - Any other value: `RNLO_WRONG_NETWORK`.

   The provider's name or URL is never used to decide the network.
2. **`tx`** with `{transaction, binary: false, api_version: 2}`.
   - `tx_json` must be an object; otherwise the response is the API v1 shape
     (`RNLO_UNSUPPORTED_API_VERSION`).
   - `hash` must equal the requested hash (`RNLO_HASH_MISMATCH`).
   - `meta` must be an object (`RNLO_INVALID_RESPONSE`).
3. **`ledger`, when `validated` is `true`.** The request is
   `{ledger_index, transactions: false, expand: false, api_version: 2}`. The checks are:
   - the ledger is `validated`;
   - its `ledger_index` and `ledger_hash` equal the transaction's;
   - the `ledger` object, where present, agrees (`RNLO_LEDGER_MISMATCH`).
4. **Observation.** The observation is
   `{format: rnnet.anchor-observation.v1, network: xrpl:testnet, tx}`. `tx` is the `tx` result
   without its envelope members `status` and `warnings`. Nothing is added: no field is invented to
   make a record pass.
5. **Checks.** The RN-NET-03A XRPL adapter checks the observation unchanged, including:
   - validated status;
   - transaction result;
   - CTIDs;
   - the AccountSet rules;
   - the anchor memo;
   - the commitment.

**Provider-reported validation.** A provider counts as having reported validation when step 3 ran
and agreed.

## 6. Ethereum Sepolia reader

The hash is `0x` followed by 64 lowercase hex digits.

1. **`eth_chainId`** must be `0xaa36a7`.
   - Not a canonical quantity: `RNLO_INVALID_RESPONSE`.
   - Any other value: `RNLO_WRONG_NETWORK`.
2. **`eth_getTransactionByHash`.**
   - `null`: `RNLO_NOT_FOUND`.
   - `hash` must equal the requested hash (`RNLO_HASH_MISMATCH`).
3. **`eth_getTransactionReceipt`.** `null` means pending.
4. **The block, if the transaction names one.** Call `eth_getBlockByHash(blockHash, false)`. The
   block must satisfy all of these (`RNLO_BLOCK_MISMATCH`):
   - it exists;
   - its `hash` and `number` equal the transaction's;
   - `transactions[transactionIndex]` is the transaction's hash.
5. **Finality** (§6.1).
6. **Observation.** The observation is
   `{format, network: evm:11155111, transaction, receipt}`, with both taken unchanged. The
   RN-NET-03A Sepolia adapter checks it unchanged.

### 6.1 Safe and finalized ancestry

For each tag, `finalized` and then `safe`, the reader:

1. calls `eth_getBlockByNumber(tag, false)`;
2. follows `parentHash` links with `eth_getBlockByHash` from that block down to the transaction's
   block height, for at most 256 steps.

Each link must lead to a block with exactly the expected hash and a number one lower. Otherwise the
result is `RNLO_BLOCK_MISMATCH`. Block numbers are compared exactly, at any size.

| Result | When |
|---|---|
| `IN_ANCESTRY` | The block reached at that height is the transaction's block |
| `CONFLICT` | Another block is at that height (another fork). This produces `RNLO_FINALITY_CONFLICT`, which fails the report. |
| `NOT_REACHED` | The tagged block is below the transaction's block |
| `UNRESOLVED` | The tag is unsupported or malformed, or its block is more than 256 above the transaction's block. In that case no walk is attempted: the number is used only to decide not to walk, never to infer finality. |

`finalized` is walked first. When it is `IN_ANCESTRY` or `CONFLICT`, `safe` takes the same result
without a walk, since the safe head descends from the finalized one. At most one full walk is made,
and the request budget (§3) covers it even when every call is retried, so a conflict is never lost
to the budget.

**Block numbers alone are never used.** A transaction is not treated as final because its number
is lower than the finalized number.

**What this result is.** It is still the provider's account of its own chain: the walk checks that
the provider's answers are consistent with each other, not that the chain is authentic.

## 7. Report

The report is a canonical JSON object.

### 7.1 Members

| Member | Value |
|---|---|
| `format` | `rnnet.live-observation-report.v1` |
| `network`, `transactionHash`, `expectedCommitment` | The inputs |
| `outcome` | `PASS`, `FAIL`, `UNSUPPORTED` or `INDETERMINATE` (§7.3) |
| `agreement` | `AGREEMENT`, `DISAGREEMENT`, `INSUFFICIENT_SOURCES` or `SOURCE_UNAVAILABLE` (§7.2) |
| `statuses` | §7.4 |
| `providers` | One entry per provider, in the requested order (see below) |
| `findings` | `{code, severity, subject}`, where `severity` is `error` or `unavailable` |
| `statements` | Taxonomy statements (§7.4) |

**Provider entry.** Each entry has `id` and `operator`, plus one of these:

- **when the provider was read:** `outcome: "OBSERVED"`, the observation's `observationSha256`, a
  `materialSha256`, the RN-NET-03A `record`, and either `providerValidated` (XRPL) or `finality`
  (Sepolia);
- **otherwise:** `outcome` and `error`.

**Other provider outcomes:**

| Outcome | Codes |
|---|---|
| `NOT_FOUND` | `RNLO_NOT_FOUND` |
| `WRONG_NETWORK` | `RNLO_WRONG_NETWORK`, `RNLO_NETWORK_UNKNOWN` |
| `INCONSISTENT` | `RNLO_HASH_MISMATCH`, `RNLO_LEDGER_MISMATCH`, `RNLO_BLOCK_MISMATCH` |
| `INVALID_RESPONSE` | `RNLO_INVALID_JSON`, `RNLO_INVALID_RESPONSE`, `RNLO_RPC_ERROR`, `RNLO_UNSUPPORTED_API_VERSION` |
| `UNAVAILABLE` | Everything else: timeouts, connection failures, rate limits, HTTP errors, blocked addresses, redirects, oversized responses, an exhausted request budget |

**What it never contains:** retrieval times, URLs or response text. Provider `id` and `operator` come from the endpoint configuration or, in replay, from the capture, where they must meet the same rules (§2: an operator is 1 to 64 letters, digits, spaces or `().&,'-`). It is a function of the response
bytes alone, so replaying a capture (§8) reproduces it byte for byte.

### 7.2 Agreement

**What is compared.** Comparable answers are observations and "not found". For an observation, the
compared value is the canonical form of its *material*:

| Network | Material |
|---|---|
| XRPL | hash, ledger index and hash, validated, transaction result, `tx_json` |
| Sepolia | hash, block hash, number and index, input, from, to, receipt status, finality |

**The four values:**

| Agreement | When |
|---|---|
| `SOURCE_UNAVAILABLE` | No comparable answer |
| `DISAGREEMENT` | Two comparable answers differ, including one provider finding the transaction and another not. It produces `RNLO_PROVIDER_DISAGREEMENT`. |
| `INSUFFICIENT_SOURCES` | Exactly one comparable answer |
| `AGREEMENT` | Two or more comparable answers, all equal |

**What agreement is not.** There is no majority vote. Agreement is not a consensus proof, and the
providers' infrastructure independence is not established by this report.

### 7.3 Outcome

| Outcome | When |
|---|---|
| `FAIL` | Any of: a finding of severity `error` other than a record that did not pass; a record that is `FAIL`; or comparable answers with no observation (every source reports not found) |
| `INDETERMINATE` | Otherwise, when no provider was read |
| `UNSUPPORTED` | Otherwise, when a record is `UNSUPPORTED` |
| `PASS` | Otherwise |

`PASS` therefore means that at least one provider was read, every observation passed the RN-NET-03A
adapter, and no provider disagreed or answered inconsistently.

### 7.4 Statuses and statements

**Statuses:**

| Status | When |
|---|---|
| `OBSERVED_FROM_RPC` | Some provider was read |
| `PROVIDER_REPORTED_VALIDATED` (XRPL) or `PROVIDER_REPORTED_FINALIZED` (Sepolia, finalized `IN_ANCESTRY`) | Every observed provider reports it |
| `MULTI_PROVIDER_AGREEMENT` | Agreement is `AGREEMENT` |
| `DISAGREEMENT` | Agreement is `DISAGREEMENT` |
| `UNRESOLVED` | Validation or finality was not established |

**Statements:**

| Subject | Classification | Basis |
|---|---|---|
| `providerObservation` | `CLAIMED` | As returned by the named RPC providers; not authenticated |
| `providerAgreement` (if `AGREEMENT`) | `CLAIMED` | Same material; independence not established; not a consensus proof |
| `finality` | `CLAIMED` when provider-reported, otherwise `UNRESOLVED` | Provider-reported validation or finalized ancestry, not authenticated |
| `chainInclusionProof` | `UNRESOLVED` | No authenticated proof of inclusion was verified |

No status, statement or record is ever `CHAIN_PROVEN`, `VERIFIED` inclusion, or assurance above
`CONSISTENT_WITH_SUPPLIED_DATA`.

## 8. Capture (`rnnet.rpc-capture.v1`)

A capture is optional. It is written only to a path given with `--capture`, and never over an
existing file.

**Members:**

| Member | Value |
|---|---|
| `format` | `rnnet.rpc-capture.v1` |
| `network`, `transactionHash` | The verification's inputs |
| `providers` | `{id, operator, origin}` for each provider. The URL path is not recorded. |
| `retrieval` | `{startedAt, finishedAt, tool}`, the only place time appears |
| `exchanges` | In order; at most 600 per provider, the attempt budget (§3), so every capture a verification can produce can be replayed |

**Each exchange** has `providerId` and the exact request bytes (`request`, base64). It also has
exactly one of:

- `response`: `{status, body (base64), sha256}`;
- `error`: a transport code.

**Replay.** Replay (`--offline-replay`) answers each request from the capture, in order, per
provider:

- The capture's request bytes must equal the bytes asked for, and each response's digest must
  match. Otherwise replay stops with `RNLO_REPLAY_MISMATCH`; a mismatch is never treated as an
  unavailable source.
- Every recorded exchange must be used. A capture with exchanges left over does not fit the
  verification (`RNLO_REPLAY_MISMATCH`).
- Replay never opens a connection, and the CLI does not load the network transport in replay mode.

**What a capture proves.** It shows which bytes were received, not that they are true.

**The four artifacts are distinct:**

| Artifact | What it is |
|---|---|
| Capture | The raw responses, with provenance |
| Observation | The normalized `rnnet.anchor-observation.v1` |
| Anchor record | The offline RN-NET-03A result |
| Live report | Provenance, agreement and the provider-reported status |

## 9. Error codes

| Code | Meaning |
|---|---|
| `RNLO_TIMEOUT`, `RNLO_CONNECTION`, `RNLO_RATE_LIMITED`, `RNLO_HTTP_STATUS` | The provider did not answer usefully |
| `RNLO_REDIRECT`, `RNLO_BLOCKED_ADDRESS`, `RNLO_RESPONSE_TOO_LARGE` | Refused by the transport's safety rules |
| `RNLO_REQUEST_BUDGET` | More than 600 attempts for one provider |
| `RNLO_INVALID_JSON`, `RNLO_INVALID_RESPONSE`, `RNLO_RPC_ERROR`, `RNLO_UNSUPPORTED_API_VERSION` | The response is malformed, an error, or of an unsupported shape |
| `RNLO_NOT_FOUND` | The provider does not know the transaction |
| `RNLO_WRONG_NETWORK`, `RNLO_NETWORK_UNKNOWN` | The provider is not on the requested network, or does not say |
| `RNLO_HASH_MISMATCH`, `RNLO_LEDGER_MISMATCH`, `RNLO_BLOCK_MISMATCH` | The provider's answers contradict each other |
| `RNLO_FINALITY_CONFLICT` | The tagged block's ancestry holds another block at the transaction's height |
| `RNLO_PROVIDER_DISAGREEMENT` | Providers gave different answers |
| `RNLO_RECORD_NOT_PASSED` | The RN-NET-03A record for an observation is not `PASS` |
| `RNLO_REPLAY_MISMATCH` | A capture does not fit the replayed verification |
