# rnnet.compat-authorization.v1 and the C6 read-only entry point

- Status: Draft (RN-NET-03B2-C6-LIVE; enabling code reviewed in RN-NET-03B2-C6-LIVE-ENABLE).
  Implemented and wired to the C6 transport; **live network access is still disabled** (§7).
- Basis: [the C6 document](../docs/genesis/rn-net-03b2c6-provider-compatibility.md) §8 (H3 and the
  live entry point); [ADR-RN-018](../docs/adr/ADR-RN-018-transaction-preparation-reads.md)
  Amendment C1, P5; [ADR-RN-013](../docs/adr/ADR-RN-013-read-only-rpc-architecture.md) limits
- Depends on: [rnnet.canonical-json.v1](rnnet.canonical-json.v1.md); the C6 manifest
  (`tools/compat/manifest.mjs`, canonical SHA-256
  `2a45e37c0067e6e7e9aaa0705a298c712335b9a85060e332f794bac935088037`)
- Implementation: `tools/compat-live/` (`authorization.mjs`, `entry.mjs`, `policy.mjs`,
  `report.mjs`, `flow.mjs`, `command.mjs`, `c6-transport.mjs`, `tty-approval.mjs`, and the command
  `compat-live.mjs`); the reviewed HTTPS transport `tools/live/https-transport.mjs`; Python
  reference: `tools/reference/rnnet_compat_reference.py --run`
- Tests: `tools/compat-live.test.mjs`, `tools/compat-live-enable.test.mjs`,
  `tools/c6-transport.test.mjs`, `tools/https-transport.test.mjs`, `fixtures/compat-c6-live/`
  (simulated run directories), `vectors/compat/sanitizer.json`; the command line:
  `tools/broadcast/live-disabled.check.mjs`

## 1. Purpose

The founder's written **H3 authorization of one read-only C6 run**: the 22 requests of the reviewed
manifest, once each, to the four reviewed providers. It authorizes reads only. It authorizes no
key generation, funding, signing, broadcasting, publication, and none of gates B to F. A second run
is a new authorization, never a retry.

## 2. The authorization

Canonical JSON (optionally followed by one newline), exactly these members:

| Member | Value |
|---|---|
| `format` | `"rnnet.compat-authorization.v1"` |
| `authorizationId` | 1 to 64 lower-case letters, digits and inner hyphens; names the run directory |
| `manifestSha256` | `"sha256:2a45e37c0067e6e7e9aaa0705a298c712335b9a85060e332f794bac935088037"`: the canonical manifest digest |
| `providers` | exactly the four reviewed providers, in manifest order, each `{ "id", "requests", "url" }` (below) |
| `requestBudget` | `22`, the sum of the provider `requests` |
| `evidenceDir` | the agreed private evidence directory, a normalized absolute path; equal to `--evidence-dir` |
| `publication` | `"none"` |
| `notAfter` | `YYYY-MM-DDTHH:MM:SSZ`; at most 60 minutes after the run starts |
| `scope` | 1 to 1000 printable ASCII characters, written by the founder |

`providers`, in this order, exactly:

| `id` | `url` | `requests` |
|---|---|---|
| `xrpl-testnet-ripple` | `https://s.altnet.rippletest.net:51234/` | 2 |
| `xrpl-testnet-xrpl-labs` | `https://testnet.xrpl-labs.com/` | 2 |
| `sepolia-publicnode` | `https://ethereum-sepolia-rpc.publicnode.com/` | 9 |
| `sepolia-1rpc` | `https://public.1rpc.io/sepolia` | 9 |

**Digest:** `sha256:` + hex of SHA-256(`"rnnet:compat-authorization:v1\0"` ‖ canonical bytes).

The file is private: a regular file (not a symbolic link) owned by the founder, mode `0600`, at
most 64 KiB.

## 3. The entry point

`tools/compat-live/compat-live.mjs --authorization <file> --endpoints <file> --evidence-dir <dir>`:
exactly these three flags, each once. There is no provider, URL, budget, retry, timeout, fallback,
approval or force option, and no variable or file that approves. **As a command it refuses at
once** (`RNCL_LIVE_DISABLED`, exit 3), before it reads an argument, a file or the environment and
before it loads the transport, while `LIVE_NETWORK_ACCESS` is `false` (§7).

Once enabled, the command first builds the C6 transport (§8) from the process environment and
Node.js options, and refuses (`RNCL_TRANSPORT_ENVIRONMENT`, exit 2) if a proxy, TLS override, extra
CA, preload or any Node.js option is present. Then the flow, in order; any refusal sends nothing:

1. the flags; `--evidence-dir` is the agreed directory (`AGREED_EVIDENCE_DIR`, `null` today);
2. the authorization: shape, then its binding. The manifest digest the code computes, the pinned
   `C6_MANIFEST_SHA256` and `manifestSha256` must be the same value; the providers, URLs, per-provider
   requests and order must be the table above; `requestBudget` must be 22; `evidenceDir` must be
   `--evidence-dir`; `publication` must be `"none"`;
3. `notAfter` has not passed and is at most 60 minutes ahead;
4. the endpoint file: its canonical bytes must hash to `REVIEWED_ENDPOINTS_SHA256`, the reviewed
   `config/rpc-endpoints.json`. Any other provider list, URL, operator or note is refused;
5. the founder's approval: the prompt shows the manifest digest, every provider with its URL and
   count, the authorization id, `notAfter`, the scope, the run directory and the authorization
   digest; the answer must be exactly `c6 <last 16 hex digits of the authorization digest>`. The
   prompt is written to, and the answer read from, the controlling terminal (`/dev/tty`) only:
   standard input is never read, so a pipe, a here-document or another program cannot answer.
   Without a terminal there is no approval (`tty-approval.mjs`);
6. the time is read again after the approval, and the authorization re-checked against it;
7. durability (N1): the evidence directory is private (`0700`, owned by the founder, not a link),
   has at least 64 MiB free, and passes a probe (a file created, written, fsynced, linked and
   removed). Then its run lock `c6-run.lock` is taken (`O_EXCL`): one run at a time in the
   directory, whatever its authorization. A lock left by a killed run stays, and blocks, until the
   founder removes it after checking that no run is active;
8. `<evidence-dir>/<authorizationId>/` is created, mode `0700`. `mkdir` fails if it exists, so an
   authorization runs at most once (`RNCL_AUTHORIZATION_USED`). The authorization text is stored
   first, then the journal is started (§5);
9. the run (`tools/compat/run.mjs`) sends the manifest requests through the request policy (§4);
10. `transcript.json` is written whatever happened. **If any evidence write failed** (a response,
    a journal record, the transcript), the run is refused here with `RNCL_EVIDENCE`: no
    `evidence.json` and no `report.json` are written, and the message lists the calls sent and
    durably recorded, sent but not durably recorded, and never sent;
11. `evidence.json` is written. The run is replayed from the stored files alone (with the report
    in memory): the JavaScript classifier runs again and must reproduce `evidence.json`, the
    journal and the report byte for byte, otherwise `RNCL_NOT_REPRODUCED`. Only then is
    `report.json` written (review F5); if that write fails, `RNCL_EVIDENCE`.

The run lock is released at the end, whatever the outcome.

Exit codes: `0` PASS, `2` refused, `3` live access disabled, `4` BLOCKED, `5` UNRESOLVED.

## 4. The request policy

`tools/compat-live/policy.mjs` wraps the transport, independently of the run's own one-pass plan.
Before each request it checks:

- the provider is one of the four authorized, at its authorized URL;
- the deadline is 10,000 ms and the response limit 262,144 bytes;
- the body is at most 4,096 bytes of JSON whose `method` is read-only on that network (and is no
  write method), and is one of that provider's planned requests in manifest order (a request may
  be skipped, NOT_SENT, never repeated or taken back);
- **the body is that manifest request byte for byte** (review F3): the policy rebuilds it from the
  manifest with only the values the run observes, each of its own form, and compares bytes. The
  observed values are: the provider's validated ledger index (a safe integer of at least 999) for
  the ranged `tx`; the pinned block number (a QUANTITY, the same on both Sepolia providers); the
  pinned block hash (32 bytes) for the account reads and the estimate. Any other key, value, order,
  spacing, duplicate key or id is refused;
- the provider's authorized count and the total of 22 are not exhausted;
- the authorization has not expired;
- **the journal has durably recorded the request** (a `send` record, appended and fsynced). If it
  cannot, the request is not sent: a request with no `send` record was never sent (N1).

It then calls the transport **once**, with a fresh copy of exactly the checked request. It does not
retry, and it never sends a request to another provider. If the transport has not answered after
the deadline, the call is a TIMEOUT.

The response is read once (review F4): its `status` and `body` are each read a single time. The
status must be an integer from 100 to 599 (review F6). The body must be a genuine `Uint8Array` or
`Buffer` (not a subclass, a Proxy or another typed array, and with no own `length`), at most
262,144 bytes; only then is it copied, and only the copy is used. Anything else is refused without
being stored or parsed (`RNLO_RESPONSE_TOO_LARGE`, or `TRANSPORT_ERROR`).

Each response body is stored as soon as it arrives (`response-NN.bin`, NN = call number), then the
call's `outcome` record is journaled. If a body or a record cannot be stored, the run stops there:
- a body that cannot be stored is recorded with `error` `RNCL_STORAGE`, never as a transport error;
- nothing more reaches the transport: every later call is refused with the failure as its policy;
- the run is refused with `RNCL_EVIDENCE` and carries no report (§3, step 10).

After the first violation, nothing more reaches the transport: every later call is refused, and
the report records the violation.

## 5. The run directory

All files `0600`. Every file except the journal is written **whole or not at all**: its bytes go
to a new temporary file `.<name>.partial` (`O_CREAT|O_EXCL|O_NOFOLLOW`), which is fsynced and then
hard-linked to its final name (which must not exist) and removed; the directory is fsynced. On any
failure the temporary file is removed, and so is the final name if it was linked, so a full disk or
an I/O error never leaves a truncated or undurable file under a run file's name.

| File | Content |
|---|---|
| `authorization.json` | the founder's authorization, byte for byte |
| `journal.ndjson` | `rnnet.provider-compat-journal.v1` (below): written as the run goes, one fsynced record at a time |
| `response-NN.bin` | the raw body of call NN, exactly as received. **Private: never published** |
| `transcript.json` | `rnnet.provider-compat-transcript.v1`: per call `call`, `providerId`, `requestSha256`, `status`, `responseFile`, `responseSha256`, `responseBytes`, `error` (a fixed transport code, `TRANSPORT_ERROR`, or `RNCL_STORAGE`), `policy` (the violation or `null`) |
| `evidence.json` | `rnnet.provider-compat-evidence.v1` (the C6 document §8), plus `authorizationId`, `authorizationDigest` and `manifestSha256` |
| `report.json` | `rnnet.provider-compat-report.v1` (§6) |
| `python-reference.txt` | written by the Python reference with `--record` (§6) |

**The journal** (`journal.ndjson`, N1) is one canonical JSON record per line, appended with
`O_APPEND` and fsynced after each record:

1. the header: `{"authorizationDigest", "authorizationId", "format": "rnnet.provider-compat-journal.v1"}`;
2. per call that passes the policy: `{"call", "event": "send", "providerId", "requestSha256"}`
   **before** the request is sent, then `{"call", "error", "event": "outcome", "responseBytes",
   "responseFile", "responseSha256", "status"}` after its response is stored;
3. per call the policy refuses: `{"call", "event": "refused", "policy"}`.

After one failed append, nothing more is appended. In a complete run the journal is exactly the
header followed by the records the transcript implies, and both checkers compare it byte for byte.

**An incomplete run** (refused with `RNCL_EVIDENCE`) holds `authorization.json` and
`journal.ndjson`, the responses stored before the failure, and `transcript.json` if it could be
written, never `evidence.json` and `report.json`. Read from the disk alone:

- a call with no `send` record was **never sent**;
- a call with a `send` record and an `outcome` (no `RNCL_STORAGE`) was **sent and recorded**;
- a call with a `send` record and no outcome is **sent but not recorded** when the transcript says
  it reached the transport, and **possibly sent** when there is no transcript (a process killed
  mid-request; or the one record whose fsync failed, whose request the transcript, when stored,
  shows as refused). The journal never under-states what was sent.

## 6. The report and its reproduction

`rnnet.provider-compat-report.v1`, canonical JSON. Its members are:

- the authorization: `authorizationId`, `authorizationDigest`, `authorizationFileSha256`,
  `manifestSha256`, `providers`, `requestBudget` and `publication`;
- `observedAt`;
- `requestCount` (the requests the run handed to the policy), `sentPerProvider` and
  `forwardedRequests` (the requests that reached the transport);
- `policyViolation`;
- `transcriptSha256`, `evidenceSha256`, and `responses` (call, file, bytes, SHA-256);
- every check's `id` and `status` (its free-text detail is in `evidence.json` only);
- `verdict`, `sepoliaBranches`, `compatibilityCandidate`, `finality`;
- `overall`:
  - `BLOCKED` if either verdict is BLOCKED;
  - `PASS` if both verdicts are PASS and no policy violation occurred;
  - `UNRESOLVED` otherwise.

The report is a pure function of the run directory. Two programs rebuild it, independently:

- `compat-live.mjs` replays it, step 10 above. Any mismatch between the replay and the transcript
  is fatal, and the replay must use every transcript call;
- `python3 -I -B tools/reference/rnnet_compat_reference.py --run <run directory> [--record]` uses
  no JavaScript. It:
  - checks the authorization's binding;
  - checks the journal is exactly the record the transcript implies;
  - rebuilds every request byte for byte and compares the digests in the transcript;
  - checks every response's digest and size;
  - recomputes every outcome, observation, check status, verdict, branch, candidate and finality
    number;
  - rebuilds `report.json` byte for byte.

  It exits 0 only if everything agrees. With `--record` it also writes its output to
  `python-reference.txt` (`0600`, exclusive). On an incomplete run it checks what is there is
  consistent (the journal a prefix of the transcript's record, every stored response's digest, no
  partial file, no report) and prints the calls sent and recorded, sent (or possibly sent) but not
  recorded, and never sent; it exits 1, since there is no report to accept.

## 7. What is enabled, and what is still disabled

RN-NET-03B2-C6-LIVE-ENABLE implemented and reviewed the enabling code:

1. the C6 transport (`c6-transport.mjs`, §8) over the reviewed HTTPS transport, hardened (§8);
2. the command wiring (`command.mjs`) and the terminal approval (`tty-approval.mjs`);
3. in the guard, `COMPAT_TRANSPORT_JOINERS` lists exactly `tools/compat-live/compat-live.mjs`, and
   `compat-live-reaches-network` is narrowed: only `compat-live.mjs` and `c6-transport.mjs` may
   reach a network file, only `tools/live/https-transport.mjs`, and only `c6-transport.mjs` may
   import it directly (`compat-live-transport-not-narrowed`); `c6-transport.mjs` imports nothing of
   `tools/compat/`. The transport file itself is no longer exempt from
   `compat-transport-join-transitive` (review N-d).

**Live network access stays disabled** behind two independent locks, each a one-line,
founder-controlled, reviewed change:

- `LIVE_NETWORK_ACCESS = false` in `tools/compat-live/compat-live.mjs`: the command refuses before
  anything (exit 3), and does not even load the transport;
- `AGREED_EVIDENCE_DIR = null` in `tools/compat-live/entry.mjs`: every run is refused
  (`RNCL_DIRECTORY_NOT_AGREED`) before the authorization is read.

The final transition sets both in one reviewed change (and updates
`tools/broadcast/live-disabled.check.mjs` and the test that pins them). Merging this code does not
enable anything. Running it then still needs the founder's H3 authorization (§2) for that one run,
and the typed approval on the terminal.

## 8. The network boundary

What can reach the network, and nothing else, once enabled:

`compat-live.mjs` → (dynamic import, enabled branch only) `c6-transport.mjs` →
`tools/live/https-transport.mjs` → `node:https`, `node:dns`, `node:net`.

The C6 transport (`c6-transport.mjs`) holds its own copy of the providers, budget and limits (a
test checks it against `fixtures/compat-c6/manifest.json` and `config/rpc-endpoints.json`), so a
fault in the run, the manifest or the policy cannot widen it. Whatever it is asked, it allows:

- exactly the four provider ids, each only at its URL in the table of §2 (byte-equal: no other
  host, port, path, scheme, credential or trailing slash; no fallback);
- at most 22 requests in all and 2, 2, 9, 9 per provider, counted before sending (a failure still
  counts: no retry); one request at a time;
- a deadline of exactly 10,000 ms and a response limit of exactly 262,144 bytes; a request body of
  1 to 4,096 bytes that is one JSON object whose method is not a write, signing or key method;
- no environment that could reroute or weaken it. It refuses to be built if any of these is
  present, in any letter case, even empty: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`,
  `NODE_USE_ENV_PROXY`, `GLOBAL_AGENT_HTTP(S)_PROXY`, `NODE_TLS_REJECT_UNAUTHORIZED`,
  `NODE_EXTRA_CA_CERTS`, `NODE_USE_SYSTEM_CA`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `OPENSSL_CONF`,
  `OPENSSL_MODULES`, `OPENSSL_ENGINES`, `SSLKEYLOGFILE`, `NODE_OPTIONS`, `NODE_DEBUG(_NATIVE)`,
  `NODE_V8_COVERAGE`, `NODE_PATH`, `NODE_REPL_EXTERNAL_MODULE`, `NODE_ICU_DATA`, `UV_USE_IO_URING`,
  `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `RES_OPTIONS`, `HOSTALIASES`, `LOCALDOMAIN`; nor any
  Node.js option (`process.execArgv` must be empty).

Underneath, `tools/live/https-transport.mjs` (ADR-RN-013, hardened here):

- HTTPS only, DNS names only (no address literal), no credentials in the URL;
- TLS stated in every request, never inherited: `rejectUnauthorized: true`, `minVersion:
  'TLSv1.2'`, `servername` the URL's host; no `agent` (no connection reuse, no global agent, no
  proxy agent); `insecureHTTPParser: false`;
- every DNS result must be public unicast (no private, loopback, link-local, CGNAT, multicast,
  documentation, benchmarking, 6to4, Teredo, NAT64 or ORCHID address; all results, against DNS
  rebinding), and the connected peer address is checked again on the socket;
- no redirect (any 3xx is `RNLO_REDIRECT`);
- `accept-encoding: identity`, and any other `content-encoding` is refused;
- the declared `content-length` and the streamed byte count are each bounded by the limit; the
  stream is destroyed at the chunk that crosses it, and nothing past the limit is kept;
- a deadline on the whole request.

There is no signing, key or broadcast capability on this path: the guard keeps tools/compat-live/
from the signer, txverify, the key tool, tools/signing/, tools/broadcast/, tools/submit/,
packages/chain-submit/, preparation and the rehearsal (`compat-live-reaches-write-or-key`).

## 9. Error messages in the evidence

`sanitizeMessage` (`tools/compat/run.mjs`; the same in the Python reference) keeps a provider's
error message only as printable ASCII, reads at most 2,048 UTF-16 units and masks at most 512
characters (bounded time and memory), keeps at most 160, and masks, in this order:

1. `scheme://…` → `<url>`;
2. any word holding `@` (user:password@host, user@host, an e-mail address) → `<userinfo>`;
3. any word holding `=` (key=value, a query string) → `<kv>`;
4. four or more dotted numbers, whatever is next to them except another digit (review N-b: `ip_10.1.2.3`) → `<ip>`;
5. IPv6 (and so the `::ffff:` left of a masked IPv4-mapped address) → `<ip>`;
6. `name:port`, `a.b.c:port` → `<host>`;
7. a word joined to another by one colon (scheme-less user:password) → `<userinfo>`;
8. a bare dotted host name whose last label starts with a letter, and `localhost` → `<host>`;
9. runs of 32 or more opaque characters → `<token>`, except 0x-prefixed hex (chain data);
10. runs of 12 to 31 characters mixing letters and digits → `<token>`, except 0x-prefixed hex.

If anything that may be a credential remains (`@`, `=`, `://`, or a word such as password,
secret, bearer, api key, private key, mnemonic, seed, credential, cookie, session, authorization,
auth, jwt, `token:`), the whole message is replaced by `<withheld>` (fail closed, review N-c).
`vectors/compat/sanitizer.json` pins the output on 40 fixed cases and the SHA-256 of the output over
a seeded corpus of 4,000 strings that both implementations generate; both must reproduce it.
