# rnnet.compat-authorization.v1 and the C6 read-only entry point

- Status: Draft (RN-NET-03B2-C6-LIVE). Implemented offline; **disabled for live network access**.
- Basis: [the C6 document](../docs/genesis/rn-net-03b2c6-provider-compatibility.md) §8 (H3 and the
  live entry point); [ADR-RN-018](../docs/adr/ADR-RN-018-transaction-preparation-reads.md)
  Amendment C1, P5; [ADR-RN-013](../docs/adr/ADR-RN-013-read-only-rpc-architecture.md) limits
- Depends on: [rnnet.canonical-json.v1](rnnet.canonical-json.v1.md); the C6 manifest
  (`tools/compat/manifest.mjs`, canonical SHA-256
  `2a45e37c0067e6e7e9aaa0705a298c712335b9a85060e332f794bac935088037`)
- Implementation: `tools/compat-live/` (`authorization.mjs`, `entry.mjs`, `policy.mjs`,
  `report.mjs`, `compat-live.mjs`); Python reference: `tools/reference/rnnet_compat_reference.py --run`
- Tests: `tools/compat-live.test.mjs`, `fixtures/compat-c6-live/` (simulated run directories);
  the command line: `tools/broadcast/live-disabled.check.mjs`

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
exactly these three flags, each once. There is no provider, URL, budget, retry, timeout, fallback
or force option. **As a command it refuses at once** (`RNCL_LIVE_DISABLED`, exit 3) and reads
nothing, until a separately reviewed enabling change (§7).

The flow, in order; any refusal sends nothing:

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
   digest; the answer must be exactly `c6 <last 16 hex digits of the authorization digest>`;
6. the time is read again after the approval, and the authorization re-checked against it;
7. `<evidence-dir>/<authorizationId>/` is created, mode `0700`. `mkdir` fails if it exists, so an
   authorization runs at most once (`RNCL_AUTHORIZATION_USED`). The authorization text is stored first;
8. the run (`tools/compat/run.mjs`) sends the manifest requests through the request policy (§4);
9. `transcript.json`, `evidence.json` and `report.json` are written;
10. the run is replayed from the stored files alone: the JavaScript classifier runs again and must
    reproduce `evidence.json` and `report.json` byte for byte, otherwise `RNCL_NOT_REPRODUCED`.

Exit codes: `0` PASS, `2` refused, `3` live access disabled, `4` BLOCKED, `5` UNRESOLVED.

## 4. The request policy

`tools/compat-live/policy.mjs` wraps the transport, independently of the run's own one-pass plan.
Before each request it checks:

- the provider is one of the four authorized, at its authorized URL;
- the deadline is 10,000 ms and the response limit 262,144 bytes;
- the body is at most 4,096 bytes of JSON whose `method` is read-only on that network (and is no
  write method), and is that provider's next planned method in manifest order (a request may be
  skipped, NOT_SENT, never repeated or taken back);
- the provider's authorized count and the total of 22 are not exhausted;
- the authorization has not expired.

It then calls the transport **once**. It does not retry, and it never sends a request to another
provider. If the transport has not answered after the deadline, the call is a TIMEOUT. A body over
the limit is refused without being stored (`RNLO_RESPONSE_TOO_LARGE`). After the first violation,
nothing more reaches the transport: every later call is refused, and the report records the
violation.

Each response body is stored as soon as it arrives (`response-NN.bin`, NN = call number). If a
body cannot be stored, the run stops there:
- the call is recorded with `error` `RNCL_STORAGE`, never as a transport error;
- the report's `policyViolation` names the failure;
- nothing more reaches the transport.

A partly written file left behind is not a recorded response, so neither checker reproduces that
run directory.

## 5. The run directory

All files `0600`, written exclusively (`O_EXCL`, `O_NOFOLLOW`), each with an `fsync` of the file
and of the directory:

| File | Content |
|---|---|
| `authorization.json` | the founder's authorization, byte for byte |
| `response-NN.bin` | the raw body of call NN, exactly as received. **Private: never published** |
| `transcript.json` | `rnnet.provider-compat-transcript.v1`: per call `call`, `providerId`, `requestSha256`, `status`, `responseFile`, `responseSha256`, `responseBytes`, `error` (a fixed transport code, `TRANSPORT_ERROR`, or `RNCL_STORAGE`), `policy` (the violation or `null`) |
| `evidence.json` | `rnnet.provider-compat-evidence.v1` (the C6 document §8), plus `authorizationId`, `authorizationDigest` and `manifestSha256` |
| `report.json` | `rnnet.provider-compat-report.v1` (§6) |
| `python-reference.txt` | written by the Python reference with `--record` (§6) |

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
  - rebuilds every request byte for byte and compares the digests in the transcript;
  - checks every response's digest and size;
  - recomputes every outcome, observation, check status, verdict, branch, candidate and finality
    number;
  - rebuilds `report.json` byte for byte.

  It exits 0 only if everything agrees. With `--record` it also writes its output to
  `python-reference.txt` (`0600`, exclusive).

## 7. What enables it (not in this milestone)

A separately reviewed enabling change, and nothing else, may:

1. set `AGREED_EVIDENCE_DIR` to the agreed private directory (H11);
2. import the reviewed transport (`tools/live/https-transport.mjs`) in `compat-live.mjs`, pass it to
   `executeRun`, read the approval from the terminal, and set `LIVE_NETWORK_ACCESS`;
3. in the guard, list `tools/compat-live/compat-live.mjs` in `COMPAT_TRANSPORT_JOINERS` and narrow
   `compat-live-reaches-network` to the transport alone;
4. update `tools/broadcast/live-disabled.check.mjs`.

Running it then still needs the founder's H3 authorization (§2) for that one run.
