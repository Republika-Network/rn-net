# tools/compat-live: the C6 read-only entry point (RN-NET-03B2-C6-LIVE, C6-LIVE-ENABLE)

**Read-only and keyless. Enabling code reviewed; LIVE NETWORK ACCESS STILL DISABLED.**
Specification: [rnnet.compat-authorization.v1](../../spec/rnnet.compat-authorization.v1.md).
The run itself: [`tools/compat/`](../compat/README.md) and the
[C6 document](../../docs/genesis/rn-net-03b2c6-provider-compatibility.md).

| File | Role |
|---|---|
| `compat-live.mjs` | The command, and the only file joined to a transport (`COMPAT_TRANSPORT_JOINERS`). While `LIVE_NETWORK_ACCESS` is `false` it exits 3 (`RNCL_LIVE_DISABLED`) before reading anything or loading the transport |
| `command.mjs` | The enabled command with its dependencies injected: the environment check, then the flow |
| `flow.mjs` | `compatLive({ argv, deps })` and `executeRun`: the whole flow, every outside dependency injected |
| `c6-transport.mjs` | The narrow C6 transport: four reviewed URLs, 22 requests (2, 2, 9, 9), 10 s, 256 KiB, no write method, one at a time, no proxy or TLS environment. The only file here that imports `tools/live/https-transport.mjs` |
| `tty-approval.mjs` | The typed approval, on `/dev/tty` only; standard input is never read |
| `authorization.mjs` | `rnnet.compat-authorization.v1` (H3): shape and digest |
| `entry.mjs` | Flags, pinned digests, binding checks, the agreed evidence directory (`null`), private-file reads, the approval check, and the durable evidence store: whole-or-nothing files, the journal, the free-space and probe check, the run lock |
| `policy.mjs` | The request policy: authorized provider and URL, limits, the manifest request byte for byte, budget, expiry before every request, journaled before it is sent, one call, its own deadline, the response read once and bounded |
| `report.mjs` | `rnnet.provider-compat-report.v1` and the replay that reproduces it (and the journal) from the run directory |
| `build-c6-live-fixtures.mjs` | Builds `fixtures/compat-c6-live/`: run directories over simulated providers, two of them incomplete |

**What it never does:**
- hold or read a key, sign, or send a write method;
- retry, or send a request to another provider;
- reach any network file other than through `c6-transport.mjs` and the reviewed transport, or the
  write path, `signer/`, `txverify/`, the key tool, `tools/signing/`, `tools/broadcast/`,
  preparation or the rehearsal (guard: `compat-live-reaches-network`,
  `compat-live-transport-not-narrowed`, `compat-live-reaches-write-or-key`,
  `compat-transport-join-transitive`);
- write a report for a run whose evidence could not be stored whole.

**Before it can run live:**
1. one founder-controlled, reviewed change that sets `AGREED_EVIDENCE_DIR` (in `entry.mjs`) and
   `LIVE_NETWORK_ACCESS = true` (in `compat-live.mjs`);
2. the founder's H3 authorization for that one run, approved by typing
   `c6 <last 16 hex digits of its digest>` on the terminal.
