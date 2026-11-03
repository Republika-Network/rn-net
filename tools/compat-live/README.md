# tools/compat-live: the C6 read-only entry point (RN-NET-03B2-C6-LIVE)

**Read-only and keyless. DISABLED for live network access.**
Specification: [rnnet.compat-authorization.v1](../../spec/rnnet.compat-authorization.v1.md).
The run itself: [`tools/compat/`](../compat/README.md) and the
[C6 document](../../docs/genesis/rn-net-03b2c6-provider-compatibility.md).

| File | Role |
|---|---|
| `compat-live.mjs` | The entry point. As a command it exits 3 (`RNCL_LIVE_DISABLED`) before reading anything. `compatLive({ argv, deps })` runs the whole flow with an injected, simulated transport (tests only) |
| `authorization.mjs` | `rnnet.compat-authorization.v1` (H3): shape and digest |
| `entry.mjs` | Flags, the pinned manifest and endpoint digests, the binding checks, the agreed evidence directory (`null`), private-file reads, the typed approval, the write-once run directory |
| `policy.mjs` | The request policy around the transport: authorized provider and URL, limits, read-only method in manifest order, budget, expiry before every request, one call, its own deadline, size limit; stores each body as it arrives |
| `report.mjs` | `rnnet.provider-compat-report.v1` and the replay that reproduces it from the run directory |
| `build-c6-live-fixtures.mjs` | Builds `fixtures/compat-c6-live/`: run directories over simulated providers |

**What it never does:**
- hold or read a key, sign, or send a write method;
- retry, or send a request to another provider;
- import a transport or network module, the write path, `signer/`, `txverify/`, the key tool,
  `tools/signing/`, `tools/broadcast/`, preparation or the rehearsal. The guard pins this
  (`compat-live-reaches-network`, `compat-live-reaches-write-or-key`, and
  `compat-transport-join-transitive` with `COMPAT_TRANSPORT_JOINERS` empty).

**Before it can run live** (none of these is authorized in C6-LIVE):
1. the agreed evidence directory, in `AGREED_EVIDENCE_DIR`;
2. a separately reviewed enabling change: it imports the transport, lists this entry point in
   `COMPAT_TRANSPORT_JOINERS` and sets `LIVE_NETWORK_ACCESS`;
3. the founder's H3 authorization for that one run.
