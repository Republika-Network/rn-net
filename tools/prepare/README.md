# tools/prepare (RN-NET-03B2-C3)

**The live preparation entry point, read-only and keyless, DISABLED for live network access.**
Specification: [rnnet.preparation-authorization.v1](../../spec/rnnet.preparation-authorization.v1.md).

| File | Role |
|---|---|
| `prepare-live.mjs` | The entry point. As a command it exits 3 (`RNPL_LIVE_DISABLED`) before reading anything. `prepareLive({ argv, deps })` runs the whole flow with injected, simulated dependencies (tests and the rehearsal only) |
| `authorization.mjs` | `rnnet.preparation-authorization.v1`: shape and digest |
| `entry.mjs` | Flags, reviewed providers, the agreed evidence directory (`null`), the Sepolia compatibility record (unrecorded), private-file reads, the typed approval |
| `policy.mjs` | The request policy: exactly the planned requests, in their planned forms, before the transport sees them |
| `evidence.mjs` | The private run directory and its files |

**What it never does:** hold or read a key, sign, send a write method, or import the transport,
`chain-submit`, `tools/submit/`, `signer/`, `tools/keytool/` or `txverify/`. The guard pins this
(`checkPrepareTools` in `tools/guards/dependency-boundaries.mjs`).

**Before it can run live** (none of these is authorized in C3):
1. ADR-RN-018 Amendment C1 and ADR-RN-016 Amendment C1 accepted after review;
2. for Sepolia, the C6 read-only compatibility check recorded in `SEPOLIA_COMPATIBILITY`;
3. the evidence directory agreed in `AGREED_EVIDENCE_DIR`;
4. a reviewed change that imports the transport here and sets `LIVE_NETWORK_ACCESS`;
5. per run, a founder-written `rnnet.preparation-authorization.v1`.
