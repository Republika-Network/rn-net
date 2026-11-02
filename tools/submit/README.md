# tools/submit/

**The keyless broadcaster harness (RN-NET-03B2-B3, ADR-RN-019; [spec](../../spec/rnnet.broadcast.v1.md)), with the controlled live boundary of RN-NET-03B2-C2 (spec §12). Live network access is DISABLED.** No file here imports the network transport (`WRITE_TRANSPORT_JOINERS` is empty), and both entry points refuse as commands (`RNSA_LIVE_DISABLED`, exit 3). Every run in this repository goes to an injected, simulated transport. Enabling live use is a reviewed change at gate E.

| File | Role |
|---|---|
| `submit-anchor.mjs` | Entry point (disabled): `submitAnchor({ argv, deps })`. Exact flags, network allowlist, reviewed endpoints, private input files, the founder's typed approval per network and per submission, then `runBroadcast` |
| `status-check.mjs` | Entry point (disabled), read-only: `statusCheck({ argv, deps })`, then `runStatusCheck`. The guard refuses any route from it to `broadcaster.mjs` |
| `entry.mjs` | What both entry points share: argument parsing, `REVIEWED_PROVIDERS`, private-file reads, the approval check |
| `policy.mjs` | The request policy: the exact pre-submit reads per provider, then one write to the authorized provider (XRPL 7 requests, Sepolia 13); the status check's read-only policy |
| `broadcaster.mjs` | `runBroadcast`: inputs, authorization, log, re-verification by both verifiers, pre-submit reads, `ATTEMPTING` and `attempt.json`, one write through a one-shot gate, classification, record, capture |
| `status.mjs` | `runStatusCheck`: the separate read-only status check that writes `RESOLVED` (INCLUDED, EXPIRED or PENDING) |
| `store.mjs` | The private, append-only log (one entry per file, mode `0600`) and evidence directories (mode `0700`, outside any git worktree). Each file is created via a temporary name, `link()` and a directory fsync |
| `python-verifier.mjs` | The second verifier: `python3 -I -B tools/reference/rnnet_tx_reference.py verify ...` with an empty environment |

**Guard rules (tools/guards/dependency-boundaries.mjs, spec §12.3):**
- **Built-ins:** an allowlist of built-in exports; `child_process` only as `execFileSync` in `python-verifier.mjs`.
- **`process`:** only `getuid` and `pid`; the entry points also `argv`, `exitCode`, `stdout` and `stderr`.
- **Imports:** relative imports only of this directory, five package entry points and `txverify/`.
- **Command line:** only the two entry points may have one.
- **No route out:** no `tools/live/`, no network module, no `signer/`, no code loader.

It receives no key, key file, seed or passphrase, and cannot sign.
