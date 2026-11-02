# tools/submit/

**The keyless broadcaster harness (RN-NET-03B2-B3, ADR-RN-019; [spec](../../spec/rnnet.broadcast.v1.md)). Offline only in B3.** This is a library: it has no command line, and it never constructs a network transport. The only callers in this repository are the tests and the fixture generator, which inject simulated providers. A live entry point needs gate E and its own review.

| File | Role |
|---|---|
| `broadcaster.mjs` | `runBroadcast`: inputs, authorization, log, re-verification by both verifiers, pre-submit reads, one write through a one-shot gate, classification, record, capture |
| `status.mjs` | `runStatusCheck`: the separate read-only status check that writes `RESOLVED` (INCLUDED, EXPIRED or PENDING) |
| `store.mjs` | The private, append-only log (one `wx` file per entry, mode `0600`) and evidence directories (mode `0700`, outside any git worktree) |
| `python-verifier.mjs` | The second verifier: `python3 -I -B tools/reference/rnnet_tx_reference.py verify ...` with an empty environment |

**Guard rules (tools/guards/dependency-boundaries.mjs):** no `process.argv`, `import.meta.main` or shebang; no import of `tools/live/`, the network transport or any network module; no `signer/`; `node:crypto` for `createHash` only; a subprocess only in `python-verifier.mjs` (`execFileSync`). It imports `txverify/`, never `signer/`, and receives no key, key file, seed or passphrase.
