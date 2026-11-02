# packages/chain-submit

**The only write requests RN-NET can express (RN-NET-03B2-B3, ADR-RN-019 §4; [spec](../../spec/rnnet.broadcast.v1.md)).** No dependencies, no transport, no file access, no key and no signing. It is pure: it builds and classifies, and the harness in `tools/submit/` does the rest.

| File | Role |
|---|---|
| `src/requests.mjs` | `WRITE_METHODS` (XRPL `submit`, Sepolia `eth_sendRawTransaction`), disjoint from chain-readonly's `READ_ONLY_METHODS`; `submitRequestBytes(network, signedTransaction)`, which takes only the signed bytes; the write limits |
| `src/authorization.mjs` | `rnnet.broadcast-authorization.v1` and `rnnet.status-authorization.v1`: shape, digest, exact match, validity |
| `src/classify.mjs` | `classifySubmitResponse`: `NOT_SENT`, `ACCEPTED_PROVISIONAL`, `REJECTED` or `UNCERTAIN`, fail closed |
| `src/record.mjs` | `rnnet.submission-record.v1` and `rnnet.submission-status.v1` |
| `src/log.mjs` | `rnnet.submission-log-entry.v1`, the log consistency check and the attempt decisions |
| `src/codes.mjs` | Outcomes and `RNBC_*` codes |

- **Dependencies:** `packages/canonical`, `packages/tx-intent`, `packages/broadcast-handoff` and the built-ins `Buffer` and `createHash`.
- **Guard rules:** no package under `packages/` may import it (chain-readonly included); it may not import `signer/`, `txverify/`, `chain-readonly`, `node:fs` or any key API; only `tools/` may import it, and no file may join it to the network transport.
