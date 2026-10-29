# packages/anchor

The offline anchoring foundation of RN-NET-03A. The package can do these things:

- encode one `rnnet.evidence-commitment.v1` commitment as a 42-byte anchor payload;
- check **supplied** XRPL Testnet and Ethereum Sepolia transaction data for that payload;
- compare the two networks.

The package never contacts a network, signs, holds keys or creates transactions.

- **Specifications:**
  [rnnet.anchor-payload.v1](../../spec/rnnet.anchor-payload.v1.md) and
  [rnnet.anchor-record.v1](../../spec/rnnet.anchor-record.v1.md).
- **Decisions:** ADR-RN-009 to ADR-RN-012 in [`docs/adr/`](../../docs/adr/README.md).
- **Dependencies:** `packages/canonical`, plus the Node.js built-ins `Buffer` and `createHash`.
  There are no blockchain SDKs.

## Verification boundary

| Level | Meaning | Status |
|---|---|---|
| 1 | A party claims an anchor | the input |
| 2 | Consistent with transaction data supplied with the claim | **implemented** (`CONSISTENT_WITH_SUPPLIED_DATA`) |
| 3 | Consistent with chain data the verifier fetched | future work |
| 4 | Authenticated inclusion and finality proof | future work |

**What a `PASS` means.** It means that the supplied data is internally consistent and carries the
expected payload. It does not prove that a transaction exists, that it is final, or that the
anchored evidence is true. `CHAIN_PROVEN` is reserved and never produced.

## API (`src/index.mjs`)

**Payload:**

- `encodeAnchorPayload(commitment)` returns the 42 bytes.
- `decodeAnchorPayload(bytes)` returns the commitment, or throws an `AnchorError` with an
  `RNAP_*` code.

**Per-network checks.** Each takes `(observationBytes, expectedCommitment)` and returns a frozen
`rnnet.anchor-record.v1` record:

- `verifyXrplObservation`;
- `verifyEvmObservation`.

**Dual-chain check:**

- `verifyDualAnchor({ xrpl, evm }, expectedCommitment)` returns a frozen
  `rnnet.anchor-verification-report.v1` report. Each observation is checked only as its own
  network.

**Encoding:**

- `encodeAnchorReport(value)` returns the canonical bytes of a record or report.

**Errors.** Inputs must be `Uint8Array` (a Proxy is refused), and commitments `sha256:<64
lowercase hex>`. Anything else is a `TypeError`. Every defect in the data itself is a finding in
the record.

## Command line

```sh
node tools/verify-anchors.mjs --commitment <sha256:...> --xrpl <file> --evm <file> [--output <file>]
```

**Exit codes:** 0 `PASS`, 1 `FAIL`, 2 `UNSUPPORTED`, 64 usage error, 66 unreadable input.

**Behaviour:**

- It reads only the named files.
- It writes a new file only with `--output`.
- It opens no URLs.
