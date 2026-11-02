# packages/broadcast-handoff

**Interface only (RN-NET-03B2-B1).** This package checks what a future broadcaster would accept. It has no transport, no RPC write method and no key.

`checkHandoff` takes:
- the approved intent and its digest;
- the signed transaction;
- the identical `rnnet.signed-tx-verification.v1` records from both verifiers (JavaScript and Python).

It does not trust the records for the bytes. It recomputes the blob hash and re-checks the intent against the approved digest. It decodes the blob with `packages/tx-intent` and compares every field with the intent. It also recomputes the XRPL transaction hash.

**What it takes from the records.** The signature checks and the Sepolia transaction hash come from the two verifiers' records, because `packages/` has no Keccak-256 and no signature code. A forged pair of records could therefore carry a bad signature. **The B3 broadcaster must re-verify the signature itself** before submitting.

The write path (XRPL `submit` with `tx_blob`, Sepolia `eth_sendRawTransaction`) is RN-NET-03B2-B3 (`packages/chain-submit`, `tools/submit/`), implemented offline only. The B3 harness calls this check and then re-verifies the signature and the Sepolia hash itself with `txverify/`. A live broadcast needs founder gate E.

- **Dependencies:** `packages/tx-intent` and the Node.js built-ins `Buffer` and `createHash`.
- **Guard rule:** this package cannot import `signer/` or the `node:crypto` signing and key APIs, and the global `crypto` is reported.
