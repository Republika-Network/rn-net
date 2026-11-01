# packages/broadcast-handoff

**Interface only (RN-NET-03B2-B1).** This package checks what a future broadcaster would accept. It has no transport, no RPC write method and no key.

`checkHandoff` takes:
- the approved intent and its digest;
- the signed transaction;
- the identical `rnnet.signed-tx-verification.v1` records from both verifiers (JavaScript and Python).

It does not trust the records on their own. It recomputes the blob hash and re-checks the intent against the approved digest. It then decodes the blob with `packages/tx-intent` and compares every field with the intent. The signature check is left to the two verifiers.

The write path (XRPL `submit` with `tx_blob`, Sepolia `eth_sendRawTransaction`) is RN-NET-03B2-B3. It needs ADR-RN-019 and founder gate E.

- **Dependencies:** `packages/tx-intent` and the Node.js built-ins `Buffer` and `createHash`.
- **Guard rule:** this package cannot import `signer/` or any private-key API.
