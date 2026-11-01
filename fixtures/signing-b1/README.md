# fixtures/signing-b1 (RN-NET-03B2-B1)

**Synthetic test fixtures.** Nothing here was or can be submitted to a network.

| File | Content |
|---|---|
| `xrpl-intent.json`, `sepolia-intent.json` | `rnnet.unsigned-tx-intent.v1` intents for the Genesis Proof 01 commitment, with made-up `Sequence`, ledger and nonce values |
| `golden.json` | The test keys' public keys and addresses, each intent's digest, the signed transaction, its hashes, and its `rnnet.signed-tx-verification.v1` record. It also holds **45 altered transactions**, each with its hand-stated error code and expected record |

**The keys** are derived from public labels (`SHA-256("rnnet:synthetic-test-key:v1:<label>")`; for secp256k1, modulo n). Anyone can recompute them, so:
- they are test keys, not identities;
- their addresses must never be funded;
- no secret is stored here.

**Rebuilding.** `node tools/signing/build-b1-fixtures.mjs` checks that these files are current. `--write` writes them and refuses to overwrite existing files.

**Independent check.** `tools/reference/rnnet_tx_reference.py` reproduces every record without the JavaScript code.
