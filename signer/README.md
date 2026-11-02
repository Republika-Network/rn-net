# signer/

**Offline, test-only signing toolchain (RN-NET-03B2-B1, ADR-RN-017).** It is a separate npm project, not an npm workspace. Its only dependencies are `@noble/hashes@2.4.0` and `@noble/curves@2.4.0`, pinned exactly in `package.json` and `package-lock.json`. Install them with:

```
npm ci --ignore-scripts --prefix signer
```

| File | Role |
|---|---|
| `src/crypto.mjs` | Recoverable secp256k1 signing (noble) and Ed25519 signing (Node built-in); re-exports the verification primitives from `txverify/` |
| `src/keys.mjs` | Binds caller-supplied key bytes to one network and purpose |
| `src/sign.mjs` | Signs an approved intent once, with an in-memory sign log, then verifies its own output with `txverify/` |
| `src/keyfile.mjs` | `rnnet.testnet-key-file.v1`, encrypt and decrypt **in memory only**; a new file needs a 20-character passphrase, decryption still accepts 12 (C4) |
| `src/keygen.mjs` | Key generation (RN-NET-03B2-C4): Ed25519 from the operating system, secp256k1 by rejection sampling, key-file salt and IV. The only `signer/` file allowed to draw randomness. Generation only: no file, terminal or network access |
| `test/fixture-keys.mjs` | Keys derived from public labels (tests and fixtures only) |

**Not in `signer/`:**
- a key loader or any file access (the C4 key tool, [`tools/keytool/`](../tools/keytool/README.md), does all file and terminal I/O);
- a CLI or `bin`;
- stdin or `readline`;
- network access.

Key generation exists only in `src/keygen.mjs` (RN-NET-03B2-C4), is implemented and tested offline with synthetic sources, and is run for real only at gate B, a separate founder authorization.

The dependency-boundary guard enforces these.

The libraries are approved only for **single-purpose testnet keys that hold no value**. They are not for custody: JavaScript gives no constant-time or memory-erasure guarantee. Any production or Mainnet use needs a new ADR.

**Verification moved to `txverify/` (RN-NET-03B2-B3).** `verify.mjs` and the verification half of `crypto.mjs` now live in [`txverify/`](../txverify/), unchanged in behaviour, so the keyless broadcaster never imports `signer/`. The signer needs both projects installed (`npm ci --ignore-scripts --prefix txverify` as well).
