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
| `src/keyfile.mjs` | `rnnet.testnet-key-file.v1`, encrypt and decrypt **in memory only** |
| `test/fixture-keys.mjs` | Keys derived from public labels (tests and fixtures only) |

**Not in B1:**
- key generation;
- a key loader or any file access;
- a CLI or `bin`;
- stdin or `readline`;
- network access.

The dependency-boundary guard enforces these.

The libraries are approved only for **single-purpose testnet keys that hold no value**. They are not for custody: JavaScript gives no constant-time or memory-erasure guarantee. Any production or Mainnet use needs a new ADR.

**Verification moved to `txverify/` (RN-NET-03B2-B3).** `verify.mjs` and the verification half of `crypto.mjs` now live in [`txverify/`](../txverify/), unchanged in behaviour, so the keyless broadcaster never imports `signer/`. The signer needs both projects installed (`npm ci --ignore-scripts --prefix txverify` as well).
