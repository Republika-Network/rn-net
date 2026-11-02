# txverify/

**Verification only (RN-NET-03B2-B3, ADR-RN-019 §3).** A separate npm project, not an npm workspace, imported by `signer/` (for its self-check) and by the broadcaster harness in `tools/submit/`. Nothing under `packages/` imports it. Its only dependencies are `@noble/hashes@2.4.0` and `@noble/curves@2.4.0`, pinned exactly in `package.json` and `package-lock.json`, the same pins as `signer/`. Install them with:

```
npm ci --ignore-scripts --prefix txverify
```

**The founder approved these packages here for verification-only use.** That approval does not cover key creation or signing (gates B-SEP and D-SEP).

| File | Role |
|---|---|
| `src/crypto.mjs` | Keccak-256 (`keccak_256`), secp256k1 public-key recovery (`secp256k1.Signature.fromBytes(..., 'recovered')`, `recoverPublicKey`), the EVM address, and Ed25519 verification (Node built-in `createPublicKey` and `verify`) |
| `src/verify.mjs` | `verifySignedTransaction` (the `rnnet.signed-tx-verification.v1` record), `verifyXrplSignature`, `verifySepoliaSignature` (recovered sender and Keccak-256 hash), `transactionHash`, `signedBytes` |
| `test/txverify.test.mjs` | The public known-answer vectors and every B1 golden and altered transaction |

`src/crypto.mjs` and `src/verify.mjs` are the verification half of the B1 signer, moved here unchanged in behaviour. The B1 tests and golden records still pass, and `signer/src/crypto.mjs` re-exports the moved primitives.

**What it cannot do.** It has no signing, no key generation, no derivation of a public key from a secret, and no key-file code. The dependency-boundary guard refuses, in `txverify/`:
- any noble name other than `keccak_256` and `secp256k1`, and any `secp256k1` member other than `Signature` and `verify`;
- `sign`, `getPublicKey`, `randomSecretKey`, `keygen`, `utils`, `getSharedSecret` and the other names that sign or reach keys, wherever they appear;
- `node:crypto` exports other than `createHash`, `createPublicKey` and `verify`, and `node:fs` or any network module in production code;
- any import of `signer/`, `packages/chain-submit` or a package other than `canonical` and `tx-intent`.
