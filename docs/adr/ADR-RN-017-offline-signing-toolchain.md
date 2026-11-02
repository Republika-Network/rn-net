# ADR-RN-017: Offline test-only signing toolchain and its dependencies

- Status: Proposed (RN-NET-03B2-B1)
- Date: 2026-11-01
- Amends: [ADR-RN-005](ADR-RN-005-guard-parser-dependency.md). Before this ADR, `acorn` was the only third-party package, and the guard read only `packages/`.
- Builds on: [ADR-RN-016](ADR-RN-016-genesis-anchoring-transactions.md), [ADR-RN-012](ADR-RN-012-cross-chain-trust-boundaries.md)
- Specification: [rnnet.unsigned-tx-intent.v1](../../spec/rnnet.unsigned-tx-intent.v1.md)
- Design: [RN-NET-03B2-B signing design](../genesis/rn-net-03b2b-signing-design.md). This link resolves once PR #13 merges.

## Context

Genesis Proof 01 will need two signed transactions (ADR-RN-016): an XRPL Testnet `AccountSet`
signed with Ed25519, and an EIP-1559 Sepolia transaction signed with recoverable secp256k1 over
Keccak-256. Node 22 has Ed25519. It has no Keccak-256, and its `crypto.sign` always hashes its
input, so it cannot sign a 32-byte digest.

The milestone instruction is to prefer established libraries over custom cryptography. The
founder approved exactly two packages on 2026-11-01, for **RN-NET-03B2-B1 only**: an offline,
test-only toolchain within authorization gate A.

## Decision

### 1. Dependencies: exactly two packages, pinned

| Package | Version | License | Dependencies | Integrity (`sha512`, as in the lockfile) |
|---|---|---|---|---|
| `@noble/hashes` | **2.4.0** | MIT | none | `X5XaVWZI…aW+eA==` |
| `@noble/curves` | **2.4.0** | MIT | `@noble/hashes` exactly 2.4.0 | `P4/62zrg…bq2Ew==` |

- **Pinning.** Both are pinned exactly, with no `^` or `~` ranges, in `signer/package.json` and
  `signer/package-lock.json`. The guard records the full version, source URL and integrity and
  refuses any other.
- **Checked on 2026-11-01:**
  - each tarball's integrity matches the registry;
  - neither has install scripts;
  - npm SLSA v1 provenance names `refs/tags/2.4.0` and `.github/workflows/release.yml` in
    `paulmillr/noble-hashes` and `paulmillr/noble-curves`;
  - the GitHub advisory database lists no advisories for either;
  - neither imports a `node:` built-in, a network API or `process.env`.
- **Audit limitation.**
  - **The 2026 audit is an unverified claim.** The `@noble/curves` README cites a Trail of
    Bits audit of 2.3.0 in August 2026, but the report is not published. RN-NET does not rely
    on that claim.
  - **No published audit covers the 2.x code.** The published audits of `secp256k1` and
    `weierstrass` are Trail of Bits at 0.7.3 (2023) and Kudelski at 1.2.0 (2023,
    `weierstrass` only). Neither covers 2.x.
  - **Keccak's audit is old.** Keccak in `@noble/hashes` was audited by Cure53 at 1.0.0
    (2022). `sha3.js` is byte-identical between 2.3.0 and 2.4.0.
- **Functions used.** Only `keccak_256`, and `secp256k1` `getPublicKey`, `sign` (with
  `{ prehash: false, format: 'recovered' }`) and `Signature.fromBytes(…, 'recovered')` /
  `recoverPublicKey`. `signer/src/crypto.mjs` is the only file that imports them.
- **XRPL uses no third-party code.** Ed25519 comes from Node (`createPrivateKey`, `sign`,
  `verify`), and the hashes are Node's SHA-256, SHA-512 and RIPEMD-160.

### 2. A separate signer project

- **Location.** `signer/` is its own npm project, outside `packages/`.
  - It is **not** an npm `workspaces` entry; ADR-RN-005 refuses that field.
  - `packages/**` stays dependency-free.
  - The root lockfile still holds only `acorn`.
- **Manifest.** The signer manifest may declare only the two dependencies above. It may not
  have `bin`, `scripts`, `exports`, `main`, `type` or any other dependency list.
- **CI.** CI installs the signer with `npm ci --ignore-scripts --prefix signer` in the `verify`
  job, **before** the network namespace. The offline checks then run the signer tests inside
  it. Dependency review covers `signer/package-lock.json`.

### 3. Dependency-boundary guard changes

The guard now reads `signer/**` with its own allowlist:

- **Built-ins:** `node:buffer` (`Buffer`) and `node:crypto` (`createHash`, `createPrivateKey`,
  `createPublicKey`, `sign`, `verify`, `scryptSync`, `createCipheriv`, `createDecipheriv`).
  - No `node:fs`, `node:readline`, network module or child process.
  - No `randomBytes` or `generateKeyPairSync`.
  - The guard also reports the global WebCrypto `crypto` and noble's key-generation helpers
    (`randomSecretKey`, `keygen`), in `signer/` and in `packages/*/src`.

  This removes the key-generation routes the guard checks for, including destructured names. A
  name built at run time or passed through other objects is beyond a static lint, so review
  remains the control.
  - Tests may add the usual test built-ins.
- **Third-party:** only `@noble/hashes/sha3.js` and `@noble/curves/secp256k1.js`.
- **RN-NET code:** only `packages/canonical` and `packages/tx-intent`, through their public
  entry points. Not `chain-readonly`, not the live transport, not `tools/`.
- **Inherited rules:** every code-loading, `process` and raw-text rule of `packages/` applies
  to `signer/` too.
- **Who may import `signer/`:**
  - nothing under `packages/` (already refused as an import outside `packages/`);
  - outside `packages/` and `signer/`, only `tools/signing/build-b1-fixtures.mjs` and
    `tools/signing.test.mjs`. The check reads the import specifiers, template-literal `import()`
    and one-line require-style loaders. It is a raw-text check: a defense in depth, with review
    as the control.
  - No file outside `signer/` may import `@noble/*`.
  - **Not detected:** an import specifier built at run time, a require-style loader spread over
    several lines, and a re-export of `signer/` through one of the two allowed files. Review
    covers these.
  - The signer lockfile's top-level fields and root entry must match the manifest exactly.
- **New packages:**
  - `packages/tx-intent`: built-ins `Buffer`, `createHash` and `node:util` `types`; packages
    `canonical` and `anchor`.
  - `packages/broadcast-handoff`: `Buffer` and `createHash`; package `tx-intent`. No signing or
    private-key API.

### 4. Transaction intent integrity

- **The approved object.** The founder approves an `rnnet.unsigned-tx-intent.v1` intent **by
  its digest**: SHA-256(`rnnet:unsigned-tx-intent:v1\0` ‖ canonical JSON).
- **What the signer checks before signing:**
  - the intent passes the ADR-RN-016 checks, which have moved to `packages/tx-intent`
    unchanged; `tools/genesis/prepare.mjs` re-exports them;
  - its digest equals the approved one;
  - the key is bound to the intent's network and purpose;
  - the key's address is the intent's sender;
  - on XRPL, `SigningPubKey` is the key.
- **Signing from a frozen copy.** It signs from the frozen canonical copy of the checked intent,
  never from the caller's object.
- **Self-check.** It verifies its own output before returning it.
- **Sign log.** An in-memory log allows one signature per key per signer: the same intent again
  is `RNTX_ALREADY_SIGNED`, and any other intent for that key is `RNTX_SEQUENCE_UNRESOLVED`.
  The persistent log and same-nonce replacement belong to the milestone before gate D.
- **One encoding per transaction.** The XRPL decoder refuses field IDs below 16 written in the
  extended forms. Both XRPL decoders require the received bytes to equal the canonical
  re-serialization, so a PASS concerns the received bytes. RLP is canonical by construction and
  limited to 4 levels of nesting.
- **Verification.** Signed bytes are verified against the approved intent by
  `signer/src/verify.mjs` and, independently, by `tools/reference/rnnet_tx_reference.py`.
  - The Python reference uses no cryptography library: Keccak from FIPS 202, integer
    secp256k1 and RFC 8032 Ed25519.
  - Both produce the same `rnnet.signed-tx-verification.v1` record, with one error code per
    failure in a fixed order.

### 5. Test-only key isolation, and no operational keys in B1

- **Keys exist only in tests.** The only keys are derived from public labels
  (`SHA-256("rnnet:synthetic-test-key:v1:<label>")`; for secp256k1, modulo n), so anyone can
  recompute them. They are never identities and must never be funded.
- **B1 has no route for a real key:**
  - no key generation;
  - no key loader;
  - no file access in `signer/`;
  - no CLI, `bin`, stdin or `readline`.

  The signing functions take key bytes from code. The guard limits which repository files may
  call them; that is a review control, not a guarantee.
- **Key files: format only, in memory.** `rnnet.testnet-key-file.v1` uses:
  - scrypt (N=2^17, r=8, p=1, 16-byte salt, `maxmem` raised to 256 MiB);
  - AES-256-GCM (12-byte IV, 16-byte tag);
  - authenticated data: the canonical JSON of every field except the ciphertext and the tag.

  After decryption, the public key and address are re-derived and compared with the file's. In
  B1 the caller supplies the salt and IV, and nothing is ever written to disk.
- **Later milestones, each with its own founder approval:**
  - generating, storing or loading a real key file (before gate B);
  - signing with an operational key (gate D);
  - broadcasting (B3, ADR-RN-019, gate E).

### 6. Limits of JavaScript private-key handling

- **Timing.** JavaScript gives no constant-time guarantee: the JIT and the garbage collector
  defeat it. noble documents its own limits.
- **Memory.** Key bytes in memory cannot be reliably erased. Strings are immutable, and copies
  may remain until garbage collection.
- **Scope of acceptance.** These risks are accepted only for **single-purpose testnet keys that
  hold no value**, used offline. The libraries are **not approved for production custody**.
  Any Mainnet or production use needs a new ADR and a new review.
- **Renewal.** The approval does not extend to gates B-SEP or D-SEP. Those need a renewed
  founder approval of the dependency.

## Consequences

- **What B1 adds:**
  - `packages/tx-intent` (no dependencies);
  - `signer/` (two pinned dependencies);
  - `packages/broadcast-handoff` (interface only: no transport, no write method);
  - the B1 fixtures and public known-answer vectors;
  - a Python reference.

  It creates no real key, makes no RPC call, and signs nothing that could be submitted.
- **Supply chain.** Two more packages are fetched in CI, verified against the lockfile
  integrity, with install scripts disabled. Changing a version is a reviewed change to this ADR
  and to the guard's pins.
- **Unchanged:**
  - every existing format, specification, vector and commitment;
  - the Genesis fixture and the ADR-RN-016 construction;
  - `packages/chain-readonly`, which stays read-only.
