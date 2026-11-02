# ADR-RN-017: Offline test-only signing toolchain and its dependencies

- Status: Accepted for offline gate A only (founder approval of PR #14 as implemented, RN-NET-03B2-B1 acceptance)
- Date: 2026-11-01
- Amendment C1: **Proposed** (RN-NET-03B2-C1), not accepted. Until it is accepted, the Decision below applies unchanged, and no real key may exist.
- Amends: [ADR-RN-005](ADR-RN-005-guard-parser-dependency.md). Before this ADR, `acorn` was the only third-party package, and the guard read only `packages/`.
- Builds on: [ADR-RN-016](ADR-RN-016-genesis-anchoring-transactions.md), [ADR-RN-012](ADR-RN-012-cross-chain-trust-boundaries.md)
- Specification: [rnnet.unsigned-tx-intent.v1](../../spec/rnnet.unsigned-tx-intent.v1.md)
- Design: [RN-NET-03B2-B signing design](../genesis/rn-net-03b2b-signing-design.md).

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
- **What this acceptance covers.** It accepts the decisions above as implemented in PR #14
  (`11ea4e3`), for the offline, test-only toolchain within gate A. It authorizes none of gates
  B to F: no key generation or key file on disk, no funding, no operational signing and no
  broadcasting. It does not renew the noble approval for gate B-SEP or D-SEP (§6), and it does
  not accept ADR-RN-018 or ADR-RN-019.
- **Unchanged:**
  - every existing format, specification, vector and commitment;
  - the Genesis fixture and the ADR-RN-016 construction;
  - `packages/chain-readonly`, which stays read-only.

## Amendment C1 (Proposed): testnet key generation, terminal approval and the persistent sign log

- Status: **Proposed** (RN-NET-03B2-C1). It is not accepted. Accepting it would allow the
  tooling below to be **implemented and tested offline** (milestone C4). It would authorize no
  key generation (gate B), no funding (C), no signing (D) and no broadcasting (E).
- Founder decisions behind it (2026-11-02):
  - WSL ext4 is the intended location of the encrypted testnet-only key files, outside every
    repository and worktree;
  - scrypt + AES-256-GCM, terminal-only passphrase entry and the network-purpose binding are
    kept.
- Not covered: the renewed `@noble/*` approval for gates B-SEP and D-SEP (§6 above). It is still
  a separate founder decision.
- Readiness analysis: [RN-NET-03B2-C operational readiness](../genesis/rn-net-03b2c-operational-readiness.md) §5.

### K1. Key generation (for gate B)

- **One fresh key per network, purpose `genesis-proof-01`.** There is no import, seed, mnemonic,
  derivation path or Mainnet value; the network enumeration stays `xrpl:testnet` and
  `evm:11155111`.
- **Randomness, from the operating system only:**
  - Ed25519 (XRPL): Node's `generateKeyPairSync('ed25519')`;
  - secp256k1 (Sepolia): `randomBytes(32)`, redrawn until 1 ≤ k < n. Reducing modulo n is not
    allowed. The public key and address come from the existing `secp256k1PublicKey` and
    `evmAddress`, so B-SEP needs the renewed noble approval.
- **Guard change.** `randomBytes` and `generateKeyPairSync` become allowed in exactly one file,
  `signer/src/keygen.mjs`. The rest of `signer/` keeps the §3 refusal, and noble's `keygen` and
  `randomSecretKey` stay refused everywhere.
- **Network namespace.** Generation runs under `unshare -rn`. The command refuses to run if any
  network interface other than loopback is present.
- **Output.** It prints only the network, purpose, public key, address and the key file's
  SHA-256. The secret is never printed, logged, put in an environment variable or passed as an
  argument.

### K2. Key files on WSL ext4

- **Format unchanged.** `rnnet.testnet-key-file.v1` stays exactly as in §5 above: scrypt N=2^17,
  r=8, p=1, 16-byte salt; AES-256-GCM, 12-byte IV, 16-byte tag; the authenticated data covers
  every field except the ciphertext and tag. The only change is that at gate B the salt and IV
  come from `randomBytes`, not from the caller.
- **Location.** `~/.local/share/rn-net-keys/genesis-01/` (`$XDG_DATA_HOME` when the founder sets
  it), on the WSL ext4 filesystem. One file per network: `xrpl-testnet.key.json` and
  `sepolia.key.json`. The founder passes the directory path as an argument; the code reads no
  environment variable.
- **What the key-file code refuses**, before writing and before every read:
  - a real path (after resolving symbolic links) under `/mnt/` or inside any git worktree or
    repository (walking up for `.git`);
  - a filesystem that `statfs` does not report as ext4 (magic `0xEF53`). This refuses the
    Windows drives that WSL mounts through drvfs/9p, where `0600` is not enforced;
  - a directory not owned by the user or not `0700`; a file not `0600`;
  - an existing file (keys are created with `wx` and never overwritten).
- **Durability.** The file is written to a temporary name, `fsync`ed, linked to its final
  name, and then the directory is `fsync`ed.
- **No copies.** No backup, no cloud sync, no CI secret. If a key file is lost, the network gets
  a new gate B and C with a new key.
- **Residual risk, accepted for testnet keys only:** the Windows host can read the WSL virtual
  disk.
- **Retirement** is unchanged (authorization doc §2.7).

### K3. Terminal-only passphrase and terminal approval

- **Passphrase.** Read from the controlling terminal (`/dev/tty`) with echo off, and from nowhere
  else: not from an argument, environment variable, file, pipe or stdin redirect. If no terminal
  is attached, the command refuses.
  - At gate B, it is entered twice and must be at least 20 characters.
  - It is never stored by RN-NET. How the founder keeps it is the founder's decision.
- **Terminal approval at gate D,** before the passphrase prompt:
  - the signer prints the full intent and the digest it recomputes;
  - it also prints the network, sender, `Sequence` or nonce, fee, `LastLedgerSequence` or
    `maxFeePerGas`, and the payload;
  - the approved digest is an argument, copied from the founder's gate-D record. A different
    recomputed digest is refused;
  - the founder confirms by typing the last 16 hex characters of the digest. A full 64-character
    retype would cost time in the XRPL window (ADR-RN-016 Amendment C1) without adding a
    control the argument does not already give.
- **What the prompt does not prove.** An agent can open a terminal too, so a prompt is not proof
  that a person is there. As in the signing design §4, the control is that **no agent session
  has the passphrase or runs during gates B and D**.
- **Signing runs under `unshare -rn`**, with the same interface check as K1.

### K4. Persistent, append-only sign log

- **Location.** `~/.local/state/rn-net/genesis-01/sign-log/`, separate from the key directory and
  from the broadcaster's submission log. The same checks as K2 apply: ext4, not `/mnt/`, not in
  a worktree, `0700`.
- **Entries.** Each entry is its own file, written once (`wx`, temporary file + `link()`, file
  and directory `fsync`, as the PR #20 review's follow-up N4 asks of the submission log). Entries are
  never changed or deleted. A new record format, `rnnet.sign-log-entry.v1`, is specified in C4.
  - **`SIGNING`**: network, key address, `Sequence` or nonce, intent digest. Written **before**
    the signature.
  - **`SIGNED`**: the same, plus the blob SHA-256 and the transaction hash. Written **before**
    the signed blob is written out.
  - **`RESIGN_BASIS`** (XRPL only): the digest of an `rnnet.submission-status.v1` whose finding is
    `EXPIRED` for the previous blob of that `Sequence`.
- **Rules, keyed on (key address, `Sequence` or nonce)**, as in the signing design §8:
  1. The same approved digest again is refused (`RNTX_ALREADY_SIGNED`). The blob already written
     is the output. The one exception: a `SIGNING` entry with no `SIGNED` entry means the
     process stopped before any blob left it. Ed25519 and RFC 6979 signatures are deterministic,
     so that same digest may be completed once. That produces the same bytes.
  2. A different intent for a `Sequence` or nonce that already has an entry is refused
     (`RNTX_SEQUENCE_UNRESOLVED`), with one exception: on XRPL, a `RESIGN_BASIS` entry naming an
     `EXPIRED` status record for that `Sequence`.
  3. A higher `Sequence` or nonce is refused while a lower one for that key is unresolved.
  4. Sepolia same-nonce replacement stays refused. It needs its own founder decision and tooling
     (readiness §11).
- **The log is local.** As with the submission log (ADR-RN-019), it cannot stop signing on a
  second machine. Gates B and D run on one machine.

### K5. Where the code goes (C4)

- `signer/src/keygen.mjs`: generation only (K1).
- A command-line entry point under `tools/keys/`, the only new file allowed to import `signer/`.
  It does all the argument, terminal and file I/O (K2 to K4), and it may not import a network
  module, `tools/live/`, `chain-readonly`, `chain-submit` or `node:child_process`.
- `signer/src/*` otherwise stays free of I/O.
- An independent review covers this before gate B.

### Consequences

- The crypto formats, the intent format, the verification record and every vector stay
  unchanged.
- The only new format is `rnnet.sign-log-entry.v1`, a private operational record that is never
  published.
- The guard gains three narrow exceptions (K1 randomness, the K5 entry point, K2–K4 I/O in that
  entry point). Each is pinned by a test.
