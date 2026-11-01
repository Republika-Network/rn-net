# RN-NET-03B2-B: signing architecture design proposal

- Status: **Proposal** (RN-NET-03B2 governance closure). No decision is taken here except the
  founder's dependency approval recorded in §1. Each decision goes into its own ADR (§12), and
  nothing below is implemented or installed by this document.
- Builds on: [ADR-RN-009 to 012](../adr/README.md) (Accepted; PR #12, merged as `a800cbf`),
  [ADR-RN-013](../adr/ADR-RN-013-read-only-rpc-architecture.md),
  [ADR-RN-016](../adr/ADR-RN-016-genesis-anchoring-transactions.md),
  [preflight](genesis-proof-01-preflight.md), [authorization](genesis-proof-01-authorization.md)
- Genesis values (unchanged): commitment
  `sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7`; payload
  `524e4e4554414e430101a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7`.

**Gate A only.** This proposal creates no key, account or wallet. It signs, funds and broadcasts
nothing, deploys nothing and installs nothing. The registry facts in §1 come from read-only
`npm view` metadata queries made on 2026-11-01.

## 1. Sepolia: Keccak-256 and recoverable secp256k1

Node 22 has neither Keccak-256 nor a way to sign a raw 32-byte digest with secp256k1.
`crypto.sign` always hashes its input first. A third-party library is therefore needed, and
ADR-RN-005 makes that a founder decision: today the repository's only package is `acorn`, and it
is for development only.

### Candidates

| Package | Version | License | Runtime dependencies | Unpacked size | Assessment |
|---|---|---|---|---|---|
| **`@noble/hashes`** | **2.4.0** (exact) | MIT | **none** | 0.7 MB | **Approved.** Provides `keccak_256`. Cure53 audit at 1.0.0 (Jan 2022), with SHA-3/Keccak in scope; report published in the project repository |
| **`@noble/curves`** | **2.4.0** (exact) | MIT | `@noble/hashes` (exact pin) | 1.6 MB | **Approved.** Its README lists audits: Trail of Bits at 2.3.0 (Aug 2026, full scope; **report not published**, see below); Trail of Bits at 0.7.3 (2023, `secp256k1` and `weierstrass` in scope); Kudelski (2023); Cure53 (2024) |
| `micro-eth-signer` | 0.20.1 | MIT | `micro-packed`, `@noble/curves`, `@noble/hashes`, `@noble/ciphers` | 3.1 MB | Not chosen. Pre-1.0, and it pulls in two more packages for functions we don't need |
| `@ethereumjs/tx` | 10.1.3 | MPL-2.0 | `@ethereumjs/{rlp,util,common}` and noble, all as `^` ranges | 1.1 MB | Not chosen. Its dependencies are ranges, not pins; it is a large framework; and its license differs |
| `ethers` | 6.17.0 | MIT | 7, including `ws`, `aes-js` (beta), an old noble 1.2.0 and `@types/node` | 13 MB | Not chosen. It includes network providers and wallet code, and its graph is large |
| `viem` | 2.57.14 | MIT | 8, including `ox`, `ws`, `abitype` and BIP-32/39 | 29 MB | Not chosen. Its graph is large, it includes networking, and the latest version was published today |
| `ox` | 1.8.12 | MIT | 10, including `zod` and post-quantum | 18 MB | Not chosen, for the same reasons |

### Decision: founder-approved versions

**The founder approved exactly `@noble/hashes@2.4.0` and `@noble/curves@2.4.0`** on 2026-11-01,
for RN-NET-03B2-B1 only. That milestone is the offline, test-only signing toolchain within gate
A. Both versions are pinned exactly, with no `^` or `~` ranges. ADR-RN-017 will record the
decision.

**What the approval does not cover.** It does not authorize:
- operational keys or funding;
- signing a live transaction;
- broadcasting;
- any Mainnet access.

**Testnet only, not production custody.** These libraries are approved only for testnet keys
that are single-purpose and hold no value. Nothing in RN-NET makes them suitable for custody of
value: JavaScript gives no constant-time or memory-erasure guarantees (below). Any production
or Mainnet use needs a new ADR and a new review.

RN-NET uses only these functions:

- **Keccak-256:** `keccak_256` from `@noble/hashes/sha3.js`.
- **Signing:** `secp256k1.sign(digest, key, { prehash: false, format: 'recovered' })`. This
  returns the recovery bit together with `r` and `s`, and the library produces low-s signatures.
- **Recovery:** `secp256k1.Signature.fromBytes(sig, 'recovered')` and its recovery method. These
  serve **only** as the signer's self-check; independent checks are in §9.
- **The recovery byte** is the first byte of the 65-byte `recovered` format and can be 0–3. The
  signer refuses 2 or 3. It writes y-parity = the recovery byte, and a test pins that mapping.

**Why 2.4.0 rather than 2.3.0:**
- **Both contain the Trail of Bits fixes.** The 2.3.0 release notes list them, including
  binding recovered ECDSA signatures to their recovery id, so 2.4.0 has them too.
- **2.4.0 only adds hardening.** A file-by-file comparison of the published tarballs shows:
  - `sha3.js` (Keccak): unchanged;
  - `secp256k1.js`: 5 changed lines, Schnorr only;
  - `abstract/weierstrass.js`: 72 changed lines of hardening. ECDSA and ECDH reject the point
    at infinity as a public key, DER signature size is bounded, and inputs are snapshotted.
- **It is not new.** 2.4.0 was published on 2026-08-27, more than two months before approval.

**Audit limitation.** The README says Trail of Bits audited version 2.3.0 in August 2026, but
**the report has not been published**. On 2026-11-01 the project's `audit/` folder held only the
2023 Trail of Bits, 2023 Kudelski and 2024 Cure53 reports. The README links only to the Trail of
Bits website, not to a report. RN-NET therefore treats the 2026 audit as **an unverified claim** and does not rely on
it.

**No published audit covers the 2.x `secp256k1` or `weierstrass` code.** The published audits
and their scope:
- **Trail of Bits, 0.7.3 (2023):** covered `secp256k1` and `weierstrass`, three major versions
  before 2.4.0.
- **Kudelski, 1.2.0 (2023):** a Starknet audit that included `weierstrass`, not `secp256k1`.
- **Cure53, 1.6.0 (2024):** covered neither.

The supporting evidence that was checked:
- those earlier published audits, with the version gap above;
- the release notes;
- the reviewed 2.3.0 → 2.4.0 diff;
- RN-NET's own known-answer tests (§9).

**Checked on 2026-11-01** (scratch copies of the tarballs, outside the repository):
- **Integrity:** each tarball's SHA-512 integrity matches the registry.
- **Install scripts:** none.
- **Provenance:** npm SLSA provenance names `refs/tags/2.4.0` and `.github/workflows/release.yml`
  in `paulmillr/noble-curves` and `paulmillr/noble-hashes`.
- **Advisories:** the GitHub advisory database lists none for either package.
- **Capabilities:** no `node:` imports, no network APIs, no `process.env`.
- **Known-answer tests:** run offline under `unshare -rn` and all pass:
  - Keccak-256 of `""` and `"abc"`;
  - the EIP-155 example's signing hash, `r`, `s`, recovery id and sender;
  - a pure-Python cross-check that recovers the same sender.

### Security implications

- **Supply chain.** Two packages are pinned in a separate `signer/package.json` and
  `signer/package-lock.json`, with exact versions and integrity hashes, and installed with
  `npm ci --ignore-scripts`. The root lockfile still contains only `acorn`. The `dependency-boundaries`
  guard is extended so that only the signer workspace (§3) may import them, and nothing under
  `packages/` may. This **amends ADR-RN-005**, under which `acorn` was the only third-party
  package and the guard read only `packages/`. ADR-RN-017 must record that amendment.
- **Constant time.** The noble README states that JavaScript cannot be relied on to run in
  constant time. That risk is accepted only because these keys are single-purpose testnet
  keys holding no value, and signing runs once, offline, on the founder's machine.
- **Memory.** Key bytes in JavaScript cannot be reliably erased. The signer runs as a
  short-lived process that holds the key for one signature, then exits.
- **Rejected route: writing secp256k1 ourselves.** It is possible against test vectors, but an
  original ECDSA signer is a larger and riskier review than a pinned, widely used library
  with published (if older) audits. That matches
  this milestone's instruction to prefer established libraries.

## 2. XRPL Testnet Ed25519 compatibility

XRPL needs no third-party package:

- **Signing:** Ed25519 through `crypto.sign(null, message, key)`. The message is
  `STX\0` (`53545800`) followed by the transaction serialized without `TxnSignature`. Ed25519
  signs the whole message; there is no prehash.
- **`SigningPubKey`:** `ED` followed by the 32-byte public key.
- **`Account`:** `RIPEMD-160(SHA-256(SigningPubKey))`, base58check-encoded with the XRPL alphabet
  and version byte `0x00`. `ripemd160` and `sha256` are built in to Node 22.23.1, checked locally.
- **Transaction hash:** SHA-512Half of `TXN\0` followed by the signed blob. This is already
  handled by the preflight hash checks.
- **Serializer.** An original, minimal XRPL binary serializer is needed. It handles only the
  fields ADR-RN-016 allows (`TransactionType`, `Flags`, `Sequence`, `LastLedgerSequence`, `Fee`,
  `SigningPubKey`, `TxnSignature`, `Account`, `Memos`/`Memo`/`MemoType`/`MemoData`), in canonical
  field order, and refuses any other field. Fields are sorted by type code, then by field code.

**Libraries rejected:**
- `xrpl` 5.3.0: 11 dependencies, a WebSocket client, and seed and secret handling.
- `ripple-keypairs` 3.1.0 and `ripple-binary-codec` 2.11.0: both pull in `@xrplf/isomorphic`,
  and through it `ws` and `eventemitter3`. The codec has 318 files and needs `bignumber.js`.

Their published binary-codec fixtures could still be used as reference vectors. That needs a
check against the `upstream-content` guard and a license note (ISC) before anything is copied.

## 3. Proposed package architecture

```
packages/tx-intent/         (new; no dependencies; built-ins: Buffer, createHash)
    canonical unsigned intent, intent digest, XRPL codec (encode/decode, allowed
    fields only), RLP codec, EIP-1559 field mapping, the ADR-RN-016 checks
    (moved from tools/genesis/prepare.mjs); outputs signing preimages, never signs
packages/chain-readonly/    (existing) + preparation readers (§6); still read-only
signer/                     (new workspace OUTSIDE packages/; the only importer of noble)
    keygen  (gate B)  · sign (gate D)  · keyfile (§4)
    imported by nothing; never imports chain-readonly, the transport or node:net/https
packages/chain-submit/      (new; no dependencies; separate ADR) keyless broadcaster (§5)
tools/reference/rnnet_tx_reference.py
                            independent Python decode and verification (§9)
```

### Rules, enforced by extending `dependency-boundaries`

- `packages/**` stays dependency-free. Only `signer/` may import `@noble/*`.
- The guard parses `signer/**` itself, with its own allowlist of built-ins and exports. Today it
  reads only `packages/`, so this is new.
- `signer/` is a separate npm project with its own lockfile. It is **not** an npm `workspaces`
  entry; ADR-RN-005 refuses that field.
- `tools/**` stays exempt from import checks: it is trusted repository tooling and may import
  `signer/`, for tests and fixture generation only.
- **No route for a real key in B1** (finding 10 of the PR #13 review):
  - `signer/` has no `bin`;
  - it may not use `node:fs`, `readline`, `process.argv` or stdin.

  So the B1 signing functions can be called only from code, with key bytes the caller already
  holds; in B1 that means only label-derived test keys.
- `signer/` may not import anything that reaches the network: no `node:net`, `node:tls`,
  `node:http(s)`, `node:dgram` or `fetch`, and not the `chain-readonly` transport.
- `chain-submit` may not import `signer/`, `node:fs` key paths, or any private-key API. Its
  only crypto import is `createHash`.
- **`tx-intent` sits between them.** The signer and the broadcaster both depend on it, never on
  each other.

ADR-RN-001 says RN-NET "does not sign artifacts on behalf of any other system". This proposal
is consistent with that: the signer signs only RN-NET's own testnet anchor transactions.

## 4. Testnet-only key isolation and storage

- **Generation (gate B).** `signer keygen --network xrpl-testnet|sepolia --purpose
  genesis-proof-01`:
  - runs under `unshare -rn`;
  - takes its randomness from the operating system (Node's built-in `generateKeyPairSync` for
    Ed25519; `crypto.randomBytes` with rejection sampling below the curve order for
    secp256k1);
  - prints only the public key and address.
- **Key file.** A new format, `rnnet.testnet-key-file.v1`, holding:
  - format, network, purpose and creation time;
  - public key and address;
  - the encryption parameters:
    - **KDF:** scrypt, N=2^17, r=8, p=1, a 16-byte random salt. This needs about 128 MiB, so
      Node's `maxmem` must be raised above its 32 MiB default.
    - **Cipher:** AES-256-GCM, with a 12-byte (96-bit) random IV and a 16-byte tag.

    Both are built in to Node.
  - the ciphertext.

  **Additional authenticated data:** the canonical JSON of **every field except the ciphertext
  and the tag**, so changing any of them makes decryption fail.

  **After decryption** the signer re-derives the public key and address from the secret and
  refuses the file unless both match.
- **Location.** `$XDG_DATA_HOME/rn-net-keys/genesis-01/` (by default
  `~/.local/share/rn-net-keys/…`):
  - directory mode `0700`, file mode `0600`;
  - written with `wx`, so an existing key is never overwritten;
  - the signer refuses a key file inside any git worktree, and refuses wider permissions;
  - on WSL2 it refuses paths under `/mnt/*` (Windows drives mounted through drvfs), where
    `0600` is not enforced. The Windows host can still read the WSL filesystem, a residual risk
    accepted only for testnet keys.
- **Passphrase.** Entered by the founder at a terminal prompt, never through an argument, an
  environment variable, a file or a CI secret. A terminal prompt does not prove that a person is
  present; an agent can allocate a terminal too. The control is that **no agent session ever
  has the passphrase**. The founder runs gates B and D personally, and no agent session runs at
  the same time.
- **Testnet binding.** A key file is bound to one network:
  - the signer refuses an intent whose network differs from the key file's;
  - **before signing**, it refuses an intent whose `Account` (and `SigningPubKey`) or `from`
    differs from the key's own address;
  - there is no Mainnet value anywhere in the network enumeration;
  - no import, mnemonic, seed or derivation path is supported. Only fresh keys can exist.
- **Retirement.** The founder chooses either destruction (shredding the file) or retention for
  a re-anchor, and the decision is recorded (authorization doc §2.7).

## 5. Signing and broadcasting are separate

| | Signer (`signer/`) | Broadcaster (`packages/chain-submit`) |
|---|---|---|
| Reads | key file, approved intent, approval digest | signed blob, PASS verification record (§5.1), endpoint config |
| Network | none (`unshare -rn`, and the guard) | the reviewed providers only, write methods below |
| Holds a key | for one signature | never |
| Writes | the signed blob file (`wx`) and a sign log | a capture of the submit exchange (`wx`) |

**Write methods allowed** (write-path ADR):
- XRPL: `submit` with `tx_blob` only;
- Sepolia: `eth_sendRawTransaction`.

The broadcaster refuses `submit` with `secret`, `seed` or `key_type`, and refuses `sign`,
`sign_for`, `wallet_propose`, `eth_sendTransaction`, `eth_sign*` and `personal_*`. Request
budgets are as in the authorization doc §3: one request, no retries, except resubmitting the
same blob where gate E allows it.

### 5.1 Hand-off

The broadcaster accepts a blob only when it comes with a verification record (§7) that:
- gives the blob's SHA-256 and the approved intent digest;
- reports `PASS` from both the JavaScript and the Python verifiers.

A record is a file anyone can write, an agent at gate E included, so the broadcaster does not
trust it alone:
- it recomputes the blob hash;
- it decodes the blob itself with `tx-intent`;
- it checks every field against the approved intent;
- it recomputes the intent digest and compares it with the approved one.

Only the signature check stays with the two verifiers, because `packages/` has no Keccak.

## 6. Read-only RPC methods for preparation

These are additions to the `chain-readonly` allowlist (an amendment to ADR-RN-013). None of
them writes.

| Network | Method | Used for |
|---|---|---|
| XRPL | `account_info` (`ledger_index: "validated"`, `signer_lists: true`) | The account exists. Its `Sequence`. Its balance against the reserve plus the fee. No `RegularKey` or signer list |
| XRPL | `server_info` (already allowed) | `network_id` = 1 from **both** reviewed providers. The validated ledger index, used for `LastLedgerSequence`. The base and load fee, which must be ≤ 12 drops |
| Sepolia | `eth_chainId` (already allowed) | `0xaa36a7` from both providers |
| Sepolia | `eth_getTransactionCount` (`latest` and `pending`) | The nonce. The two must be equal (nothing pending) |
| Sepolia | `eth_getBalance` (`latest`) | Balance ≥ 30,000 × `maxFeePerGas` |
| Sepolia | `eth_getCode` (`latest`) | Must be `0x`: no code and no EIP-7702 delegation (ADR-RN-016) |
| Sepolia | `eth_estimateGas` (the exact unsigned call) | Must be ≤ 30,000, and is expected to be 22,680 |
| Sepolia | `eth_getBlockByNumber` (`latest`, already allowed) | `baseFeePerGas`, which goes into `maxFeePerGas` |

`fee`, `eth_gasPrice`, `eth_maxPriorityFeePerGas` and `eth_feeHistory` are **not** needed,
because the fee rules are fixed (§7). Each preparation run states its exact request list and
budget.

## 7. Intent, approval and verification of signed bytes

1. **Bind.** The preparation reads (§6) fill the template's `null` fields. The bound object must
   pass `checkXrplAnchorTx` or `checkSepoliaAnchorTx` with no problems.
2. **Intent.** Format `rnnet.unsigned-tx-intent.v1`, holding:
   - network;
   - the bound transaction;
   - the commitment and payload;
   - the preparation observations: provider ids, ledger or block numbers, request digests.

   Its digest is SHA-256(`rnnet:unsigned-tx-intent:v1\0` ‖ canonical JSON).
3. **Founder approval (gate D).** Before the passphrase prompt, the signer prints the full
   intent, its decoded fields and its digest. The founder approves the printed intent **by its
   digest**.
4. **Signing.** The signer:
   - recomputes the digest, which must equal the approved one;
   - re-runs the check;
   - serializes the transaction and signs it **once**;
   - writes the blob.

   Signing exactly the canonical JSON of the checked object (ADR-RN-016 §3) closes the gap that
   [PR #10 review](https://github.com/Republika-Network/rn-net/pull/10#issuecomment-6562299674) finding 1 found between what is checked and what is signed.
5. **Independent verification** of the blob against the intent, in JavaScript (`tx-intent`
   decode) and Python (§9):
   - The blob decodes. It has no trailing bytes and no fields beyond the allowed set.
   - Every decoded field equals the intent's field.
   - **XRPL:**
     - the signature verifies (Ed25519) over `STX\0` ‖ the serialized transaction without
       `TxnSignature`;
     - `Account` is derived from `SigningPubKey`;
     - `Memos` is exactly the 73-byte anchor memo.
   - **Sepolia:**
     - type byte `0x02`, and RLP in canonical form (minimal integers, no leading zeros);
     - `chainId` = 11155111, `to` = the sender, `value` = 0, and `data` = the payload;
     - y-parity is 0 or 1, and `s` ≤ n/2 (EIP-2);
     - the sender recovered from the signature equals the intent's `from`.
   - The transaction hash is computed:
     - XRPL: SHA-512Half(`TXN\0` ‖ blob);
     - Sepolia: Keccak-256 of the type-2 envelope.
6. **Verification record.** Holds the blob SHA-256, the intent digest, the transaction hash and
   both verifier outcomes.

## 8. Fees, gas, network binding and replay protection

### Fees and gas (pinned by ADR-RN-016)

- **XRPL fee:**
  - 12 drops, with a hard cap of 1,000;
  - if the load-scaled fee in `server_info` is above 12, the run **stops**. It does not raise
    the fee.
- **Sepolia:**
  - **Fees:** `maxFeePerGas` = min(2 × base fee + 1 gwei, 20 gwei); tip 1 gwei.
  - **Gas limit:** 30,000.
  - **Refusals:** the run stops if `eth_estimateGas` is above 30,000, if the base fee is above
    19 gwei, or if the balance is below the worst case.
  - **Worst case:** 0.0006 ETH.
- **Re-checking.** The signer re-checks every one of these bounds from the intent, so a hostile
  provider can't push them past the caps.

### Network binding

- **Sepolia.** The chain ID is inside the signed type-2 payload, so the signature is invalid on
  any other chain. Two further checks:
  - both providers must report `0xaa36a7`;
  - the signer refuses any other value.
- **XRPL.** Testnet omits `NetworkID` (network ID 1 is at most 1024), so an identical blob is
  also valid on Mainnet if the same account and `Sequence` exist there. That replay is
  **mitigated, not prevented**. Once the blob is public on Testnet, anyone could relay it to
  Mainnet. It would succeed only if:
  - the account exists on Mainnet;
  - its next `Sequence` is the signed one (a new account's first `Sequence` is the ledger index
    at which it was created);
  - the Mainnet ledger is still at or below `LastLedgerSequence`.

  The mitigations: a fresh key that is never funded on Mainnet, and an expiry 20 ledgers after
  the Testnet validated ledger. **Residual risk:** the address is public, and anyone can fund it
  on Mainnet. For a zero-value `AccountSet` anchor, the consequence would be a duplicate anchor
  on Mainnet, not a loss.

  `network_id` = 1 from both providers, and submitting only to the reviewed Testnet endpoints,
  bind *our* submission to Testnet. They do not stop a third party from relaying.

### Replay and double-anchoring

- **XRPL:** `Sequence` comes from `account_info` on a validated ledger, and the transaction
  expires at `LastLedgerSequence`.
- **Sepolia:**
  - the nonce is used only when the `pending` and `latest` counts are equal;
  - the transaction has no expiry, so a retry is a gate-D **same-nonce replacement**, never a
    new nonce;
  - signing the same intent digest twice is refused, using the sign log.
- **The sign log is keyed on (key, nonce or `Sequence`)**, not only on the intent digest.
  Re-signing the same digest is harmless: RFC 6979 gives the same transaction. The real
  double-anchor risk is a second, different intent. The signer refuses any intent:
  - that uses a nonce or `Sequence` beyond one that was signed and is still unresolved;
  - on Sepolia, that reuses a signed nonce other than as a gate-D same-nonce replacement;
  - on XRPL, that uses a new `Sequence` before a validated ledger past the first transaction's
    `LastLedgerSequence` shows the first transaction absent.

  In B1 the log exists **in memory only**. The persistent log belongs to the milestone before
  gate D.
- **Cross-network:** the two networks use different curves and different keys, and every key
  file is bound to one network.

## 9. Offline negative tests and independent verification

**Independent verification.** A new file, `tools/reference/rnnet_tx_reference.py`, run with
`python3 -I -B` in `offline-checks.sh`. It follows the pattern of the existing RFC 8032
Ed25519 reference, using the Python standard library and RN-NET-written code only:

- Keccak-256 written from FIPS 202 Keccak-f[1600] with the original padding `0x01`. Python's
  `hashlib.sha3_256` uses different padding and is **not** used.
- secp256k1 recovery and verification with integer arithmetic. This is verification only;
  Python never signs.
- RLP and XRPL binary decoders.
- Ed25519 verification reused from `rnnet_evidence_reference.py`.

It also closes [PR #10 review](https://github.com/Republika-Network/rn-net/pull/10#issuecomment-6562299674) follow-up 10: it re-implements the ADR-RN-016 checks.

**Vectors.**
- Public Keccak-256 known-answer values, and the empty-input digest.
- Fixture keys derived from public labels, as today (`rnnet:synthetic-test-key:v1:<label>`;
  for secp256k1, reduced modulo n and checked to be non-zero). They are never identities and
  never funded.
- Golden signed blobs that **both** implementations decode and verify.

**Negative tests.** Each asserts its specific failure reason, which closes review follow-up 7
([PR #10 review record](https://github.com/Republika-Network/rn-net/pull/10#issuecomment-6562299674)).

**Milestone.** Tests marked *(later)* need the file system, a persistent sign log or the
broadcaster, all of which the founder excluded from B1. They belong to the milestone before gate B
(key files on disk), before gate D (persistent sign log) or B3 (broadcaster), and **are not part
of B1**. Everything else is in B1.

- **Intent and approval:**
  - the approval digest doesn't match;
  - the intent fails its check;
  - a template field is still `null`;
  - the data is non-plain (Proxy, getter, prototype);
  - the same intent, or another intent for an unresolved nonce or `Sequence`, is signed again
    (B1: in-memory log; persistent log *(later)*).
- **Key file:**
  - wrong network;
  - wrong purpose;
  - tampered additional authenticated data;
  - wrong passphrase;
  - the file is inside a worktree *(later)*;
  - mode wider than `0600` *(later)*;
  - an existing file would be overwritten *(later)*.
- **XRPL blob:**
  - an extra or reordered field, or a `NetworkID`;
  - a second memo, or a `MemoFormat`;
  - fee above 12 or above 1,000;
  - a missing `LastLedgerSequence`;
  - `Flags` other than 0;
  - a flipped signature bit;
  - an `Account` that doesn't match the key;
  - trailing bytes.
- **Sepolia blob:**
  - type 0 or 1, or legacy encoding;
  - chain ID 1;
  - non-canonical RLP;
  - high `s`;
  - y-parity 2;
  - `to` ≠ sender;
  - `value` ≠ 0;
  - changed `data`;
  - gas above 30,000;
  - fee above the cap;
  - a non-empty access list;
  - a recovered sender that doesn't match.
- **Isolation and guards:**
  - `signer/` imports a network module;
  - `chain-submit` imports `signer/` or a private-key API;
  - `packages/**` imports `@noble/*`;
  - the lockfile contains a package outside the pins.
- **Broadcaster** *(later, B3)*:
  - a blob without a PASS record;
  - a record whose blob hash doesn't match;
  - a forbidden method;
  - a request over budget.

**Independent review.** A separately instructed reviewer, as for PR #10, reviews the signer, the
codecs and the guards before gate B.

## 10. Founder authorization gates B–F

These gates are the ones in the [authorization document](genesis-proof-01-authorization.md).
This proposal changes none of them; it only says which tooling each gate needs.

| Gate | Needs, beyond the authorization doc | Run by |
|---|---|---|
| B-XRPL, B-SEP | ADR-RN-017 accepted; `signer keygen` merged and reviewed; key location agreed; **for B-SEP, a renewed founder approval of the noble dependency**, since the current one covers B1 only | Founder, at the terminal (passphrase) |
| C-XRPL, C-SEP | A faucet the founder names; a read-only balance check (`account_info`, `eth_getBalance`) | Founder |
| D-XRPL, D-SEP | ADR-RN-009 to 012 and 016 accepted; ADR-RN-018 accepted; for D-SEP, the renewed noble approval; preparation reads authorized; intent approved by digest; dual verification PASS | Founder, at the terminal (passphrase) |
| E-XRPL, E-SEP | ADR-RN-019 (write path) accepted; `chain-submit` merged and reviewed | Agent or founder; the broadcaster holds no key |
| F | Both E gates done; live read-only verification | Agent, read-only |

## 11. Remaining blockers carried from the preflight

- **1RPC finalized-block lag:** unresolved, and needs its own read-only comparison.
- **SMOKE-01 raw evidence:** not recovered.
- **Sepolia calldata gas:** confirmed only by `eth_estimateGas` at gate D.

## 12. Proposed ADRs and next milestone

| ADR | Subject |
|---|---|
| ADR-RN-017 | Signing dependencies (`@noble/curves` and `@noble/hashes` 2.4.0, exact; approval limited to B1), the ADR-RN-005 amendment, the `signer/` project and its guard rules, the testnet key-file format |
| ADR-RN-018 | Transaction-preparation reads: an ADR-RN-013 amendment for the §6 methods |
| ADR-RN-019 | Write path: the keyless broadcaster and its method allowlist |

**Next bounded milestone: RN-NET-03B2-B1, offline signing toolchain.** It stays within gate A:
fixture keys only, offline, nothing live. It includes:

- ADR-RN-017;
- installing the two pinned packages (approved: `@noble/hashes@2.4.0`, `@noble/curves@2.4.0`);
- `packages/tx-intent`;
- `signer/` signing and verification, exercised only with label-derived fixture keys;
- the key-file format, tested in memory only.

  B1 has **no `keygen`**, no file-based key loader and no interactive signing CLI. Those
  belong to the milestone before gate B, and each needs its own approval.

B1 also includes:

- `rnnet_tx_reference.py`;
- the guard extensions;
- the §9 negative tests;
- an independent review.

It creates no real key, makes no RPC call, and has no write path. ADR-RN-018 and ADR-RN-019
follow as B2 and B3, each with its own approval.
