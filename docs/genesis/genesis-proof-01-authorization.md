# Genesis Proof 01: authorization gates and execution security

- Status: Proposed (RN-NET-03B2-A). **Only gate A is authorized.**
- Decision record: [ADR-RN-016](../adr/ADR-RN-016-genesis-anchoring-transactions.md)

Every action that creates or uses a key, creates or funds an account, signs, or writes to a
network needs **its own, explicit founder decision**. Each decision:

- is recorded with its scope;
- applies to **one network** and **one attempt**;
- never carries over to another gate, another network or a retry.

An approval for a read-only RPC test does not authorize any of these gates.

## 1. Authorization matrix

| Gate | Action | Allowed under the gate | Not allowed | Preconditions | Evidence produced | Status |
|---|---|---|---|---|---|---|
| **A** | Offline preparation | Fixtures, golden values, unsigned templates, offline checks, rehearsal with synthetic data, docs, tests | Any key, account, funding, signing or network write; any live RPC call | none | This PR; CI and reference results | **Authorized (RN-NET-03B2-A)** |
| **B** | Testnet key and account creation (B-XRPL, B-SEP decided separately) | Generate **one** new Ed25519 XRPL Testnet key, or **one** new secp256k1 Sepolia key, with reviewed RN-NET code inside a network namespace; record **only** the public key and address | Importing, reusing or deriving any existing key; any Mainnet key; any Frontera or Soberanía credential; storing the secret in a repository or worktree | Gate A merged; key tooling reviewed; storage location agreed (§2) | Public key and address; key-creation log without secret | Not authorized |
| **C** | Testnet funding (C-XRPL, C-SEP) | One faucet request to the gate-B address, from a faucet the founder names | Mainnet funds, bridges, purchases, or funding from any other project's wallet | Gate B for that network | Funding transaction hash and balance (read-only check) | Not authorized |
| **D** | Signing (D-XRPL, D-SEP) | Bind the remaining fields from read-only reads; run `checkXrplAnchorTx` / `checkSepoliaAnchorTx` (must return no problems); founder approves the **exact** unsigned transaction by its digest; sign **once**, offline | Signing anything else, or a changed transaction without a new approval; blind signing | Gate C; ADR-RN-009 to 012 and 016 accepted; signer reviewed; `eth_estimateGas` confirmed (Sepolia) | Unsigned transaction and its digest; signed blob; independent decode of the blob matching the approved fields | Not authorized |
| **E** | Broadcasting (E-XRPL, E-SEP) | Submit the **one** approved signed blob from a process that has no key; resubmitting the *same* blob before expiry is allowed | A new `Sequence` or nonce, a fee bump or replacement without a new gate-D approval; any other endpoint than the reviewed providers | Gate D for that network; write path reviewed (own ADR) | Transaction hash; submit response | Not authorized |
| **F** | Public verification and publication | Read-only verification of both transactions with `--compare-providers` and captures; publishing a sanitized Genesis record: commitment, payload, transaction hashes, the dual-chain report and its stated limits | Raw RPC captures, personal paths or account secrets in public; any claim beyond ADR-RN-012 (no "proven", no claim the evidence is true) | Gates E on both networks | Live reports, dual report, public summary | Not authorized |

## 2. Key management proposal (gates B and D)

1. **New, single-purpose keys.** One XRPL Testnet Ed25519 key and one Sepolia secp256k1 key,
   used only for Genesis Proof 01. They are never imported, reused or derived from material any
   other system uses. This rules out Frontera, Soberanía and personal wallets, mnemonics, seeds and
   API credentials.
2. **Testnet only.** On Sepolia, the chain ID `0xaa36a7` is part of the signed transaction, and the
   checks refuse any other. On XRPL, Testnet and Mainnet transactions look the same offline: both
   omit `NetworkID`, so the checks **cannot** tell them apart. XRPL separation rests on two
   things: submitting only to the reviewed Testnet endpoints, and a fresh key whose account
   exists only on Testnet. The key is used for
   nothing else, before or after.
3. **Generation.** Keys come from the operating system's random source, through reviewed RN-NET
   code run in a network namespace (`unshare -rn`). Only the public key and address are printed.
4. **Storage.**
   - Keys live outside every repository and worktree, encrypted at rest, with file mode `0600`.
   - The repository guards (`secret-shapes`, `forbidden-paths`) and `.gitignore` are a last line
     of defense, not the control.
   - No key is placed in an environment variable, a shell history, a CI secret or a cloud
     service.
5. **Signing and broadcasting are kept apart.**
   - Signing runs offline and outputs only a signed blob.
   - Broadcasting runs in a separate process that never reads the key.
6. **No blind signing.** Before signing, the bound unsigned transaction is printed in full, checked
   by code, and approved by its digest.

   After signing, the blob is decoded independently, and its fields must equal the approved
   ones. Its hash is computed before broadcast:
   - XRPL: SHA-512Half of `TXN\0` + the blob;
   - Sepolia: Keccak-256 of the type-2 envelope.
7. **After Genesis Proof 01.** The keys are retired and the decision is recorded: either destroy
   them, or keep them encrypted for a later re-anchor (a founder decision). The accounts are
   never reused for anything else.

## 3. Execution security (gates D to F)

- **Request budgets.** Every live step lists its exact RPC calls and a maximum count, enforced by
  the harness, as in the SMOKE tests. There are no retries, fallbacks or polling unless the gate
  allows them.
- **Reviewed endpoints only.** Only providers in `config/rpc-endpoints.json`, selected by id. A
  write path, when approved, uses the same allowlist.
- **One attempt per approval.** A failed or expired transaction is reported and stops the run. A
  new attempt is a new gate-D decision.
  - **XRPL** expires at `LastLedgerSequence`.
  - **Sepolia has no expiry.** An underpriced transaction can stay pending and still be included
    later, until its nonce is used. A retry is therefore a gate-D **replacement with the same
    nonce** (and higher fees), never a new nonce while the first transaction is pending.
- **Evidence.** Captures and logs are written to a new local directory, without overwriting, and
  hashed. Raw captures stay local. Only sanitized summaries are published (gate F).
- **Wording.** Public text follows ADR-RN-012:
  - the anchors show the same commitment in data reported for both networks;
  - finality is a provider claim;
  - the evidence is synthetic, and the anchors say nothing about its truth.
