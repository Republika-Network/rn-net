# tools/keytool/

**The founder's testnet key tool (RN-NET-03B2-C4; ADR-RN-017 Amendment C1, K1 to K5, which is
Proposed).** Implemented and tested **offline, with synthetic keys only**. Running `keygen` for
real is gate B, and running `sign` for real is gate D, each a separate founder authorization per
network. Neither is authorized by C4; gates B-SEP and D-SEP also still need the renewed `@noble/*`
decision.

The directory is named `keytool/`, not `keys/` as K5 wrote, because `.gitignore` and the
forbidden-paths guard refuse every `keys/` directory, and that control is kept.

| File | Role |
|---|---|
| `cli.mjs` | The entry point: `keygen`, `show`, `sign`. The only file here that imports `signer/` (`keygen.mjs`, `keyfile.mjs`, `sign.mjs`) |
| `terminal.mjs` | `/dev/tty` in raw mode, no echo unless asked. The only file that touches the terminal |
| `isolation.mjs` | Refuses any network interface or route other than loopback, and real root |
| `location.mjs` | Private-directory checks: absolute, real path, not `/mnt/`, not in a repository, ext4, owner, `0700` |
| `files.mjs` | Exclusive durable creation (temporary name, `fsync`, `link()`, directory `fsync`) and safe reads |
| `keystore.mjs` | Key files by fixed name per network; never sees a secret |
| `signlog.mjs`, `signlog-store.mjs` | [`rnnet.sign-log-entry.v1`](../../spec/rnnet.sign-log-entry.v1.md) |
| `errors.mjs` | `RNKEY_*` refusal codes |

The guard (`tools/guards/dependency-boundaries.mjs`, `KEYTOOL`) pins all of this: no environment
variable, no network module, child process, worker or code loader; `node:crypto` only to hash;
imports only of this directory, `canonical`, `tx-intent` and `txverify`; nothing here may reach a
network file through the import graph; and only the key tool's own tests and the C4 fixture
generator may import it.

## Commands

```
unshare -rn node tools/keytool/cli.mjs keygen --network <net> --purpose genesis-proof-01 \
    --key-dir <dir> --log-dir <dir>
node tools/keytool/cli.mjs show --network <net> --key-dir <dir> [--log-dir <dir>]
unshare -rn node tools/keytool/cli.mjs sign --network <net> --key-dir <dir> --log-dir <dir> \
    --out-dir <dir> --intent <file> --approved-digest sha256:<64 hex> [--resign-basis <file>]
```

`<net>` is `xrpl:testnet` or `evm:11155111`. Every path is absolute. The intended locations
(K2, K4) are `~/.local/share/rn-net-keys/genesis-01/` for keys and
`~/.local/state/rn-net/genesis-01/sign-log/` for the log, on WSL ext4. Exit codes: 0 done, 1
refused, 2 usage.

- **No passphrase option.** There is no argument, environment variable, file or pipe for it.
  `keygen` and `sign` refuse unless standard input and output are terminals and `/dev/tty` opens.
- **`keygen`** checks the directories (making each one level deep, `0700`, if missing), refuses
  an existing key, partial file or recorded key for that network and purpose, prints the network,
  purpose and paths, reads the passphrase twice without echo (at least 20 characters after NFC),
  generates the key (Ed25519 from the operating system; secp256k1 by rejection sampling), encrypts
  it in the unchanged `rnnet.testnet-key-file.v1` format with a fresh salt and IV, writes it
  durably (`0600`), reads it back and decrypts it, appends `KEY_CREATED`, and prints only public
  metadata. It never continues to signing.
- **`show`** prints a key file's public members and hash, and, with `--log-dir`, whether the log
  is consistent and records that exact file. It reads no passphrase.
- **`sign`**:
  1. checks isolation, the three directories (separate, private) and the intent, which must equal
     the approved digest **exactly** when recomputed (`RNTX_INTENT_DIGEST_MISMATCH` otherwise);
  2. checks the key file's public members against the intent (network, purpose, sender, XRPL
     `SigningPubKey`) and the sign log (§5 of the spec): `RNTX_ALREADY_SIGNED`,
     `RNTX_SEQUENCE_UNRESOLVED`, `RNKEY_KEY_NOT_REGISTERED` and `RNKEY_RESIGN_BASIS_INVALID` are
     refused here, before any prompt;
  3. prints the network, purpose, sender, `Sequence` or nonce, fee, `LastLedgerSequence` or gas
     and fee caps, payload, the canonical intent and the **complete 64-character digest**;
  4. asks the founder to type the **last 16 characters** of the digest (echoed), and refuses
     anything else (`RNKEY_CONFIRMATION_MISMATCH`), with no retry and no passphrase prompt;
  5. reads the passphrase without echo and decrypts the key; re-reads the log and re-decides;
  6. appends `RESIGN_BASIS` (XRPL re-sign only) and `SIGNING`; signs with the B1 signer, which
     re-checks everything and verifies its own output; stages the output; appends `SIGNED`; links
     the output to `<network>-<sequence>-<first 16 hex of the digest>.signed.json` (`0600`); and
     prints the public result and the fields the gate-E authorization will need.

  The signed output is the B1 signer's result (`signedTransaction`, `blobSha256`,
  `transactionHash`, the `rnnet.signed-tx-verification.v1` record), unchanged.

## Crash recovery

Nothing is repaired automatically and nothing is ever deleted except the tool's own staging
names after a successful link. Every leftover is refused with a message that names the case:

| Leftover | Meaning | What to do |
|---|---|---|
| `.<name>.key.json.partial` and no key file | `keygen` stopped before the key file was complete. No `KEY_CREATED` exists and no address was shown | Remove the partial file and run `keygen` again |
| `.<name>.key.json.partial` that is a second name of the key file (same inode) | `keygen` stopped after the file was complete, before the clean-up | Remove the partial name. If `KEY_CREATED` is missing too, see the next row |
| A key file with no `KEY_CREATED` entry (`sign` refuses `RNKEY_KEY_NOT_REGISTERED`; `keygen` refuses `RNKEY_KEY_EXISTS`) | `keygen` stopped between the key file and the log entry. The address was never printed, so it was never funded | Remove that key file and run `keygen` again (a new key; a new gate B record) |
| `.NNNNNN.json.tmp` in the sign log (`RNKEY_SIGNLOG_INCOMPLETE`) | A run stopped while writing entry N, before it was linked: entry N does not exist | Check that `NNNNNN.json` does not exist (or is the same inode), then remove the temporary name. Nothing was signed after an unwritten `SIGNING` |
| A pending `SIGNING` with no `SIGNED` | `sign` stopped before the signed output was staged | Run the same `sign` again: it completes that digest once, to the same bytes (`COMPLETE`) |
| `SIGNED`, a staged `.<output>.partial`, no final output | `sign` stopped before the final link | Run the same `sign` again: it refuses `RNTX_ALREADY_SIGNED`, checks the staged copy against the `SIGNED` entry and links it, without the passphrase |
| `.<output>.tmp` or `.<output>.partial.tmp` in the output directory (`RNKEY_OUTPUT_CONFLICT`) | A run stopped while staging | Remove it and run the same `sign` again |

## Limits

- **Not a sandbox.** The checks run at each step, but another process of the same user could
  change a directory between two checks, open a terminal, or read the process memory. The control
  is the operating procedure: no agent session runs, and none has the passphrase, during gates B
  and D (signing design §4; K3).
- **No memory erasure.** The tool overwrites the buffers it holds (secret, derived key, terminal
  input), but a JavaScript string (the passphrase) cannot be erased, and the runtime may keep
  copies. Accepted for testnet keys that hold no value only.
- **The isolation check** reads `/proc/self/net`. It confirms that the process is in a namespace
  with only loopback; it does not create one, so the commands must be started under
  `unshare -rn`.
- **The ext4 check** is `statfs` magic `0xEF53`, which ext2 and ext3 share. It refuses drvfs, 9p,
  tmpfs, overlay and network file systems. The Windows host can still read the WSL virtual disk
  (K2 residual risk, accepted for testnet keys only).
- **Local log only** (spec §6).
