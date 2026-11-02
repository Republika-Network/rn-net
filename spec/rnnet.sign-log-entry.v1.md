# rnnet.sign-log-entry.v1

- Status: implemented and tested offline (RN-NET-03B2-C4). It is the format ADR-RN-017
  Amendment C1, K4 (**Proposed**) says C4 specifies. Writing a real entry is part of gate B
  (`KEY_CREATED`) or gate D (the others); neither is authorized by C4.
- Implementations: [`tools/keytool/signlog.mjs`](../tools/keytool/signlog.mjs) (rules),
  [`tools/keytool/signlog-store.mjs`](../tools/keytool/signlog-store.mjs) (files), and,
  independently, [`tools/reference/rnnet_keytool_reference.py`](../tools/reference/rnnet_keytool_reference.py).
- Fixtures: [`fixtures/keytool-c4/cases.json`](../fixtures/keytool-c4/cases.json).

## 1. Purpose

The founder's private, persistent record of which testnet key was created and what it signed. It
is the replay guard of the signer: before a signature the tool replays the whole log and refuses
any signing it does not allow (§5). It is never published, never committed and holds **public
data only**: key identities, digests, sequence numbers, hashes and times. Never a secret key,
seed, passphrase or decrypted material.

## 2. Storage

- One directory, outside every repository and worktree, on ext4, mode `0700`, owned by the
  founder, separate from the key directory and from the signed output (ADR-RN-017 Amendment C1,
  K4: `~/.local/state/rn-net/genesis-01/sign-log/` is the intended place). The directory is passed
  as an argument; no environment variable is read.
- Entry N is the file `NNNNNN.json` (six digits): its rnnet.canonical-json.v1 bytes and one
  newline, mode `0600`, at most 4096 bytes. Entries are created once and never changed or
  removed; the tool has no code that changes or removes one.
- Writing entry N: the bytes go to `.NNNNNN.json.tmp` (created exclusively, `O_NOFOLLOW`, `0600`),
  are `fsync`ed, the file is linked to `NNNNNN.json` (`link()` fails if that name exists), the
  temporary name is removed and the directory `fsync`ed. Then the whole log is read back and
  replayed; it must be exactly the previous entries followed by the new one.
- Reading: every name must be an entry name, from `000000.json` with no gap. A
  `.NNNNNN.json.tmp` name is `RNKEY_SIGNLOG_INCOMPLETE`. Any other name, a gap, a file that is not
  a regular `0600` file of this user, a file whose bytes are not exactly its canonical JSON and a
  newline, or an entry that breaks a rule of §4, is `RNKEY_SIGNLOG_INVALID`. The tool never
  repairs, skips or truncates history.

## 3. Entries

Every entry has exactly these common members, plus the members of its type:

| Member | Value |
|---|---|
| `format` | `"rnnet.sign-log-entry.v1"` |
| `index` | Its position, from 0 |
| `previous` | `null` for entry 0; otherwise the digest (below) of entry `index - 1` |
| `type` | The string `KEY_CREATED`, `SIGNING`, `SIGNED` or `RESIGN_BASIS` (any other value, including an array or object, is refused) |
| `network` | `xrpl:testnet` or `evm:11155111` |
| `purpose` | `genesis-proof-01` |
| `address` | XRPL: the classic address. Sepolia: `0x` + 40 lower-case hex |
| `recordedAt` | `YYYY-MM-DDTHH:MM:SSZ`, a real UTC second of years 0001 to 9999, never earlier than the entry before |

Digest of an entry: `sha256:` + hex of SHA-256(`rnnet:sign-log-entry:v1\0` ‖ its canonical JSON).

| Type | Further members | Written |
|---|---|---|
| `KEY_CREATED` | `publicKey` (XRPL `ED` + 64 upper-case hex; Sepolia `04` + 128 lower-case hex, a point on secp256k1), `keyFileSha256` (SHA-256 of the key file's bytes) | By `keygen`, after the key file is durable and has been read back and decrypted |
| `SIGNING` | `sequence` (the XRPL `Sequence` or Sepolia nonce, decimal, no leading zero; XRPL below 2^32, Sepolia below 2^64), `intentDigest` | **Before** the signature is made |
| `SIGNED` | `sequence`, `intentDigest`, `blobSha256`, `transactionHash` (XRPL 64 upper-case hex; Sepolia `0x` + 64 lower-case hex) | After the signed output is staged durably under a hidden name, **before** it is linked to its final name. K4 says SIGNED comes before the blob is "written out": here the blob is on disk (staged) before SIGNED, but it is only published under its final name after; a crash in between leaves a pending `SIGNING`, which completes to the same bytes |
| `RESIGN_BASIS` | `sequence`, `intentDigest` (the new intent), `expiredIntentDigest`, `expiredTransactionHash`, `statusRecordDigest` | XRPL only, before the `SIGNING` of a re-sign |

`KEY_CREATED` is an addition to the three types K4 names: it records the key's public identity
(founder decision: key creation is recorded with public metadata only) and lets `sign` refuse a
key file the log does not know (`RNKEY_KEY_NOT_REGISTERED`).

## 4. Replay rules

A log is valid only if every entry passes, in order:

1. Shape and values as in §3; `index` is the position; `previous` chains; times never decrease.
2. `KEY_CREATED`: at most one per address, and at most one per (`network`, `purpose`); it comes
   before any other entry for that address. Every other entry names an address with a
   `KEY_CREATED` entry of the same network and purpose.
3. Per address:
   - `SIGNING`: no `SIGNING` of this key is pending (without its `SIGNED`); this digest was never
     in a `SIGNING` of this key. The first `SIGNING` fixes the key's sequence. Any later one must
     have the same sequence **and** an unused `RESIGN_BASIS` naming exactly its digest, which it
     uses up.
   - `SIGNED`: completes the pending `SIGNING` with the same digest and sequence.
   - `RESIGN_BASIS`: nothing pending and no unused basis; the key's sequence; `expiredIntentDigest`
     and `expiredTransactionHash` are those of the latest `SIGNED` of this key; the
     `statusRecordDigest` was never used before (in the whole log); the new digest was never
     signed with this key.

Nothing in the log resolves a sequence (there is no `INCLUDED` entry): after a key signs one
sequence, a different sequence is always refused. Genesis Proof 01 needs one transaction per
network, so this is sufficient for it; a later milestone that needs more must add a resolution
entry with its own review.

## 5. The signing decision

For a request (network, purpose, address, public key, key-file SHA-256, sequence, intent digest,
optional re-sign basis), against a log that replays cleanly:

| Situation | Result |
|---|---|
| No `KEY_CREATED` for exactly this key file (address, public key, file hash, network, purpose) | `RNKEY_KEY_NOT_REGISTERED` |
| This digest has a `SIGNED` entry for this key | `RNTX_ALREADY_SIGNED`: the output already written is the output |
| This digest's `SIGNING` is pending (a run stopped before `SIGNED`) | `COMPLETE`: append `SIGNED` only. Ed25519 and RFC 6979 are deterministic, so this gives the same bytes. A basis given must be the one used |
| Another digest is pending | `RNTX_SEQUENCE_UNRESOLVED` |
| Nothing signed with this key yet | `SIGN`: `SIGNING`, then `SIGNED` (a basis given is `RNKEY_RESIGN_BASIS_INVALID`) |
| Another sequence than the key's | `RNTX_SEQUENCE_UNRESOLVED` |
| An unused basis names this digest | `SIGN` (a basis given must be that one) |
| An unused basis names another digest | `RNTX_SEQUENCE_UNRESOLVED` |
| Same sequence, no basis given | `RNTX_SEQUENCE_UNRESOLVED` |
| Same sequence, basis given: Sepolia, or not for the latest signed transaction, or a used status record | `RNKEY_RESIGN_BASIS_INVALID` |
| Same sequence, a valid XRPL basis | `RESIGN`: `RESIGN_BASIS`, `SIGNING`, `SIGNED` |

The basis is an `rnnet.submission-status.v1` record (spec/rnnet.broadcast.v1.md §10) with
`network` `xrpl:testnet`, `finding` `EXPIRED` and an XRPL `transactionHash`; its digest is
`sha256:` + hex of SHA-256(`rnnet:submission-status:v1\0` ‖ canonical JSON). The record is a file
anyone could write: the founder vouches for it at gate D; the key tool checks that it names the
latest transaction signed for that sequence and that it is used once.

Sepolia same-nonce replacement is refused (ADR-RN-017 Amendment C1, K4 rule 4).

## 6. Limits

- The log is local. It cannot stop signing on another machine or from a copy of the key file;
  gates B and D run on one machine (K4).
- **Removing the last entries is not detectable.** The chain links each entry to the one before,
  so a change, insertion, reordering or gap is refused, but a log cut after any entry is a valid,
  shorter log. Someone who can write to the directory as the founder's user could remove trailing
  `SIGNING`/`SIGNED` entries and so allow signing again. The control is the same as for the key
  file: the directory is the founder's alone, and no agent session runs during gate D; the gate-D
  record (outside this directory) keeps the digests signed.
- The checks run before every read and write, but another process of the same user could change
  the directory between two checks. The control for that is the operating procedure: no agent
  session runs, and none has the passphrase, during gates B and D.
- Two runs cannot both append the same index (§2), and each re-reads the log after appending;
  the later run is refused (`RNKEY_SIGNLOG_CONFLICT`).
