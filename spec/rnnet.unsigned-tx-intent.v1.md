# rnnet.unsigned-tx-intent.v1

- Status: Draft (RN-NET-03B2-B1)
- Decision record: [ADR-RN-017](../docs/adr/ADR-RN-017-offline-signing-toolchain.md); construction from [ADR-RN-016](../docs/adr/ADR-RN-016-genesis-anchoring-transactions.md)
- Depends on: [rnnet.canonical-json.v1](rnnet.canonical-json.v1.md), [rnnet.anchor-payload.v1](rnnet.anchor-payload.v1.md)
- Implementations:
  - `packages/tx-intent` (intent, codecs, comparison);
  - `signer/` (signing, verification, key file);
  - `packages/broadcast-handoff` (hand-off check);
  - `tools/reference/rnnet_tx_reference.py` (independent verification).
- Vectors:
  - `vectors/signing/known-answers.json` (public sources);
  - `fixtures/signing-b1/` (synthetic).

This specification also defines `rnnet.signed-tx-verification.v1` (§5) and
`rnnet.testnet-key-file.v1` (§7).

## 1. Purpose

An intent is the exact unsigned transaction the founder approves, **by digest**, before anything
is signed (authorization gate D). It binds four things:
- the network;
- the purpose;
- the anchored commitment;
- the transaction.

A signer signs only an intent whose digest equals the approved one. A verifier checks signed
bytes against that intent, field by field.

## 2. The intent

An intent is a JSON object with exactly these members:

| Member | Value |
|---|---|
| `format` | `"rnnet.unsigned-tx-intent.v1"` |
| `network` | `"xrpl:testnet"` or `"evm:11155111"` (Sepolia). There is no Mainnet value |
| `purpose` | `"genesis-proof-01"` |
| `commitment` | `sha256:<64 lowercase hex>`: the `rnnet.evidence-commitment.v1` commitment anchored |
| `transaction` | The completed unsigned transaction. It must pass the ADR-RN-016 check for its network (`checkXrplAnchorTx` / `checkSepoliaAnchorTx`) |
| `preparation` | An object recording how the transaction was bound: an [`rnnet.tx-preparation.v1`](rnnet.tx-preparation.v1.md) record when bound from read-only observations (RN-NET-03B2-B2), or `{"source": "synthetic", ...}` in the B1 fixtures. Covered by the digest |

**Additional rules:**
- **The intent must be plain JSON data.** No inherited members, accessors or proxies.
- **XRPL:**
  - `transaction` must include `SigningPubKey` (`ED` + 64 upper-case hex). It is bound at
    gate D, before approval, so the digest covers it.
  - `Account` must be that key's classic address: base58check of RIPEMD-160(SHA-256(key)),
    XRPL alphabet, version byte 0.
- **Sepolia:** `transaction.from` is the sender. It is not part of the signed bytes; the
  verifier recovers it from the signature.

- **Sepolia:** `nonce` is below 2^64 (EIP-2681).
- **JSON values:** every value is within `rnnet.canonical-json.v1`: safe integers only, no `-0`
  and no lone surrogates. An intent is exchanged as its canonical JSON text. Text that is not
  canonical (for example `1.0`, `1e6` or `-0`) may be parsed differently by different hosts, and
  verifiers may refuse it.

Anything else is `RNTX_INTENT_INVALID`.

## 3. Digest

```
digest = "sha256:" || hex( SHA-256( "rnnet:unsigned-tx-intent:v1" || 0x00 || canonical(intent) ) )
```

`canonical` is `rnnet.canonical-json.v1`. A signer must sign from the canonical copy of the
checked intent, never from an object a caller can still change.

## 4. Signed bytes

### 4.1 XRPL Testnet

- **Serialization.** The XRPL binary format of the `AccountSet`, with these fields only, in
  canonical order (by type code, then field code):
  - `TransactionType` (1/2), `Flags` (2/2, only if present and 0), `Sequence` (2/4),
    `LastLedgerSequence` (2/27);
  - `Fee` (6/8, XRP drops);
  - `SigningPubKey` (7/3), `TxnSignature` (7/4);
  - `Account` (8/1);
  - `Memos` (15/9), with one `Memo` (14/10) holding `MemoType` (7/12) and `MemoData` (7/13).
- **Signature.** Ed25519 over `STX\0` (`53545800`) ‖ the serialization without
  `TxnSignature`.
- **Hash.** The transaction hash is SHA-512Half(`TXN\0` (`54584E00`) ‖ the signed blob), in
  upper case.
- **Writing.** The blob is written as upper-case hex.

### 4.2 Sepolia (EIP-1559)

- **Unsigned bytes.** `0x02 ‖ rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas,
  to, value, input, accessList])`.
- **Signed bytes.** The same list followed by `[yParity, r, s]`.
- **Encoding rules.** Integers are minimal big-endian, and zero is the empty string. RLP must
  be canonical.
- **Signature.** secp256k1 over Keccak-256(unsigned bytes), with low s (EIP-2), and yParity is
  the recovery id: 0 or 1.
- **Hash.** The transaction hash is Keccak-256(signed bytes).
- **Writing.** Signed bytes are written as `0x` + lower-case hex.

## 5. Verification and `rnnet.signed-tx-verification.v1`

A verifier takes the intent, the approved digest and the signed bytes. It returns exactly this
record (canonical JSON):

```
{ "format": "rnnet.signed-tx-verification.v1", "network", "intentDigest", "blobSha256",
  "transactionHash", "outcome": "PASS" | "FAIL", "code": null | <first error code> }
```

Each step that fails stops verification with its code. The steps run in this order:

1. **Intent.** It must be valid (§2), else `RNTX_INTENT_INVALID`. Its digest must equal the
   approved digest, else `RNTX_INTENT_DIGEST_MISMATCH`. On either failure, `network`,
   `intentDigest`, `blobSha256` and `transactionHash` are `null`.
2. **Bytes.** They must be written as §4 requires, else `RNTX_DECODE`. On success,
   `blobSha256` and `transactionHash` are computed from them.
3. **Decoding.** These failures stop verification:
   - `RNTX_DECODE`: truncated or malformed bytes, or RLP lists nested more than 4 deep;
   - `RNTX_TRAILING_BYTES`;
   - `RNTX_NONCANONICAL_ENCODING`: field order, RLP form, leading zeros, an XRPL field ID below
     16 in an extended form, or XRPL bytes that are not exactly the canonical re-serialization
     (this includes an XRPL `TransactionType` other than `AccountSet`, which the codec cannot
     re-serialize);
   - `RNTX_UNKNOWN_FIELD`: an XRPL field outside §4.1, `MemoFormat` included;
   - `RNTX_WRONG_CHAIN`: XRPL `NetworkID`;
   - `RNTX_WRONG_TX_TYPE`: an EVM type byte other than `0x02`;
   - `RNTX_FIELD_MISMATCH`: an EVM `to` that is not 20 bytes.
4. **Comparison with the intent.** Fields are compared in this order, and the first difference
   gives its code:

   | Network | Field and code |
   |---|---|
   | XRPL | `TransactionType`, `Flags` (`RNTX_FIELD_MISMATCH`); `Sequence` (`RNTX_NONCE_MISMATCH`); `LastLedgerSequence` (`RNTX_FIELD_MISMATCH`); `Fee` (`RNTX_FEE_MISMATCH`); `Memos` (`RNTX_PAYLOAD_MISMATCH`); `Account`, `SigningPubKey` (`RNTX_SENDER_MISMATCH`) |
   | Sepolia | `type` (`RNTX_WRONG_TX_TYPE`); `chainId` (`RNTX_WRONG_CHAIN`); `nonce` (`RNTX_NONCE_MISMATCH`); `maxPriorityFeePerGas`, `maxFeePerGas`, `gas` (`RNTX_FEE_MISMATCH`); `to`, `value` (`RNTX_FIELD_MISMATCH`); `input` (`RNTX_PAYLOAD_MISMATCH`); `accessList` (`RNTX_FIELD_MISMATCH`) |
5. **Signature.**
   - **XRPL:** the Ed25519 signature must verify, else `RNTX_SIGNATURE_INVALID`.
   - **Sepolia**, in this order:
     - yParity ≤ 1, else `RNTX_BAD_Y_PARITY`;
     - r and s in [1, n−1], else `RNTX_SIGNATURE_INVALID`;
     - s ≤ n/2, else `RNTX_HIGH_S`;
     - a public key must recover, else `RNTX_SIGNATURE_INVALID`;
     - its address must equal `from`, else `RNTX_SENDER_MISMATCH`.

A PASS shows that the bytes are the approved transaction, signed by the intent's sender. It says
nothing about whether the transaction was, or will be, included on a network (ADR-RN-012).

## 6. Broadcaster hand-off (interface only)

A future broadcaster (RN-NET-03B2-B3, ADR-RN-019, gate E) accepts a signed transaction only
after `checkHandoff` succeeds. It holds no key and never imports `signer/`.

`checkHandoff` requires:
- the approved intent and its digest;
- the signed transaction;
- **two identical** verification records with outcome PASS, from the JavaScript and the Python
  verifier.

The records are not trusted for the bytes. The hand-off also:
- recomputes the blob hash (`RNTX_HANDOFF_BLOB_MISMATCH`);
- re-checks the intent against the digest;
- decodes the blob and compares every field with the intent (the §5 codes);
- recomputes the XRPL transaction hash.

It takes the signature checks and the Sepolia hash from the records. **A broadcaster must
re-verify the signature itself before submitting.**

The other hand-off failures are `RNTX_HANDOFF_INVALID` and `RNTX_HANDOFF_NOT_PASS`. B1 defines
this interface and has no transport and no RPC write method.

## 7. `rnnet.testnet-key-file.v1` (format only)

| Member | Value |
|---|---|
| `format` | `"rnnet.testnet-key-file.v1"` |
| `network`, `purpose` | As in §2. The key signs only intents with the same values |
| `createdAt` | `YYYY-MM-DDTHH:MM:SSZ` |
| `publicKey`, `address` | XRPL: `ED` + hex and the classic address. Sepolia: the uncompressed key (hex) and the address |
| `kdf` | `{ "name": "scrypt", "N": 131072, "r": 8, "p": 1, "salt": <16 bytes hex> }` |
| `cipher` | `{ "name": "aes-256-gcm", "iv": <12 bytes hex>, "tag": <16 bytes hex> }` |
| `ciphertext` | The encrypted 32-byte secret (hex) |

**Encryption:**
- **Key:** scrypt(passphrase NFC UTF-8, salt), 32 bytes. The passphrase is at least 12
  characters.
- **Authenticated data:** the canonical JSON of every member except `ciphertext` and
  `cipher.tag`.
- **After decryption:** the public key and address are re-derived and must match the file.

**Errors:** a wrong passphrase or any changed member is `RNTX_KEYFILE_DECRYPT`; a malformed file
is `RNTX_KEYFILE_INVALID`.

In RN-NET-03B2-B1 this format is implemented and tested **in memory only**. Nothing reads or
writes key files, and nothing generates keys.

## 8. Signer refusals

These come before signing:
- `RNTX_INTENT_INVALID` and `RNTX_INTENT_DIGEST_MISMATCH`;
- `RNTX_KEY_INVALID`: not 32 bytes, out of range, unknown network or purpose;
- `RNTX_KEY_NETWORK_MISMATCH` and `RNTX_KEY_PURPOSE_MISMATCH`;
- `RNTX_SENDER_MISMATCH`: the key's address is not the intent's sender, or on XRPL
  `SigningPubKey` is not the key;
- `RNTX_ALREADY_SIGNED` and `RNTX_SEQUENCE_UNRESOLVED`, from the sign log;
- `RNTX_SIGNATURE_INVALID`: a recovery byte above 1, or failed self-verification.
