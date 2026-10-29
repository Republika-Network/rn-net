# rnnet.anchor-payload.v1

- Status: Draft (RN-NET-03A)
- Decision record: [ADR-RN-009](../docs/adr/ADR-RN-009-anchor-payload-encoding.md)
- Depends on: [rnnet.evidence-commitment.v1](rnnet.evidence-commitment.v1.md)
- Implementation: `packages/anchor/src/payload.mjs`
- Conformance vectors: `vectors/anchor/payload.json`

## 1. Purpose

An anchor payload is the exact byte string that RN-NET places in a public-ledger transaction to
anchor one `rnnet.evidence-commitment.v1` commitment. The same bytes are used on every network.
Only their transport differs between chains (`rnnet.anchor-record.v1`).

The payload carries a commitment, never evidence. It contains no evidence content, personal
data, keys, signatures or URLs.

## 2. Bytes

A v1 anchor payload is exactly **42 bytes**:

| Offset | Length | Value |
|---|---|---|
| 0 | 8 | Magic: the ASCII bytes `RNNETANC` (`52 4e 4e 45 54 41 4e 43`) |
| 8 | 1 | Payload version: `01` |
| 9 | 1 | Commitment format: `01` = `rnnet.evidence-commitment.v1` |
| 10 | 32 | The 32 commitment digest bytes, in the order SHA-256 outputs them |

**Byte order.** The payload contains no multi-byte integers, so there is no byte order to
choose. The digest bytes are the raw SHA-256 output: the commitment `sha256:<hex>` written as
bytes, first hex pair first.

**Example.** The commitment
`sha256:7082efeb67d3252191c9a1b7d59c757ed82382b943460cc512c16859ba5e59ff` gives:

```
524e4e4554414e43 01 01 7082efeb67d3252191c9a1b7d59c757ed82382b943460cc512c16859ba5e59ff
```

**Separation from other formats.**

- The magic and version separate an anchor payload from:
  - any other data a transaction might carry;
  - other RN-NET structures. None of them begins with `RNNETANC`; canonical JSON begins with
    a JSON value, and the domain separators begin with `rnnet:`.
- The format byte names which commitment format the digest belongs to. A future commitment
  format gets a new code and cannot be confused with v1.

## 3. Decoding

A decoder applies these checks to a byte string in order and reports the first failure:

| Step | Check | Error |
|---|---|---|
| 1 | At least 8 bytes, and bytes 0–7 equal the magic | `RNAP_NOT_ANCHOR_PAYLOAD` |
| 2 | At least 9 bytes | `RNAP_INVALID_LENGTH` |
| 3 | Byte 8 is `01` | `RNAP_UNSUPPORTED_VERSION` |
| 4 | Exactly 42 bytes | `RNAP_INVALID_LENGTH` |
| 5 | Byte 9 is `01` | `RNAP_UNSUPPORTED_COMMITMENT_FORMAT` |

On success, the decoded commitment is `sha256:` followed by the lowercase hex of bytes 10–41.

**Why the version comes before the length.** The version is checked before the exact length,
so a later version with a different length is reported as unsupported, not as malformed.

**Why trailing data is rejected.** Trailing bytes are an error. A transport that carries more
data must place the payload in its own field (`rnnet.anchor-record.v1`).

## 4. Matching a commitment

A payload **matches** a commitment when it decodes successfully and the decoded commitment is
equal, as a string, to the expected `sha256:<64 lowercase hex>` commitment. A payload that
decodes to another commitment is `RNAP_COMMITMENT_MISMATCH`.

## 5. Encoding

- The encoder accepts only a well-formed commitment string (`sha256:` followed by 64
  lowercase hex digits) and returns the 42 bytes of §2.
- Encoding is deterministic: one commitment has exactly one payload.

## 6. Duplicates

- This format defines one payload per commitment.
- How many payloads a single transaction may carry is defined by the transport
  (`rnnet.anchor-record.v1`). In v1 it is exactly one, and a second payload in the same
  transaction is an error, even if it is identical.
- Anchoring the same commitment in several transactions is not an error at this layer. Each
  transaction is checked on its own.

## 7. Error codes

| Code | Meaning |
|---|---|
| `RNAP_NOT_ANCHOR_PAYLOAD` | The bytes do not begin with the magic |
| `RNAP_INVALID_LENGTH` | Truncated, or not exactly 42 bytes for v1 |
| `RNAP_UNSUPPORTED_VERSION` | A payload version other than `01` |
| `RNAP_UNSUPPORTED_COMMITMENT_FORMAT` | A commitment format code other than `01` |
| `RNAP_COMMITMENT_MISMATCH` | A well-formed payload for a different commitment |
