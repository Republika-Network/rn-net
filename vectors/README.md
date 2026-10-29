# Conformance vectors

Each file is a JSON object with `"format": "rnnet.conformance-vectors.v1"`, the specification
it tests in `profile`, a `kind`, and a `vectors` array. Expected values are written by hand
from the specifications; both implementations in this repository must reproduce them.

## Input

Every vector has exactly one of:

| Field | Bytes under test |
|---|---|
| `input` | The UTF-8 encoding of this string |
| `inputHex` | These bytes, for inputs that are not valid UTF-8 or must be byte-exact |
| `inputPattern` | The UTF-8 encoding of `prefix + repeat × count + suffix`, for inputs too large to store literally |

## Expected results

| File | Fields |
|---|---|
| `canonical/valid.json` | `expected` (canonical text) or `expectedPattern` (same shape as `inputPattern`), and `expectedSha256` of its UTF-8 bytes |
| `canonical/invalid.json` | `expectedError`: the first error code under `rnnet.canonical-json.v1` §3.6 |
| `commitment/valid.json` | `expectedCanonical` and `expectedCommitment` |
| `commitment/invalid.json` | `expectedError`, and `expectedField` when the error concerns one field |
| `tamper/commitment-tamper.json` | `presentedDigest` and `expected`: `{"valid": true}` or `{"valid": false, "code": ...}` from verification; `base` records the untampered envelope and its commitment |

Vectors whose id starts with `first-error-` contain several defects at once and pin the
error precedence the specifications define.

## Evidence verification (`evidence/evidence.json`)

Profile `rnnet.synthetic-evidence.v1`, kind `evidence-verification`. Each vector has an input
(as above), optionally a `commitment` (`envelope` text and presented `digest`), and:

| Field | Meaning |
|---|---|
| `expectedOutcome` | `PASS`, `FAIL` or `UNSUPPORTED` (`rnnet.verification-report.v1` §2), stated by hand |
| `expectedFindings` | The finding codes in report order, stated by hand |
| `expectedReport` | The full report as canonical JSON text |

These vectors contain Ed25519 signatures, so they are generated rather than written by hand:
`node tools/vectors/evidence-vectors.mjs --write` rebuilds the file from test keys derived from
public labels, and stops if the verifier disagrees with any hand-stated outcome or code. A test
checks the committed file is exactly what the generator builds. The Python reference
(`tools/reference/rnnet_evidence_reference.py`, with its own RFC 8032 Ed25519) rebuilds every
`expectedReport` independently.

## Anchoring (`anchor/`)

Synthetic: every transaction record, hash, ledger, block and account is derived from a label and
does not exist on any network. Built by `node tools/vectors/anchor-vectors.mjs --write`, which
stops if the implementation disagrees with a hand-stated outcome or code; a test checks the
committed files are exactly what it builds, and `tools/reference/rnnet_anchor_reference.py`
rebuilds every expected record and report independently.

| File | Fields |
|---|---|
| `anchor/payload.json` | `payloadHex`, and `expectedCommitment` or `expectedError` (`rnnet.anchor-payload.v1`) |
| `anchor/xrpl.json`, `anchor/evm.json` | `input` (an `rnnet.anchor-observation.v1`), `expectedCommitment`, `expectedOutcome`, `expectedFindings`, `expectedRecord` |
| `anchor/dual.json` | `xrpl` and/or `evm` observations, `expectedCommitment`, `expectedOutcome`, `expectedConclusions`, `expectedFindings`, `expectedReport` |
