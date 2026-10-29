# packages/verifier

The independent evidence verifier of RN-NET-02. It is offline and deterministic: it reads only
the bytes it is given, makes no network calls, holds no keys and consults no trust source.

- **Specifications:**
  - [rnnet.synthetic-evidence.v1](../../spec/rnnet.synthetic-evidence.v1.md), the evidence
    format;
  - [rnnet.verification-report.v1](../../spec/rnnet.verification-report.v1.md), the report.
- **Decisions:** ADR-RN-006, ADR-RN-007 and ADR-RN-008 in [`docs/adr/`](../../docs/adr/README.md).
- **Dependencies:** `packages/canonical`, `packages/commitment`, and Node.js built-ins
  (`createHash`, `createPublicKey`, `verify`, `Buffer`). There is no third-party package.

## API (`src/index.mjs`)

### `verifyEvidence(evidenceBytes, options?)`

It verifies an `rnnet.synthetic-evidence.v1` document and returns a frozen
`rnnet.verification-report.v1` report.

**Arguments:**

- `evidenceBytes` is a `Uint8Array` with the exact bytes of the evidence file.
  - Strings are not accepted, because decoding can hide bytes that were changed.
  - A Proxy is refused.
  - The bytes are copied once.
- `options.commitment` is optional: `{ envelope: Uint8Array, digest: string }`.
  - `envelope` holds the bytes of an `rnnet.evidence-commitment.v1` envelope.
  - `digest` is the commitment presented for it.

**Input size.** Input over the 262,144-byte limit is rejected (`RNSE_EVIDENCE_TOO_LARGE`), but it is
still copied once and hashed for `input.sha256` first, so its cost grows with its size. Callers
that accept untrusted files should bound what they read; the CLI reads the whole named file.

**Errors.** Every defect in the evidence or the commitment is reported in the report. A
`TypeError` is thrown only for invalid arguments, which are programming errors.

**Results:**

- **`outcome`** is one of:
  - `PASS`: the document is valid, its digest matches, every signature verifies, and the
    commitment matches if one was supplied;
  - `FAIL`;
  - `UNSUPPORTED`.

  `PASS` does not mean the claims are true or that a signer is who they say they are; read
  `statements`.
- **`findings`** lists every failed check, with a stable code.
- **`statements`** gives the taxonomy classification of everything that was checked:
  - the digest is `VERIFIED`;
  - signatures are `CONSISTENT_UNDER_EMBEDDED_KEYS`;
  - signer identity is `UNRESOLVED`;
  - claims are `CLAIMED`.

### Other exports

**Report and digest helpers:**

- `encodeReport(report)` returns the report's canonical bytes. Equal inputs give equal bytes.
- `computeEvidenceDigest(body)` returns `sha256:<hex>`.
- `evidenceDigestBytes(body)` returns the 32 raw bytes.
- `signingMessage(digestBytes)` returns the exact bytes a signature record signs. Producers use
  it with their own signing tools; the verifier never signs.

**Constants:**

- `FORMAT`, `REPORT_FORMAT`, `LIMITS`, `OUTCOMES`;
- `DIGEST_DOMAIN_SEPARATOR`, `SIGNATURE_DOMAIN_SEPARATOR`;
- `Outcome`, `SignatureResult`, `EvidenceErrorCode`.

## Command line

```sh
node tools/verify-evidence.mjs <evidence-file> [--commitment <envelope-file> --commitment-digest <sha256:...>] [--output <report-file>]
```

**Behaviour:**

- It prints the report as one line of canonical JSON. With `--output`, it writes a new file
  instead and refuses to overwrite one.
- It reads only the named files.

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | `PASS` |
| 1 | `FAIL` |
| 2 | `UNSUPPORTED` |
| 64 | Usage error |
| 66 | An input file cannot be read |

## Conformance

**Vectors.** `vectors/evidence/evidence.json` holds 69 cases with the full expected reports.
They are checked by:

- `packages/conformance/test/evidence-vectors.test.mjs`;
- `tools/reference/rnnet_evidence_reference.py`, a second implementation with its own RFC 8032
  Ed25519.

**Rebuilding the vectors.** Run `node tools/vectors/evidence-vectors.mjs --write`. Its test
keys are derived from public labels, so they are test-only by construction.
