# Genesis Proof 01 fixture

The synthetic evidence that Genesis Proof 01 will anchor, with its immutable offline golden values.
**Nothing here has been anchored.** See
[the preflight document](../../docs/genesis/genesis-proof-01-preflight.md).

| File | Content |
|---|---|
| `evidence.json` | `rnnet.synthetic-evidence.v1` document: canonical bytes, no trailing newline, one fixture-key signature |
| `envelope.json` | Its `rnnet.evidence-commitment.v1` envelope, canonical bytes |
| `golden.json` | `rnnet.genesis-preflight.v1`. Holds the hashes, the RN-NET-02 report, the commitment, the 42-byte payload, the unsigned XRPL and Sepolia templates, and synthetic rehearsal observations with their expected dual-chain report. |

**Commitment:** `sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7`

**The files are byte-exact** (`.gitattributes`: `fixtures/** -text`). They are built by
`node tools/genesis/build-genesis-01.mjs`. Run without arguments, it checks them; with `--write` it
writes them, and it refuses to overwrite existing files. Two independent checks cover them:

- `tools/genesis.test.mjs`;
- `tools/reference/rnnet_genesis_reference.py`.

**Synthetic data only:**

- The evidence describes no real operation, person or organization.
- The fixture key is derived from a public label, so it is not an identity.
- Every hash, account, ledger and block in the rehearsal is a label-derived placeholder that
  exists on no network.
