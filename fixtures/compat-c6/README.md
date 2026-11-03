# fixtures/compat-c6: C6 provider compatibility, simulated (RN-NET-03B2-C6-PREP)

**Simulated providers only. No response in these files is a real provider answer.** Error texts
are illustrative; no provider's real error shape is known before the C6 run.

- `manifest.json`: the 22-request read-only manifest (`rnnet.provider-compat-manifest.v1`), as
  `tools/compat/manifest.mjs` describes it. The digest a read authorization would bind is the SHA-256 of its
  canonical bytes (`manifestBytes()`), cited in
  [the C6 document](../../docs/genesis/rn-net-03b2c6-provider-compatibility.md); this file is an
  indented copy for reading.
- `cases.json`: 57 scenarios, including a fixture on each side of every threshold. Each holds the transcript of simulated responses, in the order sent
  (`text`, plus `pad` trailing spaces for the oversized case), and the
  `rnnet.provider-compat-evidence.v1` evidence `tools/compat/run.mjs` produced from it.

Regenerate with `node tools/compat/build-c6-fixtures.mjs` (offline); `--check` compares.
`tools/compat.test.mjs` replays every transcript, and `tools/reference/rnnet_compat_reference.py`
reproduces every request, outcome and classification independently. The Sepolia address is the
public, label-derived B1 test address; it must never be funded.
