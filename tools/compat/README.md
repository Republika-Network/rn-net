# tools/compat: the C6 provider compatibility check (offline preparation)

RN-NET-03B2-C6-PREP. See [the C6 document](../../docs/genesis/rn-net-03b2c6-provider-compatibility.md).

- `manifest.mjs`: the 22 read-only requests, the four reviewed providers at their reviewed URLs,
  the per-provider budget and limits (one attempt, 10 s, 256 KiB).
- `run.mjs`: one run over an **injected** transport: each request at most once, to its own
  provider, `NOT_SENT` when a dependency is missing, sanitized evidence.
- `classify.mjs`: PASS / BLOCKED / UNRESOLVED per check, the verdicts, the Sepolia branches A–E
  and the compatibility candidate.
- `simulated.mjs`, `build-c6-fixtures.mjs`: simulated providers and the fixture generator.

**No live entry point exists.** Nothing here imports a transport or a network module, the write
path, the signer or the key tool; the guard enforces it (`compat-reaches-network`,
`compat-reaches-write-or-key`), and no file anywhere may join `tools/compat/` to a network file
(`compat-transport-join-transitive`, `COMPAT_TRANSPORT_JOINERS` empty). Running C6 against real providers needs a separately reviewed
entry point and a founder read authorization for exactly 22 requests.
