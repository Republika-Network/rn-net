# tools/gate-f — offline durable gate-F verification core (WP4-B1)

ADR-RN-020 (Proposed) · spec `rnnet.gate-f-sepolia-verification.v1`

**Partial and offline.** B1 covers:
- the subject;
- the binding of the intent, signed bytes, txverify record and submission record;
- the offline replay of an `rnnet.rpc-capture.v1` capture through the existing reader;
- inclusion and provider-reported finality (ADR-RN-015, unchanged; CONFLICT is preserved and is FAIL);
- `t_i` from the captured inclusion block linked to the PublicNode walk;
- the strict record, its digest and the append-only chain.

**No gas is evaluated.** Every gas state is `NOT_EVALUATED` and every gas value is `null`, so a B1 record is only ever `FAIL` or `UNRESOLVED`, never `ELIGIBLE_FOR_FOUNDER_REVIEW`. Gas is WP4-B2. Nothing is ever `CHAIN_PROVEN`.

| File | Role |
|---|---|
| `record.mjs` | Record schema and state rules (§6.1), digest (§6.2), chain validation (§6.3) |
| `core.mjs` | `evaluateGateF(inputs, policy)` (§2–§3, §5); pure; the policy is a parameter |
| `verify.mjs` | Operational `verifyGateF(inputs)`: **refuses every subject**, since no Stage B policy exists (ADR-RN-020 D1) |
| `test-seam.mjs` | **TEST ONLY**: a synthetic-preparation intent stands in for a hypothetical Stage B subject. Its importers are pinned by `tools/gate-f.test.mjs` |
| `build-gate-f-fixtures.mjs` | Builds `fixtures/gate-f-b1/cases.json` from a simulated chain (SYNTHETIC) |

What it does not contain:
- no command line;
- no network, transport, clock, environment, key, signer or write path;
- no import of `chain-submit`. The submission and status digests are recomputed here, and the tests cross-check them.

It does not change preparation, signing, submission, finality policy, the S1 allowlist or any live switch.
