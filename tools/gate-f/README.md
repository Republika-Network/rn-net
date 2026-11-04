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
| `core.mjs` | §2–§3 and §5; pure. Exports `evaluateGateFOperational(inputs)` (accepts no subject) and the TEST-ONLY `evaluateGateFTestStandIn(inputs)` (accepts a synthetic-preparation intent only). **No caller can supply an eligibility rule** (WP4-B1-SEC-01 R2) |
| `verify.mjs` | Operational `verifyGateF(inputs)`: **refuses every subject**, since no Stage B policy exists (ADR-RN-020 D1) |
| `test-seam.mjs` | **TEST ONLY**: wraps the stand-in evaluator |
| `build-gate-f-fixtures.mjs` | Builds `fixtures/gate-f-b1/cases.json` and `fixtures/gate-f-b1-sec01/cases.json` from a simulated chain (SYNTHETIC) |

What it does not contain:
- no command line;
- no network, transport, clock, environment, key, signer or write path;
- no import of `chain-submit`. The submission and status digests are recomputed here, and the tests cross-check them.

**Importer pins.** The repository guard enforces them (`dependency-boundaries` `GATE_F_RESTRICTED`):
- `core.mjs` may be imported only by `verify.mjs` and the seam;
- the seam only by `tools/gate-f.test.mjs` and the builder;
- the builder only by the test.

Any other import of these files, or any code file naming them, fails the guard, and no `import()` with a computed path is allowed in this directory. JavaScript cannot hide an export from a file that imports `core.mjs`, so this guard, which CI runs on every change, is the enforcement point.

**Provider comparison.** It follows spec §3.3.1 (WP4-B1-SEC-01 R1):
- a material difference, or a missing observation that another provider contradicts, is `FAIL`;
- a difference in finality only is decided by the §3.4 table;
- any `CONFLICT`, on the `finalized` or the `safe` walk, is `FAIL` and is always recorded.

It does not change preparation, signing, submission, finality policy, the S1 allowlist or any live switch.
