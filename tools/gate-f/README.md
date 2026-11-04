# tools/gate-f — offline durable gate-F verification (WP4-B1, B1-SEC-01, WP4-B2)

ADR-RN-020 (Proposed) · spec `rnnet.gate-f-sepolia-verification.v1`

**Partial and offline.** B1 covers:
- the subject;
- the binding of the intent, signed bytes, txverify record and submission record;
- the offline replay of an `rnnet.rpc-capture.v1` capture through the existing reader;
- inclusion and provider-reported finality (ADR-RN-015, unchanged; CONFLICT is preserved and is FAIL);
- `t_i` from the captured inclusion block linked to the PublicNode walk;
- the strict record, its digest and the append-only chain.

**Gas (WP4-B2, `gas.mjs`), offline.** It covers:
- the receipt gas evidence (§3.6);
- the integrity of the recorded v2 gas member (§4.1, through the WP2 engine);
- the inclusion rule set from the linked `t_i` and the verifier's reviewed history only (§4.2);
- same-rule and fork-crossing accounting (§4.3).

Gas runs only with a linked `t_i` (PublicNode `IN_ANCESTRY`).

**Authority stays null.** Operationally:
- the review history is the reviewed constant `SEPOLIA_GAS_RULES_REVIEW`, which is null, so the history is empty;
- a supplied `reviewHistory` must equal it;
- the subject is refused at §3.1 whatever its gas.

So the operational result is never `ELIGIBLE_FOR_FOUNDER_REVIEW`. Only the TEST ONLY Stage B stand-in can reach rule 3, and only on synthetic vectors. Nothing is ever `CHAIN_PROVEN`.

| File | Role |
|---|---|
| `record.mjs` | Record schema and state rules (§6.1), digest (§6.2), chain validation (§6.3) |
| `core.mjs` | §2–§3 and §5; pure. Exports `evaluateGateFOperational(inputs)` (accepts no subject; the history is the reviewed constant), the TEST ONLY B1 `evaluateGateFTestStandIn(inputs)` (synthetic subject, no gas member; unchanged) and the TEST ONLY B2 `evaluateGateFTestStandInStageB(inputs, stageBPreparation)` (the same subject, plus a v2 preparation and a TEST ONLY history). **No caller can supply an eligibility rule** (WP4-B1-SEC-01 R2) |
| `gas.mjs` | §4: `verifierReviewHistory()`, `checkReviewHistory`, `isPreparationV2`, `verifyRecordedGas`, `inclusionRuleSet`, `evaluateRecordedGas`. Pure; the history is an argument, passed only by `core.mjs` |
| `verify.mjs` | Operational `verifyGateF(inputs)`: **refuses every subject**, since no Stage B policy exists (ADR-RN-020 D1) |
| `test-seam.mjs` | **TEST ONLY**: wraps the two stand-in evaluators (`verifyGateFHypotheticalStageB`, `verifyGateFHypotheticalStageBGas`) |
| `build-gate-f-fixtures.mjs` | Builds `fixtures/gate-f-b1/`, `gate-f-b1-sec01/` and `gate-f-b2/` `cases.json` from a simulated chain (SYNTHETIC; the B1 and SEC-01 files are byte-identical to their merged versions) |

What it does not contain:
- no command line;
- no network, transport, clock, environment, key, signer or write path;
- no import of `chain-submit`. The submission and status digests are recomputed here, and the tests cross-check them.

**Importer pins.** The repository guard enforces them (`dependency-boundaries` `GATE_F_RESTRICTED`):
- `core.mjs` may be imported only by `verify.mjs` and the seam;
- `gas.mjs` only by `core.mjs` and `tools/gate-f-gas.test.mjs`;
- the seam only by the two gate-F tests and the builder;
- the builder only by the two gate-F tests.

Any other import of these files, or any code file naming them, fails the guard, and no `import()` with a computed path is allowed in this directory. JavaScript cannot hide an export from a file that imports `core.mjs`, so this guard, which CI runs on every change, is the enforcement point.

**Provider comparison.** It follows spec §3.3.1 (WP4-B1-SEC-01 R1):
- a material difference, or a missing observation that another provider contradicts, is `FAIL`;
- a difference in finality only is decided by the §3.4 table;
- any `CONFLICT`, on the `finalized` or the `safe` walk, is `FAIL` and is always recorded.

It does not change preparation, signing, submission, finality policy, the S1 allowlist or any live switch.
