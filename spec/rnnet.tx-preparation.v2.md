# rnnet.tx-preparation.v2: fork-aware Sepolia preparation record

- Status: **Proposed**, with an offline implementation (RN-NET-03B2-WP3). It follows
  [ADR-RN-018 Amendment C2](../docs/adr/ADR-RN-018-transaction-preparation-reads.md) (Proposed),
  G1–G10 and founder decision Q4. Nothing here authorizes live preparation, a read authorization
  (H6), signing or broadcasting.
- Implementation: `packages/tx-prepare/src/prepare-v2.mjs` (`prepareSepoliaIntentV2`,
  `verifySepoliaPreparationV2`). The gas rules come from `packages/tx-intent/src/gas-rules.mjs`
  (WP2). The independent reference is `tools/reference/rnnet_prep_v2_reference.py`, and the
  fixtures are `fixtures/preparation-v2/cases.json`.
- Supersedes nothing. [rnnet.tx-preparation.v1](rnnet.tx-preparation.v1.md) stays in force,
  unchanged, for XRPL, for the C1 Sepolia path, and for every existing record and fixture.

## 1. Scope

v2 is the record of a **Sepolia** preparation made under Amendment C2.
- XRPL keeps v1. There is no XRPL v2.
- A C2 Sepolia preparation produces v2 only. The C1 path (`prepareSepoliaIntent`) produces v1
  only, and v1 records are never rewritten or upgraded.
- The record is the `preparation` member of an
  [rnnet.unsigned-tx-intent.v1](rnnet.unsigned-tx-intent.v1.md) intent, so the intent digest
  covers all of it.

## 2. Requests

The requests are exactly those of v1 §3 for Sepolia (ADR-RN-018 C1 P1–P3):
- **Three passes:** head, pin, pinned;
- **8 requests per provider:** `eth_chainId`, `eth_getBlockByNumber` (`latest`),
  `eth_getBlockByNumber` (P), `eth_getTransactionCount` (H), `eth_getTransactionCount`
  (`pending`), `eth_getBalance` (H), `eth_getCode` (H), `eth_estimateGas` (H);
- one attempt each, no retry, no fallback. Every H read carries
  `{"blockHash": H, "requireCanonical": true}`.

16 requests for the two reviewed providers. v2 adds no request.

## 3. Members

The record is plain canonical JSON (rnnet.canonical-json.v1). Every listed member is required,
and **no other member is allowed**, at any level. Integers are JSON integers in the safe range:
no floats, strings or defaults.

```
{ "format": "rnnet.tx-preparation.v2",
  "source": "rpc-read",
  "rules": "ADR-RN-018-C2",
  "observedAt": <integer: the preparation time, Unix seconds>,
  "gas": {
    "ruleSetId": "prague" | "amsterdam",
    "fork": <string: the reviewed activation in force at the pin, e.g. "osaka">,
    "reviewDigest": "sha256:<hex of SHA-256 of the canonical JSON of review>",
    "review": { "reviewedAt", "reviewer", "horizon", "sources", "knownUnreviewedActivations" },
    "standard": <integer>, "floor": <integer>, "need": <integer>,
    "gasLimit": 30000 },
  "providers": [ <entry>, ... ] }
```

`gas.review` is the rules-review record of C2 G5 R2 (Q1), exactly as the authority holds it.
`sources` is exactly the seven pinned G2 sources, each `{source, revision, sha256}`, in the
order of `REVIEWED_GAS_RULE_SOURCES`.

Each provider entry, in the order the providers were given:
- `id`, `operator`;
- `block`: `{number, hash, timestamp, baseFeePerGas}` of the pinned block P. It is the same on
  every entry (one agreed pin);
- `code`: the `eth_getCode` result at H, which is `"0x"` in every accepted record;
- `estimateGas`: the `eth_estimateGas` result at H, as received;
- `exchanges`: exactly 8 `{method, requestSha256, responseSha256}`, in the §2 order.

**No duplicated value without a consistency rule.**
- The pin timestamp is `providers[*].block.timestamp`; there is no separate copy.
- `gas.gasLimit` must equal the transaction's `gas` (`0x7530`).
- `gas.reviewDigest` must equal the digest of `gas.review`.
- `gas.ruleSetId` and `gas.fork` must equal the selection at the pin timestamp.

## 4. How a v2 record is made (the refusal order)

1. **Input:** exactly `commitment`, `from`, `now`, `providers`, `transport`. Each field is read
   once, and the providers must be plain data. The C1 provider checks apply.
2. **The rules authority at `now`:** a missing, malformed, future-dated (`reviewedAt > now`) or
   expired review, a wrong source, or a horizon past 30 days or past a known unreviewed activation
   is refused **before any request**.
3. **Head pass, pin, pinned pass** with the C1 checks: freshness, skew, one hash per number, the
   pin precedes the head, the same pin hash and contents, and per provider the pending nonce and
   `code == "0x"`.
4. **Nonce agreement;** the fee from the pin; the completed transaction, with gas fixed at
   30,000.
5. **The WP2 engine** on that transaction, the pin timestamp, `now`, the authority and each
   provider's code:
   - `pin ≤ now`;
   - the review horizon;
   - the boundary window;
   - the preconditions;
   - `need`.
6. **Per provider:** estimate > 30,000 is refused (`RNTP_GAS_TOO_HIGH`); estimate < `need` is
   refused (`RNTP_INCONSISTENT`). No other tolerance applies: an estimate is an upper bound by
   design.
7. Balance ≥ 30,000 × `maxFeePerGas`.
8. The record and the intent, built once.

Engine refusals use the existing codes (C2 G5): `RNTP_GAS_TOO_HIGH` for the limit, and
`RNTP_INCONSISTENT` otherwise. The property `gasRules` carries the exact `RNTX_GAS_*` code.

**Change from v1.** v1 checks the estimate inside the pinned pass against the Prague bound.
v2 checks it after the engine, against the fork-aware need.

**The estimate.** An estimate in range shows numerical consistency with the reviewed rule set. It
does **not** show that the provider honored the block hash (C2 G8, G9).

## 5. The rules authority

The operational path takes the review from one reviewed constant, `SEPOLIA_GAS_RULES_REVIEW` in
`packages/tx-intent/src/gas-rules.mjs`. That constant is **null**, so every operational v2
preparation and verification is refused.
- Recording a review is a separate governance change. It must not be filled in from a clock, a
  file, a provider answer or caller input.
- No operational parameter changes the authority, the activation table or the rule set. An extra
  input member is refused.
- The `…WithAuthority` functions take an explicit review for synthetic TEST records only. They are
  not exported from `packages/tx-prepare`, a repository test pins their importers, and the guard
  forbids joining tx-prepare to any transport.

## 6. Verification

`verifySepoliaPreparationV2(intent, approvedDigest)` checks, in this order:
1. the intent and that `approvedDigest` is its digest;
2. the exact structure of §3. An unsupported `format` is refused (`RNTP_INTENT_INVALID`), and that
   includes v1;
3. one agreed pin across entries;
4. gas `0x7530` and `gasLimit` 30,000, and `maxFeePerGas` as the pin's base fee implies;
5. the WP2 engine re-run on the transaction, the pin timestamp, `observedAt`, the authority and the
   recorded codes;
6. `gas.review` equals the authority. `ruleSetId`, `fork`, `reviewDigest`, `standard`, `floor`,
   `need` and `gasLimit` each equal the recomputation;
7. every estimate within `[need, 30000]`.

Responses are not in the record. A verifier holding the exchanges, such as the Python reference
with the fixtures, also re-reads every response against its digest.

## 7. Versions

- v1 is verified only under v1. v2 is verified only under v2. A format mismatch is a refusal,
  never a fallback.
- No default treats an unknown or future version as v2.
- Changing a format string is not a migration. A v1 record relabelled v2 fails §6.2 (missing
  `gas`, `code`) or the digest.

## 8. Known conflict and limits (reported, not changed here)

- **The intent specification names only v1 as the preparation record.**
  [rnnet.unsigned-tx-intent.v1](rnnet.unsigned-tx-intent.v1.md) §2 describes `preparation` as
  "an rnnet.tx-preparation.v1 record … or {source: synthetic}", but `makeIntent` accepts any
  object. The signer, txverify and the broadcaster never read `preparation`. They act on the
  approved digest. So a v2 intent is neither interpreted as v1 nor explicitly refused by them.
  Making later gates require a known preparation version is an acceptance-policy change for a
  later work package (WP4). This document does not make it.
- **No operational caller.** `tools/prepare/` (disabled), the C3 rehearsal and gate F do not call
  v2.
- **The verifier cannot see responses.** It cannot detect a pin timestamp altered consistently on
  every entry and re-approved. The digest and the founder's approval cover that; the response
  digests bind it for a verifier that has the exchanges.
