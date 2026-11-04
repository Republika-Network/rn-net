# rnnet.tx-preparation.v2: fork-aware Sepolia preparation record (Stage A candidate)

- Status: **Proposed**, with an offline implementation (RN-NET-03B2-WP3, revised in WP3-R1 after
  RN-NET S1, #40). It follows
  [ADR-RN-018 Amendment C2](../docs/adr/ADR-RN-018-transaction-preparation-reads.md) (Proposed),
  G1–G10 and Q4 with its two-stage lifecycle. Nothing here authorizes live preparation, a read
  authorization (H6), signing or broadcasting.
- Implementation:
  - the candidate envelope: `packages/tx-intent/src/candidate.mjs` (`makePreparationCandidate`,
    `candidateDigest`, `verifiedPreparationCandidate`);
  - preparation and verification: `packages/tx-prepare/src/prepare-v2.mjs`
    (`prepareSepoliaCandidateV2`, `verifySepoliaCandidateV2`);
  - the gas rules: `packages/tx-intent/src/gas-rules.mjs` (WP2);
  - the independent reference `tools/reference/rnnet_prep_v2_reference.py`, and the fixtures
    `fixtures/preparation-v2/cases.json`.
- Supersedes nothing. [rnnet.tx-preparation.v1](rnnet.tx-preparation.v1.md) stays in force,
  unchanged, for XRPL, for the C1 Sepolia path, and for every existing record and fixture.

## 1. Scope and lifecycle

v2 is the record of a **Sepolia** preparation made under Amendment C2.
- XRPL keeps v1. There is no XRPL v2.
- A C2 Sepolia preparation produces v2 only. The C1 path produces v1 only, and v1 records are
  never rewritten or upgraded.

**Two stages (C2 Q4):**
- **Stage A, implemented here:** the record travels in a **candidate**,
  `rnnet.tx-preparation-v2-candidate.v1` (§5), with its own digest domain. A candidate is **not**
  an `rnnet.unsigned-tx-intent.v1`, and it is not a signing or broadcasting authorization.
- **Stage B, not implemented, not accepted:** an approved intent whose `preparation` is the v2
  record. It needs:
  - a separately reviewed acceptance-policy amendment, adding v2 to the S1 allowlist of
    `makeIntent` with full downstream format and semantic verification;
  - the complete verified record bound to the intent digest;
  - founder authorization.

  Until then every intent consumer refuses a v2 preparation (S1).

## 2. Requests

The requests are exactly those of v1 §3 for Sepolia (ADR-RN-018 C1 P1–P3):
- **Three passes:** head, pin, pinned;
- **8 requests per provider:** `eth_chainId`, `eth_getBlockByNumber` (`latest`),
  `eth_getBlockByNumber` (P), `eth_getTransactionCount` (H), `eth_getTransactionCount`
  (`pending`), `eth_getBalance` (H), `eth_getCode` (H), `eth_estimateGas` (H);
- one attempt each, no retry, no fallback. Every H read carries
  `{"blockHash": H, "requireCanonical": true}`.

16 requests for the two reviewed providers. v2 adds no request.

## 3. The v2 record

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
  every entry;
- `code`: the `eth_getCode` result at H, which is `"0x"` in every accepted record;
- `estimateGas`: the `eth_estimateGas` result at H, as received;
- `exchanges`: exactly 8 `{method, requestSha256, responseSha256}`, in the §2 order.

**Consistency rules** (no duplicated value without one):
- The pin timestamp is `providers[*].block.timestamp`; there is no separate copy.
- `gas.gasLimit` equals the transaction's `gas` (`0x7530`).
- `gas.reviewDigest` equals the digest of `gas.review`.
- `gas.ruleSetId` and `gas.fork` equal the selection at the pin timestamp.

## 4. How a record is made (the refusal order)

1. **Input:** exactly `commitment`, `from`, `now`, `providers`, `transport`. Each field is read
   once, and the providers must be plain data. The C1 provider checks apply.
2. **The rules authority at `now`:** a missing, malformed, future-dated or expired review, a wrong
   source, or a horizon past 30 days or past a known unreviewed activation is refused **before
   any request**.
3. **Head pass, pin, pinned pass** with the C1 checks, including, per provider, the pending nonce
   and `code == "0x"`.
4. **Nonce agreement;** the fee from the pin; the completed transaction, with gas fixed at
   30,000.
5. **The WP2 engine:** `pin ≤ now`, the horizon, the boundary window, the preconditions, `need`.
6. **Per provider:** estimate > 30,000 is `RNTP_GAS_TOO_HIGH`; estimate < `need` is
   `RNTP_INCONSISTENT`. An estimate is an upper bound by design, so no other tolerance applies.
7. Balance ≥ 30,000 × `maxFeePerGas`.
8. The record and its **candidate** (§5), built once.

Engine refusals use the existing codes (C2 G5): `RNTP_GAS_TOO_HIGH` for the limit, and
`RNTP_INCONSISTENT` otherwise. The property `gasRules` carries the exact `RNTX_GAS_*` code.

**The estimate.** An estimate in range shows numerical consistency with the reviewed rule set. It
does **not** show that the provider honored the block hash (C2 G8, G9).

## 5. The Stage A candidate

```
{ "format": "rnnet.tx-preparation-v2-candidate.v1",
  "network": "evm:11155111",
  "purpose": "genesis-proof-01",
  "commitment": "sha256:<hex>",
  "transaction": <the completed Genesis Sepolia transaction, as in an intent: type 0x2, to == from,
                  value 0x0, input = the payload, gas 0x7530, maxFeePerGas from the pin, accessList []>,
  "preparation": <the §3 record> }
```

- **Members:** exactly these six. The `transaction` passes the same checks as an intent's
  (`checkSepoliaAnchorTx`, nonce below 2^64). The `preparation` top level is exactly the §3 keys,
  with `format` `rnnet.tx-preparation.v2`.
- **Serialization:** rnnet.canonical-json.v1.
- **Digest:** `"sha256:" + hex(SHA-256("rnnet:tx-preparation-v2-candidate:v1\0" ‖ canonical
  bytes))`. **It is not the intent digest.** The domains differ, so the same bytes never give the
  same digest in both.
- **Refusals.** The envelope functions refuse every other format, network, purpose or member,
  with `RNTX_INTENT_INVALID`; that includes an `rnnet.unsigned-tx-intent.v1`, a v1 record and a
  future version. A digest that is not the candidate digest, such as an intent-domain digest, is
  `RNTX_INTENT_DIGEST_MISMATCH`. Preparation and the verifier report both as
  `RNTP_INTENT_INVALID`.
- **No authority.**
  - `makeIntent`, `approvedIntent`, the signer, the keytool, txverify, the hand-off, the
    broadcaster and status refuse a candidate, because its `format` is not the intent format.
  - A candidate relabelled as an intent is refused by the S1 allowlist, because its preparation
    is v2.
  - No adapter disguises v2 as v1 or synthetic.

## 6. The rules authority

The operational path takes the review from one reviewed constant, `SEPOLIA_GAS_RULES_REVIEW`
(`packages/tx-intent/src/gas-rules.mjs`). That constant is **null**, so every operational
preparation and verification is refused.
- Recording a review is a separate governance change. No clock, file, provider answer or caller
  input sets it.
- No operational parameter changes the authority, the activation table or the rule set.
- The `…WithAuthority` functions take synthetic TEST reviews only. They are not exported from
  `packages/tx-prepare`, a repository test pins their importers, and the guard forbids joining
  tx-prepare to any transport.

## 7. Verification

`verifySepoliaCandidateV2(candidate, digest)` checks, in this order:
1. the candidate envelope and that `digest` is its candidate digest (§5);
2. the exact §3 structure. `source`, `rules` and `observedAt` are checked, and an unsupported
   preparation format is refused (`RNTP_INTENT_INVALID`);
3. one agreed pin across entries;
4. gas `0x7530` and `gasLimit` 30,000, and `maxFeePerGas` as the pin's base fee implies;
5. the WP2 engine re-run on the transaction, the pin timestamp, `observedAt`, the authority and the
   recorded codes;
6. `gas.review` equals the authority. `ruleSetId`, `fork`, `reviewDigest`, `standard`, `floor`,
   `need` and `gasLimit` each equal the recomputation;
7. every estimate within `[need, 30000]`.

A verified candidate grants nothing. Responses are not in the record; a verifier holding the
exchanges, such as the Python reference, also re-reads every response against its digest.

## 8. Versions

- v1 is verified only under v1. v2 is verified only under v2, and only as a candidate.
- A format mismatch is a refusal, never a fallback. No default treats an unknown or future
  version as v2.
- Changing a format string is not a migration.

## 9. Limits

- **No operational caller.** `tools/prepare/` (disabled), the C3 rehearsal and gate F do not call
  v2.
- **The verifier cannot see responses.** It cannot detect a pin timestamp altered consistently on
  every entry and re-digested. The response digests bind it for a verifier that has the exchanges.
- **Stage B, a v2 intent, is a future acceptance-policy change** (§1). The earlier conflict with
  the intent specification is resolved by S1 and this two-stage lifecycle: the intent protocol
  still names only v1 and synthetic, and now enforces that.
