# fixtures/preparation-b2 (RN-NET-03B2-B2)

**Synthetic preparation cases.** No provider was contacted, and nothing here was or can be sent
to a network.

`cases.json` (`rnnet.preparation-b2-fixtures.v2`) holds 94 cases: 13 accepted and 81 refused,
covering all 15 `RNTP_*` codes and both blocked reasons.

RN-NET-03B2-C3 regenerated it:
- **XRPL** binds `LastLedgerSequence` = the lower validated ledger + 80 (ADR-RN-016 Amendment C1).
  The recorded exchanges are unchanged, so each accepted XRPL intent differs from its B2 version
  only by `LastLedgerSequence` (+ 60).
- **Sepolia** follows ADR-RN-018 Amendment C1: a head pass, the pin (the lowest head − 2) agreed by
  hash, then reads pinned to `{blockHash, requireCanonical: true}`, 8 requests per provider.
- **New field.** `expected.blocked` marks a refused pinned read (`BLOCK_HASH_READ_REFUSED` or
  `GAS_ESTIMATION_UNAVAILABLE`).

Each case has:
- the inputs (the commitment, the sender, `now` and the providers);
- every exchange: the exact request text, and the response status and body or the transport
  error;
- the expected result: the intent and its digest, or the refusal code and provider.

**What is made up:**
- **The providers.** `*.fixture.invalid` hosts, which cannot resolve.
- **The values.** All ledger, block, balance, nonce and fee values.
- **The senders.** The public test-key addresses of [`fixtures/signing-b1`](../signing-b1/),
  derived from public labels. They are never identities and must never be funded.

**Rebuilding.** `node tools/preparation/build-b2-fixtures.mjs` checks that the file is current.
`--write` writes it and refuses to overwrite an existing file. The expected codes are stated by
hand in that script.

**Independent checks.**
- `tools/preparation.test.mjs` replays every case through `packages/tx-prepare` from the recorded
  exchanges alone.
- `tools/reference/rnnet_prep_reference.py` reproduces every case without the JavaScript code.
