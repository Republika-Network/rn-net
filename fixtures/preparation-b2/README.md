# fixtures/preparation-b2 (RN-NET-03B2-B2)

**Synthetic preparation cases.** No provider was contacted, and nothing here was or can be sent
to a network.

`cases.json` (`rnnet.preparation-b2-fixtures.v1`) holds 71 cases: 10 accepted and 61 refused,
covering every `RNTP_*` code. Each case has:
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
