# fixtures/broadcast-b3 (RN-NET-03B2-B3)

**Synthetic broadcaster runs.** No provider was contacted, and nothing here was or can be sent to a network.

`cases.json` (`rnnet.broadcast-b3-fixtures.v1`) holds 165 submit runs and 11 status checks, covering 57 distinct outcome codes. Each case has:
- the inputs (intent text, approved digest, signed transaction, authorization, any supplied records) and the second verifier's record;
- the submission log before the run;
- every exchange: the exact request text, and the response status and body or the transport error;
- the expected result: outcome, code, request and write counts, the record and its digest, and the log entries the run appended.

**What is made up:**
- **The providers.** `*.fixture.invalid` hosts, which cannot resolve.
- **The values.** All ledger, block, balance, nonce, fee and engine-result values.
- **The transactions.** The B1 signed fixtures (`fixtures/signing-b1`), their altered copies, and two replacement transactions signed by the generator with the same label-derived test keys. Anyone can recompute those keys; their addresses must never be funded. The broadcaster itself never sees a key.

**Rebuilding.** `node tools/broadcast/build-b3-fixtures.mjs` checks that the file is current. `--write` writes it and refuses to overwrite an existing file. The expected outcomes and codes are stated by hand in that script.

**Independent checks.**
- `tools/broadcast.test.mjs` replays every case through `tools/submit/` from the recorded exchanges alone.
- `tools/reference/rnnet_broadcast_reference.py` reproduces every case without the JavaScript code, and confirms each second-verifier record with `rnnet_tx_reference.py`.
