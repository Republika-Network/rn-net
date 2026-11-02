# packages/tx-prepare

**Read-only transaction preparation (RN-NET-03B2-B2, [ADR-RN-018](../../docs/adr/ADR-RN-018-transaction-preparation-reads.md), [spec](../../spec/rnnet.tx-preparation.v1.md)).**

`prepareXrplIntent` and `prepareSepoliaIntent` do four things:
- they read account and fee state from 2 to 4 providers, through a transport the caller injects;
- they refuse stale, inconsistent or malformed data;
- they bind the Genesis template's `null` fields (ADR-RN-016);
- they return an `rnnet.unsigned-tx-intent.v1` intent and its digest, for approval by digest.

Its `preparation` member records the observations and the SHA-256 of every exchange.

- **Fails closed.** Every refusal is a `PrepError` with one `RNTP_*` code and the provider it
  concerns, and gives no intent.
- **Exact requests.** XRPL: `server_info`, `account_info` (2 per provider). Sepolia (ADR-RN-018
  Amendment C1), 8 per provider in three passes:
  - `eth_chainId` and the latest block on every provider;
  - the pin (the lowest head − 2) by number, with one hash on every provider;
  - the nonce, balance, code and gas estimate at `{blockHash, requireCanonical: true}`, and the
    pending nonce.

  One attempt each, no retry, no fallback. A refused pinned read is `RNTP_PROVIDER_ERROR`, marked
  `blocked`.
- **XRPL expiry.** `LastLedgerSequence` = the lower validated ledger + 80 (ADR-RN-016 Amendment C1).
- **Bounds stay fixed.** The fee, gas, chain and form bounds are ADR-RN-016's, re-checked by
  `makeIntent` after binding. The providers can make preparation refuse; they cannot widen a
  bound.
- **No key, no signing, no write method, no network code.** The package depends only on
  `packages/chain-readonly`, `packages/tx-intent`, `Buffer` and `createHash`. Nothing depends on
  it.
- **Offline only.** The only transports are simulated providers and the recorded exchanges of
  [`fixtures/preparation-b2/`](../../fixtures/preparation-b2/). The live entry point
  ([`tools/prepare/`](../../tools/prepare/), RN-NET-03B2-C3) is disabled for live network access.
  A live preparation run needs its own `rnnet.preparation-authorization.v1`.
