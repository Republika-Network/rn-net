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
- **Exact requests.** XRPL: `server_info`, `account_info`. Sepolia: `eth_chainId`, the latest
  block, then the nonce (pinned and `pending`), balance, code and gas estimate, pinned to that
  block. One attempt each, no retry.
- **Bounds stay fixed.** The fee, gas, chain and form bounds are ADR-RN-016's, re-checked by
  `makeIntent` after binding. The providers can make preparation refuse; they cannot widen a
  bound.
- **No key, no signing, no write method, no network code.** The package depends only on
  `packages/chain-readonly`, `packages/tx-intent`, `Buffer` and `createHash`. Nothing depends on
  it.
- **Offline only.** In RN-NET-03B2-B2, the only transports are simulated providers and the
  recorded exchanges of [`fixtures/preparation-b2/`](../../fixtures/preparation-b2/). There is no
  live entry point. A live preparation run belongs to gate D and needs its own approval.
