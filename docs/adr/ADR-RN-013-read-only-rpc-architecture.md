# ADR-RN-013: Read-only RPC architecture

- Status: Proposed (RN-NET-03B1)
- Date: 2026-10-29
- Specification: [rnnet.live-observation-report.v1](../../spec/rnnet.live-observation-report.v1.md) §2–§4

## Context

RN-NET-03A verifies supplied transaction data offline. RN-NET-03B1 must read real transactions from
public XRPL Testnet and Sepolia RPC providers.

That reading must not weaken anything already in place:

- the offline packages;
- the network-isolated CI;
- the dependency guard, which forbids network code under `packages/`.

It also must not open a path to writing, signing or arbitrary destinations.

## Decision

1. **The package opens no connections.** `packages/chain-readonly` contains no network code. It
   takes an injected transport and builds every request itself.
   - Method names come from an exact per-network allowlist: XRPL `server_info`, `tx` and `ledger`;
     Ethereum `eth_chainId`, `eth_getTransactionByHash`, `eth_getTransactionReceipt`,
     `eth_getBlockByHash` and `eth_getBlockByNumber`.
   - No other method can be expressed, so no signing, submitting or account method can be called.
   - The dependency guard keeps it this way: the package may use only `Buffer`, `createHash`,
     `canonical` and `anchor`, and `fetch` and the network modules are refused. No guard exception
     was needed.
2. **One network-capable file.** The single network transport is `tools/live/https-transport.mjs`.
   - It speaks HTTPS only and verifies certificates.
   - It follows no redirects and enforces a deadline and a response-size limit.
   - It refuses, at connection time, any destination that resolves to a non-public address. That
     covers SSRF and DNS rebinding.
   - The CLI loads it only in live mode.
3. **Endpoints come from a reviewed allowlist** (`config/rpc-endpoints.json`), changed only by pull
   request.
   - Entries are HTTPS, on DNS host names, with no credentials, query or fragment.
   - The CLI accepts provider ids, never URLs. Nothing in evidence or responses can name a
     destination.
   - There is no fallback between networks or to Mainnet.
4. **Bounded work.** One request is in flight at a time, with these limits:
   - at most 2 attempts, and the second only on timeouts, connection failures, 429 and 502–504;
   - 600 attempts per provider, retries included (at least twice the most a reading can need, so
     the budget never cuts a finality walk short);
   - 256 KiB per response;
   - 10 s per request.

   There is no polling, no pagination and no background process.
5. **Strict parsing.** Responses are parsed as strict JSON: duplicate keys are refused, the depth is
   limited, and objects have a null prototype. Numbers that are not safe integers have no canonical
   form, so they cannot enter an observation.
6. **Offline tests.** All tests use injected simulated servers inside the existing network
   namespace. The live path runs only on explicit request, and never in CI.

## Consequences

- **What the package cannot do.** It cannot reach a network even if misused, and adding a method
  requires a reviewed change to the allowlist.
- **Endpoint list.** The initial list is proposed in this PR, from xrpl.org's published public
  servers and two public Sepolia endpoints. Its approval is the founder's decision. Public endpoints
  may rate-limit or disappear, and endpoints that need API keys are not supported in v1.
- **What TLS establishes.** It authenticates the endpoint operator's server, not the truth of what
  that server reports (ADR-RN-015).
