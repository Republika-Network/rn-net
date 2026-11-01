# RN-NET-03B1 live read-only smoke tests: public summary

- Status: Record (RN-NET-03B2-A)
- Scope: connectivity checks of the reviewed providers in
  [`config/rpc-endpoints.json`](../../config/rpc-endpoints.json), each under its own founder
  authorization. Only read-only methods were used. No key, account, signature or transaction was
  involved.
- **Raw RPC captures are kept locally by the operator and are not published.** This summary
  holds only:
  - requests RN-NET wrote;
  - public chain values;
  - digests of the local evidence files.

## SMOKE-01

| Network | Provider | Result |
|---|---|---|
| XRPL Testnet | `xrpl-testnet-ripple` (Ripple) | PASS |
| XRPL Testnet | `xrpl-testnet-xrpl-labs` (XRPL Labs) | PASS |
| Sepolia | `sepolia-publicnode` (PublicNode) | PASS |
| Sepolia | `sepolia-drpc` (dRPC, since removed) | Unavailable: `eth_chainId` returned HTTP 400 with JSON-RPC error 35, "chain is not available on free plan" |

**Follow-up.** PR #9 (RN-NET-03B1-RPC-01, `2382ddf`) replaced dRPC with Automata 1RPC.

**Evidence status: not independently re-verified.**

- **Not recovered.** The SMOKE-01 raw RPC captures **could not be recovered**: a search of the
  RN-NET workspace and its scratch areas during RN-NET-03B2-A found none.
- **No digests.** No SHA-256 digests of them are recorded anywhere in this repository.
- **Not re-verified.** SMOKE-01 has therefore **not been independently re-verified**.
- **Source of the results.** The table above holds the founder-recorded outcomes. The dRPC error
  text is quoted from PR #9.
- **Nothing filled in.** No evidence or digest has been reconstructed or substituted for the
  missing captures.

## SMOKE-02

| Item | Value |
|---|---|
| Authorization | One run; provider `sepolia-1rpc` only; at most 2 HTTP requests including retries; `eth_getBlockByNumber` only if `eth_chainId` = `0xaa36a7` |
| Repository commit | `2382ddf0f33c9e3b40b3fb4ab20180290932efae` |
| Endpoint | `https://public.1rpc.io/sepolia` (Automata 1RPC), through `tools/live/https-transport.mjs` |
| Time (UTC) | 2026-11-01 18:19:16.136 to 18:19:18.797 |
| Requests | **2** (2 TLS connections; no retries) |
| Offline checks before the run | 543/543 tests; Python reference 177/177, 69/69, 120/120; harness self-test 9/9 |
| **Outcome** | **PASS** |

**Requests**, exact bytes in canonical JSON:

| # | Request body | SHA-256 | HTTP |
|---|---|---|---|
| 1 | `{"id":1,"jsonrpc":"2.0","method":"eth_chainId","params":[]}` | `7cd718c15e7d48ea187956a752c86b96515cded0520142627ba5da9729233bee` | 200 |
| 2 | `{"id":1,"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["finalized",false]}` | `1b1529f7594d853300cbdaa5f35809d510658615527b735970e7a7ee464dbeba` | 200 |

**Reported public values:**

| Value | |
|---|---|
| Chain ID | `0xaa36a7` (11155111) |
| Finalized block number | 12042415 (`0xb7c0af`) |
| Finalized block hash | `0xe2e3894506c632fc79b44d38dcc9bd0dba887b2c695dff977f45b14dc8be41c3` |
| Parent hash | `0x9d1f7616aa5d80e8c81483743c7484d52159dcca9fb7e9661618eaaa8fe6e79d` |
| Block timestamp | `0x6ae772d4` = 2026-11-01 17:11:48 UTC |
| Base fee | `0x11` (17 wei) |

**Reproduce.** Anyone can check the block against any Sepolia source by its number:
`eth_getBlockByNumber("0xb7c0af", false)`. The `hash` must equal the value above.

**Local evidence digests.** These identify the operator's local files. The files themselves are
not published.

| File | SHA-256 |
|---|---|
| `exchanges.json` (request and response bytes, timings) | `fd00acf752d8e5260eb2d02bfacc9be81f08df80d052f751a0a7ff04b92f50f1` |
| `summary.json` | `f332a7e1dfc454a5180587d888ccd12f64bed5d25fe185d82a9f6a81e9b516ee` |
| Response 1 body | `52b41408ada7aa0d74c2cab3c5e9b1e8845bc1601e5e46dae6c58bbd47fb7f4c` |
| Response 2 body | `91e5418cb5c1bd21f47eaee694c75502e1ad9f7214810af188d8c68987c53752` |
| Scratch harness (not in the repository) | `1b00d5e0b18408c12af352720da4bbabd8e1853d0ebd57986755add734fe9767` |

The two evidence-file digests were re-verified with `sha256sum -c` during RN-NET-03B2-A.

**Method.** The harness called the reviewed `httpsTransport` directly, once per request:

- **No retries.** It did not go through `call()`, which retries.
- **Request bodies:** built with `requestBytes`.
- **Endpoint:** taken from `loadEndpointConfig` and checked by id, URL and network.
- **Two caps:** a send counter that refuses a third request, and a counter of TLS connections that
  ends the process on a third.

### Observation: 1RPC finalized-block lag

**Unresolved operational observation.** The finalized block 1RPC reported has a timestamp about
**67 minutes** older than the request (17:11:48 against 18:19:16 UTC). Sepolia finality normally
trails the chain head by about 13 to 15 minutes (two epochs).

Possible causes, none of which has been established:

- a stale or cached view at the provider;
- a real delay in Sepolia finality at that time;
- an older node behind the endpoint.

What this means for anchoring:

- A single provider's `finalized` tag is not used as the finality signal.
- Genesis Proof 01 compares both reviewed Sepolia providers and uses the more conservative view: the lower (older) of the two finalized block numbers
  ([preflight §3.5](../genesis/genesis-proof-01-preflight.md#35-after-submission-what-verification-must-show)).
- Resolving the lag needs a separately authorized, read-only comparison of the finalized block on
  `sepolia-publicnode` and `sepolia-1rpc` at the same moment.
