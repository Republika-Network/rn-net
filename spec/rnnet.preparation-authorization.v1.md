# rnnet.preparation-authorization.v1 and the live preparation entry point

- Status: Draft (RN-NET-03B2-C3). Implemented offline; **disabled for live network access**.
- Decision records: [ADR-RN-018](../docs/adr/ADR-RN-018-transaction-preparation-reads.md) Amendment C1
  (Proposed) and [ADR-RN-019](../docs/adr/ADR-RN-019-controlled-testnet-broadcasting.md) Amendment C1,
  E1 and E2 (Proposed)
- Depends on: [rnnet.tx-preparation.v1](rnnet.tx-preparation.v1.md), [rnnet.canonical-json.v1](rnnet.canonical-json.v1.md)
- Implementation: `tools/prepare/` (`authorization.mjs`, `entry.mjs`, `policy.mjs`, `evidence.mjs`, `prepare-live.mjs`)
- Tests: `tools/prepare-live.test.mjs`; the command line: `tools/broadcast/live-disabled.check.mjs`

## 1. Purpose

One founder-written authorization of **one read-only preparation run**: one network, the two
reviewed providers, one sender, the Genesis Proof 01 commitment and an exact request count. It
authorizes reads only. It authorizes no key, no signature, no write and none of gates B to F.

## 2. The authorization

Canonical JSON (optionally followed by one newline), exactly these members:

| Member | Value |
|---|---|
| `format` | `"rnnet.preparation-authorization.v1"` |
| `authorizationId` | 1 to 64 lower-case letters, digits and inner hyphens; names the run directory |
| `network` | `"xrpl:testnet"` or `"evm:11155111"` |
| `purpose` | `"genesis-proof-01"` |
| `commitment` | `sha256:<64 lower-case hex>`; the entry point accepts only the Genesis Proof 01 commitment |
| `providerIds` | the two reviewed providers of the network, in reading order |
| `sender` | XRPL: a classic address; Sepolia: a lower-case address |
| `signingPubKey` | XRPL: `ED` + 64 upper-case hex, whose classic address is `sender`; Sepolia: `null` |
| `requestBudget` | exactly 4 on XRPL, 16 on Sepolia (2 × the per-provider request list) |
| `notAfter` | `YYYY-MM-DDTHH:MM:SSZ`; at most 60 minutes after the run starts |
| `scope` | 1 to 1000 printable ASCII characters, written by the founder |

**Digest:** `sha256:` + hex of SHA-256(`"rnnet:preparation-authorization:v1\0"` ‖ canonical bytes).

## 3. The entry point

`tools/prepare/prepare-live.mjs --network <n> --authorization <file> --endpoints <file> --evidence-dir <dir>`:
exactly these four flags, each once. There is no retry, fee, field, provider, block or force
option. While `LIVE_NETWORK_ACCESS` is `false` (RN-NET-03B2-C3), the command exits 3 with
`RNPL_LIVE_DISABLED` before reading anything.

Checks, in order. Each failure ends the run with nothing read:
1. the flags, the network (no mainnet) and the agreed evidence directory (`AGREED_EVIDENCE_DIR`,
   `null` in C3: `RNPL_DIRECTORY_NOT_AGREED`);
2. the authorization: a private file (absolute path, regular, not a link, mode 0600, owned by this
   user, at most 64 KiB) of the form in §2 (`RNPL_AUTHORIZATION`);
3. its network is `--network` (`RNPL_NETWORK_MISMATCH`); its commitment and purpose are Genesis
   Proof 01's (`RNPL_NOT_GENESIS`); its budget is exact; on XRPL its sender is its key's address;
4. `notAfter` has not passed (`RNPL_AUTHORIZATION_EXPIRED`) and is at most 60 minutes ahead;
5. the endpoint file holds exactly the reviewed providers (id, network, URL and operator), and
   they are the authorization's `providerIds` (`RNPL_ENDPOINTS_NOT_REVIEWED`);
6. Sepolia only: both providers are recorded (`SEPOLIA_COMPATIBILITY`, from the C6 read-only
   check, ADR-RN-018 Amendment C1, P5) as accepting the block-hash object on the account reads and
   on `eth_estimateGas`. Otherwise the outcome is `BLOCKED` (`RNPL_COMPATIBILITY_UNRECORDED`), with
   the reason `BLOCK_HASH_READ_REFUSED` or `GAS_ESTIMATION_UNAVAILABLE`, before any read. In C3
   nothing is recorded, so Sepolia is always blocked here;
7. the founder's typed approval: `<network> <last 16 hex digits of the authorization digest>`;
8. the time is read again, after the approval (`notAfter` is checked again), and is the `now` that
   preparation checks freshness against;
9. `<evidence-dir>` is private (0700, this user's, not a link), and `<evidence-dir>/<authorizationId>/`
   is created (0700). It must not exist (`RNPL_AUTHORIZATION_USED`): one run per authorization,
   whatever its outcome.

Then `packages/tx-prepare` runs ([rnnet.tx-preparation.v1](rnnet.tx-preparation.v1.md)) through
the request policy (§4).

## 4. The request policy

Checked before the transport sees a request; a refused request is never sent, and the run is
`REFUSED` with `RNPL_REQUEST_POLICY`:
- only the two providers, each at its configured URL;
- per provider, exactly the request list of rnnet.tx-preparation.v1 §3, in order, once each;
- every request in its planned form: XRPL `server_info` `{api_version: 2}` and `account_info` of
  the authorized sender at `"validated"`; Sepolia the head by `["latest", false]`, the pin by
  number (one number for both providers, only after both head passes), and the pinned reads only
  after both pins, each with the same `{blockHash, requireCanonical: true}` object, the pending
  nonce excepted;
- no write method is in any plan.

## 5. Outcomes and evidence

| Outcome | Exit | Meaning |
|---|---|---|
| `PREPARED` | 0 | An intent was prepared. It is **not approved**: gate D is the founder's approval by digest in the key tool, a separate authorization |
| `REFUSED` | 2 | An entry check or a preparation check failed (`RNPL_*` or `RNTP_*`) |
| `LIVE_DISABLED` | 3 | The command line in RN-NET-03B2-C3 |
| `BLOCKED` | 4 | Sepolia cannot be prepared under the reviewed strategy: §3 step 6, or a refused pinned read (rnnet.tx-preparation.v1 §4.4). Never retried another way |

After step 9, the run writes in its directory, exclusively and durably (mode 0600, the file and the
directory fsynced):
- `response-NN.bin`: each response body, as received;
- `evidence.json`, `rnnet.preparation-evidence.v1` (canonical JSON): `authorizationId`,
  `authorizationDigest`, `network`, `providerIds`, `observedAt`, `outcome`, `code`, `providerId`,
  `blocked`, `intentDigest` (or `null`), `requestCount`, and `exchanges`, one per request sent:
  `{providerId, request, requestSha256, status, responseSha256, responseFile}` or
  `{providerId, request, requestSha256, error}`;
- `intent.json`, when prepared: the intent's canonical JSON. It is the key tool's `--intent`.

Evidence stays private (ADR-RN-019 §7). Nothing here is proof of anything on a chain (ADR-RN-015).
