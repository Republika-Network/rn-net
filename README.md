# RN-NET

RN-NET is the development lane for **Republika Network**: a planned,
blockchain-agnostic layer for independently verifying evidence produced by
governed autonomous operations, and for anchoring cryptographic commitments to
that evidence on public test networks.

## Status

**Early implementation (RN-NET-01 to RN-NET-03B1).** This repository contains:

- the canonical JSON profile and the evidence commitment format;
- an independent, offline evidence verifier for one original, synthetic evidence
  format (`rnnet.synthetic-evidence.v1`), with Ed25519 signature checks and a
  deterministic verification report;
- an offline anchoring foundation: a 42-byte anchor payload for a commitment, and checks of
  *supplied* XRPL Testnet and Ethereum Sepolia transaction data, with a dual-chain report;
- read-only reading of anchoring transactions from reviewed public XRPL Testnet and Sepolia RPC
  providers (`packages/chain-readonly/`, `tools/verify-live-anchor.mjs`), with provider comparison,
  captures and offline replay. It never signs or submits anything;
- their specifications, conformance vectors and second implementations;
- repository security guards.

It submits no transactions and holds no keys. Only `tools/verify-live-anchor.mjs`, when run in
live mode, contacts a network, and only with read-only methods. What providers report stays a
claim: nothing here is an authenticated proof of chain inclusion (`CHAIN_PROVEN` is never
produced). All test inputs, including every transaction record, are synthetic.
The verifier establishes integrity and signature consistency under keys the
evidence carries. It does **not** establish signer identity, policy enforcement or
that any described event happened (see the
[report specification](spec/rnnet.verification-report.v1.md)).

- **No operating network exists.** There are no nodes, no federation and no
  service to connect to.
- **Testnet-only intended scope.** The first planned anchoring targets are
  XRPL Testnet and Ethereum Sepolia. Mainnet use is out of scope.
- **No consensus.** RN-NET does not implement or claim a consensus protocol,
  Byzantine fault tolerance or decentralization.
- **No financial or execution authority.** RN-NET does not execute payments,
  issue authorizations or capabilities, or sign artifacts on behalf of any
  other system. It only reads evidence and verifies it.
- **No tokens.** No token, staking, smart contract or tokenomics is planned.

## Licensing

**No software license has been granted yet.** Licensing is pending legal
confirmation. Until a `LICENSE` file is added to this repository, all rights
are reserved, and nothing here may be reused except as permitted by law or
by GitHub's Terms of Service for viewing and forking public repositories.

## Relationship to other projects

RN-NET is downstream of Soberanía Protocol and Frontera and is maintained
separately from them. It does not include, and must not include, source code,
documentation text, specifications or artifacts from those projects unless
their use has been expressly authorized and recorded in this repository.

## Roadmap

| Package | Scope |
|---|---|
| RN-NET-01 | Canonical evidence commitment specification and test vectors |
| RN-NET-02 | Independent, offline evidence verifier |
| RN-NET-03 | XRPL Testnet and Ethereum Sepolia anchoring with verifiable receipts |
| RN-NET-04 | Federation of signed verifier attestations (not consensus) |
| RN-NET-05 | Public testnet beta |

Architecture decisions are recorded in [`docs/adr/`](docs/adr/README.md).

## Specifications

| Specification | Implementation |
|---|---|
| [`rnnet.canonical-json.v1`](spec/rnnet.canonical-json.v1.md) | [`packages/canonical/`](packages/canonical/) |
| [`rnnet.evidence-commitment.v1`](spec/rnnet.evidence-commitment.v1.md) | [`packages/commitment/`](packages/commitment/) |
| [`rnnet.verification-taxonomy.v1`](spec/rnnet.verification-taxonomy.v1.md) | [`packages/commitment/`](packages/commitment/) |
| [`rnnet.synthetic-evidence.v1`](spec/rnnet.synthetic-evidence.v1.md) | [`packages/verifier/`](packages/verifier/README.md) |
| [`rnnet.verification-report.v1`](spec/rnnet.verification-report.v1.md) | [`packages/verifier/`](packages/verifier/README.md) |
| [`rnnet.anchor-payload.v1`](spec/rnnet.anchor-payload.v1.md) | [`packages/anchor/`](packages/anchor/README.md) |
| [`rnnet.anchor-record.v1`](spec/rnnet.anchor-record.v1.md) | [`packages/anchor/`](packages/anchor/README.md) |
| [`rnnet.live-observation-report.v1`](spec/rnnet.live-observation-report.v1.md) | [`packages/chain-readonly/`](packages/chain-readonly/) |

Conformance vectors live in [`vectors/`](vectors/) (format described in
[`vectors/README.md`](vectors/README.md)) and are checked by two implementations:
the JavaScript packages ([`packages/conformance/`](packages/conformance/)) and a
Python reference ([`tools/reference/`](tools/reference/)) written from the
specifications. The two share a similar structure, so agreement between them is
evidence, not proof, of correctness. Everything runs on Node.js 22 and Python 3
built-ins only. The runtime packages have no dependencies; repository tooling has one pinned
development dependency, the Acorn parser used by the dependency-boundary guard
([ADR-RN-005](docs/adr/ADR-RN-005-guard-parser-dependency.md)). Install it with
`npm ci --ignore-scripts` before running the tests or guards.

To verify an evidence file locally (offline; it reads only the paths given and holds no keys):

```sh
node tools/verify-evidence.mjs evidence.json                     # report on stdout
node tools/verify-evidence.mjs evidence.json \
  --commitment envelope.json --commitment-digest sha256:<hex>     # also check a commitment
```

Exit codes: 0 `PASS`, 1 `FAIL`, 2 `UNSUPPORTED`, 64 usage error, 66 unreadable input. See
[`packages/verifier/README.md`](packages/verifier/README.md) for the API.

To check supplied anchoring data for a commitment on both test networks (offline; same exit
codes; see [`packages/anchor/README.md`](packages/anchor/README.md)):

```sh
node tools/verify-anchors.mjs --commitment sha256:<hex> --xrpl xrpl-observation.json --evm sepolia-observation.json
```

To read a real anchoring transaction from reviewed providers (read-only; providers by id from
[`config/rpc-endpoints.json`](config/rpc-endpoints.json)), and to replay a capture offline:

```sh
node tools/verify-live-anchor.mjs --network sepolia --tx 0x<hash> --commitment sha256:<hex> --compare-providers --capture cap.json
node tools/verify-live-anchor.mjs --offline-replay cap.json --commitment sha256:<hex>
```

Exit codes: 0 `PASS`, 1 `FAIL`, 2 `UNSUPPORTED`, 3 `INDETERMINATE` (no provider available), 64
usage error, 66 unreadable input, 73 output cannot be created.

Behaviour changes to the JavaScript API, and what consumers can rely on, are recorded in
[`docs/api-compatibility.md`](docs/api-compatibility.md).

## Contributing and security

Changes reach `main` only through pull requests that pass the required checks.
Required checks are not a substitute for independent review; see
[`docs/governance/review-process.md`](docs/governance/review-process.md).

Run the same checks as CI locally, in a network namespace without network access:

```sh
npm ci --ignore-scripts                  # the guard's parser, before going offline
unshare -rn tools/ci/offline-checks.sh   # syntax, tests, Python reference; proves isolation first
tools/ci/offline-checks.test.sh          # the isolation script fails closed
node tools/guards/run.mjs
```

Network isolation comes from the namespace: an operating-system boundary. The test
preload (`tools/offline.mjs`) is JavaScript-level instrumentation that only adds
defense in depth by making common Node network, worker and subprocess APIs throw;
it is not a sandbox. Likewise the dependency guard is a source lint, not a sandbox. Without `unshare`, the
tests can be run directly with
`node --import ./tools/offline.mjs --test "tools/*.test.mjs" "tools/guards/*.test.mjs" "packages/*/test/*.test.mjs"`
and `python3 -I -B tools/reference/rnnet_reference.py` (and `rnnet_evidence_reference.py`, `rnnet_anchor_reference.py`), but then nothing
enforces that they stay offline.

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).
