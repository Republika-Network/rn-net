# RN-NET

RN-NET is the development lane for **Republika Network**: a planned,
blockchain-agnostic layer for independently verifying evidence produced by
governed autonomous operations, and for anchoring cryptographic commitments to
that evidence on public test networks.

## Status

**Early implementation (RN-NET-01).** This repository contains the canonical
JSON profile, the evidence commitment format, their specifications and
conformance vectors, and repository security guards. It contains no evidence
verifier, no anchoring code and no real evidence; all test inputs are synthetic.

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

Conformance vectors live in [`vectors/`](vectors/) and are checked by two
independent implementations: the JavaScript packages
([`packages/conformance/`](packages/conformance/)) and a Python reference
([`tools/reference/`](tools/reference/)). Everything runs on Node.js 22 and
Python 3 built-ins only; there are no third-party dependencies.

## Contributing and security

Changes reach `main` only through pull requests that pass the required checks.
Run the same checks locally:

```sh
node --import ./tools/offline.mjs --test "tools/*.test.mjs" "tools/guards/*.test.mjs" "packages/*/test/*.test.mjs"
python3 -I -B tools/reference/rnnet_reference.py
node tools/guards/run.mjs
```

Tests run with network access blocked (`tools/offline.mjs`).

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).
