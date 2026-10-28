# RN-NET

RN-NET is the development lane for **Republika Network**: a planned,
blockchain-agnostic layer for independently verifying evidence produced by
governed autonomous operations, and for anchoring cryptographic commitments to
that evidence on public test networks.

## Status

**Pre-implementation.** This repository currently contains governance files,
CI and repository security guards only. It contains no verifier, no anchoring
code and no evidence.

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

## Contributing and security

Changes reach `main` only through pull requests that pass the required checks.
Run the repository guards locally with Node.js 22:

```sh
node --test "tools/guards/*.test.mjs"
node tools/guards/run.mjs
```

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).
