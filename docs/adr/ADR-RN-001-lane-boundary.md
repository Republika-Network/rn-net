# ADR-RN-001: Lane boundary and authority

- Status: Accepted
- Date: 2026-10-28

## Context

Republika Network is intended to verify evidence produced by governed
autonomous operations and to anchor commitments to that evidence on public
test networks, without depending on any single blockchain.

The systems that produce such evidence already exist and are maintained
separately, under their own licenses, security invariants and release
processes. A verification layer that could change those systems, or act on
their behalf, would weaken the independence it exists to provide.

## Decision

1. **Downstream and read-only.** RN-NET consumes evidence as files plus their
   digests. It never modifies, calls into or deploys any upstream system or
   repository.
2. **No authority.** RN-NET does not execute payments, issue authorizations
   or capabilities, or sign artifacts on behalf of any other system. Its only
   future signatures are its own anchoring transactions and, later, its own
   verification attestations.
3. **Testnet only.** Anchoring targets are XRPL Testnet and Ethereum Sepolia.
   Mainnet networks are refused by name in configuration and code.
4. **Founder-held keys.** Testnet anchoring keys are generated and held by the
   founder outside GitHub and outside CI. The repository contains only public
   addresses and public keys. CI never signs or submits transactions.
5. **No tokens, staking, smart contracts or consensus.** Commitments are
   carried by ordinary transactions. A future federation consists of
   independently signed attestations, not a consensus protocol, and running
   several nodes is not a claim of decentralization.
6. **Clean room.** No source code, documentation text, specification text or
   artifact from a proprietary or private repository enters this repository
   unless a written authorization covering it is recorded here first.
7. **Verified versus claimed.** Every RN-NET output distinguishes facts
   verified cryptographically by RN-NET from claims it could not verify, such
   as who held a signing key.

## Enforcement

| Rule | Mechanism |
|---|---|
| Key material never tracked | `.gitignore`, `forbidden-paths` and `secret-shapes` guards, GitHub push protection |
| Clean room | `upstream-content` guard, pull request checklist |
| Format namespace | `format-namespace` guard (`rnnet.*` only) |
| Changes reviewed and checked | `main` ruleset: pull requests only, required checks bound to GitHub Actions |
| CI cannot write or sign | Read-only workflow token, no repository secrets or environments |

## Consequences

- Verifying any upstream evidence format requires either a public
  specification or an explicit written authorization from its owner.
- Upstream fixes that RN-NET needs, such as additional exported fields, must
  be requested through the upstream project's own process.
- Single-maintainer review is a known limitation: the founder can edit
  repository rulesets, and this is visible only through the audit log.
