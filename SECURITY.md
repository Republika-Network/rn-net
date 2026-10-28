# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on this repository.
Do not open a public issue for a suspected vulnerability.

Please include the affected file or component, the steps to reproduce, and
the impact you expect. You will receive an acknowledgement in the advisory
thread.

## Scope

This repository is pre-implementation. It runs no service, holds no funds and
operates no network. In scope today: the repository guards, the CI workflow,
and any content that should not have been published.

## Key material

- No private key, seed, mnemonic, API token or credential may ever be committed
  to this repository or stored in its CI configuration.
- Future testnet anchoring keys will be held by the founder, outside GitHub and
  outside CI. This repository will only ever contain public addresses and
  public keys.
- If you find credential-like material in this repository, report it as a
  vulnerability even if it appears to be a test value.

## Supported versions

No version has been released. There are no supported releases yet.
