# packages/tx-intent

The approved unsigned transaction of RN-NET-03B2-B1 (ADR-RN-017, `spec/rnnet.unsigned-tx-intent.v1.md`).

- **`rnnet.unsigned-tx-intent.v1`:** the intent, checked and frozen by `makeIntent`, and its digest from `intentDigest`.
- **The ADR-RN-016 checks:** `checkXrplAnchorTx` and `checkSepoliaAnchorTx`, moved here unchanged from `tools/genesis/prepare.mjs`, which re-exports them.
- **XRPL:** binary encoding and decoding of the Genesis `AccountSet` only, in canonical field order, with base58check addresses and the signing preimage and transaction hash.
- **Sepolia:** strict RLP, and EIP-1559 type-2 encoding and decoding.
- **Comparison:** decoded signed bytes against the intent, in a fixed order, so both verifiers report the same error code.

This package has no keys, does no signing or hashing with Keccak, and never touches the network. Signing and signature checks live in `signer/`.

- **Dependencies:** `packages/canonical`, `packages/anchor`, and the Node.js built-ins `Buffer`, `createHash` and `types` (from `node:util`).
