# ADR-RN-009: Anchor payload and domain encoding

- Status: Proposed (RN-NET-03A)
- Date: 2026-10-29
- Specification: [rnnet.anchor-payload.v1](../../spec/rnnet.anchor-payload.v1.md)

## Context

RN-NET-03 anchors one `rnnet.evidence-commitment.v1` commitment on two unrelated public test
networks, XRPL Testnet and Ethereum Sepolia. A verifier must recover the same commitment from
each network's transaction data, independently and without ambiguity. Ledger space is limited,
and anything placed in it is public and permanent.

## Decision

1. **A raw byte payload, not JSON.** It is 42 bytes:
   - the ASCII magic `RNNETANC`;
   - a version byte, `01`;
   - a commitment-format byte, `01` = `rnnet.evidence-commitment.v1`;
   - the 32 raw digest bytes.

   It has no variable-length fields, no integers and so no byte order, and nothing to
   canonicalize. It is the smallest encoding that names itself, its version and its digest
   format.
2. **One payload for every network.** The same bytes are used on every network. Only the
   transport differs: an XRPL memo, or Ethereum transaction input. The two can therefore be
   compared byte for byte.
3. **Domain separation by position.**
   - The magic identifies an RN-NET anchor. No other RN-NET structure begins with it: canonical
     JSON begins with a JSON value, and the domain separators begin with `rnnet:`.
   - The version and format bytes separate future payloads and commitment formats from v1.
4. **Strict decoding in a fixed order.** The version is checked before the length, so a later
   version is "unsupported" rather than "malformed". Trailing bytes are rejected.
5. **A commitment, never the evidence.** The payload contains only the commitment. No
   evidence, personal data, keys, signatures or URLs are ever placed on a ledger.

## Consequences

- **Fixed output.** Any party can rebuild the expected payload from the commitment alone and
  compare it with ledger data.
- **What an anchor reveals.** It reveals only a digest, which is meaningless without the
  evidence. Whether the evidence is ever published is a separate decision.
- **Format changes.** A future change (another digest, more fields) gets a new version byte or
  format code. v1 decoders report it as unsupported.
