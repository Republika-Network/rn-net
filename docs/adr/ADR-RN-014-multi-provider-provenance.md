# ADR-RN-014: Multi-provider observation and provenance

- Status: Proposed (RN-NET-03B1)
- Date: 2026-10-29
- Specification: [rnnet.live-observation-report.v1](../../spec/rnnet.live-observation-report.v1.md) §7–§8

## Context

**One provider.** A single provider can be wrong, stale, misconfigured or malicious.

**Several providers.** Asking several helps operationally, but only if disagreement is reported
rather than averaged away. Even then, two URLs may share infrastructure.

**Replay.** A verification should also be repeatable without the network, from the exact bytes
received.

## Decision

1. **Each provider is read and checked on its own.** For each one the report records:
   - its id and operator;
   - its outcome: observed, not found, unavailable, invalid, wrong network, or inconsistent;
   - its observation digest and material digest;
   - its RN-NET-03A record.
2. **Agreement.** This is a comparison of material digests, including "not found":
   - `AGREEMENT`: two or more comparable answers, all equal;
   - `DISAGREEMENT`: any two differ. This always makes the report `FAIL`;
   - `INSUFFICIENT_SOURCES`: exactly one;
   - `SOURCE_UNAVAILABLE`: none.

   There is no majority vote. A provider that answers inconsistently, or for another network, also
   fails the report.
3. **Agreement is `CLAIMED`.** It is never more. Independence of the providers' infrastructure is
   explicitly not established.
4. **Deterministic report.** The report depends only on the response bytes. It contains no times,
   URLs or response text.
5. **Captures.** A capture (`rnnet.rpc-capture.v1`) holds the provenance:
   - the exact request and response bytes with digests;
   - provider ids, operators and origins, but no URL path;
   - the retrieval time.

   Captures are written only on request, never over existing files.
6. **Replay.** Replay reproduces the report byte for byte with no network. Any request the capture
   does not contain is an error, never "unavailable".

## Consequences

- **Data retention.** Captures contain only public chain data and public endpoint origins. They are
  kept only where the operator writes them, and nothing is retained by default.
- **What a capture proves.** It proves which bytes were received, not that they are true.
- **What multiple providers do.** They increase confidence in operations, not cryptographic
  assurance (ADR-RN-015).
