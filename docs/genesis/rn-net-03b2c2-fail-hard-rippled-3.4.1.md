# RN-NET-03B2-C2: `submit` with `fail_hard` in rippled 3.4.1

- Status: **finding recorded** (ADR-RN-019 Amendment C1, E6). It changes no classification class;
  the classifier stays conservative. The amendment itself stays **Proposed**.
- Source read: [XRPLF/rippled](https://github.com/XRPLF/rippled) tag `3.4.1`, tag object `33619157`,
  commit `00e640751460c137636fdb6dae6b4280de355d81`. This is public source code, read as text. No
  XRPL server was contacted, and rippled was not run.
- Why this version: both XRPL Testnet providers reported `build_version` `3.4.1` in the recorded
  RN-NET-03B1-SMOKE capture (2026-10-29). The C6 read-only run must check the version again: if a
  provider runs another version, that version's source is read before gate E-XRPL.
- Naming in 3.4.1: namespace `xrpl`, flag `TapFailHard` (not `tapFAIL_HARD`), handler
  `src/xrpld/rpc/handlers/transaction/Submit.cpp`.

## 1. How `fail_hard` reaches the engine

- `Submit.cpp` (`getFailHard`) parses it. A non-boolean value is an error, and nothing is processed.
- `doSubmit` calls `processTransaction(tx, unlimited, bLocal = true, failType)`. With
  `bLocal = true` this runs `doTransactionSync`, which applies the transaction before it answers.
- `NetworkOPsImp::apply` adds `TapFailHard` to the apply flags and calls `TxQ::apply`.

## 2. What each result does under `fail_hard`

Quoted lines below were checked against the source at the commit above.

- **tec: discarded.** `src/libxrpl/tx/Transactor.cpp`:
  ```cpp
  if (isTecClaim(result) && ((view().flags() & TapFailHard) != 0u))
  {
      // If the TapFailHard flag is set, a tec result
      // must not do anything
      ctx_.discard();
      canApplyTmp = false;
  }
  ```
  The transaction is not applied: no fee is claimed and the Sequence is not used.
- **The exception: `tecINVARIANT_FAILED`.** The `TapFailHard` check runs before the invariant
  checks. A `tes` result that then fails an invariant becomes `tecINVARIANT_FAILED`, is reset to
  fee-only, and **is applied** to the open ledger. It needs a rippled defect, but it is a path by
  which a tec answer comes with an applied transaction. (Read from the control flow; not tested.)
- **Never relayed or kept unless tes.** `src/xrpld/app/misc/NetworkOPs.cpp`:
  ```cpp
  auto const enforceFailHard = e.failType == FailHard::Yes && !isTesSuccess(e.result);
  if (addLocal && !enforceFailHard) { ... e.transaction->setKept(); }
  if ((e.applied || ... || (e.result == terQUEUED)) && !enforceFailHard) { /* relay */ }
  ```
- **Never queued.** `src/xrpld/app/misc/detail/TxQ.cpp` (`TxQ::canBeHeld`):
  ```cpp
  // TapFailHard transactions are never held
  if (tx.isFieldPresent(sfPreviousTxnID) || tx.isFieldPresent(sfAccountTxnID) ||
      ((flags & TapFailHard) != 0u))
      return telCAN_NOT_QUEUE;
  ```
  Every path to `terQUEUED` goes through this check. Under `fail_hard`, a fee below the
  open-ledger cost gives `telCAN_NOT_QUEUE`, never `terQUEUED`.
- **The response flags.** `Submit.cpp`: `accepted` is `applied || broadcast || queued || kept`. If
  the result is still the default `temUNCERTAIN`, `engine_result` and every flag are left out.
- **tesSUCCESS:** applied to **that server's open ledger** only, with `broadcast` true unless the
  same transaction was relayed recently. The engine's own text is "The transaction was applied.
  Only final in a validated ledger." Later retries at ledger close run without `fail_hard`, so the
  final result can still be a tec, or no inclusion at all.
- **tefPAST_SEQ:** in this server's open view, the account's Sequence is already past the
  transaction's. This transaction, or another with that Sequence, may already be in a ledger that is
  not yet validated.
- **tefALREADY:** this exact transaction is already in this server's open ledger, so it was
  applied earlier and probably relayed.
- **tefNO_TICKET:** what an already-applied Ticket-based transaction gets back. The Genesis
  intents use a Sequence, never a Ticket.
- **Timeout, connection loss:** the request runs to completion with no cancellation;
  `doTransactionSync` applies and relays before the answer is built. A client that times out or
  disconnects learns nothing about whether the transaction was applied and relayed. At each ledger
  close, `OpenLedger::accept` also relays transactions of the open ledger not relayed recently.

## 3. Classification, unchanged in its classes

| Answer under `fail_hard` | Applied | Relayed | Kept | Queued | RN-NET class |
|---|---|---|---|---|---|
| `tesSUCCESS`, accepted, broadcast, not queued | yes (open ledger) | yes | yes | no | `ACCEPTED_PROVISIONAL`: never inclusion or finality |
| `tesSUCCESS`, any other flags | yes | maybe later | — | — | `UNCERTAIN` (flags) |
| tec*, every flag false | no | no | no | no | `UNCERTAIN` (kept) |
| tec* with `applied` true (invariant failure) | yes | at next close | no | no | `UNCERTAIN` |
| `terQUEUED` | cannot occur | | | | `UNCERTAIN` (an inconsistent answer) |
| `tefPAST_SEQ`, `tefALREADY`, `tefNO_TICKET` | — | — | — | — | `UNCERTAIN`: this or a same-Sequence transaction may be in a ledger |
| other tef*, tel*, tem*, other ter*, every flag false | no | no | no | no | `REJECTED` |
| no `engine_result`, RPC error, HTTP error, timeout, disconnect | unknown | unknown | unknown | unknown | `UNCERTAIN` |

**Why tec* stays `UNCERTAIN`, although rippled discards it:**
1. the `tecINVARIANT_FAILED` path is applied;
2. the answer describes one server's open view, not a validated ledger;
3. the signed blob stays valid until `LastLedgerSequence`, and a provider (or anyone holding the
   blob) may submit it again without `fail_hard`.

`UNCERTAIN` costs only a status check. Reclassifying tec* as `REJECTED` would allow a resend
without one. That would need its own reviewed amendment, with the classifier and its Python
reference changed together, and the founder has not asked for it.

**What `REJECTED` means here:** this submission did nothing on this server. It does not mean the
blob can never be included: until a validated ledger passes `LastLedgerSequence`, it can be. The
log rules hold either way: after `REJECTED`, only a resend of **the same** blob is permitted, and a
replacement needs a `RESOLVED EXPIRED` status finding first.

## 4. What C2 changed

- `tefNO_TICKET` joins `tefALREADY` and `tefPAST_SEQ` as `UNCERTAIN`. This only tightens the
  classifier: JavaScript, Python reference and fixtures were changed together.
- Fixture cases `xrpl-tef-no-ticket` and `xrpl-tec-discarded-under-fail-hard` were added.
- The classifier's header now cites this finding.

## 5. Remaining ambiguity, not assumed away

- The invariant-failure path was read from the control flow; it was not exercised.
- When `tefALREADY` occurs for a Sequence-based transaction was not fully traced (`tefPAST_SEQ`
  normally comes first). Both are `UNCERTAIN`, so the answer does not depend on it.
- `broadcast: true` means rippled called its relay function, not that a peer received the
  transaction. With no peers it is still true.
- Whether an `internalSubmit` exception can follow a change to the open ledger was not settled.
  Such an answer has no `engine_result` and is `UNCERTAIN`.
- If the server had seen the transaction before, it answers from its cached copy. Not analysed
  further.
- The xrpl.org documentation quoted in the full notes is the current site, not a versioned
  snapshot.
- Each provider runs its own build. `build_version` is read again at C6, and must be `3.4.1`, or the
  other version's source must be read, before gate E-XRPL.
